use blake2::digest::generic_array::arr::Inc;
use eyre::Result;
use rand::{thread_rng, Rng};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    vec,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        Mutex,
    },
};

const DEFAULT_TTL: u8 = 7;
const DEFAULT_SEND_TO_N: u32 = 100;

// TODO: context ID a la kafka // half done

/// MessageTypes have IDs:
/// 0: Message
/// 1: MessageAnswer
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum MessageEnum {
    Message(Message),
    MessageAnswer(MessageAnswer),
}
impl Deserialize for MessageEnum {
    fn deserialize(&self) -> Result<Vec<u8>> {
        match self {
            MessageEnum::Message(msg) => msg.deserialize(),
            MessageEnum::MessageAnswer(msg) => msg.deserialize(),
        }
    }
}

trait Deserialize {
    fn deserialize(&self) -> Result<Vec<u8>>;
}

// 1 + 8 + 2 + 16 + ?
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageAnswer {
    message_type: u8,
    message_length: u64,
    route_id: u16,

    context: u128,

    data: Vec<u8>,
}
impl MessageAnswer {
    pub fn new_from_data(route: u16, context_id: u128, data: Vec<u8>) -> MessageAnswer {
        MessageAnswer {
            message_type: 1,
            /// Hardcoded currently
            message_length: 27 + data.len() as u64,
            route_id: route,
            context: context_id,
            data,
        }
    }

    async fn from_readable(readable: &mut (dyn AsyncRead + Unpin + Send)) -> Result<MessageAnswer> {
        let message_type: u8 = readable.read_u8().await?;
        let message_length: u64 = readable.read_u64().await?;

        // Have to convert u64 to usize so message buffer in huge messages could fail
        let mut message_buffer: Vec<u8> = vec![0; (message_length - 9).try_into()?];

        readable.read_exact(&mut message_buffer).await?;

        let message = MessageAnswer {
            message_type,
            message_length,
            route_id: u16::from_be_bytes(message_buffer[0..2].try_into()?),
            context: u128::from_be_bytes(message_buffer[2..18].try_into()?),
            data: message_buffer[18..].to_vec(),
        };

        Ok(message)
    }
}
impl Deserialize for MessageAnswer {
    fn deserialize(&self) -> Result<Vec<u8>> {
        let deserialized: Vec<u8> = vec![
            self.message_type.to_be_bytes().to_vec(),
            self.message_length.to_be_bytes().to_vec(),
            self.route_id.to_be_bytes().to_vec(),
            self.context.to_be_bytes().to_vec(),
            self.data.to_vec(),
        ]
        .concat();

        Ok(deserialized)
    }
}

// 1 + 8 + 2 + 1 + 1 + 8 + 16 + ? = 36bytes + ? bytes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Message {
    message_type: u8,
    /// Hardcoded Currently
    message_length: u64,
    route_id: u16,
    broadcasting_type: u8,
    /// 0 message to all, 1 get answer from first peer
    time_to_live: u8,
    timestamp: i64,

    context: u128,

    data: Vec<u8>,
}
impl Message {
    /// broadcasting_type: 0 message to all, 1 get answer from first peer
    pub fn new_from_data(route: u16, broadcasting_type: u8, data: Vec<u8>) -> Message {
        Message {
            message_type: 0,
            /// Hardcoded Currently
            message_length: 37 + data.len() as u64,
            route_id: route,
            broadcasting_type,
            time_to_live: DEFAULT_TTL,
            timestamp: chrono::Utc::now().timestamp(),
            context: thread_rng().gen(),
            data,
        }
    }

    async fn from_readable(readable: &mut (dyn AsyncRead + Unpin + Send)) -> Result<Message> {
        let message_type: u8 = readable.read_u8().await?;
        let message_length: u64 = readable.read_u64().await?;

        // Have to convert u64 to usize so message buffer in huge messages could fail
        let mut message_buffer: Vec<u8> = vec![0; (message_length - 9).try_into()?];

        readable.read_exact(&mut message_buffer).await?;

        let message = Message {
            message_type,
            message_length,
            route_id: u16::from_be_bytes(message_buffer[0..2].try_into()?),
            broadcasting_type: message_buffer[2],
            time_to_live: message_buffer[3],
            timestamp: i64::from_be_bytes(message_buffer[4..12].try_into()?),
            context: u128::from_be_bytes(message_buffer[12..28].try_into()?),
            data: message_buffer[28..].to_vec(),
        };

        Ok(message)
    }
}
impl Deserialize for Message {
    fn deserialize(&self) -> Result<Vec<u8>> {
        let deserialized: Vec<u8> = vec![
            self.message_type.to_be_bytes().to_vec(),
            self.message_length.to_be_bytes().to_vec(),
            self.route_id.to_be_bytes().to_vec(),
            [self.broadcasting_type].to_vec(),
            [self.time_to_live].to_vec(),
            self.timestamp.to_be_bytes().to_vec(),
            self.context.to_be_bytes().to_vec(),
            self.data.to_vec(),
        ]
        .concat();

        Ok(deserialized)
    }
}

#[derive(Debug)]
struct MessageContoller {
    // Messages from here will be send periodacally
    queue_to_send: UnboundedReceiver<MessageEnum>,
    cache: Arc<Mutex<IncommingMessageCache>>,
    context_cache: Arc<Mutex<ContextCache>>,
    channel_to_client: UnboundedSender<MessageEnum>,
}
impl MessageContoller {
    fn new(
        cache: Arc<Mutex<IncommingMessageCache>>,
        channel_to_client: UnboundedSender<MessageEnum>,
    ) -> (Self, UnboundedSender<MessageEnum>) {
        let (tx, rx): (UnboundedSender<MessageEnum>, UnboundedReceiver<MessageEnum>) =
            unbounded_channel::<MessageEnum>();
        (
            MessageContoller {
                queue_to_send: rx,
                cache,
                channel_to_client,
            },
            tx,
        )
    }
    async fn sequential_send(&mut self, mutex_peer_list: Arc<Mutex<Vec<Peer>>>) {
        loop {
            let msg = self.queue_to_send.recv().await;
            match msg {
                Some(msg) => {
                    Self::send_to_n(mutex_peer_list.clone(), msg, DEFAULT_SEND_TO_N).await;
                }
                None => eprintln!("No Message to send in sequential_send"),
            }
        }
    }
    async fn send_to_n(mutex_peer_list: Arc<Mutex<Vec<Peer>>>, message: MessageEnum, n: u32) {
        let peer_list = mutex_peer_list.lock().await;

        println!("Sending Message: '{:?}' to Peers: {:?}", message, peer_list);

        let mut send_to_peer_list = vec![];

        for (i, peer) in peer_list.iter().enumerate() {
            if i >= n as usize {
                break;
            }
            send_to_peer_list.push(peer.clone());
        }
        drop(peer_list);

        println!("Generated Custom Peer List: '{:?}'", send_to_peer_list);

        let derialized_message = message
            .deserialize()
            .expect("failed to serialize message in send_to_n");

        println!("Deserialized Message: '{:?}'", derialized_message);

        for peer in send_to_peer_list {
            let tcp_stream = TcpStream::connect((peer.ip_addr, peer.port)).await;

            println!("Opened TcpStream to: {:?}", peer);

            match tcp_stream {
                Ok(mut tcp_stream) => {
                    if let Err(err) = tcp_stream.write_all(&derialized_message).await {
                        eprintln!("error writing into tcp_stream in send_to_n, err: {}", err);
                    }

                    // TODO: Oneshot channel in return for answering?

                    match message.clone() {
                        MessageEnum::Message(msg) => {
                            if msg.broadcasting_type == 1 {
                                // Then wait for answer

                                tokio::spawn(async {});
                            }
                        }
                        _ => todo!(),
                    }
                }
                Err(err) => eprintln!(
                    "failed to open tcp stream to {:?} with err: {:?}",
                    peer, err
                ),
            }
        }
    }
}
#[derive(Clone, Debug)]
struct ContextCache {
    // Context,Peer
    cache: HashMap<u128, Peer>,
}
impl ContextCache {
    /// Returns if there was a collision
    fn get_if_existing(&self, context_id: u128) -> Option<Peer> {
        if self.cache.contains_key(&context_id) {
            return Some(
                self.cache
                    .get_key_value(&context_id)
                    .ok_or("Internal Error contains but does not contain")
                    .unwrap()
                    .1
                    .clone(),
            );
        }
        None
    }
    fn insert(&mut self, context_id: u128, peer: Peer) {
        self.cache.insert(context_id, peer);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IncommingMessageCache {
    cache: HashSet<MessageEnum>,
}
impl IncommingMessageCache {
    fn new() -> IncommingMessageCache {
        IncommingMessageCache {
            cache: HashSet::new(),
        }
    }

    /// Returns if there was a collision
    fn insert_and_collide(&mut self, msg_enum: MessageEnum) -> bool {
        if self.cache.contains(&msg_enum) {
            return true;
        } else {
            self.cache.insert(msg_enum);
            return false;
        }
    }
}

// TODO: Peer Structure with more Data
#[derive(Debug, Clone, Copy)]
pub struct Peer {
    pub ip_addr: IpAddr,
    pub port: u16,
}

pub struct P2PController {
    pub port: u16,

    known_peers: Arc<Mutex<Vec<Peer>>>,

    message_cache: Arc<Mutex<IncommingMessageCache>>,

    // for sending and recieving from the network
    message_contoller: Arc<Mutex<MessageContoller>>,
    /// This is for consumer to send into
    message_sending_channel: UnboundedSender<MessageEnum>,

    // for sending to and from P2PController
    /// This is for consumer to recieve from
    incomming_message_rx_channel: Arc<Mutex<UnboundedReceiver<MessageEnum>>>,
    incomming_message_tx_channel: UnboundedSender<MessageEnum>,
}
impl P2PController {
    pub fn new(port: u16) -> Self {
        let message_cache = Arc::new(Mutex::new(IncommingMessageCache::new()));

        let (incomming_message_tx_channel, incomming_message_rx_channel) =
            unbounded_channel::<MessageEnum>();

        let (message_contoller, message_sending_channel) =
            MessageContoller::new(message_cache.clone(), incomming_message_tx_channel.clone());

        P2PController {
            port,
            known_peers: Arc::new(Mutex::new(vec![])),
            message_cache,
            message_contoller: Arc::new(Mutex::new(message_contoller)),
            message_sending_channel,
            incomming_message_rx_channel: Arc::new(Mutex::new(incomming_message_rx_channel)),
            incomming_message_tx_channel,
        }
    }

    pub async fn connect_and_populate(&self) -> Result<()> {
        Ok(())
    }

    pub async fn add_peer(&self, peer: Peer) {
        let mut peers = self.known_peers.lock().await;

        peers.push(peer.clone());

        drop(peers);

        println!("added {:?} to peers", peer);
    }

    /// Spawns Tasks to start TcpListener and Sending Messages
    pub async fn start(&mut self) -> Result<()> {
        let tcp_listener = Arc::new(TcpListener::bind(("0.0.0.0", self.port)).await?);

        let incomming_message_tx_channel = self.incomming_message_tx_channel.clone();
        let message_cache = self.message_cache.clone();
        let message_sending_channel = self.message_sending_channel.clone();

        tokio::spawn(async move {
            loop {
                let combo = tcp_listener.as_ref().accept().await;
                let incomming_message_tx_channel = incomming_message_tx_channel.clone();
                let message_cache = message_cache.clone();
                let message_sending_channel = message_sending_channel.clone();
                match combo {
                    Ok(combo) => {
                        tokio::spawn(async move {
                            let res = Self::handle_tcp_stream(
                                incomming_message_tx_channel.clone(),
                                message_sending_channel.clone(),
                                message_cache.clone(),
                                combo,
                            )
                            .await;
                            match res {
                                Ok(_) => {}
                                Err(err) => eprintln!("{}", err),
                            }
                        });
                    }
                    Err(err) => eprintln!("err: {} at line: {}", err, line!()),
                }
            }
        });

        let mutexed_message_contoller = self.message_contoller.clone();
        let mutexed_peers = self.known_peers.clone();

        tokio::spawn(async move {
            mutexed_message_contoller
                .lock()
                .await
                .sequential_send(mutexed_peers.clone())
                .await;
        });

        Ok(())
    }

    async fn handle_tcp_stream(
        consumer_tx_channel: UnboundedSender<MessageEnum>,
        message_sending_channel: UnboundedSender<MessageEnum>,
        message_cache: Arc<Mutex<IncommingMessageCache>>,
        (mut tcp_stream, _socket_addr): (TcpStream, SocketAddr),
    ) -> Result<()> {
        // TODO: make it possible to use MessageAnswer

        // Peek first byte to detect MessageEnum Type:
        let mut message_type_buf: Vec<u8> = vec![0u8; 1];
        tcp_stream.peek(&mut message_type_buf).await?;
        let message_type = message_type_buf[0];

        match message_type {
            // Message Type: Message
            0 => {
                let message = Message::from_readable(&mut tcp_stream).await?;

                let mut cache = message_cache.lock().await;

                if cache.insert_and_collide(MessageEnum::Message(message.clone())) {
                    println!("message: {:?} already in cache, skipping...", message);
                    return Ok(());
                } else {
                    consumer_tx_channel.send(MessageEnum::Message(message.clone()))?;

                    //TODO: send to MessageSender for Broadcasting
                    //TODO: improve over putting it all into messaging queue

                    if message.time_to_live > 1 && message.broadcasting_type == 0 {
                        let mut new_message = message.clone();
                        new_message.time_to_live -= 1;
                        message_sending_channel
                            .send(MessageEnum::Message(new_message))
                            .unwrap();
                    }
                }
            }
            // Message Type: MessageAnswer
            1 => {
                // TODO: Improve Answer Handling
                let message_answer = MessageAnswer::from_readable(&mut tcp_stream).await?;

                consumer_tx_channel.send(MessageEnum::MessageAnswer(message_answer.clone()))?;
            }
            _ => {
                eprintln!("Non-handleable message recieved, ignoring....");
            }
        }
        Ok(())
    }

    /// Channel to get parsed messages out of
    pub fn get_reader(&mut self) -> Arc<Mutex<UnboundedReceiver<MessageEnum>>> {
        self.incomming_message_rx_channel.clone()
    }
    /// Channel to send/broadcast messages from
    pub fn get_to_message_channel(&self) -> UnboundedSender<MessageEnum> {
        self.message_sending_channel.clone()
    }
    /// Channel pair to get parsed messages and to send/broadcast messages
    pub fn get_recv_send_pair(
        &mut self,
    ) -> (
        Arc<Mutex<UnboundedReceiver<MessageEnum>>>,
        &UnboundedSender<MessageEnum>,
    ) {
        (
            self.incomming_message_rx_channel.clone(),
            &self.message_sending_channel,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{Deserialize, Message, MessageAnswer};

    #[tokio::test]
    async fn message_serialization_deserialization() {
        let message = Message::new_from_data(7, 7, vec![7; 7]);

        println!("{:?}", message);

        let deserialized = message.deserialize().unwrap();

        println!("deserialized: {:?}", deserialized);

        use std::io::Cursor;
        let mut readable_deserialized = Cursor::new(deserialized);

        let message_from_readable = Message::from_readable(&mut readable_deserialized)
            .await
            .unwrap();

        assert_eq!(message, message_from_readable);
    }

    #[tokio::test]
    async fn message_answer_serialization_deserialization() {
        let message = MessageAnswer::new_from_data(7, 7777777, vec![7; 7]);

        println!("{:?}", message);

        let deserialized = message.deserialize().unwrap();

        println!("deserialized: {:?}", deserialized);

        use std::io::Cursor;
        let mut readable_deserialized = Cursor::new(deserialized);

        let message_from_readable = MessageAnswer::from_readable(&mut readable_deserialized)
            .await
            .unwrap();

        assert_eq!(message, message_from_readable);
    }
}
