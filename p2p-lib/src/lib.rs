use tokio::{sync::mpsc::{unbounded_channel,UnboundedReceiver,UnboundedSender}};
use std::{collections::HashMap, io::Read, vec};
use eyre::Result;

const DEFAULT_TTL: u8 = 5;

enum MessageEnum{
    Message,
    MessageAnswer
}

struct MessageAnswer{
    route_id: u16,
    data: Vec<u8>,
}

// 8 + 2 + 1 + 1 + 8 + ? = 20bytes + ? bytes
#[derive(Debug,Clone,PartialEq, Eq)]
struct Message{
    message_length: u64,

    route_id: u16,
    broadcasting_type: u8, // 0 message to all, 1 get answer from first peer
    time_to_live: u8,
    timestamp: i64,

    data: Vec<u8>,
}
impl Message{
    fn new_from_data(route: u16, broadcasting_type: u8, data: Vec<u8>) -> Message{
        Message{
            message_length: 20 + data.len() as u64,
            route_id: route,
            broadcasting_type,
            time_to_live: DEFAULT_TTL,
            timestamp: chrono::Utc::now().timestamp(),
            data,
        }
    }

    fn deserialize(&self) -> Result<Vec<u8>> {
        let deserialized: Vec<u8> = vec![
            self.message_length.to_be_bytes().to_vec(),
            self.route_id.to_be_bytes().to_vec(),
            [self.broadcasting_type].to_vec(),
            [self.time_to_live].to_vec(),
            self.timestamp.to_be_bytes().to_vec(),
            self.data.to_vec()
        ].concat();

        Ok(deserialized)
    }

    fn from_readable(readable: &mut dyn Read) -> Result<Message>{
        let mut message_length_buf: [u8; 8] = [0;8];
        readable.read_exact(&mut message_length_buf)?;
        let message_length: u64 = u64::from_be_bytes(message_length_buf);

        // Have to convert u64 to usize so message buffer in huge messages could fail
        let mut message_buffer: Vec<u8> = vec![0; (message_length - 8).try_into()?];

        readable.read_exact(&mut message_buffer)?;

        let message = Message{
            message_length,
            route_id: u16::from_be_bytes(message_buffer[0..2].try_into()?),
            broadcasting_type: message_buffer[2],
            time_to_live: message_buffer[3],
            timestamp: i64::from_be_bytes(message_buffer[4..12].try_into()?),
            data: message_buffer[12..].to_vec(),
        };

        Ok(message)
    }
}

#[derive(Debug)]
struct MessageContoller{
    // Messages from here will be send periodacally
    queue_to_send: UnboundedReceiver<Message>
}
impl MessageContoller{
    fn new() -> (Self,UnboundedSender<Message>){
        let (tx,rx): (UnboundedSender<Message>,UnboundedReceiver<Message>) = unbounded_channel::<Message>();
        (MessageContoller{
            queue_to_send: rx,
        },tx)
    }
}

struct Peer{

}

struct P2PController{
    // TODO: Peer Structure with more Data
    known_peers: Vec<String>,

    // for sending anf recieving from the network
    message_contoller: MessageContoller,
    message_sending_channel: UnboundedSender<Message>,

    // for sending to and from P2PController
    incomming_message_rx_channel: UnboundedReceiver<MessageEnum>,
    incomming_message_tx_channel: UnboundedSender<MessageEnum>
}
impl P2PController{
    fn new() -> Self{
        let (message_contoller,message_sending_channel) = MessageContoller::new();
        let (incomming_message_tx_channel,incomming_message_rx_channel) = unbounded_channel::<MessageEnum>();
        P2PController{
            known_peers: vec![],
            message_contoller,
            message_sending_channel,
            incomming_message_rx_channel,
            incomming_message_tx_channel,
        }
    }
    fn get_reader(&'_ self) -> &'_ UnboundedReceiver<MessageEnum>{
        &self.incomming_message_rx_channel
    }
    fn get_to_message_channel(&self) -> UnboundedSender<Message>{
        self.message_sending_channel.clone()
    }
}



#[cfg(test)]
mod tests {
    use crate::Message;

    #[test]
    fn messege_serialization_deserialization() {
        let message = Message::new_from_data(7,7,vec![7;5]);

        println!("{:?}",message);

        let mut deserialized = message.deserialize().unwrap();
        
        println!("deserialized: {:?}",deserialized);

        use std::io::Cursor;
        let mut readable_deserialized = Cursor::new(deserialized);

        let message_from_readable = Message::from_readable(&mut readable_deserialized).unwrap();

        assert_eq!(message,message_from_readable);
    }
}
