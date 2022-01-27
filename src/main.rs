use promptly::{prompt, prompt_default, prompt_opt};

use parking_lot::Mutex;
use std::sync::{mpsc::channel, Arc};
use std::thread;

use std::error::Error;

use blake2::{Blake2s256, Digest};
use chrono::Utc;

use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey, Signature};
use sodiumoxide::crypto::sign::{self, sign_detached};

use serde::{Deserialize, Serialize};

use tiny_http::{Server, Response};

const MINER_REWARD: u64 = 100;
const STARTING_DIFFICULTY: u8 = 20;

type Hash = [u8;32];

#[derive(Debug)]
struct Blockchain {
    stack: Vec<Block>,
    hashes: Vec<[u8; 32]>,
    difficulty: u8,
    current_mining_block: Block,
    current_block_updated_flag: bool,
    cancel_mining_flag: bool,
}
impl Blockchain {
    fn genesis() -> Self {
        let genesis_block = Block::new_from_current_time(0u8, 0, [0u8; 32], STARTING_DIFFICULTY);

        Blockchain {
            stack: vec![genesis_block.clone()],
            hashes: vec![genesis_block.hash()],
            difficulty: STARTING_DIFFICULTY,
            current_mining_block: Block::new_from_current_time(
                0u8,
                0,
                [0u8; 32],
                STARTING_DIFFICULTY,
            ),
            current_block_updated_flag: false,
            cancel_mining_flag: false,
        }
    }

    fn add_new_transaction_to_mining_block(&mut self, transaction: Transaction) {
        self.current_block_mut().add_transaction(transaction);
        self.current_block_updated_flag = true;
    }
    fn current_block_mut(&mut self) -> &mut Block {
        self.stack
            .last_mut()
            .ok_or("fatal: no block on stack")
            .unwrap()
    }
    fn current_block_ref(&mut self) -> &Block {
        self.stack.last().ok_or("fatal: no block on stack").unwrap()
    }
    fn current_hash(&self) -> Hash {
        *self
            .hashes
            .last()
            .ok_or("fatal: no block on stack")
            .unwrap()
    }
    fn add_block(&mut self, block: Block) {
        self.stack.push(block);
        self.current_block_updated_flag = false;
    }
    fn add_hash_to_new_block(&mut self, hash: Hash) {
        self.hashes.push(hash);
    }
    fn update_current_mining_block(&mut self, block: Block) {
        self.current_mining_block = block;
    }
    fn is_updated(&mut self) -> bool {
        let temp = self.current_block_updated_flag;
        self.current_block_updated_flag = false;
        temp
    }
    fn set_cancel_mining_flag(&mut self, state: bool) {
        self.cancel_mining_flag = state;
    }
    fn get_cancel_mining_flag(&mut self) -> bool {
        let temp = self.cancel_mining_flag;
        self.cancel_mining_flag = false;
        temp
    }
    fn destroy_current_block(&mut self) {
        self.stack.pop();
    }
    fn check_balance_of_account(&self,account_pk: PublicKey) -> u64{
        let mut total: u64 = 0;

        for block in &self.stack{
            for transaction in &block.transactions{
                if transaction.reciever == account_pk{
                    total += transaction.amount;
                }
                if transaction.sender == account_pk{
                    total -= transaction.amount;
                }
            }
        }

        total
    }
}
fn mine_new_block(blockchain: Arc<Mutex<Blockchain>>,blockchain_controller: Arc<Mutex<BlockchainController>>,identity: Identity) -> bool {
    // Get MutexGuard
    let mut current_blockchain_handle = blockchain.lock();

    let previous_hash = current_blockchain_handle.current_hash();
    let mut block: Block = Block::new_from_current_time(
        0u8,
        current_blockchain_handle.current_block_ref().index + 1,
        previous_hash,
        current_blockchain_handle.difficulty,
    );

    // Add own Mining fee in case we are successfull
    block.add_transaction(Transaction::generate_miner_transaction(identity.public_key));

    current_blockchain_handle.current_mining_block = block.clone();

    // Release MutexGuard
    std::mem::drop(current_blockchain_handle);

    println!(
        "struct: {:?},as_bytes: {:?}",
        block,
        block.serialize_to_bytes()
    );

    const BATCH_SIZE: usize = 1028;

    let max_batch_number = u32::MAX / BATCH_SIZE as u32;
    let mut batch_number = 0;

    while batch_number < max_batch_number {
        // Current Batch
        let batch: Vec<u32> = (0..BATCH_SIZE)
            .map(|x| x as u32 + batch_number * BATCH_SIZE as u32)
            .collect();
        //println!("batch: {:?}",batch);

        // Iterate over Batch and check if u have a mined block
        for nonce in batch {
            let hash_result = block.hash();

            let leading_zeros = get_leading_zeros_of_u8_slice(&hash_result);

            block.nonce = nonce;

            if leading_zeros >= block.difficulty as u32 {
                println!("successfully mined block!");
                println!("resulting hash: {:?}", hex::encode(hash_result));
                println!(
                    "nonce: '{:?}',',leading zeros: {:?}",
                    block.nonce, leading_zeros
                );

                let mut current_blockchain_handle = blockchain.lock();
                current_blockchain_handle.add_block(block);
                current_blockchain_handle.add_hash_to_new_block(hash_result);
                return true;
            }
        }

        let mut current_blockchain_handle = blockchain.lock();
        if current_blockchain_handle.is_updated() {
            block = current_blockchain_handle.current_mining_block.clone();
            batch_number = 0;
        }
        if current_blockchain_handle.get_cancel_mining_flag() {
            eprintln!("canceled mining new block! was at batch: {}", batch_number);
            return false;
        }
        std::mem::drop(current_blockchain_handle);
        batch_number += 1;
    }
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Identity {
    public_key: PublicKey,
    secret_key: SecretKey,
}
impl Identity {
    fn generate_new() -> Identity {
        let id: (PublicKey, SecretKey) = sign::gen_keypair();
        Identity {
            public_key: id.0,
            secret_key: id.1,
        }
    }
    fn load_from_file(filename: &str) -> Result<Identity, Box<dyn Error>> {
        let data = std::fs::read(format!("{}.identity", filename))?;
        let id: Identity = serde_json::from_slice(&data)?;
        Ok(id)
    }
    fn save_to_file(&self, filename: &str) -> Result<(), Box<dyn Error>> {
        std::fs::write(
            format!("{}.identity", filename),
            serde_json::to_string(self)?,
        )?;
        Ok(())
    }
    fn origin_public_key() -> PublicKey {
        PublicKey::from_slice(&[0u8; 32])
            .ok_or("fatal: failed to generate origin identity")
            .unwrap()
    }
}

// 1 + 8 + 32 + 8 + 1 + 4 + 2 + ? = 56 bytes + ? bytes
// 137 bytes per Transaction: ? x 137 bytes
#[derive(Debug, Clone,PartialEq, Eq)]
struct Block {
    version: u8,
    index: u64,

    previous_hash: Hash,
    timestamp: i64,

    difficulty: u8,
    nonce: u32,

    num_transactions: u16,
    transactions: Vec<Transaction>,
}
impl Block {
    fn deserialize_from_bytes(data: &[u8]) -> Result<Block,Box<dyn Error>>{
        Ok(Block { 
            version: data[0],  // 1
            index: u64::from_be_bytes(data[1..9].try_into()?), // 8
            previous_hash: data[9..41].try_into()?, // 32
            timestamp: i64::from_be_bytes(data[41..49].try_into()?), // 8
            difficulty: data[49], // 1
            nonce: u32::from_be_bytes(data[50..54].try_into()?), // 4
            num_transactions: u16::from_be_bytes(data[54..56].try_into()?), // 2
            transactions: data[56..].chunks(137).filter(|x|!x.is_empty()).map(|chunk| {
                Transaction::deserialize_from_bytes(chunk)
            }).map(|transaction| transaction.ok()).filter(|x| x.is_some()).map(|f| f.ok_or("fatal: error while deserializing Block").unwrap()).collect()
        })
    }   
    fn serialize_to_bytes(&self) -> Vec<u8> {
        [
            [self.version].to_vec(),
            self.index.to_be_bytes().to_vec(),
            self.previous_hash.to_vec(),
            self.timestamp.to_be_bytes().to_vec(),
            [self.difficulty].to_vec(),
            self.nonce.to_be_bytes().to_vec(),
            self.num_transactions.to_be_bytes().to_vec(),
            self.transactions
                .iter()
                .map(|transaction| transaction.serialize_to_bytes())
                .collect::<Vec<Vec<u8>>>()
                .concat(),
        ]
        .to_vec()
        .concat()
    }
    fn hash(&self) -> Hash {
        let mut hasher = Blake2s256::new();
        // write input message
        hasher.update(self.serialize_to_bytes());

        // read hash digest
        let result = hasher.finalize();

        result.try_into().unwrap()
    }
    fn check_validity(&self) -> bool {
        if !get_leading_zeros_of_u8_slice(&self.hash()) >= self.difficulty as u32 {
            return false;
        }
        if self.num_transactions as usize != self.transactions.len() {
            return false;
        }
        true
    }

    fn add_transaction(&mut self, transaction: Transaction) {
        self.transactions.push(transaction);
        self.num_transactions += 1;
    }
    fn new_from_current_time(
        version: u8,
        index: u64,
        previous_hash: Hash,
        difficulty: u8,
    ) -> Block {
        Block {
            version,
            index,
            previous_hash,
            timestamp: Utc::now().timestamp(),
            difficulty,
            nonce: 0,
            num_transactions: 0,
            transactions: vec![],
        }
    }
}

// 32 + 32 + 8 + 64 + 1 = 137 bytes
#[derive(Debug, Clone,std::cmp::PartialEq, Eq)]
struct Transaction {
    sender: PublicKey,
    reciever: PublicKey,
    amount: u64,
    signature_of_sender: Signature,
    miner_reward_flag: u8,
}
impl Transaction {
    fn deserialize_from_bytes(data: &[u8]) -> Result<Transaction,Box<dyn Error>>{
        Ok(Transaction {
            sender: PublicKey::from_slice(&data[0..32]).ok_or("Failed to deserialize Transaction bytes")?,
            reciever: PublicKey::from_slice(&data[32..64]).ok_or("Failed to deserialize Transaction bytes")?,
            amount: u64::from_be_bytes(data[64..72].try_into()?),
            signature_of_sender: Signature::from_bytes(&data[72..136]).unwrap(),
            miner_reward_flag: data[136],
                
        })
    }

    fn serialize_to_bytes(&self) -> Vec<u8> {
        [
            self.sender.as_ref(),
            self.reciever.as_ref(),
            &self.amount.to_be_bytes().to_vec(),
            &self.signature_of_sender.to_bytes(),
            &[self.miner_reward_flag],
        ]
        .to_vec()
        .concat()
    }

    fn generate_transaction_from_secret_key(
        secret_key: SecretKey,
        reciever_public_key: PublicKey,
        amount: u64,
    ) -> Self {
        let to_be_signed = Self::in_flight_transaction_to_be_signed(
            secret_key.clone(),
            reciever_public_key,
            amount,
        );
        Transaction {
            sender: secret_key.public_key(),
            reciever: reciever_public_key,
            amount,
            signature_of_sender: sign_detached(&to_be_signed, &secret_key),
            miner_reward_flag: 0,
        }
    }
    fn generate_miner_transaction(miner_public_key: PublicKey) -> Self {
        let to_be_signed = Self::in_flight_transaction_to_be_signed(
            SecretKey::from_slice(&[0u8; 64])
                .ok_or("failed to generate 0ed Secretkey for miner reward")
                .unwrap(),
            miner_public_key,
            MINER_REWARD,
        );
        Transaction {
            sender: PublicKey::from_slice(&[0u8; 32])
                .ok_or("failed to generate 0ed Secretkey for miner reward")
                .unwrap(),
            reciever: miner_public_key,
            signature_of_sender: sign_detached(
                &to_be_signed,
                &SecretKey::from_slice(&[0u8; 64])
                    .ok_or("failed to generate 0ed Secretkey for miner reward")
                    .unwrap(),
            ),
            miner_reward_flag: 1,
            amount: MINER_REWARD,
        }
    }

    fn in_flight_transaction_to_be_signed(
        secret_key: SecretKey,
        reciever_public_key: PublicKey,
        amount: u64,
    ) -> Vec<u8> {
        [
            secret_key.as_ref(),
            reciever_public_key.as_ref(),
            &amount.to_be_bytes().to_vec(),
        ]
        .to_vec()
        .concat()
    }
}

struct BlockchainController{
    blockchain: Arc<Mutex<Blockchain>>,
    peers: Vec<String>,
    mined_flag: bool,
}
impl BlockchainController{
    fn publish_new_mined_block(block_to_be_published: Block){

    }
}

fn get_leading_zeros_of_u8_slice(v: &[u8]) -> u32 {
    let n_zeroes = match v.iter().position(|&x| x != 0) {
        Some(n) => n,
        None => return 8 * v.len() as u32,
    };

    v.get(n_zeroes).map_or(0, |x| x.leading_zeros()) + 8 * n_zeroes as u32
}

fn ask_for_user_action(
    blockchain: Arc<Mutex<Blockchain>>,
    blockchain_controller: Arc<Mutex<BlockchainController>>
) -> Result<(), Box<dyn std::error::Error>> {
    let mut current_identity = Identity::generate_new();
    println!(
        "new identity automaticly generated: {:?}, use command 'load' to load other identity",
        hex::encode(current_identity.public_key.as_ref())
    );
    loop {
        let command: String = prompt("Enter a command")?;
        if command == "mine" {
            let thread_blockchain_mutex = blockchain.clone();
            let thread_blockchain_controller_mutex = blockchain_controller.clone();
            let thread_current_identity = current_identity.clone();
            thread::spawn(move || {
                mine_new_block(thread_blockchain_mutex,thread_blockchain_controller_mutex,thread_current_identity);
            });
        } else if command == "balance" {
            let account_to_balance_check: Option<String> = prompt_opt("What account do you want to balance check? (leave empty for current identity)")?;
            match account_to_balance_check{
                Some(account_to_balance_check) => {

                    let public_key_to_check = hex::decode(account_to_balance_check.clone())?;
                    let current_blockchain_handle = blockchain.lock();

                    let amount = current_blockchain_handle.check_balance_of_account(PublicKey::from_slice(&public_key_to_check).ok_or("error parsing to private key")?);

                    std::mem::drop(current_blockchain_handle);

                    println!("account: '{}' has a balance of: {} coins",account_to_balance_check,amount);
                },
                None => {
                    let public_key_to_check = current_identity.public_key;
                    let current_blockchain_handle = blockchain.lock();

                    let amount = current_blockchain_handle.check_balance_of_account(public_key_to_check);

                    std::mem::drop(current_blockchain_handle);

                    println!("your account has a balance of: {} coins",amount);

                },
            }
        }else if command == "print" {
            let current_blockchain_handle = blockchain.lock();
            println!("{:#?}", current_blockchain_handle);
        } else if command == "cancel" {
            let mut current_blockchain_handle = blockchain.lock();
            current_blockchain_handle.set_cancel_mining_flag(true);
        } else if command == "load" {
            let name_to_load: String = prompt("What identity should i load?")?;
            let are_u_sure: bool = prompt_default(
                format!(
                    "are you sure you want to load {} as your current identity",
                    name_to_load
                ),
                false,
            )?;
            match are_u_sure {
                true => {
                    current_identity = Identity::load_from_file(&name_to_load)?;
                    println!("loaded identity-file: '{}'", name_to_load);
                    println!(
                        "new identity: {}",
                        hex::encode(current_identity.public_key.as_ref())
                    );
                }
                false => {
                    println!("Not Saving then...")
                }
            }
        } else if command == "save" {
            let name_to_save: String = prompt("Save identity as?")?;
            let are_u_sure: bool = prompt_default(
                "are you sure you want to save your current identity as: ".to_owned()
                    + &name_to_save,
                false,
            )?;
            match are_u_sure {
                true => {
                    current_identity.save_to_file(&name_to_save)?;
                    println!("saved to file: '{}'", name_to_save);
                }
                false => {
                    println!("Not Saving then...")
                }
            }
        } else if command == "exit" {
            break;
        } else if command == "transfer" {
            unimplemented!();
        } else {
            println!(
                "
            Commands:
                connect - connects to a given node in the network and gets their peers
                mine - tries to mine next block
                cancel - cancels the mining of this block
                transfer - transfers fund to account
                generate - generates a wallet keypait
                balance - check balance of account (defaulting to your own)
                exit - stops the programm # Not Working use Ctrl+C
                load - loads saved identity
                save - saves current identity 
            "
            )
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>>{
    println!("sl-coin version: 0.0.1");

    sodiumoxide::init().unwrap();

    let blockchain = Blockchain::genesis();
    let arced_mutexed_blockchain = Arc::new(Mutex::new(blockchain));

    let blockchain_controller = BlockchainController{
        blockchain: arced_mutexed_blockchain.clone(),
        peers: vec![],
        mined_flag: false,
    };
    let arced_mutexed_blockchain_controller = Arc::new(Mutex::new(blockchain_controller));


    let blockchain_for_user_func = arced_mutexed_blockchain.clone();
    let blockchain_controller_for_user_func = arced_mutexed_blockchain_controller.clone();
    let user_action_thread = thread::spawn(move ||{
        ask_for_user_action(blockchain_for_user_func,blockchain_controller_for_user_func).unwrap();
    });

    let server = Server::http("0.0.0.0:8421").unwrap();

    for mut request in server.incoming_requests() {
        
        let mut content = String::new();
        request.as_reader().read_to_string(&mut content).unwrap();

        match request.url(){
            "/get_blockchain" => {
                println!("{} wants the entire Blockchain",request.remote_addr());

                let blockchain_controller_handle = arced_mutexed_blockchain_controller.lock();

                let response = Response::from_string("hello world");
                request.respond(response)?;

                std::mem::drop(blockchain_controller_handle);
            },
            "/post_block" => {
                println!("got Block: {}",content);
            },
            "/post_add_peers" => {
                println!("{} wants to add peers: {}",request.remote_addr(),content);
            },
            "/get_blockchain_hashed_and_length" => {
                println!("{} wants our blockchain length and hashed",request.remote_addr());
            },
            "/connect" =>{
                let mut blockchain_controller_handle = arced_mutexed_blockchain_controller.lock();

                blockchain_controller_handle.peers.push(request.remote_addr().to_string());

                std::mem::drop(blockchain_controller_handle);
            },
            _ => {
                println!("received request! method: {:?}, url: {:?}, body_length: {:?}",
                    request.method(),
                    request.url(),
                    request.body_length()
                );
            }
        }
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use crate::{Transaction, Identity,Block};

    #[test]
    fn transaction_serialize_deserialize_eq() {
        sodiumoxide::init().unwrap();
        let current_identity = Identity::generate_new();
        let transaction: Transaction = Transaction::generate_miner_transaction(current_identity.public_key);
        let serialized = transaction.serialize_to_bytes();
        let deserialized = Transaction::deserialize_from_bytes(&serialized);

        assert_eq!(transaction,deserialized.unwrap());
    }
    #[test]
    fn block_serialize_deserialize_eq(){
        sodiumoxide::init().unwrap();
        let current_identity = Identity::generate_new();
        let transaction: Transaction = Transaction::generate_miner_transaction(current_identity.public_key);
        let mut block = Block::new_from_current_time(0u8, 0, [7u8; 32], 20);
        block.add_transaction(transaction);
        let serialized = block.serialize_to_bytes();
        let deserialized = Block::deserialize_from_bytes(&serialized);

        assert_eq!(block,deserialized.unwrap());
    }
}