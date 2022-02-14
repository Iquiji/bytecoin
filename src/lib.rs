use parking_lot::Mutex;
use std::collections::HashSet;
use std::io::Read;
use std::sync::Arc;

use std::error::Error;

use blake2::{Blake2s256, Digest};
use chrono::Utc;

use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey, Signature};
use sodiumoxide::crypto::sign::{self, sign_detached};

use serde::{Deserialize, Serialize};

const MINER_REWARD: u64 = 100;
const STARTING_DIFFICULTY: u8 = 18;
const VERSION: u8 = 0;

type Hash = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPlague {
    pub initiatior: String,            // Peer that started the Plague
    pub already_infected: Vec<String>, // Peers already infected
}

pub struct BlockchainController {
    pub blockchain: Arc<Mutex<Blockchain>>,
    pub peers: HashSet<String>,
    pub mined_flag: bool,
    pub port: usize,
}
impl BlockchainController {
    pub fn publish_new_mined_block(
        &self,
        block_to_be_published: &Block,
    ) -> Result<(), Box<dyn Error>> {
        let all_peers = self.peers.iter().cloned().collect::<Vec<String>>();

        BlockchainController::publish_data_to_given_peers(
            &hex::encode(block_to_be_published.serialize_to_bytes()),
            all_peers,
            "/post_mined_block"
        )?;

        Ok(())
    }
    pub fn publish_data_to_given_peers(
        data: &str,
        peers: Vec<String>,
        suffix: &str
    ) -> Result<(), Box<dyn Error>> {
        for peer in peers {
            let peer_http_patted = "http://".to_owned() + &peer + suffix;

            println!(
                "sending block to {:?} in seperate func 'publish_to_given_peers'",
                peer_http_patted
            );

            let response = ureq::post(&peer_http_patted)
                .timeout(std::time::Duration::from_millis(10000))
                .send_string(data)?;
            println!("response: {:?}", response);
        }

        Ok(())
    }

    pub fn connect_to_peer_and_get_peers(
        &mut self,
        peer_to_connect_to: &str,
    ) -> Result<(), Box<dyn Error>> {
        let response = ureq::post(peer_to_connect_to).send_string(&self.port.to_string())?;
        println!("response: {:?}", response);

        let mut content: String = String::new();
        response.into_reader().read_to_string(&mut content)?;

        let new_peers: Vec<&str> = content.split_whitespace().collect();

        for peer in new_peers {
            self.peers.insert(peer.to_string());
            println!("Added Peer: '{}' to Peerlist", peer);
        }

        Ok(())
    }
    pub fn spread_peer_plague(&self, plague: PeerPlague) {
        let mut evolved_plague = plague.clone();

        let all_peers = self.peers.iter().cloned().collect::<Vec<String>>();

        // Compute new plague with new peers if existing
        for peer in &all_peers {
            if evolved_plague.already_infected.contains(peer) || peer == &evolved_plague.initiatior
            {
                continue;
            } else {
                evolved_plague.already_infected.push(peer.to_string());
            }
        }

        // Spread to all uninfected peers
        for peer in all_peers {
            if plague.already_infected.contains(&peer) || peer == evolved_plague.initiatior {
                continue;
            }

            let peer_http_patted = "http://".to_owned() + &peer + "/spread_plague";

            println!("sending Plague to {:?}", peer_http_patted);

            if let Ok(response) = ureq::post(&peer_http_patted)
                .timeout(std::time::Duration::from_millis(2000))
                .send_string(&serde_json::to_string(&evolved_plague).unwrap())
            {
                println!("response: {:?}", response);
            }
        }
    }
    pub fn get_entire_blockchain_stack_from_peer(
        peer_to_connect_to: &str,
    ) -> Result<Vec<Block>, Box<dyn Error>> {
        let peer_http_patted = "http://".to_owned() + peer_to_connect_to + "/get_blockchain";

        println!("requesting entire Blockchain from: {:?}", peer_http_patted);

        match ureq::post(&peer_http_patted)
            .timeout(std::time::Duration::from_millis(10000))
            .call()
        {
            Ok(response) => {
                let mut content: Vec<u8> = vec![];
                response.into_reader().read_to_end(&mut content)?;

                let response_decoded = hex::decode(content)?;

                let blockchain_stack = Blockchain::deserialize_stack_from_bytes(&response_decoded)?;

                Ok(blockchain_stack)
            }
            Err(err) => Err(Box::new(err)),
        }
    }

    pub fn spread_transaction_to_all_peers(&self,transaction_to_be_published: Transaction) -> Result<(),Box<dyn Error>>{
        
        let all_peers = self.peers.iter().cloned().collect::<Vec<String>>();

        BlockchainController::publish_data_to_given_peers(
            &hex::encode(transaction_to_be_published.serialize_to_bytes()),
            all_peers,
            "/post_transaction"
        )?;

        Ok(())
    }
}

pub fn get_leading_zeros_of_u8_slice(v: &[u8]) -> u32 {
    let n_zeroes = match v.iter().position(|&x| x != 0) {
        Some(n) => n,
        None => return 8 * v.len() as u32,
    };

    v.get(n_zeroes).map_or(0, |x| x.leading_zeros()) + 8 * n_zeroes as u32
}

#[derive(Debug, PartialEq, Eq)]
pub struct Blockchain {
    pub stack: Vec<Block>,
    //pub hashes: Vec<Hash>,
    pub difficulty: u8,
    current_mining_block: Block,
    current_block_updated_flag: bool,
    cancel_mining_flag: bool,
    pub currently_mining: bool,
    transaction_queue: Vec<Transaction>
}
impl Blockchain {
    pub fn genesis() -> Self {
        let genesis_block = Block::generate_genisis_block(VERSION, STARTING_DIFFICULTY);

        Blockchain {
            stack: vec![genesis_block.clone()],
            //hashes: vec![genesis_block.hash()],
            difficulty: STARTING_DIFFICULTY,
            current_mining_block: genesis_block,
            current_block_updated_flag: false,
            cancel_mining_flag: false,
            currently_mining: false,
            transaction_queue: vec![],
        }
    }

    pub fn update_stack(&mut self, stack: Vec<Block>) {
        self.stack = stack;
        self.set_cancel_mining_flag(true);
    }

    pub fn verify(&self) -> bool {
        // TODO: Check if Balance of all acounts is valid

        // Verifiy integrity of hashes for each block:
        // for (block, hash) in self.stack.iter().cloned().zip(&self.hashes) {
        //     if &block.hash() != hash {
        //         eprintln!("Hash of Block isnt the same as saved Hash.block: {:?},hash of block: {:?},hash: {:?}",block,hex::encode(block.hash()),hex::encode(hash));
        //         return false;
        //     }
        // }

        // Verify integrity of hashes in blocks in each other:
        for blocks in self.stack.windows(2) {
            let prev = &blocks[0];
            let current = &blocks[1];

            if prev.hash() != current.previous_hash {
                eprintln!("hash of previous block and saved in this block are different!\n prev: {:?}\n,hash of prev: '{:?}'\n current: {:?}",prev,prev.hash(),current);
                return false;
            }
        }

        // Verify timestamp correspondence in all blocks:
        for blocks in self.stack.windows(2) {
            let prev = &blocks[0];
            let current = &blocks[1];

            if prev.timestamp > current.timestamp {
                eprintln!("timestamp of previous block is bigger than this block!");
                return false;
            }
        }
        // Verify index correspondence in all blocks:
        for blocks in self.stack.windows(2) {
            let prev = &blocks[0];
            let current = &blocks[1];

            if prev.index > current.index {
                eprintln!("index of previous block is bigger than this block!");
                return false;
            }
        }

        // Verify inner block integrity
        for block in &self.stack {
            if !block.verify() {
                eprintln!("inner Verification of block failed. block: {:?}", block);
                return false;
            }
        }

        true
    }

    pub fn serialize_stack_to_bytes(&self) -> Vec<u8> {
        self.stack
            .iter()
            .map(|block| block.serialize_to_bytes())
            .collect::<Vec<Vec<u8>>>()
            .concat()
    }
    pub fn deserialize_stack_from_bytes(data: &[u8]) -> Result<Vec<Block>, Box<dyn Error>> {
        // Remaining Data to be split into Blocks
        let mut remaining_data = data;

        let mut stack: Vec<Block> = vec![];

        // Basic block is 56 bytes long
        // 1 Transaction is 137 bytes long
        while remaining_data.len() > 55 {
            // Transaction amount in bytes 54 & 55 (started from 0)
            // get number of transactions in this Block-bytespace
            let num_transactions = u16::from_be_bytes([remaining_data[54], remaining_data[55]]);

            // Get all bytes in this Block-bytespace
            let this_block_data_temp =
                remaining_data.split_at(56 + num_transactions as usize * 137);
            // and push the rest for to be used in next loop
            remaining_data = this_block_data_temp.1;
            // our now data
            let this_block_data = this_block_data_temp.0;

            let next_block: Block = Block::deserialize_from_bytes(this_block_data)?;

            // println!("num_transactions: {:?}",num_transactions);
            // println!("block: {:?}",next_block);
            // println!("remaining_data_length: {} vs. {} data length",remaining_data.len(),data.len());

            stack.push(next_block);
        }

        Ok(stack)
    }

    pub fn add_new_transaction_to_transaction_queue(&mut self, transaction: Transaction) {
        self.transaction_queue.push(transaction);
        //self.current_mining_block.add_transaction(transaction);
        self.current_block_updated_flag = true;
    }
    pub fn current_block_mut(&mut self) -> &mut Block {
        self.stack
            .last_mut()
            .ok_or("fatal: no block on stack")
            .unwrap()
    }
    pub fn current_block_ref(&mut self) -> &Block {
        self.stack.last().ok_or("fatal: no block on stack").unwrap()
    }
    pub fn add_block(&mut self, block: Block) {
        self.stack.push(block);
        self.current_block_updated_flag = false;
    }
    pub fn update_current_mining_block(&mut self, block: Block) {
        self.current_mining_block = block;
    }
    pub fn is_updated(&mut self) -> bool {
        let temp = self.current_block_updated_flag;
        self.current_block_updated_flag = false;
        temp
    }
    pub fn set_cancel_mining_flag(&mut self, state: bool) {
        self.cancel_mining_flag = state;
    }
    pub fn get_cancel_mining_flag(&mut self) -> bool {
        let temp = self.cancel_mining_flag;
        self.cancel_mining_flag = false;
        temp
    }
    pub fn destroy_current_block_and_hash(&mut self) {
        self.stack.pop();
    }
    pub fn check_balance_of_account(&self, account_pk: PublicKey) -> u64 {
        let mut total: u64 = 0;

        for block in &self.stack {
            for transaction in &block.transactions {
                if transaction.reciever == account_pk {
                    total += transaction.amount;
                }
                if transaction.sender == account_pk {
                    total -= transaction.amount;
                }
            }
        }

        total
    }
    fn get_all_pending_transactions(&mut self) -> Vec<Transaction>{
        let res = self.transaction_queue.clone();
        self.transaction_queue = vec![];
        res
    }
}
pub fn mine_new_block(
    blockchain: Arc<Mutex<Blockchain>>,
    blockchain_controller: Arc<Mutex<BlockchainController>>,
    identity: Identity,
) -> bool {
    // Get MutexGuard
    let mut current_blockchain_handle = blockchain.lock();

    if current_blockchain_handle.currently_mining {
        println!("already mining! EXITING mining function");
        return false;
    } else {
        current_blockchain_handle.currently_mining = true;
    }

    let previous_hash = current_blockchain_handle.current_block_ref().hash();
    let mut block: Block = Block::new_from_current_time(
        0u8,
        current_blockchain_handle.current_block_ref().index + 1,
        previous_hash,
        current_blockchain_handle.difficulty,
    );

    for transaction in current_blockchain_handle.get_all_pending_transactions(){
        block.add_transaction(transaction);
    }

    // Add own Mining fee in case we are successfull
    block.add_transaction(Transaction::generate_miner_transaction(identity.public_key));

    current_blockchain_handle.current_mining_block = block.clone();

    // Release MutexGuard
    std::mem::drop(current_blockchain_handle);

    println!("struct: {:?}", block,);

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

                if current_blockchain_handle.get_cancel_mining_flag() {
                    eprintln!("canceled mining new block! was at batch: {}", batch_number);

                    current_blockchain_handle.currently_mining = false;

                    return false;
                }

                if current_blockchain_handle.is_updated() {
                    block = current_blockchain_handle.current_mining_block.clone();
                    batch_number = 0;

                    println!("dropped this succesfully mined block because of new block update");
                    println!("Updated Mining Block!: {:?}",block);

                    for transaction in current_blockchain_handle.get_all_pending_transactions(){
                        block.add_transaction(transaction);
                    }     

                    current_blockchain_handle.current_mining_block = block.clone();
                    continue;
                }

                current_blockchain_handle.add_block(block.clone());

                // Publish new block to all peers
                let blockchain_controller_handle = blockchain_controller.lock();

                let res = blockchain_controller_handle.publish_new_mined_block(&block);
                match res {
                    Ok(_) => {},
                    Err(err) => eprintln!("Error while calling blockchain_controller_handle.publish_new_mined_block: '{:?}'",err),
                }

                current_blockchain_handle.currently_mining = false;

                return true;
            }
        }

        let mut current_blockchain_handle = blockchain.lock();
        if current_blockchain_handle.is_updated() {
            block = current_blockchain_handle.current_mining_block.clone();

            for transaction in current_blockchain_handle.get_all_pending_transactions(){
                block.add_transaction(transaction);
            }

            current_blockchain_handle.current_mining_block = block.clone();

            println!("Updated Mining Block!: {:?}",block);

            batch_number = 0;
        }
        if current_blockchain_handle.get_cancel_mining_flag() {
            eprintln!("canceled mining new block! was at batch: {}", batch_number);

            current_blockchain_handle.currently_mining = false;

            return false;
        }
        std::mem::drop(current_blockchain_handle);
        batch_number += 1;
    }
    // Get Blockchain and say we exited mining
    let mut current_blockchain_handle = blockchain.lock();

    current_blockchain_handle.currently_mining = false;

    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub public_key: PublicKey,
    secret_key: SecretKey,
}
impl Identity {
    pub fn generate_new() -> Identity {
        let id: (PublicKey, SecretKey) = sign::gen_keypair();
        Identity {
            public_key: id.0,
            secret_key: id.1,
        }
    }
    pub fn load_from_file(filename: &str) -> Result<Identity, Box<dyn Error>> {
        let data = std::fs::read(format!("{}.identity", filename))?;
        let id: Identity = serde_json::from_slice(&data)?;
        Ok(id)
    }
    pub fn save_to_file(&self, filename: &str) -> Result<(), Box<dyn Error>> {
        std::fs::write(
            format!("{}.identity", filename),
            serde_json::to_string(self)?,
        )?;
        Ok(())
    }
    pub fn origin_public_key() -> PublicKey {
        PublicKey::from_slice(&[0u8; 32])
            .ok_or("fatal: failed to generate origin identity")
            .unwrap()
    }
}

// 1 + 8 + 32 + 8 + 1 + 4 + 2 + ? = 56 bytes + ? bytes
// 137 bytes per Transaction: ? x 137 bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    version: u8,
    index: u64,

    previous_hash: Hash,
    timestamp: i64,

    difficulty: u8,
    nonce: u32,

    num_transactions: u16, // byte 54 & 55
    transactions: Vec<Transaction>,
}
impl Block {
    pub fn verify(&self) -> bool {
        for transaction in &self.transactions {
            if !transaction.verify() {
                return false;
            }
        }

        true
    }
    fn generate_genisis_block(version: u8, difficulty: u8) -> Block {
        Block {
            version,
            index: 0,
            previous_hash: [0u8; 32],
            timestamp: 0i64,
            difficulty,
            nonce: 0,
            num_transactions: 0,
            transactions: vec![],
        }
    }

    pub fn deserialize_from_bytes(data: &[u8]) -> Result<Block, Box<dyn Error>> {
        Ok(Block {
            version: data[0],                                               // 1
            index: u64::from_be_bytes(data[1..9].try_into()?),              // 8
            previous_hash: data[9..41].try_into()?,                         // 32
            timestamp: i64::from_be_bytes(data[41..49].try_into()?),        // 8
            difficulty: data[49],                                           // 1
            nonce: u32::from_be_bytes(data[50..54].try_into()?),            // 4
            num_transactions: u16::from_be_bytes(data[54..56].try_into()?), // 2
            transactions: data[56..]
                .chunks(137)
                .filter(|x| !x.is_empty())
                .map(Transaction::deserialize_from_bytes)
                .map(|transaction| transaction.ok())
                .filter(|x| x.is_some())
                .map(|f| f.ok_or("fatal: error while deserializing Block").unwrap())
                .collect(),
        })
    }
    pub fn serialize_to_bytes(&self) -> Vec<u8> {
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
    pub fn hash(&self) -> Hash {
        let mut hasher = Blake2s256::new();
        // write input message
        hasher.update(self.serialize_to_bytes());

        // read hash digest
        let result = hasher.finalize();

        result.try_into().unwrap()
    }
    pub fn check_validity(&self) -> bool {
        if !get_leading_zeros_of_u8_slice(&self.hash()) >= self.difficulty as u32 {
            return false;
        }
        if self.num_transactions as usize != self.transactions.len() {
            return false;
        }
        true
    }

    pub fn add_transaction(&mut self, transaction: Transaction) {
        self.transactions.push(transaction);
        self.num_transactions += 1;
    }
    pub fn new_from_current_time(
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
#[derive(Debug, Clone, std::cmp::PartialEq, Eq)]
pub struct Transaction {
    sender: PublicKey,
    reciever: PublicKey,
    amount: u64,
    signature_of_sender: Signature,
    miner_reward_flag: u8,
}
impl Transaction {
    pub fn verify(&self) -> bool {
        // TODO: Check if balance does exist...

        let mut is_valid = true;

        if (self.miner_reward_flag == 1 && self.sender.as_ref() != [0u8; 32])
            || (!sign::verify_detached(
                &self.signature_of_sender,
                &Transaction::in_flight_transaction_to_be_signed(
                    self.sender,
                    self.reciever,
                    self.amount,
                ),
                &self.sender,
            ))
        {
            is_valid = false;
        }

        is_valid
    }

    pub fn deserialize_from_bytes(data: &[u8]) -> Result<Transaction, Box<dyn Error>> {
        Ok(Transaction {
            sender: PublicKey::from_slice(&data[0..32])
                .ok_or("Failed to deserialize Transaction bytes")?,
            reciever: PublicKey::from_slice(&data[32..64])
                .ok_or("Failed to deserialize Transaction bytes")?,
            amount: u64::from_be_bytes(data[64..72].try_into()?),
            signature_of_sender: Signature::from_bytes(&data[72..136]).unwrap(),
            miner_reward_flag: data[136],
        })
    }

    pub fn serialize_to_bytes(&self) -> Vec<u8> {
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

    pub fn generate_transaction_from_identity(
        sender_id: Identity,
        reciever_public_key: PublicKey,
        amount: u64,
    ) -> Self {
        let to_be_signed = Self::in_flight_transaction_to_be_signed(
            sender_id.public_key,
            reciever_public_key,
            amount,
        );
        Transaction {
            sender: sender_id.public_key,
            reciever: reciever_public_key,
            amount,
            signature_of_sender: sign_detached(&to_be_signed, &sender_id.secret_key),
            miner_reward_flag: 0,
        }
    }
    pub fn generate_miner_transaction(miner_public_key: PublicKey) -> Self {
        let to_be_signed = Self::in_flight_transaction_to_be_signed(
            PublicKey::from_slice(&[0u8; 32])
                .ok_or("failed to generate 0ed PublicKey for miner reward")
                .unwrap(),
            miner_public_key,
            MINER_REWARD,
        );
        Transaction {
            sender: PublicKey::from_slice(&[0u8; 32])
                .ok_or("failed to generate 0ed PublicKey for miner reward")
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

    pub fn in_flight_transaction_to_be_signed(
        public_key: PublicKey,
        reciever_public_key: PublicKey,
        amount: u64,
    ) -> Vec<u8> {
        [
            public_key.as_ref(),
            reciever_public_key.as_ref(),
            &amount.to_be_bytes().to_vec(),
        ]
        .to_vec()
        .concat()
    }
}
