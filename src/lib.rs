use parking_lot::Mutex;
use std::sync::Arc;

use std::error::Error;

use blake2::{Blake2s256, Digest};
use chrono::Utc;

use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey, Signature};
use sodiumoxide::crypto::sign::{self, sign_detached};

use serde::{Deserialize, Serialize};

const MINER_REWARD: u64 = 100;
const STARTING_DIFFICULTY: u8 = 10;

type Hash = [u8;32];

pub struct BlockchainController{
    pub blockchain: Arc<Mutex<Blockchain>>,
    pub peers: Vec<String>,
    pub mined_flag: bool,
}
impl BlockchainController{
    pub fn publish_new_mined_block(block_to_be_published: Block){

    }
}

pub fn get_leading_zeros_of_u8_slice(v: &[u8]) -> u32 {
    let n_zeroes = match v.iter().position(|&x| x != 0) {
        Some(n) => n,
        None => return 8 * v.len() as u32,
    };

    v.get(n_zeroes).map_or(0, |x| x.leading_zeros()) + 8 * n_zeroes as u32
}

#[derive(Debug,PartialEq, Eq)]
pub struct Blockchain {
    pub stack: Vec<Block>,
    pub hashes: Vec<[u8; 32]>,
    pub difficulty: u8,
    current_mining_block: Block,
    current_block_updated_flag: bool,
    cancel_mining_flag: bool,
}
impl Blockchain {
    pub fn genesis() -> Self {
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

    pub fn serialize_stack_to_bytes(&self) -> Vec<u8>{
        self.stack.iter().map(|block| block.serialize_to_bytes()).collect::<Vec<Vec<u8>>>().concat()
    }
    pub fn deserialize_stack_from_bytes(data: &[u8]) -> Result<Vec<Block>,Box<dyn Error>>{
        // Remaining Data to be split into Blocks
        let mut remaining_data = data;

        let mut stack: Vec<Block> = vec![];
        
        // Basic block is 56 bytes long
        // 1 Transaction is 137 bytes long
        while remaining_data.len() > 55{
            // Transaction amount in bytes 54 & 55 (started from 0)
            // get number of transactions in this Block-bytespace
            let mut num_transactions = u16::from_be_bytes([remaining_data[54],remaining_data[55]]);

            // Get all bytes in this Block-bytespace
            let this_block_data_temp = remaining_data.split_at(56 + num_transactions as usize * 137);
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

    pub fn add_new_transaction_to_mining_block(&mut self, transaction: Transaction) {
        self.current_block_mut().add_transaction(transaction);
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
    pub fn current_hash(&self) -> Hash {
        *self
            .hashes
            .last()
            .ok_or("fatal: no block on stack")
            .unwrap()
    }
    pub fn add_block(&mut self, block: Block) {
        self.stack.push(block);
        self.current_block_updated_flag = false;
    }
    pub fn add_hash_to_new_block(&mut self, hash: Hash) {
        self.hashes.push(hash);
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
    pub fn destroy_current_block(&mut self) {
        self.stack.pop();
    }
    pub fn check_balance_of_account(&self,account_pk: PublicKey) -> u64{
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
pub fn mine_new_block(blockchain: Arc<Mutex<Blockchain>>,blockchain_controller: Arc<Mutex<BlockchainController>>,identity: Identity) -> bool {
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
#[derive(Debug, Clone,PartialEq, Eq)]
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
    pub fn deserialize_from_bytes(data: &[u8]) -> Result<Block,Box<dyn Error>>{
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
#[derive(Debug, Clone,std::cmp::PartialEq, Eq)]
pub struct Transaction {
    sender: PublicKey,
    reciever: PublicKey,
    amount: u64,
    signature_of_sender: Signature,
    miner_reward_flag: u8,
}
impl Transaction {
    pub fn deserialize_from_bytes(data: &[u8]) -> Result<Transaction,Box<dyn Error>>{
        Ok(Transaction {
            sender: PublicKey::from_slice(&data[0..32]).ok_or("Failed to deserialize Transaction bytes")?,
            reciever: PublicKey::from_slice(&data[32..64]).ok_or("Failed to deserialize Transaction bytes")?,
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

    pub fn generate_transaction_from_secret_key(
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
    pub fn generate_miner_transaction(miner_public_key: PublicKey) -> Self {
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

    pub fn in_flight_transaction_to_be_signed(
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