use chrono::Utc;
use sha2::{Digest, Sha512};

// 8 + 64 + 512 + 64 + 8 + 32 + 16 + ? = 448 + ? bytes
#[derive(Debug)]
struct Block {
    version: u8,
    index: u64,

    previous_hash: [u8; 64],
    timestamp: i64,

    difficulty: u8,
    nonce: u32,

    num_transactions: u16,
    transactions: Vec<Transaction>,
}
impl Block {
    fn serialize_to_byte_vec(&self) -> Vec<u8> {
        [
            [self.version].to_vec(),
            self.index.to_be_bytes().to_vec(),
            self.previous_hash.to_vec(),
            self.timestamp.to_be_bytes().to_vec(),
            [self.difficulty].to_vec(),
            self.nonce.to_be_bytes().to_vec(),
            self.num_transactions.to_be_bytes().to_vec(),
            self.transactions.iter().map(|transaction| {transaction.serialize_to_byte_vec()}).collect::<Vec<Vec<u8>>>().concat(),
        ]
        .to_vec()
        .concat()
    }
}

#[derive(Debug)]
struct Transaction {
    id: u8,
}
impl Transaction {
    fn serialize_to_byte_vec(&self) -> Vec<u8> {
        [self.id].to_vec()
    }
}

fn get_leading_zeros_of_u8_slice(v: &[u8]) -> u32 {
    let n_zeroes = match v.iter().position(|&x| x != 0) {
        Some(n) => n,
        None => return 8*v.len() as u32,
    };

    v.get(n_zeroes).map_or(0, |x| x.leading_zeros()) + 8 * n_zeroes as u32
}

fn main() {
    println!("Hello, world!");

    let mut previous_hash = [6u8; 64];
    for block_num in 0..100{
        println!("minning block Nr.{}",block_num);

        let dt = Utc::now();
        let timestamp: i64 = dt.timestamp();

        let mut block: Block = Block {
            version: 0u8,
            index: block_num,
            previous_hash,
            timestamp,
            difficulty: 5u8,
            nonce: 0,
            num_transactions: 1,
            transactions: vec![Transaction{id: 0}],
        };
        println!(
            "struct: {:?},as_bytes: {:?}",
            block,
            block.serialize_to_byte_vec()
        );
        for _ in 0..100000000 {
            let mut hasher = Sha512::new();
            // write input message
            hasher.update(block.serialize_to_byte_vec());

            // read hash digest
            let result = hasher.finalize();

            let leading_zeros = get_leading_zeros_of_u8_slice(&result);

            //println!("{:?}",result);
            //println!("num: '{:?}',hash first 32bits: '{:032b}',leading zeros: {:?}",block.num,num,num.leading_zeros());

            block.nonce += 1;

            if leading_zeros >= block.difficulty as u32{
                println!("resulting hash: {:?}", result);
                println!(
                    "nonce: '{:?}',',leading zeros: {:?}",
                    block.nonce,
                    leading_zeros
                );
                println!("{:?}",result);
                previous_hash = result.as_slice().get(0..64);
                break;
            }
        }
        break;
    }
}
