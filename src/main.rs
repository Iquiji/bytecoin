use sha3::{Digest, Sha3_256};

#[derive(Debug)]
struct Block{
    previous_hash: [u8; 32],

    

    num: u32
}
impl Block{
    fn serialize_to_byte_vec(&self) -> Vec<u8>{
        [self.previous_hash.to_vec(),
        self.num.to_be_bytes().to_vec()].to_vec().concat()
    }
    
}

fn main() {
    println!("Hello, world!");
    let mut block: Block = Block{
        previous_hash: [0u8;32],
        num: 32
    };
    println!("struct: {:?},as_bytes: {:?}",block,block.serialize_to_byte_vec());

    for _ in 0..100000000{
        let mut hasher = Sha3_256::new();
        // write input message
        hasher.update(block.serialize_to_byte_vec());

        // read hash digest
        let result = hasher.finalize();

        let num = u32::from_be_bytes([result[0],result[1],result[2],result[3]]);

        //println!("{:?}",result);
        //println!("num: '{:?}',hash first 32bits: '{:032b}',leading zeros: {:?}",block.num,num,num.leading_zeros());

        block.num += 1;

        if num.leading_zeros() > 12{
            println!("num: '{:?}',hash first 32bits: '{:032b}',leading zeros: {:?}",block.num,num,num.leading_zeros());
            break;
        }
    }
}