use criterion::{black_box, criterion_group, criterion_main, Criterion};
use criterion::BenchmarkId;
use criterion::Throughput;

use bytecoin_lib::{BlockchainController,Blockchain,Block,Transaction,Identity,mine_new_block};

use hex::{encode,decode};

pub fn blockchain_stack_serialize_100_blocks_variable_transaction_count(c: &mut Criterion) {
    let id = Identity::generate_new();

    let mut blockchain = Blockchain::genesis();
        
    let mut group = c.benchmark_group("blockchain_stack_serialize_100_blocks_variable_transaction_count");

    let mut blockchain = Blockchain::genesis();

    for num_transactions_per_block in [1,5,10,25,50,100,200,500,1000,2500].iter() {

        // add 100 Blocks with num_transactions_per_block Transactions each to the blockchain
        for _ in 0..100{
            let mut block = Block::new_from_current_time(0u8, 0, [7u8; 32], 20);

            for _ in 0..*num_transactions_per_block {
                let transaction: Transaction = Transaction::generate_miner_transaction(id.public_key);
                block.add_transaction(transaction);
    
            }
            blockchain.add_block(block);
        }

        group.throughput(Throughput::Elements(100*num_transactions_per_block));
        group.bench_with_input(BenchmarkId::from_parameter((100*num_transactions_per_block).to_string() + " Transactions"), &blockchain,|b, blockchain| {
            b.iter(|| blockchain.serialize_stack_to_bytes());
        });
        
        blockchain = Blockchain::genesis();
    }
    group.finish();
}

pub fn blockchain_stack_deserialize_100_blocks_variable_transaction_count(c: &mut Criterion) {
    let id = Identity::generate_new();

    let mut blockchain = Blockchain::genesis();
        
    let mut group = c.benchmark_group("blockchain_stack_serialize_100_blocks_variable_transaction_count");

    let mut blockchain = Blockchain::genesis();

    for num_transactions_per_block in [1,5,10,25,50,100,200,500,1000,2500].iter() {

        // add 100 Blocks with num_transactions_per_block Transactions each to the blockchain
        for _ in 0..100{
            let mut block = Block::new_from_current_time(0u8, 0, [7u8; 32], 20);

            for _ in 0..*num_transactions_per_block {
                let transaction: Transaction = Transaction::generate_miner_transaction(id.public_key);
                block.add_transaction(transaction);
    
            }
            blockchain.add_block(block);
        }

        let data = blockchain.serialize_stack_to_bytes();

        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter((100*num_transactions_per_block).to_string() + " Transactions from Bytes deserialized"), &data,|b, data| {
            b.iter(|| Blockchain::deserialize_stack_from_bytes(data));
        });
        
        blockchain = Blockchain::genesis();
    }
    group.finish();
}

criterion_group!(benches, blockchain_stack_serialize_100_blocks_variable_transaction_count,blockchain_stack_deserialize_100_blocks_variable_transaction_count);
criterion_main!(benches);