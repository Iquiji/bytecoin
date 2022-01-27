use promptly::{prompt, prompt_default, prompt_opt};

use parking_lot::Mutex;

use std::sync::Arc;
use std::thread;

use sodiumoxide::crypto::sign::ed25519::PublicKey;

use tiny_http::{Server, Response};

use bytecoin_lib::{BlockchainController,Blockchain,Block,Transaction,Identity,mine_new_block};

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
    use rand::Rng;

    use crate::{Transaction, Identity,Block, Blockchain};

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
        
        let mut block = Block::new_from_current_time(0u8, 0, [7u8; 32], 20);

        let transaction: Transaction = Transaction::generate_miner_transaction(current_identity.public_key);
        block.add_transaction(transaction);

        let transaction: Transaction = Transaction::generate_miner_transaction(current_identity.public_key);
        block.add_transaction(transaction);

        let transaction: Transaction = Transaction::generate_miner_transaction(current_identity.public_key);
        block.add_transaction(transaction);

        let serialized = block.serialize_to_bytes();
        let deserialized = Block::deserialize_from_bytes(&serialized);

        assert_eq!(block,deserialized.unwrap());
    }
    #[test]
    fn blockchain_stack_serialize_deserialize_eq(){
        sodiumoxide::init().unwrap();
        let mut rng = rand::thread_rng();

        let current_identity = Identity::generate_new();

        let mut blockchain = Blockchain::genesis();
        
        let mut num_transactions: u64 = 0;

        for _ in 0..10{
            let mut block = Block::new_from_current_time(0u8, 0, [7u8; 32], 20);

            for _ in 0..50 {
                let transaction: Transaction = Transaction::generate_miner_transaction(current_identity.public_key);
                block.add_transaction(transaction);

                num_transactions += 1;
            }
            
            blockchain.add_block(block);
            
        }

        //println!("blockchain: {:?}",blockchain);

        //panic!();

        let serialized = blockchain.serialize_stack_to_bytes();

        //println!("serialized: {:?}",serialized);
        println!("serialized: {:?}",serialized.len());
        println!("num_transactions: {:?}",num_transactions);
        println!("serialized/num_transactions: {:?} \n\n\n",serialized.len() as f64/ num_transactions as f64);

        //panic!();
        
        let deserialized = Blockchain::deserialize_stack_from_bytes(&serialized);

        assert_eq!(blockchain.stack,deserialized.unwrap());
    }
}