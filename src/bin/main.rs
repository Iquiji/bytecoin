use promptly::{prompt, prompt_default, prompt_opt};

use parking_lot::Mutex;
use rand::{thread_rng, Rng};

use std::thread;
use std::{collections::HashSet, sync::Arc};

use sodiumoxide::crypto::sign::ed25519::PublicKey;

use tiny_http::{Response, Server};

use bytecoin_lib::{
    mine_new_block, Block, Blockchain, BlockchainController, Identity,
};

fn ask_for_user_action(
    blockchain: Arc<Mutex<Blockchain>>,
    blockchain_controller: Arc<Mutex<BlockchainController>>,
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
                mine_new_block(
                    thread_blockchain_mutex,
                    thread_blockchain_controller_mutex,
                    thread_current_identity,
                );
            });
        } else if command == "balance" {
            let account_to_balance_check: Option<String> = prompt_opt(
                "What account do you want to balance check? (leave empty for current identity)",
            )?;
            match account_to_balance_check {
                Some(account_to_balance_check) => {
                    let public_key_to_check = hex::decode(account_to_balance_check.clone())?;
                    let current_blockchain_handle = blockchain.lock();

                    let amount = current_blockchain_handle.check_balance_of_account(
                        PublicKey::from_slice(&public_key_to_check)
                            .ok_or("error parsing to private key")?,
                    );

                    std::mem::drop(current_blockchain_handle);

                    println!(
                        "account: '{}' has a balance of: {} coins",
                        account_to_balance_check, amount
                    );
                }
                None => {
                    let public_key_to_check = current_identity.public_key;
                    let current_blockchain_handle = blockchain.lock();

                    let amount =
                        current_blockchain_handle.check_balance_of_account(public_key_to_check);

                    std::mem::drop(current_blockchain_handle);

                    println!("your account has a balance of: {} coins", amount);
                }
            }
        } else if command == "print" {
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
            todo!();
        } else if command == "connect" {
            let connect_to: String = prompt("Adress to connect to")?;

            let connect_to_http_patted = "http://".to_owned() + &connect_to + "/connect";

            let are_u_sure: bool = prompt_default(
                "are you sure you want to connect to: ".to_owned() + &connect_to_http_patted,
                false,
            )?;

            match are_u_sure {
                true => {
                    let mut blockchain_controller_handle = blockchain_controller.lock();

                    blockchain_controller_handle
                        .connect_to_peer_and_get_peers(&connect_to_http_patted)?;

                    blockchain_controller_handle.peers.insert(connect_to);

                    std::mem::drop(blockchain_controller_handle);
                }
                false => {
                    println!("Not Connecting then...")
                }
            }
        } else {
            println!(
                "
            Commands:
                connect - connects to a given node in the network and gets their peers ❗
                mine - tries to mine next block ✔️
                cancel - cancels the mining of this block ✔️  
                transfer - transfers fund to account ❗
                generate - generates a wallet keypait ✔️
                balance - check balance of account (defaulting to your own) ✔️
                exit - stops the programm ❗
                load - loads saved identity ✔️
                save - saves current identity ✔️
            "
            )
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("sl-coin version: 0.0.1");

    sodiumoxide::init().unwrap();

    let blockchain = Blockchain::genesis();
    let arced_mutexed_blockchain = Arc::new(Mutex::new(blockchain));

    let blockchain_controller = BlockchainController {
        blockchain: arced_mutexed_blockchain.clone(),
        peers: HashSet::new(),
        mined_flag: false,
    };
    let arced_mutexed_blockchain_controller = Arc::new(Mutex::new(blockchain_controller));

    let blockchain_for_user_func = arced_mutexed_blockchain.clone();
    let blockchain_controller_for_user_func = arced_mutexed_blockchain_controller.clone();
    let _user_action_thread = thread::spawn(move || {
        ask_for_user_action(
            blockchain_for_user_func,
            blockchain_controller_for_user_func,
        )
        .unwrap();
    });

    let mut rng = thread_rng();
    let port: usize = rng.gen_range(8000..9000);

    let server = Server::http("0.0.0.0:".to_owned() + &port.to_string()).unwrap();
    println!("listening server on port: {}", port);

    for mut request in server.incoming_requests() {
        let mut content = vec![];
        request.as_reader().read_to_end(&mut content)?;

        let remote_addr = request.remote_addr().to_string();

        match request.url() {
            "/get_blockchain" => {
                println!("{} wants the entire Blockchain", remote_addr);

                let blockchain_controller_handle = arced_mutexed_blockchain_controller.lock();
                let blockchain_handle = arced_mutexed_blockchain.lock();

                let data_as_hex = hex::encode(blockchain_handle.serialize_stack_to_bytes());

                let response = Response::from_string(data_as_hex);
                request.respond(response)?;

                std::mem::drop(blockchain_controller_handle);
            }
            "/post_block" => {
                println!("got Block: {:?}", content);

                let content_hex_decoded = hex::decode(content)?;

                // Convert block into Struct
                let new_block = Block::deserialize_from_bytes(&content_hex_decoded);
                println!("got Block: {:?}", new_block);
            }
            "/post_add_peers" => {
                println!("{} wants to add peers: {:?}", remote_addr, content);
            }
            "/get_blockchain_hashed_and_length" => {
                println!("{} wants our blockchain length and hashed", remote_addr);
            }
            "/connect" => {
                // Add their address to peer list
                let mut blockchain_controller_handle = arced_mutexed_blockchain_controller.lock();

                blockchain_controller_handle
                    .peers
                    .insert(remote_addr.clone());

                // And then respond with our current peer list // whitespace seperated
                let response = Response::from_string(
                    blockchain_controller_handle
                        .peers
                        .iter()
                        .cloned()
                        .collect::<Vec<String>>()
                        .join(" "),
                );
                request.respond(response)?;

                std::mem::drop(blockchain_controller_handle);

                println!(
                    "Added '{}' to peers and gave them our peer list",
                    remote_addr
                );
            }
            _ => {
                println!(
                    "received request! method: {:?}, url: {:?}, body_length: {:?}",
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
    use bytecoin_lib::{Block, Blockchain, Identity, Transaction};

    #[test]
    fn transaction_serialize_deserialize_eq() {
        sodiumoxide::init().unwrap();
        let current_identity = Identity::generate_new();
        let transaction: Transaction =
            Transaction::generate_miner_transaction(current_identity.public_key);
        let serialized = transaction.serialize_to_bytes();
        let deserialized = Transaction::deserialize_from_bytes(&serialized);

        assert_eq!(transaction, deserialized.unwrap());
    }
    #[test]
    fn block_serialize_deserialize_eq() {
        sodiumoxide::init().unwrap();
        let current_identity = Identity::generate_new();

        let mut block = Block::new_from_current_time(0u8, 0, [7u8; 32], 20);

        let transaction: Transaction =
            Transaction::generate_miner_transaction(current_identity.public_key);
        block.add_transaction(transaction);

        let transaction: Transaction =
            Transaction::generate_miner_transaction(current_identity.public_key);
        block.add_transaction(transaction);

        let transaction: Transaction =
            Transaction::generate_miner_transaction(current_identity.public_key);
        block.add_transaction(transaction);

        let serialized = block.serialize_to_bytes();
        let deserialized = Block::deserialize_from_bytes(&serialized);

        assert_eq!(block, deserialized.unwrap());
    }
    #[test]
    fn blockchain_stack_serialize_deserialize_eq() {
        sodiumoxide::init().unwrap();

        let current_identity = Identity::generate_new();

        let mut blockchain = Blockchain::genesis();

        let mut num_transactions: u64 = 0;

        for _ in 0..10 {
            let mut block = Block::new_from_current_time(0u8, 0, [7u8; 32], 20);

            for _ in 0..50 {
                let transaction: Transaction =
                    Transaction::generate_miner_transaction(current_identity.public_key);
                block.add_transaction(transaction);

                num_transactions += 1;
            }

            blockchain.add_block(block);
        }

        //println!("blockchain: {:?}",blockchain);

        //panic!();

        let serialized = blockchain.serialize_stack_to_bytes();

        //println!("serialized: {:?}",serialized);
        println!("serialized: {:?}", serialized.len());
        println!("num_transactions: {:?}", num_transactions);
        println!(
            "serialized/num_transactions: {:?} \n\n\n",
            serialized.len() as f64 / num_transactions as f64
        );

        //panic!();

        let deserialized = Blockchain::deserialize_stack_from_bytes(&serialized);

        assert_eq!(blockchain.stack, deserialized.unwrap());
    }

    #[test]
    fn blockchain_generate_and_check_validity() {
        sodiumoxide::init().unwrap();

        // Building blockchain
        let current_identity = Identity::generate_new();

        let mut blockchain = Blockchain::genesis();

        for _ in 0..10 {
            let mut block = Block::new_from_current_time(0u8, 0, [7u8; 32], 20);

            for _ in 0..50 {
                let transaction: Transaction =
                    Transaction::generate_miner_transaction(current_identity.public_key);
                block.add_transaction(transaction);
            }

            blockchain.add_block(block);
        }

        // Verify Blockchain
        assert!(!blockchain.verify());
    }
}
