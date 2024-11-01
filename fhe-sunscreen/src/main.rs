
use std::error::Error;
use std::time::Duration;

use futures::prelude::*;
use futures::stream::StreamExt;
use tokio::{
    io,
    io::AsyncBufReadExt,
    select
};
use libp2p::{
    kad::{self, store::{MemoryStore, MemoryStoreConfig}, Mode, Config},
    mdns,
    noise,
    Swarm,
    swarm::{NetworkBehaviour, SwarmEvent},
    PeerId,
    tcp,
    yamux
};
use tracing_subscriber::EnvFilter;
use serde_json;
use serde::{Deserialize, Serialize};
use regex::Regex;

mod fhe_sunscreen;
use fhe_sunscreen::{EncryptedPosition, Position, User, AVS};

// Create a custom network behaviour that combines Kademlia and mDNS.
#[derive(NetworkBehaviour)]
struct Behaviour {
    kademlia: kad::Behaviour<MemoryStore>,
    mdns: mdns::tokio::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();
    println!("\nSetting up IPFS node with Kademlia DHT...");

    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {

            let memory_store_config = MemoryStore::with_config(
                key.public().to_peer_id(),
                MemoryStoreConfig {
                    // The maximum number of records.
                    max_records: 1024,
                    // The maximum size of record values, in bytes.
                    // Note: make this big as FHE ciphertexts are very large (+6mil characters)
                    max_value_bytes: 4_294_967_296, // max uint32 -> 4,294,967,296 bytes
                    // The maximum number of providers stored for a key.
                    // This should match up with the chosen replication factor.
                    max_providers_per_key: 1024,
                    // The maximum number of provider records for which the
                    // local node is the provider.
                    max_provided_keys: MemoryStoreConfig::default().max_provided_keys,
                }
            );

            let mut config: Config = Default::default();
            // ciphertexts are +865kb, increase packet size to 1048576 = 1024**2
            config.set_max_packet_size(4_294_967_296);

            let kad_behaviour = kad::Behaviour::with_config(
                key.public().to_peer_id(),
                memory_store_config,
                config
            );

            Ok(Behaviour {
                kademlia: kad_behaviour,
                mdns: mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                )?,
            })
        })?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();

    // use clap or something better for cmd ling args
    let cmd_args = std::env::args().collect::<Vec<String>>();
    let user_name = cmd_args.get(1).expect("\n[ERROR] Missing name, run: cargo run -- <alice/bob>");

    println!("Setting up AVS with FHE program...");
    let mut avs = AVS::setup()?;
    // FHE scheme parameters are public to the protocol, so Alice has them.
    println!("Setting up keys for user...\n");
    let mut user = User::setup(&avs.compiled_move_position.metadata.params, user_name)?;

    swarm.behaviour_mut().kademlia.set_mode(Some(Mode::Server));

    // read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();
    // Tell the swarm to listen on all interfaces and a random, OS-assigned port
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    loop {
        select! {
            Ok(Some(line)) = stdin.next_line() => handle_input_line(
                swarm.local_peer_id().clone(),
                &mut swarm.behaviour_mut().kademlia,
                line,
                &mut user,
                &mut avs
            ),
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    let local_peer_id = swarm.local_peer_id().clone();
                    println!("[Local Peer]: <{user_name}> {local_peer_id} listening on {address:?}\n");
                    avs.set_peer_id(Some(local_peer_id));
                },
                SwarmEvent::ConnectionClosed { cause, peer_id, ..} => {
                    println!("ConnectionClosed for peer {peer_id}: {cause:?}");
                },
                SwarmEvent::ConnectionEstablished { peer_id, ..} => {
                    handle_connection_established(peer_id, &mut user, &mut avs, &mut swarm)?;
                },
                SwarmEvent::Behaviour(
                    BehaviourEvent::Mdns(mdns::Event::Discovered(list))
                ) => {
                    for (peer_id, multiaddr) in list {
                        let kademlia = &mut swarm.behaviour_mut().kademlia;
                        kademlia.add_address(&peer_id, multiaddr);
                    }
                },
                SwarmEvent::Behaviour(
                    BehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed { result, ..})
                ) => {
                    match result {
                        kad::QueryResult::GetRecord(Ok(
                            kad::GetRecordOk::FoundRecord(kad::PeerRecord { record, .. })
                        )) => {
                            handle_get_record_result(record, &mut user, &mut avs)?;
                        }
                        kad::QueryResult::GetRecord(Err(err)) => {
                            eprintln!("Failed to get record: {err:?}");
                        }
                        kad::QueryResult::PutRecord(Ok(kad::PutRecordOk { key })) => {
                            println!(
                                "Successfully put record {:?}",
                                std::str::from_utf8(key.as_ref()).unwrap()
                            );
                        }
                        kad::QueryResult::PutRecord(Err(err)) => {
                            eprintln!("Failed to put record: {err:?}");
                        }
                        _ => {}
                    }
                },
                _ => {
                    println!("...")
                },
            }
        }
    }
}



fn handle_connection_established(
    peer_id: libp2p::PeerId,
    user: &mut User,
    avs: &mut AVS,
    swarm: &mut Swarm<Behaviour>,
) -> Result<(), Box<dyn Error>> {

    println!("[Remote Peer]: {peer_id}: ConnectionEstablished!");
    let local_peer_id = swarm.local_peer_id().clone();
    let key = form_avs_public_key(&local_peer_id.to_string());
    let kademlia = &mut swarm.behaviour_mut().kademlia;
    let avs_public_key_value: Vec<u8> = user.ecdh_public_key.to_sec1_bytes().to_vec();

    kademlia.put_record(
        kad::Record {
            key: kad::RecordKey::new(&key),
            value: avs_public_key_value,
            publisher: None,
            expires: None,
        },
        kad::Quorum::One
    )?;

    if user.name == Some("alice".to_string()) {
        avs.peer_ids.insert("bob".to_string(), peer_id);
        avs.peer_ids.insert("alice".to_string(), local_peer_id);
    }
    if user.name == Some("bob".to_string()) {
        avs.peer_ids.insert("alice".to_string(), peer_id);
        avs.peer_ids.insert("bob".to_string(), local_peer_id);
    }

    kademlia.get_record(kad::RecordKey::new(&form_avs_public_key(&peer_id.to_string())));
    Ok(())
}

fn handle_get_record_result(
    record: kad::Record,
    user: &mut User,
    avs: &mut AVS
) -> Result<(), Box<dyn Error>> {

    let kad::Record { key, value, publisher, ..  } = record;
    let key_str = std::str::from_utf8(key.as_ref()).expect("key.as_ref() missing?");

    if is_encrypted_fhe_key(key_str) {
        // replicate alice decryption key for testing purposes

        let peer_id = publisher.expect("there should be a publisher").to_string();

        println!("Getting alice keys for Bob...");
        let peer_keys: UserKeyPair = serde_json::from_slice(&value)
            .expect("serde_json::from_utf8() failed");

        user.peer_fhe_decryption_keys.insert(peer_id, peer_keys);
        println!("saved alice's encrypted FHE keys and ECDH public key in AVS node");

    } else if is_position_key(key_str) {
        // encrypted position
        println!("read encrypted position from IPFS kademlia...");
        println!("unpacking encrypted positions (ciphertexts are +870 kb)...");
        let encrypted_position: EncryptedPosition = serde_json::from_slice(&value)
            .expect("from_slice failed");

        let peer_id = get_peer_id_from_position_key(&key_str);

        println!("Decoding encrypted positions...");
        println!("publisher: {:?}", publisher);
        println!("avs.peer_id: {:?}", avs.peer_id);

        let position = match publisher == avs.peer_id {
            true  => user.decrypt_own_position(encrypted_position)?,
            false => user.decrypt_peer_position(encrypted_position, &peer_id)?,
        };

        println!("Decrypted position for {key_str}: {position:?}");

    } else if is_avs_public_key(key_str) {

        let avs_public_key: k256::PublicKey = k256::PublicKey::from_sec1_bytes(&value)
            .expect("deserialize avs_public_key");

        avs.peer_public_keys.insert(key_str.to_string(), avs_public_key);

        let check_avs_pubkey = avs.peer_public_keys.get(key_str)
            .expect("should have saved peer_avs_public_key")
            .as_affine();

        println!("\nSaved {}: {:?} of length: {}", key_str, check_avs_pubkey, value.len());
        // use this public_key to encrypt alice's FHE key intended for Bob

    } else {
        println!("Unhandled key")
    }
    Ok(())
}

fn handle_input_line(
    local_peer_id: PeerId,
    kademlia: &mut kad::Behaviour<MemoryStore>,
    line: String,
    user: &mut User,
    avs: &mut AVS
) {
    let mut args = line.split(' ');

    match (args.next(), args.next()) {
        (None, _) => {
            eprintln!("expected GET, PUT, MOVE or SHARE_KEY");
        }
        (Some(_), None) => {
            eprintln!("Expected key in 2nd argument");
        }
        (Some("GET"), Some(cmd)) => {

            let name = args.next().expect("expected alice or bob for 3rd argument");
            let peer_id = avs.peer_ids.get(name)
                .expect(&format!("{} missing in avs.peer_ids", name))
                .to_string();

            match cmd {
                AVS_PUBLIC_KEY => {
                    kademlia.get_record(kad::RecordKey::new(&form_avs_public_key(&peer_id)));
                }
                POSITION => {
                    kademlia.get_record(kad::RecordKey::new(&form_position_key(&peer_id)));
                }
                ENCRYPTED_FHE_KEY => {
                    kademlia.get_record(kad::RecordKey::new(&form_encrypted_fhe_key(&peer_id)));
                }
                _ => {
                    eprintln!("Unrecognised GET command: choose AVS_PUBLICKEY, POSITION, or ENCRYPTED_FHE_KEY");
                }
            }
        }
        (Some("SHARE_KEY"), Some(_name)) => {
            // Encrypt Alice's FHE private key and share it with Bob using Elliptic-curve Diffie–Hellman (ECDH).
            // This is for testing only. Alice should not be sharing private keys.
            let peer_id = match user.name.clone().unwrap().as_str() {
                "alice" => avs.peer_ids.get("bob").expect("bob peer_id missing").clone().to_string(),
                "bob" => avs.peer_ids.get("alice").expect("alice peer_id missing").clone().to_string(),
                _ => {
                    eprintln!("unexpected name");
                    return;
                }
            };

            // Get Bob's ECDH public key
            let avs_peer_ecdh_public_key = match avs.peer_public_keys
                .get(&form_avs_public_key(&peer_id)) {
                Some(pkey) => pkey,
                None => {
                    eprintln!("avs_peer_ecdh_public_key for {peer_id} missing");
                    return;
                }
            };

            // ECDH encrypt so Bob can decrypt using his shared secret
            println!("encrypting {}'s private_key for bob...", user.name.as_ref().expect("user.name missing"));
            let alice_fhe_private_key_encrypted = user.encrypt_fhe_key_for_peer(avs_peer_ecdh_public_key);

            let encrypted_fhe_keys_str = serde_json::to_string(&(UserKeyPair {
                ecdh_public_key: user.ecdh_public_key,
                fhe_private_key_encrypted: alice_fhe_private_key_encrypted
            })).expect("serde_json::to_string(UserKeyPair) failed");

            match kademlia.put_record(
                kad::Record {
                    key: kad::RecordKey::new(&form_encrypted_fhe_key(&local_peer_id.to_string())),
                    value: encrypted_fhe_keys_str.as_bytes().to_vec(),
                    publisher: Some(local_peer_id),
                    expires: None,
                },
                kad::Quorum::One
            ) {
                Ok(query_id) => println!("stored {local_peer_id}_private_key queryId: {query_id}"),
                Err(e) => println!("{:?}", e),
            }
        }
        (Some("MOVE"), Some(name)) => match args.next() {
            None => eprintln!(r#"Expected a position value like {{"x":1,"y":2}}"#),
            Some(value) => {

                let position = serde_json::from_str::<Position>(&value).unwrap();
                println!("Moving to: ({}, {})", position.x, position.y);

                let move_tx = user.create_move_transaction(position.clone())
                    .expect("alice.create_move_transaction");

                let new_encrypted_position = avs.run_contract(
                    move_tx,
                    &user.fhe_public_key // can use peer AVS's public key. Then peer can decrypt Alice's position
                ).expect("AVS.run_contract");

                let peer_id = avs.peer_ids.get(name)
                    .expect(&format!("{} missing in avs.peer_ids", name))
                    .to_string();

                let key_str = form_position_key(&peer_id);

                println!("saving encrypted position...");
                // save encrypted position to Kademlia
                let record = kad::Record {
                    key: kad::RecordKey::new(&key_str),
                    value: serde_json::to_vec(&new_encrypted_position).expect("serde_json::to_vec(new_encrypted_position) failed"),
                    // DEFAULT_MAX_PACKET_SIZE = 16 * 1024; = 16,384
                    // Configure Kademlia packet size to accomodate +900kb ciphertexts (Vec<u8>)
                    publisher: Some(local_peer_id),
                    expires: None,
                };

                match kademlia.put_record(record, kad::Quorum::One) {
                    Ok(query_id) => println!("stored with queryId: {query_id}"),
                    Err(e) => println!("{:?}", e),
                }
            }
        }
        (Some(s), _) => eprintln!("Unrecognised command: {s}")
    }
}


#[derive(Serialize, Deserialize)]
struct UserKeyPair {
    ecdh_public_key: k256::PublicKey,
    fhe_private_key_encrypted: Vec<u8>,
}

const POSITION: &str = "POSITION";
const AVS_PUBLIC_KEY: &str = "AVS_PUBLIC_KEY";
const ENCRYPTED_FHE_KEY: &str = "ENCRYPTED_FHE_KEY";

pub fn form_position_key(peer_id: &str) -> String {
    format!("{POSITION}_{peer_id}")
}

pub fn form_avs_public_key(peer_id: &str) -> String {
    format!("{AVS_PUBLIC_KEY}_{peer_id}")
}

pub fn form_encrypted_fhe_key(peer_id: &str) -> String {
    format!("{ENCRYPTED_FHE_KEY}_{peer_id}")
}

pub fn is_position_key(str: &str) -> bool {
    let re = Regex::new(&format!(r"{}_(?<peer_id>\w*)", POSITION)).unwrap();
    let Some(_capture) = re.captures(str) else {
        return false;
    };
    return true;
}

pub fn get_peer_id_from_position_key(str: &str) -> String {
    let results = str.split("_").collect::<Vec<&str>>();
    let peer_id = results[1].to_string();
    return peer_id
}

pub fn is_avs_public_key(str: &str) -> bool {
    let re = Regex::new(&format!(r"{}_(?<peer_id>\w*)", AVS_PUBLIC_KEY)).unwrap();
    let Some(_capture) = re.captures(str) else {
        return false;
    };
    return true;
}

pub fn is_encrypted_fhe_key(str: &str) -> bool {
    let re = Regex::new(&format!(r"{}_(?<peer_id>\w*)", ENCRYPTED_FHE_KEY)).unwrap();
    let Some(capture) = re.captures(str) else {
        return false;
    };
    println!("ENCRYPTED_FHE_KEY: Peer ID is: {}", &capture["peer_id"]);
    return true;
}