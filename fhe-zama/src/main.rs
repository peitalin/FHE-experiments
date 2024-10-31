
use std::time::Instant;
use anyhow::Result;

use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint32};
use tfhe::prelude::*;
use clap::{Parser, Subcommand};
use ecdh;
use ecdh::k256;

mod mpc_network;
use mpc_network::MpcNetwork;

mod fhe_distance;
use fhe_distance::{
    FOW_VIEW_RANGE, PRECISION, Position,
    fhe_distance_example,
    fhe_distance_calc
};


#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Basic FHE example
    Basic { },
    /// FHE with MPC for keygen
    Mpc {
        #[arg(short, long)]
        threshold: usize,

        #[arg(short, long)]
        number_of_parties: usize
    },
}

struct User {
    name: String,
    pub ecdh_pubkey: k256::PublicKey,
    ecdh_skey: k256::ecdh::EphemeralSecret,
}
impl User {
    pub fn new(name: &str) -> Self {
        let (sk, pk) = ecdh::generate_ecdh_keys();
        User {
            name: name.to_string(),
            ecdh_pubkey: pk,
            ecdh_skey: sk
        }
    }

    pub fn decrypt_ecdh_message(&self, msg: &[u8], pubkey: &k256::PublicKey) -> Vec<u8> {
        let shared_secret = ecdh::compute_shared_secret(&self.ecdh_skey, pubkey);
        ecdh::decrypt(msg, &shared_secret)
    }
}


#[tokio::main]
async fn main() -> Result<()> {

    let start = Instant::now();
    let args: Cli = Cli::parse();

    match args.command {
        Commands::Basic {} => {
            let config = ConfigBuilder::default().build();
            let (client_key, server_key) = generate_keys(config);
            fhe_distance_example(client_key, server_key);
        },
        Commands::Mpc {
            threshold,
            number_of_parties
        } => {

            // Server Side:
            // Setup FHE keys
            let config = ConfigBuilder::default().build();
            let (fhe_client_key, fhe_server_key) = generate_keys(config);
            // Setup MPC network
            let (
                mut mpc_network,
                mpc_pub_key
            ) = setup_mpc_network(threshold, number_of_parties, fhe_server_key);

            // Client-side
            println!("\nAlice:");
            let alice = User::new("alice");
            let p1 = Position {
                x: 2,
                y: 2
            };
            println!("\tEncrypting Alice's Position {{ x: {}, y: {} }} with FHE client_key", p1.x, p1.y);
            let x1 = FheUint32::encrypt(p1.x, &fhe_client_key);
            let y1 = FheUint32::encrypt(p1.y, &fhe_client_key);

            println!("\tSerializing and encrypting position with MPC public_key...");
            let msg_x1 = bincode::serialize(&x1)?;
            let msg_y1 = bincode::serialize(&y1)?;
            // Encrypt a message with the society's public-key.
            let ciphertext_x1 = mpc_pub_key.encrypt(msg_x1.clone());
            let ciphertext_y1 = mpc_pub_key.encrypt(msg_y1.clone());
            println!("\t==> Sending to MPC_Network");

            println!("\nBob:");
            let p2 = Position {
                x: 4,
                y: 4
            };
            println!("\tEncrypting Bob's Position {{ x: ?, y: ? }} with FHE client_key");
            let x2 = FheUint32::encrypt(p2.x, &fhe_client_key);
            let y2 = FheUint32::encrypt(p2.y, &fhe_client_key);
            println!("\tSerializing and encrypting position with MPC public_key...");
            let msg_x2 = bincode::serialize(&x2)?;
            let msg_y2 = bincode::serialize(&y2)?;
            // Encrypt a message with the society's public-key.
            let ciphertext_x2 = mpc_pub_key.encrypt(msg_x2.clone());
            let ciphertext_y2 = mpc_pub_key.encrypt(msg_y2.clone());
            println!("\t==> Sending to MPC_Network");

            // Server-side
            println!("\nMPC_Network:");
            println!("\tFetching MPC shares and decrypting for FHE ciphertexts...");
            let result_x1 = mpc_network.mpc_decrypt(ciphertext_x1)?;
            let result_y1 = mpc_network.mpc_decrypt(ciphertext_y1)?;
            let result_x2 = mpc_network.mpc_decrypt(ciphertext_x2)?;
            let result_y2 = mpc_network.mpc_decrypt(ciphertext_y2)?;
            // MPC network will also perform FHE operations after MPC decrypting the msg
            set_server_key(mpc_network.fhe_server_key.clone());
            println!("\tRunning FHE operations on Position ciphertexts...");
            let fhe_x1: FheUint32 = bincode::deserialize(&result_x1)?;
            let fhe_y1: FheUint32 = bincode::deserialize(&result_y1)?;
            let fhe_x2: FheUint32 = bincode::deserialize(&result_x2)?;
            let fhe_y2: FheUint32 = bincode::deserialize(&result_y2)?;

            let (distance, rem) = fhe_distance_calc(
                &fhe_x1,
                &fhe_y1,
                &fhe_x2,
                &fhe_y2,
            );
            let reveal_position = distance.le(FOW_VIEW_RANGE * PRECISION.pow(2));
            let should_reveal_bob: bool = reveal_position.decrypt(&fhe_client_key);
            println!("\tAlice's fog-of-war view range: {}", FOW_VIEW_RANGE);
            println!("\tshould_reveal_bob?: {}", should_reveal_bob);

            // Here you can compare Alice and Bob's positions as they as encrypted under the same FHE key
            // The MPC network can decrypt comparison results (alice.x > bob.x) without revealing the
            // positions of Alice and Bob (with some trust assumptions on the MPC network).
            // Then conditional on Alice being "close" to Bob, the MPC network can decrypt Bob's position
            // re-encrypt it using Alice's pubkey, and send it to Alice.
            //
            // MPC network then needs to encrypt the FHE ciphertext response using Alice's pubkey (ECDH)
            // or it can be intercepted and decrypted by anyone with the fhe_client_key

            if (should_reveal_bob) {
                println!("\n\tBob is within Alice's FOW view range, decrypting Bob's position...");
                let revealed_x2: u32 = fhe_x2.decrypt(&fhe_client_key);
                let revealed_y2: u32 = fhe_x2.decrypt(&fhe_client_key);
                // println!("\nBob's position: ({}, {})", revealed_x2, revealed_y2);
                println!("\tEncrypting response and sending to Alice...");

                let x2_for_alice = mpc_network.ecdh_encrypt(&revealed_x2.to_string().as_bytes(), &alice.ecdh_pubkey);
                let y2_for_alice = mpc_network.ecdh_encrypt(&revealed_y2.to_string().as_bytes(), &alice.ecdh_pubkey);

                println!("\nAlice:");
                let x2_result = alice.decrypt_ecdh_message(&x2_for_alice, &mpc_network.ecdh_pub_key);
                let x2_result = std::str::from_utf8(&x2_result)?.parse::<u32>()?;

                let y2_result = alice.decrypt_ecdh_message(&y2_for_alice, &mpc_network.ecdh_pub_key);
                let y2_result = std::str::from_utf8(&y2_result)?.parse::<u32>()?;

                println!("\tAlice received and decrypted Bob's Position {{ x: {}, y: {} }}", x2_result, y2_result);
                assert!(x2_result == 4);
                assert!(y2_result == 4);
            } else {
                println!("Alice wasn't close enough to Bob to reveal his position");
            }
        },
    }

    let duration = start.elapsed();
    println!("\nTime elapsed: {:?}", duration);

    Ok(())
}


fn setup_mpc_network(
    threshold: usize,
    number_of_parties: usize,
    fhe_server_key: tfhe::ServerKey
) -> (MpcNetwork, blsttc::PublicKey) {
    // Create a `MpcNetwork` with 3 actors.
    // messages are encrypted with the society's public key, needs 2 or more actors to decrypt (decryption threshold is 1).
    // The secret society creates master keys, then deals secret-key shares and public-key shares to each actor.
    let mpc_network = MpcNetwork::new(number_of_parties, threshold, fhe_server_key);
    let mpc_pubkey = mpc_network.publish_public_key();
    (mpc_network, mpc_pubkey)
}

