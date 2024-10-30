
use std::time::Instant;
use anyhow::Result;

use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint32};
use tfhe::prelude::*;
use clap::{Parser, Subcommand};

mod mpc_network;
use mpc_network::MpcNetwork;

mod fhe_distance;
use fhe_distance::{fhe_distance_example, Position};


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
            let p1 = Position {
                x: 3,
                y: 2
            };
            println!("\tEncrypting Position {{ x: {}, y: {} }} with FHE client_key", p1.x, p1.y);
            let x1 = FheUint32::encrypt(p1.x, &fhe_client_key);
            // let y1 = FheUint32::encrypt(p1.y, &client_key);

            println!("\tSerializing and encrypting position with MPC pub_key...");
            let msg = bincode::serialize(&x1)?;

            // Encrypt a message with the society's public-key.
            let ciphertext = mpc_pub_key.encrypt(msg.clone());
            println!("\tSending to MPC server to decrypt and run FHE operations on...");

            // Server-side
            println!("\nServer:");
            println!("\tFetching MPC shares and decrypting position...");
            let result = mpc_network.mpc_decrypt(ciphertext)?;
            // MPC network will also perform FHE operations after MPC decrypting the msg
            set_server_key(mpc_network.fhe_server_key);
            println!("\tDeserializing result and running FHE operations +1...");
            let fhe_msg: FheUint32 = bincode::deserialize(&result)?;
            let fhe_msg2 = bincode::serialize(&(fhe_msg + 1))?;
            println!("\tSerializing response and sending back to user...");
            // MPC network needs to encrypt the FHE ciphertext response using Alice's pubkey (ECDH)
            // or it can be intercepted and decrypted by anyone with the fhe_client_key

            println!("\nAlice:");
            let fhe_msg3: FheUint32 = bincode::deserialize(&fhe_msg2)?;
            let original_msg: u32 = fhe_msg3.decrypt(&fhe_client_key);
            println!("\tReceived response: Position: x + 1 = {}", original_msg);
            assert!(original_msg == 4);
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

