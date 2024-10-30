
use std::ops::Mul;
use std::time::Instant;
use anyhow::Result;

use serde::{Serialize, Deserialize};
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint32};
use tfhe::prelude::*;
use clap::{Parser, Subcommand};

mod mpc_network;
use mpc_network::MpcNetwork;


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

const PRECISION: u32 = 100;
const FOW_VIEW_RANGE: u32 = 11;

#[derive(Deserialize, Serialize, Debug)]
struct Position {
    x: u32,
    y: u32
}

fn fhe_distance_example(
    alice_key: tfhe::ClientKey,
    server_key_alice: tfhe::ServerKey
) {

    // Client-side
    println!("\nAlice:");
    let p1 = Position {
        x: 3,
        y: 2
    };
    // movement
    let m = Position {
        x: 9,
        y: 8
    };

    println!("\tEncrypting starting position ({}, {})", p1.x, p1.y);
    println!("\tEncrypting move: ({}, {}) and sending to server", m.x, m.y);
    let x1 = FheUint32::encrypt(p1.x, &alice_key);
    let y1 = FheUint32::encrypt(p1.y, &alice_key);
    // new position:
    let x2 = FheUint32::encrypt(p1.x + m.x, &alice_key);
    let y2 = FheUint32::encrypt(p1.y + m.y, &alice_key);

    // Server-side
    set_server_key(server_key_alice);
    println!("\nServer:");
    println!("\tPerforming FHE operations to calculate distance to new position");
    let (g, rem) = fhe_distance(&x1, &y1, &x2, &y2);
    let reveal_position = g.le(FOW_VIEW_RANGE * PRECISION.pow(2));

    //Client-side
    println!("\nAlice:");
    let new_position = Position {
        x: x2.decrypt(&alice_key),
        y: y2.decrypt(&alice_key),
    };
    println!("\tDecypted new position: {new_position:?}");
    println!("\tReveal position?: {}", reveal_position.decrypt(&alice_key));
    let distance_decrypted: u32 = g.decrypt(&alice_key);
    let rem: u32 = rem.decrypt(&alice_key);
    let distance_final = (distance_decrypted + rem/2) as f32 / PRECISION as f32;
    println!("\tDistance: {:?}", distance_final);

    assert_eq!(new_position.x, m.x + p1.x);
    assert_eq!(new_position.y, m.y + p1.y);

    println!("\tAssert distance: f32::sqrt(9.powf(2) + 8.powf(2)) = {}", check_distance(9.0, 8.0));
}

fn check_distance(dx: f32, dy: f32) -> f32 {
    let distance_sq: f32 = dx.powf(2.0) + dy.powf(2.0);
    f32::sqrt(distance_sq)
}

// Server-side calculation of distance
fn fhe_distance(
    x1: &FheUint32, y1: &FheUint32,
    x2: &FheUint32, y2: &FheUint32,
) -> (FheUint32, FheUint32) {

    let dx = x2 - x1;
    let dy = y2 - y1;

    let dx_sq = dx.clone().mul(dx);
    let dy_sq = dy.clone().mul(dy);

    // multiply by 10_000 (then divide by sqrt(10k) = 100) to calculate sqrt on integers with 2-decimal precision
    let distance_sq = (dx_sq + dy_sq) * PRECISION.pow(2);

    let initial_sqrt_guess = 1000_u32;
    println!("\tinitial_sqrt_guess: {:?}", initial_sqrt_guess);

    let (g, _rem) = sqrt_newtowns_approx_initial_step(
        &distance_sq,
        initial_sqrt_guess
    );
    // run ~2 iterations for the square root approximation
    // number of iterations depends on how close your initial_sqrt_guess is
    let (g, rem) = sqrt_newtowns_approx_iteration(&distance_sq, &g);

    (g, rem)
}

// https://en.wikipedia.org/wiki/Newton%27s_method
fn sqrt_newtowns_approx_initial_step(n: &FheUint32, g: u32) -> (FheUint32, FheUint32) {
    (g + (n/g)).div_rem(2)
}

fn sqrt_newtowns_approx_iteration(n: &FheUint32, g: &FheUint32) -> (FheUint32, FheUint32) {
    (g.clone() + (n/g)).div_rem(2)
}
