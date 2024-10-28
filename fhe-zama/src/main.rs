
use std::ops::{Div, Mul};
use std::time::{Duration, Instant};
use num_traits::pow::Pow;

use serde::{Serialize, Deserialize};
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint32};
use tfhe::prelude::*;

const PRECISION: u32 = 100;

#[derive(Deserialize, Serialize, Debug)]
struct Position {
    x: u32,
    y: u32
}

fn main() {

    let start = Instant::now();

    let config = ConfigBuilder::default().build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);

    // simple_example(client_key.clone(), server_key.clone());
    distance_example(client_key, server_key);

    let duration = start.elapsed();
    println!("\nTime to run: {:?}", duration);
}


fn simple_example(client_key: tfhe::ClientKey, server_key: tfhe::ServerKey) {
    let clear_a = 27_u32;
    let clear_b = 128_u32;

    let a = FheUint32::encrypt(clear_a, &client_key);
    let b = FheUint32::encrypt(clear_b, &client_key);

    //Server-side
    set_server_key(server_key);
    let result = a + b;

    //Client-side
    let decrypted_result: u32 = result.decrypt(&client_key);
    let clear_result = clear_a + clear_b;

    assert_eq!(decrypted_result, clear_result);
    println!("decrypted_result: {}", decrypted_result);
}


fn distance_example(client_key: tfhe::ClientKey, server_key: tfhe::ServerKey) {

    // Client-side
    println!("\nClient Side:");
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
    println!("\tEncrypting movement ({}, {}) and sending to server", m.x, m.y);
    let x1 = FheUint32::encrypt(p1.x, &client_key);
    let y1 = FheUint32::encrypt(p1.y , &client_key);
    // new position:
    let x2 = FheUint32::encrypt(p1.x + m.x, &client_key);
    let y2 = FheUint32::encrypt(p1.y + m.y, &client_key);

    //Server-side
    set_server_key(server_key);
    println!("\nServer Side:");
    println!("\tPerforming FHE operations to calculate distance to new position");
    let (g, rem) = fhe_distance(&x1, &y1, &x2, &y2);

    //Client-side
    println!("\nClient Side:");
    let new_position = Position {
        x: x2.decrypt(&client_key),
        y: y2.decrypt(&client_key),
    };
    println!("\tDecypted new position: {new_position:?}");

    let distance_decrypted: u32 = g.decrypt(&client_key);
    let rem: u32 = rem.decrypt(&client_key);
    println!("\tDistance: {:?}", (distance_decrypted + rem) as f32 / PRECISION as f32);

    assert_eq!(new_position.x, m.x + p1.x);
    assert_eq!(new_position.y, m.y + p1.y);

    println!("\tAssert distance: f32::sqrt(9.powf(2) + 8.powf(2)) = {}", check_distance(9.0, 8.0))
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