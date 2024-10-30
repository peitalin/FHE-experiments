use std::ops::Mul;
use serde::{Serialize, Deserialize};
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint32};
use tfhe::prelude::*;


pub const PRECISION: u32 = 100;
pub const FOW_VIEW_RANGE: u32 = 11;

#[derive(Deserialize, Serialize, Debug)]
pub struct Position {
    pub x: u32,
    pub y: u32
}

pub fn fhe_distance_example(
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