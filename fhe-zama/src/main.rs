
use std::ops::{Div, Mul};

use serde::{Serialize, Deserialize};
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint32};
use tfhe::prelude::*;

#[derive(Deserialize, Serialize, Debug)]
struct Position {
    x: u32,
    y: u32
}

fn main() {

    let config = ConfigBuilder::default().build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);

    simple_example(client_key.clone(), server_key.clone());

    // distance_example(client_key, server_key);

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
}


fn distance_example(client_key: tfhe::ClientKey, server_key: tfhe::ServerKey) {

    // Client-side
    let p1 = Position {
        x: 3,
        y: 2
    };
    let p2 = Position {
        x: 9,
        y: 8
    };

    let x1 = FheUint32::encrypt(p1.x, &client_key);
    let y1 = FheUint32::encrypt(p1.y , &client_key);

    let x2 = FheUint32::encrypt(p2.x, &client_key);
    let y2 = FheUint32::encrypt(p2.y, &client_key);

    //Server-side
    set_server_key(server_key);

    let dx_sq = (x2.clone() - x1.clone()).mul(x2.clone() - x1.clone());
    let dy_sq = (y2.clone() - y1.clone()).mul(y2.clone() - y1.clone());
    // 36 + 36 = 72
    // multiply by 10_000 so we can calculate sqrt on integers with more precision
    // sqrt(x*10_000)/100 = sqrt(x)
    // let distance_sq = (dx_sq + dy_sq) * 10_000;
    let distance_sq = (dx_sq + dy_sq) * 10_000;
    let distance_sq_decrypted: u32 = distance_sq.decrypt(&client_key);
    println!("distance_sq: {:?}", distance_sq_decrypted);

    let initial_sqrt_guess = 1000_u32;
    println!("initial_sqrt_guess: {:?}", initial_sqrt_guess);

    let (g, _rem) = sqrt_newtowns_approximation(
        &distance_sq,
        &FheUint32::encrypt(initial_sqrt_guess, &client_key)
    );
    // run ~2 iterations for the square root approximation
    let (g, rem) = sqrt_newtowns_approximation(&distance_sq, &g);

    //Client-side
    let distance_decrypted: u32 = g.decrypt(&client_key);
    let rem: u32 = rem.decrypt(&client_key);
    println!("newton distance: {:?}", distance_decrypted);
    println!("newton remainder: {:?}", rem);
    println!("distance fractional: {:?}", (distance_decrypted + rem) as f32 / 100.0);

    let new_position = Position {
        x: (x1 + x2).decrypt(&client_key),
        y: (y1 + y2).decrypt(&client_key),
    };

    assert_eq!(new_position.x, p2.x + p1.x);
    assert_eq!(new_position.y, p2.y + p1.y);

    println!("Decypted new position: {new_position:?}");
}

fn sqrt_newtowns_approximation(n: &FheUint32, g: &FheUint32) -> (FheUint32, FheUint32) {
    // https://en.wikipedia.org/wiki/Newton%27s_method
    (g.clone() + (n/g)).div_rem(2)
}