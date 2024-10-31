
## FHE fog-of-war experiments

Build the repo:
```
cargo build --bin fhe-zama --release
```

Test out distance calculations and speed of the tfhe-rs library
```
./target/release/fhe-zama basic
```

#### Threshold FHE example with mock MPC network

Mock MPC(t=1, n=3) network and FHE example.
```
./target/release/fhe-zama mpc -t 1 -n 3
```

Which outputs
```
Alice:
        Encrypting Alice's Position { x: 2, y: 2 } with FHE client_key
        Serializing and encrypting position with MPC public_key...
        ==> Sending to MPC_Network

Bob:
        Encrypting Bob's Position { x: ?, y: ? } with FHE client_key
        Serializing and encrypting position with MPC public_key...
        ==> Sending to MPC_Network

MPC_Network:
        Fetching MPC shares and decrypting for FHE ciphertexts...
        Running FHE operations on Position ciphertexts...
        Alice's fog-of-war view range: 11
        should_reveal_bob?: true

        Bob is within Alice's FOW view range, decrypting the Bob's position...
        Encrypting response and sending to Alice...

Alice:
        Alice received and decrypted Bob's Position { x: 4, y: 4 }

Time elapsed: 12.706566s
```

In the above example `should_reveal_bob` is a FHE ciphertext the MPC network decrypts and sees is `true`.
Then conditional on `should_reveal_bob = true`, it decrypts Bob's position and re-encrypts it for Alice using
Diffie-Hellman.
- This is undesirable as the MPC network is trusted with decrypting Bob's position.
- We would need a way to Zk-prove that the MPC network decrypted Bob's position if and only if `should_reveal_bob = true`


### Key issue: conditional decryption
Need a way to conditionally reveal encrypted state to some users, without the MPC nodes every seeing plaintext.
- Decrypt Bob just for Alice to see, conditional on Bob being "close" to Alice.

Perhap Private-set-intersection (PSI) can help:
[PSI](https://github.com/gausslabs/MP-PSI/blob/main/pkg/README.md):
- PSI being used for confidential "coincidence of wants" in social apps:
    - tinder
    - job matching
    - auctions
    - liking/upvoting risky content / political views
