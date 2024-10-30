
### FHE Zama tests

Build the program
```
cargo build --bin fhe-zama --release
```

Then run
```
./target/release/fhe-zama basic
```

Which should output:
```
Client Side:
	Encrypting starting position (3, 2)
	Encrypting movement (9, 8) and sending to server

Server Side:
	Performing FHE operations to calculate distance to new position
	initial_sqrt_guess: 1000

Client Side:
	Decypted new position: Position { x: 12, y: 10 }
	Distance: 12.04
	Assert distance: f32::sqrt(9.powf(2) + 8.powf(2)) = 12.0415945

Time to run: 12.512262417s
```


### MPC example

Open up 4 terminals.

**Terminal 1** is the MPC server:
```
cargo run --bin mpc-server
```

**Terminal 2-4** are the three clients who will be participating in the DKG ceremony:
```
cargo run --bin fhe-zama -- keygen -t 1 -n 3 -i 1 --output local-share1.json

cargo run --bin fhe-zama -- -t 1 -n 3 -i 1 --output local-share1.json
cargo run --bin fhe-zama -- -t 1 -n 3 -i 2 --output local-share2.json
cargo run --bin fhe-zama -- -t 1 -n 3 -i 3 --output local-share3.json
```


Once these keys are generated...

### TODO: explore ways to compute on shared state
We will need MPC or private-set-intersection (PSI) for the AVS node to calculate
whether Alice and Bob's positions are close enough to each other to see each other's position.

[PSI](https://github.com/gausslabs/MP-PSI/blob/main/pkg/README.md):
Need some way to run functions on shared encrypted state, then conditionally reveal encrypted state to some users.
- PSI being used for confidential "coincidence of wants" in social apps:
    - tinder
    - job matching
    - auctions
    - liking/upvoting risky content / political views

- Writing
    - [ ] Cryptographic fog of war
    - [ ] Privacy and anonymity mining as a basis for an AVS
    - [ ] Gaming as a Trojan horse for private money transfer and confidential compute