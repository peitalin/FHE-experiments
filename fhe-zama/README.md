
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

Mock MPC(t=1, n=3) network and FHE example.
```
./target/release/fhe-zama mpc -t 1 -n 3
```


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