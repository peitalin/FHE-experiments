
### FHE fog-of-war experiments

Build the repo:
```
cargo build --bin fhe-zama --release;
```

Test out distance calculations and speed of the tfhe-rs library
```
./target/release/fhe-zama basic
```

Mock MPC(t=1, n=3) network and FHE example.
```
./target/release/fhe-zama mpc -t 1 -n 3
```