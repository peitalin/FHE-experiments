
### FHE fog-of-war tests with libp2p

Open up two terminals.

**On Terminal 1 (Alice) run:**
```
cargo run --bin fhe-sunscreen -- alice
```

**On Terminal 2 (Bob) run:**
```
cargo run --bin fhe-sunscreen -- bob /ip4/127.0.0.1/tcp/<IP-address-of-alice-node>
```

Wait for Bob's IPFS node to say `ConnectionEstablished`.

This will create two local IPFS Kademlia DHT nodes to test our FHE fog-of-war demo.


Then run the following commands...

**Terminal 1 (Alice)**
```
MOVE alice {"x":3,"y":2}
GET POSITION alice
```
On terminal 1 (Alice), `GET POSITION alice` will decrypt the position, as alice is the encrypter.

Because only Alice can decrypt her position, attempting to `GET alice` with Terminal 2 (Bob) will fail
with a `TooMuchNoise` error.

However for testing purposes, let's share Alice's decryption key to Bob's node.

**Terminal 1 (Alice)**
```
SHARE_KEY bob
```

Bob's node reads the key, then is able to decrypte Alice's encrypted position.
**Terminal 2 (Bob)**
```
GET ENCRYPTED_FHE_KEY alice
GET POSITION alice
```

Try moving alice a few more times and reading from Bob's terminal to see FHE calculations changing Alice's position.
**Terminal 1 (Alice)**
```
MOVE alice {"x":11,"y":1}
```

**Terminal 2 (Bob)**
```
GET POSITION alice
```

The AVS node does the FHE updates, and never knows Alice's position.
Only Alice can decrypt her position.
Alice then allows her ally Bob to decrypt her position after sharing FHE decryption keys via shared secret.

#### TODO
- remove double queries bug on IPFS



### TODO: explore ways to compute on shared state
We will need MPC or private-set-intersection (PSI) for the AVS node to calculate
whether Alice and Bob's positions are close enough to each other to see each other's position.

[PSI](https://github.com/cursive-team/2P-PSI): analogous to bitmasks in traditional fog-of-war implementations?
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
