
### Elliptic Curve Diffie-Hellman functions

Generate keys
```
pub fn generate_ecdh_keys() -> (EphemeralSecret, k256::PublicKey)
```

Compute shared secret using target public key
```
pub fn compute_shared_secret(ecdh_private_key: &EphemeralSecret, public_key: &k256::PublicKey) -> Vec<u8>
```

Functions `encrypt` and `decrypt` inputs and outputs bytestrings.
You will need to use `serde` or `bincode` to serialize and deserialize the bytestrings into appropriate structs,
e.g. a `suncreen::PrivateKey` struct.

Encrypt using a `shared_secret`
```
pub fn encrypt(cleartext: &[u8], shared_secret: &[u8]) -> Vec<u8>
```

Decrypt using a `shared_secret`
```
pub fn decrypt(obsf: &[u8], shared_secret: &[u8]) -> Vec<u8>
```