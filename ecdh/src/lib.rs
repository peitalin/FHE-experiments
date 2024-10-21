
use rand_core::OsRng; // requires 'getrandom' feature
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::generic_array::{GenericArray, typenum::Unsigned},
    aead::{Aead, AeadCore, KeyInit}
};
use k256::{ecdh::EphemeralSecret, EncodedPoint};

pub fn generate_ecdh_keys() -> (EphemeralSecret, k256::PublicKey) {

    let ecdh_private_key = EphemeralSecret::random(&mut OsRng);
    let ecdh_public_key= k256::PublicKey::from_sec1_bytes(
        EncodedPoint::from(ecdh_private_key.public_key()).as_ref()
    ).expect("alice's public key is invalid");

    (ecdh_private_key, ecdh_public_key)
}

pub fn compute_shared_secret(
    ecdh_private_key: &EphemeralSecret,
    public_key: &k256::PublicKey
) -> Vec<u8> {
    let shared_secret = ecdh_private_key.diffie_hellman(public_key);
    let shared_secret_key = shared_secret.raw_secret_bytes().to_vec();
    shared_secret_key
}

pub fn encrypt(cleartext: &[u8], shared_secret: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(shared_secret));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut obsf = cipher.encrypt(&nonce, cleartext).unwrap();
    obsf.splice(..0, nonce.iter().copied());
    obsf
}

pub fn decrypt(obsf: &[u8], shared_secret: &[u8]) -> Vec<u8> {
    type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(shared_secret));
    let (nonce, ciphertext) = obsf.split_at(NonceSize::to_usize());
    let nonce = GenericArray::from_slice(nonce);
    let plaintext: Vec<u8> = cipher.decrypt(nonce, ciphertext).unwrap();
    plaintext
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
