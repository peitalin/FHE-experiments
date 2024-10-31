
use std::collections::BTreeMap;
use blsttc::{
    Ciphertext,
    DecryptionShare,
    PublicKey,
    PublicKeySet,
    PublicKeyShare,
    SecretKeySet,
    SecretKeyShare
};
use anyhow::{anyhow, Context, Result};
use ecdh;
use ecdh::k256;

// Mock MPC Network source:
// https://github.com/maidsafe/blsttc/tree/master/examples

// the `MpcNetwork` is the "trusted key dealer". The trusted dealer is
// responsible for key generation. The society creates a master public-key, which anyone can use to
// encrypt a message to the society's members; the society is also responsible for giving each
// actor their respective share of the secret-key.
pub struct MpcNetwork {
    actors: Vec<Actor>,
    pk_set: PublicKeySet,
    pub fhe_server_key: tfhe::ServerKey,
    pub ecdh_pub_key: k256::PublicKey,
    ecdh_skey: k256::ecdh::EphemeralSecret,
}

impl MpcNetwork {
    // `n_actors` - the number of actors (members) in the secret society.
    // `threshold` - the number of actors that must collaborate to successfully
    // decrypt a message must exceed this `threshold`.
    pub fn new(n_actors: usize, threshold: usize, fhe_server_key: tfhe::ServerKey) -> Self {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(threshold, &mut rng);
        let pk_set = sk_set.public_keys();

        let actors = (0..n_actors).map(|id| {
            let sk_share = sk_set.secret_key_share(id);
            let pk_share = pk_set.public_key_share(id);
            Actor::new(id, pk_share, sk_share)
        }).collect::<Vec<Actor>>();

        let (ecdh_sk, ecdh_pk) = ecdh::generate_ecdh_keys();

        MpcNetwork {
            actors: actors,
            pk_set: pk_set,
            fhe_server_key: fhe_server_key,
            ecdh_pub_key: ecdh_pk,
            ecdh_skey: ecdh_sk,
        }
    }

    // The secret society publishes its public-key to a publicly accessible key server.
    pub fn publish_public_key(&self) -> PublicKey {
        self.pk_set.public_key()
    }

    fn get_actor(&mut self, id: usize) -> &mut Actor {
        self.actors.get_mut(id)
            .expect(&format!("Actor ID: {} does not exist", id))
    }

    // Sends an encrypted message to Actor
    fn send_message(&mut self, id: usize, enc_msg: Ciphertext) {
        let actor = self.get_actor(id);
        actor.msg_inbox = Some(enc_msg);
    }

    // Starts a new meeting of the secret society. Each time the set of actors receive an encrypted
    // message, at least 2 of them (i.e. 1 more than the threshold) must work together to decrypt
    // the ciphertext.
    fn start_decryption_meeting(&self) -> DecryptionMeeting {
        DecryptionMeeting {
            pk_set: self.pk_set.clone(),
            ciphertext: None,
            dec_shares: BTreeMap::new()
        }
    }

    pub fn mpc_decrypt(&mut self, ciphertext: blsttc::Ciphertext) -> Result<Vec<u8>> {
        mpc_decrypt(self, ciphertext)
    }

    pub fn ecdh_encrypt(&self, msg: &[u8], target_public_key: &k256::PublicKey) -> Vec<u8> {
        let shared_secret_key = ecdh::compute_shared_secret(&self.ecdh_skey, target_public_key);
        ecdh::encrypt(&msg, &shared_secret_key)
    }
}


// assumes 3 nodes for this example.
pub fn mpc_decrypt(
    society: &mut MpcNetwork,
    ciphertext: blsttc::Ciphertext,
) -> Result<Vec<u8>> {
    // In practice this will be implemented in some network which broadcasts ciphertexts to nodes
    // in rounds before beginning the decryption
    let alice = society.get_actor(0).id;
    let bob = society.get_actor(1).id;
    let clara = society.get_actor(2).id;

    society.send_message(alice, ciphertext.clone());
    society.send_message(bob, ciphertext.clone());
    society.send_message(clara, ciphertext.clone());

    let mut meeting = society.start_decryption_meeting();

    meeting.accept_decryption_share(society.get_actor(alice));
    meeting.accept_decryption_share(society.get_actor(bob));

    let res = meeting.decrypt_message()?;
    Ok(res)
}


#[derive(Debug, Clone)]
pub struct Actor {
    id: usize,
    pk_share: PublicKeyShare,
    sk_share: SecretKeyShare,
    msg_inbox: Option<Ciphertext>,
}

impl Actor {
    fn new(id: usize, pk_share: PublicKeyShare, sk_share: SecretKeyShare) -> Self {
        Actor {
            id: id,
            pk_share: pk_share,
            sk_share: sk_share,
            msg_inbox: None
        }
    }
}

// A meeting where Actors collaborate and decrypt a shared ciphertext
pub struct DecryptionMeeting {
    pk_set: PublicKeySet,
    ciphertext: Option<Ciphertext>,
    dec_shares: BTreeMap<usize, DecryptionShare>
}

impl DecryptionMeeting {

    fn accept_decryption_share(&mut self, actor: &mut Actor) {
        // Check that the actor's ciphertext is the same ciphertext decrypted at the meeting.
        // The first actor to arrive at the decryption meeting sets the meeting's ciphertext.
        let ciphertext = actor.msg_inbox.take()
            .expect("no ciphertexts in the msg_inbox");

        if let Some(ref meeting_ciphertext) = self.ciphertext {
            if ciphertext != *meeting_ciphertext {
                return;
            }
        } else {
            self.ciphertext = Some(ciphertext.clone());
        }

        let dec_share = actor.sk_share.decrypt_share(&ciphertext)
            .expect("decrypt_share() err");

        if actor.pk_share.verify_decryption_share(&dec_share, &ciphertext) {
            self.dec_shares.insert(actor.id, dec_share);
        } else {
            println!("invalid decryption share for actor {}", actor.id);
            return;
        }
    }

    // Tries to decrypt the shared ciphertext using the decryption shares.
    fn decrypt_message(&self) -> Result<Vec<u8>> {
        let ciphertext = self.ciphertext.clone().expect("unwrap None ciphertext err");
        self.pk_set.decrypt(&self.dec_shares, &ciphertext)
            .map_err(|e| anyhow!("decryption failed {e}"))
    }
}