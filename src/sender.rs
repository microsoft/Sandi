use curve25519_dalek::{RistrettoPoint, Scalar};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::{accountability_server::AccountabilityServer, tag::Tag, utils::G};

pub struct Sender {
    handle: String,
    epk: RistrettoPoint,
    esk: Scalar,
}

impl Sender {
    pub fn new<R>(handle: &str, rng: &mut R) -> Sender
    where
        R: CryptoRng + RngCore {
        let mut sk = [ 0u8; 32 ];
        rng.fill_bytes(&mut sk);
        let esk = Scalar::from_bytes_mod_order(sk);
        let epk = G() * esk;

        Sender {
            handle: handle.to_owned(),
            esk,
            epk,
        }
    }

    pub fn get_tag<R>(
        &self,
        msg: &str,
        receiver_handle: &str,
        accountability_server: &AccountabilityServer,
        rng: &mut R,
    ) -> (Tag, Vec<u8>)
    where
        R: RngCore + CryptoRng,
    {
        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut randomness);
        let mut mac = Hmac::<Sha256>::new_from_slice(&randomness).unwrap();
        mac.update(receiver_handle.as_bytes());
        mac.update(msg.as_bytes());
        let commitment = mac.finalize();

        let tag =
            accountability_server.issue_tag(&commitment.into_bytes().to_vec(), &self.handle, 24);

        (tag, randomness.to_vec())
    }
}
