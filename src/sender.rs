use curve25519_dalek::{RistrettoPoint, Scalar};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::{accountability_server::AccountabilityServer, tag::Tag, utils::G, nizqdleq};

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
    ) -> (Tag, Vec<u8>, (Scalar, Scalar), RistrettoPoint)
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
            accountability_server.issue_tag(&commitment.into_bytes().to_vec(), &self.handle, 24, rng);

        // Check if X is valid
        let new_x = self.esk * tag.x_big;
        if new_x != tag.x_big {
            panic!("Invalid tag: X does not match");
        }
        let r_big = self.esk * tag.q_big;
        let z = nizqdleq::prove(&tag.basepoint_order, &tag.g_prime, &tag.x_big, &tag.q_big, &r_big, &self.esk, rng);
        (tag, randomness.to_vec(), z, r_big)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountability_server::AccountabilityServer;
    use rand::rngs::OsRng;

    #[test]
    fn test_sender() {
        let mut rng = OsRng;
        let accountability_server = AccountabilityServer::new(100, 10, &mut rng);
        let sender = Sender::new("Alice", &mut rng);
        accountability_server.set_sender_pk(&sender.epk, &sender.handle);
        let (tag, randomness, z, r_big) = sender.get_tag("Hello Bob", "Bob", &accountability_server, &mut rng);
    }
}