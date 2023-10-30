use curve25519_dalek::{RistrettoPoint, Scalar};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::{
    accountability_server::{AccSvrError, AccountabilityServer},
    nizqdleq,
    tag::Tag,
    utils::{G, basepoint_order},
};

pub struct Sender {
    pub handle: String,
    pub epk: RistrettoPoint,
    esk: Scalar,
}

#[derive(Debug)]
pub struct SenderError(String);

impl Sender {
    pub fn new<R>(handle: &str, rng: &mut R) -> Sender
    where
        R: CryptoRng + RngCore,
    {
        let mut sk = [0u8; 32];
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
    ) -> Result<(Tag, Vec<u8>, (Scalar, Scalar), RistrettoPoint), SenderError>
    where
        R: RngCore + CryptoRng,
    {
        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut randomness);
        let mut mac = Hmac::<Sha256>::new_from_slice(&randomness).unwrap();
        mac.update(receiver_handle.as_bytes());
        mac.update(msg.as_bytes());
        let commitment = mac.finalize();

        let tag_res =
            accountability_server.issue_tag(&commitment.into_bytes().to_vec(), &self.handle, rng);

        match tag_res {
            Ok(tag) => {
                // Check if X is valid
                let new_x = self.esk * tag.g_prime;
                if new_x != tag.x_big {
                    return Err(SenderError("Invalid tag: X does not match".to_string()));
                }
                let r_big = self.esk * tag.q_big;
                let z = nizqdleq::prove(
                    &basepoint_order(),
                    &tag.g_prime,
                    &tag.x_big,
                    &tag.q_big,
                    &r_big,
                    &self.esk,
                    rng,
                );

                Ok((tag, randomness.to_vec(), z, r_big))
            }
            Err(AccSvrError(err_msg)) => Err(SenderError(err_msg)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountability_server::{AccServerParams, AccountabilityServer};
    use rand::rngs::OsRng;

    #[test]
    fn get_tag_test() {
        let mut rng = OsRng;
        let mut accsvr = AccountabilityServer::new(
            AccServerParams {
                maximum_score: 100,
                report_threashold: 10,
                epoch_duration: 24,
                tag_duration: 2,
            },
            &mut rng,
        );
        let sender = Sender::new("Alice", &mut rng);
        accsvr.set_sender_pk(&sender.epk, &sender.handle);
        let tag_opt = sender.get_tag("Hello Bob", "Bob", &accsvr, &mut rng);
        assert!(tag_opt.is_ok());

        let tag = tag_opt.unwrap();

        let binary: heapless::Vec<u8, 420> = postcard::to_vec(&tag).unwrap();
        assert_eq!(binary.len(), 411);
    }
}
