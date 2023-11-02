use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use flatbuffers::FlatBufferBuilder;
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::{
    accountability_server::{AccSvrError, AccountabilityServer},
    nizqdleq,
    serialization::{FixedBuffer16, FixedBuffer32, FixedBuffer64},
    tag::Tag,
    utils::{basepoint_order, G},
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

    pub fn tag_to_vec(tag: &(Tag, Vec<u8>, (Scalar, Scalar), RistrettoPoint)) -> Vec<u8> {
        let mut builder = FlatBufferBuilder::new();
        let commitment = &FixedBuffer32(tag.0.commitment.clone().try_into().unwrap());
        let enc_sender_id = &FixedBuffer16(tag.0.enc_sender_id.clone().try_into().unwrap());
        let signature = &FixedBuffer64(tag.0.signature.clone().try_into().unwrap());
        let q_big = &FixedBuffer32(tag.0.q_big.compress().to_bytes());
        let g_prime = &FixedBuffer32(tag.0.g_prime.compress().to_bytes());
        let x_big = &FixedBuffer32(tag.0.x_big.compress().to_bytes());
        let randomness = &FixedBuffer32(tag.1.clone().try_into().unwrap());
        let z_c = &FixedBuffer32(tag.2 .0.to_bytes());
        let z_s = &FixedBuffer32(tag.2 .1.to_bytes());
        let r_big = &FixedBuffer32(tag.3.compress().to_bytes());

        let args = crate::serialization::FullTagArgs {
            commitment: Some(commitment),
            expiration: tag.0.exp_timestamp,
            score: tag.0.score,
            enc_sender_id: Some(enc_sender_id),
            q_big: Some(q_big),
            g_prime: Some(g_prime),
            x_big: Some(x_big),
            signature: Some(signature),
            randomness: Some(randomness),
            proof_c: Some(z_c),
            proof_s: Some(z_s),
            r_big: Some(r_big),
        };
        let tag_offset = crate::serialization::FullTag::create(&mut builder, &args);
        builder.finish(tag_offset, None);
        builder.finished_data().to_vec()
    }

    pub fn vec_to_tag(bytes: &Vec<u8>) -> Result<(Tag, Vec<u8>, (Scalar, Scalar), RistrettoPoint), String> {
        // Deserialize tag using flatbuffers
        let full_tag = crate::serialization::root_as_full_tag(bytes.as_slice());
        if full_tag.is_err() {
            return Err(format!("Failed to deserialize tag: {}", full_tag.unwrap_err()));
        }

        let full_tag = full_tag.unwrap();
        let commitment = full_tag.commitment().0.to_vec();
        let exp_timestamp = full_tag.expiration();
        let score = full_tag.score();
        let enc_sender_id = full_tag.enc_sender_id().0.to_vec();
        let q_big = CompressedRistretto::from_slice(&full_tag.q_big().0)
            .unwrap()
            .decompress()
            .ok_or("Failed to decompress q_big")?;
        let g_prime = CompressedRistretto::from_slice(&full_tag.g_prime().0)
            .unwrap()
            .decompress()
            .ok_or("Failed to decompress g_prime")?;
        let x_big = CompressedRistretto::from_slice(&full_tag.x_big().0)
            .unwrap()
            .decompress()
            .ok_or("Failed to decompress x_big")?;
        let signature = full_tag.signature().0.to_vec();
        let randomness = full_tag.randomness().0.to_vec();
        let z_c = Scalar::from_canonical_bytes(full_tag.proof_c().0).unwrap();
        let z_s = Scalar::from_canonical_bytes(full_tag.proof_s().0).unwrap();
        let big_r = CompressedRistretto::from_slice(&full_tag.r_big().0)
            .unwrap()
            .decompress()
            .ok_or("Failed to decompress r_big")?;

        let tag = Tag {
            commitment,
            exp_timestamp,
            score,
            enc_sender_id,
            q_big,
            g_prime,
            x_big,
            signature,
        };

        Ok((tag, randomness, (z_c, z_s), big_r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        accountability_server::{AccServerParams, AccountabilityServer},
        utils::{random_point, random_scalar},
    };
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

    #[test]
    fn full_tag_serialization_test() {
        let mut rng = OsRng;
        let tag = Tag {
            commitment: vec![0; 32],
            exp_timestamp: 0,
            score: 0,
            enc_sender_id: vec![0; 16],
            q_big: random_point(&mut rng),
            g_prime: random_point(&mut rng),
            x_big: random_point(&mut rng),
            signature: vec![0; 64],
        };

        let full_tag = (
            tag,
            vec![0; 32],
            (random_scalar(&mut rng), random_scalar(&mut rng)),
            random_point(&mut rng),
        );
        let serialized_tag = Sender::tag_to_vec(&full_tag);
        assert_eq!(serialized_tag.len(), 372);

        let deserialized_tag = Sender::vec_to_tag(&serialized_tag);
        assert!(deserialized_tag.is_ok());
        let deserialized_tag = deserialized_tag.unwrap();
        assert_eq!(deserialized_tag.0.commitment, vec![0; 32]);
        assert_eq!(deserialized_tag.0.exp_timestamp, 0);
        assert_eq!(deserialized_tag.0.score, 0);
        assert_eq!(deserialized_tag.0.enc_sender_id, vec![0; 16]);
        assert_eq!(deserialized_tag.0.q_big, full_tag.0.q_big);
        assert_eq!(deserialized_tag.0.g_prime, full_tag.0.g_prime);
        assert_eq!(deserialized_tag.0.x_big, full_tag.0.x_big);
        assert_eq!(deserialized_tag.0.signature, vec![0; 64]);
        assert_eq!(deserialized_tag.1, vec![0; 32]);
        assert_eq!(deserialized_tag.2, full_tag.2);
        assert_eq!(deserialized_tag.3, full_tag.3);
    }
}
