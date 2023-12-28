use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use flatbuffers::FlatBufferBuilder;
use serde::{Deserialize, Serialize};

use crate::{
    serialization::{FixedBuffer32, FixedBuffer48, FixedBuffer64},
    tag::Tag,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SenderTag {
    pub tag: Tag,
    pub randomness: Vec<u8>,
    pub proof: (Scalar, Scalar),
    pub r_big: RistrettoPoint,
}

impl SenderTag {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut builder = FlatBufferBuilder::new();
        let commitment = &FixedBuffer32(self.tag.commitment.clone().try_into().unwrap());
        let enc_sender_id = &FixedBuffer48(self.tag.enc_sender_id.clone().try_into().unwrap());
        let signature = &FixedBuffer64(self.tag.signature.clone().try_into().unwrap());
        let q_big = &FixedBuffer32(self.tag.q_big.compress().to_bytes());
        let g_prime = &FixedBuffer32(self.tag.g_prime.compress().to_bytes());
        let x_big = &FixedBuffer32(self.tag.x_big.compress().to_bytes());
        let randomness = &FixedBuffer32(self.randomness.clone().try_into().unwrap());
        let z_c = &FixedBuffer32(self.proof.0.to_bytes());
        let z_s = &FixedBuffer32(self.proof.1.to_bytes());
        let r_big = &FixedBuffer32(self.r_big.compress().to_bytes());

        let args = crate::serialization::FullTagArgs {
            commitment: Some(commitment),
            expiration: self.tag.exp_timestamp,
            score: self.tag.score,
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

    pub fn from_vec(bytes: &Vec<u8>) -> Result<Self, String> {
        // Deserialize tag using flatbuffers
        let full_tag = crate::serialization::root_as_full_tag(bytes.as_slice());
        if full_tag.is_err() {
            return Err(format!(
                "Failed to deserialize tag: {}",
                full_tag.unwrap_err()
            ));
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
        let r_big = CompressedRistretto::from_slice(&full_tag.r_big().0)
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

        Ok(SenderTag {
            tag,
            randomness,
            proof: (z_c, z_s),
            r_big,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::{random_point, random_scalar};
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn full_tag_serialization_test() {
        let mut rng = OsRng;
        let tag = Tag {
            commitment: vec![0; 32],
            exp_timestamp: 0,
            score: 0,
            enc_sender_id: vec![0; 48],
            q_big: random_point(&mut rng),
            g_prime: random_point(&mut rng),
            x_big: random_point(&mut rng),
            signature: vec![0; 64],
        };

        let full_tag = SenderTag {
            tag,
            randomness: vec![0; 32],
            proof: (random_scalar(&mut rng), random_scalar(&mut rng)),
            r_big: random_point(&mut rng),
        };

        let serialized_tag = full_tag.to_vec();
        assert_eq!(serialized_tag.len(), 404);

        let deserialized_tag = SenderTag::from_vec(&serialized_tag);
        assert!(deserialized_tag.is_ok());
        let deserialized_tag = deserialized_tag.unwrap();
        assert_eq!(deserialized_tag.tag.commitment, vec![0; 32]);
        assert_eq!(deserialized_tag.tag.exp_timestamp, 0);
        assert_eq!(deserialized_tag.tag.score, 0);
        assert_eq!(deserialized_tag.tag.enc_sender_id, vec![0; 48]);
        assert_eq!(deserialized_tag.tag.q_big, full_tag.tag.q_big);
        assert_eq!(deserialized_tag.tag.g_prime, full_tag.tag.g_prime);
        assert_eq!(deserialized_tag.tag.x_big, full_tag.tag.x_big);
        assert_eq!(deserialized_tag.tag.signature, vec![0; 64]);
        assert_eq!(deserialized_tag.randomness, vec![0; 32]);
        assert_eq!(deserialized_tag.proof, full_tag.proof);
        assert_eq!(deserialized_tag.r_big, full_tag.r_big);
    }
}
