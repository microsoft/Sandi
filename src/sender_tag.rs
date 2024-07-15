use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use flatbuffers::FlatBufferBuilder;
use serde::{Deserialize, Serialize};

use crate::{
    serialization::{FixedBuffer32, FixedBuffer48, FixedBuffer64},
    tag::{EncSenderId, Tag, TagSignature},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SenderTag {
    pub tag: Tag,
    pub randomness_hr: [u8; 32],
    pub randomness_vks: [u8; 32],
    pub vks: RistrettoPoint,
    pub proof: (Scalar, Scalar),
    pub r_big: RistrettoPoint,
}

impl SenderTag {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut builder = FlatBufferBuilder::new();
        let commitment_hr = &FixedBuffer32(self.tag.commitment_hr.clone().try_into().unwrap());
        let commitment_vks = &FixedBuffer32(self.tag.commitment_vks.clone().try_into().unwrap());
        let enc_sender_id = &FixedBuffer48(self.tag.enc_sender_id.0.clone().try_into().unwrap());
        let signature = &FixedBuffer64(self.tag.signature.0.clone().try_into().unwrap());
        let q_big = &FixedBuffer32(self.tag.q_big.compress().to_bytes());
        let g_prime = &FixedBuffer32(self.tag.g_prime.compress().to_bytes());
        let x_big = &FixedBuffer32(self.tag.x_big.compress().to_bytes());
        let randomness_hr = &FixedBuffer32(self.randomness_hr.clone().try_into().unwrap());
        let randomness_vks = &FixedBuffer32(self.randomness_vks.clone().try_into().unwrap());
        let vks = &FixedBuffer32(self.vks.compress().to_bytes());
        let z_c = &FixedBuffer32(self.proof.0.to_bytes());
        let z_s = &FixedBuffer32(self.proof.1.to_bytes());
        let r_big = &FixedBuffer32(self.r_big.compress().to_bytes());

        let args = crate::serialization::FullTagArgs {
            commitment_hr: Some(commitment_hr),
            commitment_vks: Some(commitment_vks),
            expiration: self.tag.exp_timestamp,
            score: self.tag.score,
            enc_sender_id: Some(enc_sender_id),
            q_big: Some(q_big),
            g_prime: Some(g_prime),
            x_big: Some(x_big),
            signature: Some(signature),
            randomness_hr: Some(randomness_hr),
            randomness_vks: Some(randomness_vks),
            vks: Some(vks),
            proof_c: Some(z_c),
            proof_s: Some(z_s),
            r_big: Some(r_big),
        };
        let tag_offset = crate::serialization::FullTag::create(&mut builder, &args);
        builder.finish(tag_offset, None);
        builder.finished_data().to_vec()
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, String> {
        // Deserialize tag using flatbuffers
        let full_tag = crate::serialization::root_as_full_tag(bytes);
        if full_tag.is_err() {
            return Err(format!(
                "Failed to deserialize tag: {}",
                full_tag.unwrap_err()
            ));
        }

        let full_tag = full_tag.unwrap();
        let commitment_hr = full_tag.commitment_hr().0;
        let commitment_vks = full_tag.commitment_vks().0;
        let exp_timestamp = full_tag.expiration();
        let score = full_tag.score();
        let enc_sender_id = full_tag.enc_sender_id().0;
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
        let signature = full_tag.signature().0;
        let randomness_hr = full_tag.randomness_hr().0;
        let randomness_vks = full_tag.randomness_vks().0;
        let vks = CompressedRistretto::from_slice(&full_tag.vks().0)
            .unwrap()
            .decompress()
            .ok_or("Failed to decompress vks")?;
        let z_c = Scalar::from_canonical_bytes(full_tag.proof_c().0).unwrap();
        let z_s = Scalar::from_canonical_bytes(full_tag.proof_s().0).unwrap();
        let r_big = CompressedRistretto::from_slice(&full_tag.r_big().0)
            .unwrap()
            .decompress()
            .ok_or("Failed to decompress r_big")?;

        let tag = Tag {
            commitment_hr,
            commitment_vks,
            exp_timestamp,
            score,
            enc_sender_id: EncSenderId(enc_sender_id),
            q_big,
            g_prime,
            x_big,
            signature: TagSignature(signature),
        };

        Ok(SenderTag {
            tag,
            randomness_hr,
            randomness_vks,
            vks,
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
            commitment_hr: [0; 32],
            commitment_vks: [0; 32],
            exp_timestamp: 0,
            score: 0,
            enc_sender_id: EncSenderId([0; 48]),
            q_big: random_point(&mut rng),
            g_prime: random_point(&mut rng),
            x_big: random_point(&mut rng),
            signature: TagSignature([0; 64]),
        };

        let full_tag = SenderTag {
            tag,
            randomness_hr: [0; 32],
            randomness_vks: [0; 32],
            vks: random_point(&mut rng),
            proof: (random_scalar(&mut rng), random_scalar(&mut rng)),
            r_big: random_point(&mut rng),
        };

        let serialized_tag = full_tag.to_vec();
        assert_eq!(serialized_tag.len(), 508);

        let deserialized_tag = SenderTag::from_slice(&serialized_tag);
        assert!(deserialized_tag.is_ok());
        let deserialized_tag = deserialized_tag.unwrap();
        assert_eq!(deserialized_tag.tag.commitment_hr, [0; 32]);
        assert_eq!(deserialized_tag.tag.commitment_vks, [0; 32]);
        assert_eq!(deserialized_tag.tag.exp_timestamp, 0);
        assert_eq!(deserialized_tag.tag.score, 0);
        assert_eq!(deserialized_tag.tag.enc_sender_id, EncSenderId([0; 48]));
        assert_eq!(deserialized_tag.tag.q_big, full_tag.tag.q_big);
        assert_eq!(deserialized_tag.tag.g_prime, full_tag.tag.g_prime);
        assert_eq!(deserialized_tag.tag.x_big, full_tag.tag.x_big);
        assert_eq!(deserialized_tag.tag.signature, TagSignature([0; 64]));
        assert_eq!(deserialized_tag.randomness_hr, [0; 32]);
        assert_eq!(deserialized_tag.randomness_vks, [0; 32]);
        assert_eq!(deserialized_tag.vks, full_tag.vks);
        assert_eq!(deserialized_tag.proof, full_tag.proof);
        assert_eq!(deserialized_tag.r_big, full_tag.r_big);
    }
}
