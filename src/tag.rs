use crate::serialization::{FixedBuffer16, FixedBuffer32, FixedBuffer64, TagArgs};
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint};
use flatbuffers::FlatBufferBuilder;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tag {
    pub commitment: Vec<u8>,
    pub exp_timestamp: i64,
    pub score: i32,
    pub enc_sender_id: Vec<u8>,
    pub q_big: RistrettoPoint,
    pub g_prime: RistrettoPoint,
    pub x_big: RistrettoPoint,
    pub signature: Vec<u8>,
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.signature == other.signature
    }
}

impl Tag {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        let mut builder = FlatBufferBuilder::new();
        let commitment = &FixedBuffer32(self.commitment.clone().try_into().unwrap());
        let enc_sender_id = &FixedBuffer16(self.enc_sender_id.clone().try_into().unwrap());
        let signature = &FixedBuffer64(self.signature.clone().try_into().unwrap());
        let q_big = &FixedBuffer32(self.q_big.compress().to_bytes());
        let g_prime = &FixedBuffer32(self.g_prime.compress().to_bytes());
        let x_big = &FixedBuffer32(self.x_big.compress().to_bytes());
        let args = TagArgs {
            commitment: Some(commitment),
            expiration: self.exp_timestamp,
            score: self.score,
            enc_sender_id: Some(enc_sender_id),
            q_big: Some(q_big),
            g_prime: Some(g_prime),
            x_big: Some(x_big),
            signature: Some(signature),
        };
        let tag_offset = crate::serialization::Tag::create(&mut builder, &args);
        builder.finish(tag_offset, None);
        vec.extend_from_slice(builder.finished_data());
        vec
    }

    pub fn from_vec(bytes: &Vec<u8>) -> Result<Self, String> {
        // Deserialize tag using flatbuffers
        let tag = crate::serialization::root_as_tag(bytes.as_slice());
        if tag.is_err() {
            return Err(format!("Failed to deserialize tag: {}", tag.unwrap_err()));
        }

        let tag = tag.unwrap();
        let commitment = tag.commitment().0.to_vec();
        let exp_timestamp = tag.expiration();
        let score = tag.score();
        let enc_sender_id = tag.enc_sender_id().0.to_vec();
        let q_big = CompressedRistretto::from_slice(&tag.q_big().0)
            .unwrap()
            .decompress()
            .ok_or("Failed to decompress q_big")?;
        let g_prime = CompressedRistretto::from_slice(&tag.g_prime().0)
            .unwrap()
            .decompress()
            .ok_or("Failed to decompress g_prime")?;
        let x_big = CompressedRistretto::from_slice(&tag.x_big().0)
            .unwrap()
            .decompress()
            .ok_or("Failed to decompress x_big")?;
        let signature = tag.signature().0.to_vec();

        Ok(Tag {
            commitment,
            exp_timestamp,
            score,
            enc_sender_id,
            q_big,
            g_prime,
            x_big,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::random_point;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn serialize_tag_test() {
        let mut rng = OsRng;
        let mut signature: [u8; 64] = [0; 64];
        rng.fill_bytes(&mut signature);

        let tag = Tag {
            commitment: vec![0; 32],
            exp_timestamp: 0,
            score: 0,
            enc_sender_id: vec![0; 16],
            q_big: random_point(&mut rng),
            g_prime: random_point(&mut rng),
            x_big: random_point(&mut rng),
            signature: signature.to_vec(),
        };

        let vec = tag.to_vec();
        assert_eq!(vec.len(), 236);

        let tag2 = Tag::from_vec(&vec);
        assert!(tag2.is_ok());
        let tag2 = tag2.unwrap();

        assert_eq!(tag.q_big, tag2.q_big);
        assert_eq!(tag.g_prime, tag2.g_prime);
        assert_eq!(tag.x_big, tag2.x_big);
        assert_eq!(tag.signature, tag2.signature);
    }
}
