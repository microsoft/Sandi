// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use crate::serialization::{FixedBuffer32, FixedBuffer48, FixedBuffer64, TagArgs};
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint};
use flatbuffers::FlatBufferBuilder;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncSenderId(pub [u8; 48]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagSignature(pub [u8; 64]);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tag {
    pub commitment_hr: [u8; 32],
    pub commitment_vks: [u8; 32],
    pub exp_timestamp: i64,
    pub score: u8,
    pub enc_sender_id: EncSenderId,
    pub q_big: RistrettoPoint,
    pub g_prime: RistrettoPoint,
    pub x_big: RistrettoPoint,
    pub signature: TagSignature,
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
        let commitment_hr = &FixedBuffer32(self.commitment_hr.clone());
        let commitment_vks = &FixedBuffer32(self.commitment_vks.clone());
        let enc_sender_id = &FixedBuffer48(self.enc_sender_id.0.clone());
        let signature = &FixedBuffer64(self.signature.0.clone());
        let q_big = &FixedBuffer32(self.q_big.compress().to_bytes());
        let g_prime = &FixedBuffer32(self.g_prime.compress().to_bytes());
        let x_big = &FixedBuffer32(self.x_big.compress().to_bytes());
        let args = TagArgs {
            commitment_hr: Some(commitment_hr),
            commitment_vks: Some(commitment_vks),
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

    pub fn from_slice(bytes: &[u8]) -> Result<Self, String> {
        // Deserialize tag using flatbuffers
        let tag = crate::serialization::root_as_tag(bytes);
        if tag.is_err() {
            return Err(format!("Failed to deserialize tag: {}", tag.unwrap_err()));
        }

        let tag = tag.unwrap();
        let commitment_hr = tag.commitment_hr().0;
        let commitment_vks = tag.commitment_vks().0;
        let exp_timestamp = tag.expiration();
        let score = tag.score();
        let enc_sender_id = tag.enc_sender_id().0;
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
        let signature = tag.signature().0;

        Ok(Tag {
            commitment_hr,
            commitment_vks,
            exp_timestamp,
            score,
            enc_sender_id: EncSenderId(enc_sender_id),
            q_big,
            g_prime,
            x_big,
            signature: TagSignature(signature),
        })
    }
}

// Manually implement Deserialize for EncSenderId
impl<'de> Deserialize<'de> for EncSenderId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        if vec.len() != 48 {
            return Err(serde::de::Error::invalid_length(
                vec.len(),
                &"expected 48 bytes",
            ));
        }
        let mut array = [0u8; 48];
        array.copy_from_slice(&vec);
        Ok(EncSenderId(array))
    }
}

// Manually implement Serialize for EncSenderId
impl Serialize for EncSenderId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

// Manually implement Deserialize for TagSignature
impl<'de> Deserialize<'de> for TagSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        if vec.len() != 64 {
            return Err(serde::de::Error::invalid_length(
                vec.len(),
                &"expected 64 bytes",
            ));
        }
        let mut array = [0u8; 64];
        array.copy_from_slice(&vec);
        Ok(TagSignature(array))
    }
}

// Manually implement Serialize for TagSignature
impl Serialize for TagSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
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

        let mut tag = Tag {
            commitment_hr: [0; 32],
            commitment_vks: [0; 32],
            exp_timestamp: 0,
            score: 0,
            enc_sender_id: EncSenderId([0; 48]),
            q_big: random_point(&mut rng),
            g_prime: random_point(&mut rng),
            x_big: random_point(&mut rng),
            signature: TagSignature(signature),
        };

        rng.fill_bytes(&mut tag.enc_sender_id.0);

        let vec = tag.to_vec();
        assert_eq!(vec.len(), 304);

        let tag2 = Tag::from_slice(&vec);
        assert!(tag2.is_ok());
        let tag2 = tag2.unwrap();

        assert_eq!(tag.q_big, tag2.q_big);
        assert_eq!(tag.g_prime, tag2.g_prime);
        assert_eq!(tag.x_big, tag2.x_big);
        assert_eq!(tag.enc_sender_id, tag2.enc_sender_id);
        assert_eq!(tag.signature, tag2.signature);
    }
}
