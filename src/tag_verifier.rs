use crate::tag::Tag;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Debug)]
pub struct VerificationError(String);

pub fn verify(
    receiver_handle: &str,
    message: &str,
    tag: &Tag,
    randomness: Vec<u8>,
    verifying_key: &Vec<u8>,
) -> Result<i32, VerificationError> {
    if tag.exp_timestamp < Utc::now().timestamp() {
        // Tag is expired
        return Err(VerificationError("Tag is expired".to_string()));
    }

    // Verify signature
    let mut data_to_sign = Vec::new();
    data_to_sign.extend_from_slice(&tag.commitment);
    data_to_sign.extend_from_slice(tag.exp_timestamp.to_be_bytes().as_slice());
    data_to_sign.extend_from_slice(tag.score.to_be_bytes().as_slice());
    data_to_sign.extend_from_slice(&tag.enc_sender_id);
    data_to_sign.extend_from_slice(tag.sender_handle.as_bytes());

    let vkbytes: [u8; PUBLIC_KEY_LENGTH] = verifying_key[..PUBLIC_KEY_LENGTH]
        .try_into()
        .map_err(|_| VerificationError("Invalid verifying key".to_string()))?;

    let sigbytes: [u8; 64] = tag.signature[..64]
        .try_into()
        .map_err(|_| VerificationError("Invalid signature".to_string()))?;

    let signature = Signature::from_bytes(&sigbytes);

    VerifyingKey::from_bytes(&vkbytes)
        .map_err(|_| VerificationError("Invalid verifying key".to_string()))?
        .verify(&data_to_sign, &signature)
        .map_err(|_| VerificationError("Invalid signature".to_string()))?;

    // Verify message
    let mut mac = Hmac::<Sha256>::new_from_slice(&randomness)
        .map_err(|_| VerificationError("Invalid randomness".to_string()))?;

    mac.update(receiver_handle.as_bytes());
    mac.update(message.as_bytes());
    let commitment = mac.finalize();

    if commitment.into_bytes().to_vec() != tag.commitment {
        return Err(VerificationError("Invalid commitment".to_string()));
    }

    Ok(tag.score)
}
