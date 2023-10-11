use crate::{tag::Tag, utils::{verify_signature, SignatureVerificationError, verifying_key_from_vec}};
use chrono::Utc;
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
    let verif_key = verifying_key_from_vec(verifying_key)
    .map_err(|err_msg| VerificationError(err_msg))?;

    let signature_result = verify_signature(tag, &verif_key);
    match signature_result {
        Ok(_) => {}
        Err(SignatureVerificationError(err_msg)) => {
            return Err(VerificationError(format!(
                "Error verifying signature: {}",
                err_msg
            )));
        }
    }

    // Verify message correctness
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
