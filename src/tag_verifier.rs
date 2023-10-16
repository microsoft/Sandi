use crate::{
    nizqdleq,
    tag::Tag,
    utils::{verify_signature, verifying_key_from_vec, SignatureVerificationError},
};
use chrono::Utc;
use curve25519_dalek::{RistrettoPoint, Scalar};
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Debug)]
pub struct VerificationError(String);

pub fn verify(
    receiver_handle: &str,
    message: &str,
    tag: &Tag,
    randomness: &Vec<u8>,
    proof: &(Scalar, Scalar),
    r_big: &RistrettoPoint,
    verifying_key: &Vec<u8>,
) -> Result<i32, VerificationError> {
    if tag.exp_timestamp < Utc::now().timestamp() {
        // Tag is expired
        return Err(VerificationError("Tag is expired".to_string()));
    }

    // Verify signature
    let verif_key =
        verifying_key_from_vec(verifying_key).map_err(|err_msg| VerificationError(err_msg))?;

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

    // Verify NIZKDLEG
    let nizqdleq_result = nizqdleq::verify(
        &tag.basepoint_order,
        &tag.g_prime,
        proof,
        &tag.x_big,
        &tag.q_big,
        r_big,
    );
    if !nizqdleq_result {
        return Err(VerificationError("Invalid NIZKDLEQ proof".to_string()));
    }

    Ok(tag.score)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountability_server::AccountabilityServer;
    use crate::sender::Sender;
    use rand::rngs::OsRng;

    #[test]
    fn verify_tag_test() {
        let receiver_handle = "receiver";
        let message = "message to be sent";
        let mut rng = OsRng;
        let mut accsvr = AccountabilityServer::new(100, 10, &mut rng);
        let sender = Sender::new("sender", &mut rng);
        accsvr.set_sender_pk(&sender.epk, &sender.handle);

        let tag = sender.get_tag(message, receiver_handle, &accsvr, &mut rng);

        // Tag should be valid
        let verif_result = verify(
            receiver_handle,
            message,
            &tag.0,
            &tag.1,
            &tag.2,
            &tag.3,
            &accsvr.get_verifying_key(),
        );
        assert!(verif_result.is_ok(), "{}", verif_result.unwrap_err().0);
    }
}
