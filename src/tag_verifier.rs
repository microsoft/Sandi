use crate::{
    nizqdleq,
    tag::Tag,
    utils::{
        basepoint_order, verify_signature, verifying_key_from_vec, SignatureVerificationError,
    },
};
use chrono::Utc;
use curve25519_dalek::{RistrettoPoint, Scalar};
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Debug)]
pub struct VerificationError(pub String);

pub fn verify(
    receiver_handle: &str,
    vks: &RistrettoPoint,
    tag: &Tag,
    randomness_hr: &Vec<u8>,
    randomness_vks: &Vec<u8>,
    proof: &(Scalar, Scalar),
    r_big: &RistrettoPoint,
    verifying_key: &Vec<u8>,
) -> Result<i8, VerificationError> {
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
    let mut mac = Hmac::<Sha256>::new_from_slice(&randomness_hr)
        .map_err(|_| VerificationError("Invalid randomness".to_string()))?;

    mac.update(receiver_handle.as_bytes());
    let commitment = mac.finalize();

    if commitment.into_bytes().to_vec() != tag.commitment_hr {
        return Err(VerificationError("Invalid receiver commitment".to_string()));
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(&randomness_vks)
        .map_err(|_| VerificationError("Invalid randomness".to_string()))?;

    mac.update(vks.compress().as_bytes());
    let commitment = mac.finalize();

    if commitment.into_bytes().to_vec() != tag.commitment_vks {
        return Err(VerificationError("Invalid vks commitment".to_string()));
    }

    // Verify NIZKDLEG
    let nizqdleq_result = nizqdleq::verify(
        &basepoint_order(),
        &tag.g_prime,
        &tag.x_big,
        &tag.q_big,
        r_big,
        proof,
    );
    if !nizqdleq_result {
        return Err(VerificationError("Invalid NIZKDLEQ proof".to_string()));
    }

    Ok(tag.score)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountability_server::{AccServerParams, AccountabilityServer};
    use crate::sender::Sender;
    use rand::rngs::OsRng;

    #[test]
    fn verify_tag_test() {
        let receiver_handle = "receiver";
        let mut rng = OsRng;
        let mut accsvr = AccountabilityServer::new(
            AccServerParams {
                maximum_score: 100.0,
                report_threashold: 10,
                epoch_duration: 24,
                tag_duration: 2,
                compute_score: None,
                noise_distribution: None,
            },
            &mut rng,
        );
        let sender = Sender::new("sender", &mut rng);
        accsvr.set_sender_pk(&sender.epk, &sender.handle);

        let tag = sender
            .get_tag(receiver_handle, &accsvr, &mut rng)
            .unwrap();

        // Tag should be valid
        let verif_result = verify(
            receiver_handle,
            &sender.get_verifying_key(),
            &tag.tag,
            &tag.randomness_hr,
            &tag.randomness_vks,
            &tag.proof,
            &tag.r_big,
            &accsvr.get_verifying_key(),
        );
        assert!(verif_result.is_ok(), "{}", verif_result.unwrap_err().0);
    }
}
