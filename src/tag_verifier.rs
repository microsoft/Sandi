// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use crate::{
    nizqdleq,
    sender_tag::SenderTag,
    utils::{
        basepoint_order, verify_signature, verifying_key_from_slice, SignatureVerificationError,
    },
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Debug)]
pub struct VerificationError(pub String);

pub fn verify(
    receiver_addr: &str,
    sender_tag: &SenderTag,
    as_vks: &[u8],
) -> Result<u8, VerificationError> {
    if sender_tag.report_tag.tag.exp_timestamp < Utc::now().timestamp() {
        // Tag is expired
        return Err(VerificationError("Tag is expired".to_string()));
    }

    // Verify signature
    let verif_key =
        verifying_key_from_slice(as_vks).map_err(|err_msg| VerificationError(err_msg))?;

    let signature_result = verify_signature(&sender_tag.report_tag.tag, &verif_key);
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
    let mut mac = Hmac::<Sha256>::new_from_slice(&sender_tag.randomness_hr)
        .map_err(|_| VerificationError("Invalid randomness receiver".to_string()))?;

    mac.update(receiver_addr.as_bytes());
    let commitment = mac.finalize();

    if commitment.into_bytes().to_vec() != sender_tag.report_tag.tag.commitment_hr {
        return Err(VerificationError("Invalid receiver commitment".to_string()));
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(&sender_tag.randomness_vks)
        .map_err(|_| VerificationError("Invalid randomness vks".to_string()))?;

    mac.update(sender_tag.vks.compress().as_bytes());
    let commitment = mac.finalize();

    if commitment.into_bytes().to_vec() != sender_tag.report_tag.tag.commitment_vks {
        return Err(VerificationError("Invalid vks commitment".to_string()));
    }

    // Verify NIZKDLEG
    let nizqdleq_result = nizqdleq::verify(
        &basepoint_order(),
        &sender_tag.report_tag.tag.g_prime,
        &sender_tag.report_tag.tag.x_big,
        &sender_tag.report_tag.tag.q_big,
        &sender_tag.report_tag.r_big,
        &sender_tag.report_tag.proof,
    );
    if !nizqdleq_result {
        return Err(VerificationError("Invalid NIZKDLEQ proof".to_string()));
    }

    Ok(sender_tag.report_tag.tag.score)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountability_server::{AccServerParams, AccountabilityServer};
    use crate::sender::Sender;
    use rand::rngs::OsRng;

    #[test]
    fn verify_tag_test() {
        let receiver_addr = "receiver";
        let mut rng = OsRng;
        let mut accsvr = AccountabilityServer::new(
            AccServerParams {
                maximum_score: 100.0,
                report_threshold: 10,
                epoch_start: 0,
                epoch_duration: 24,
                tag_duration: 2,
                max_vks_per_epoch: 5,
                compute_reputation: None,
                noise_distribution: None,
            },
            &mut rng,
        );
        let mut sender = Sender::new("sender", &mut rng);
        let set_pk_result = accsvr.set_sender_epk(&sender.epk, &sender.handle);
        assert!(set_pk_result.is_ok(), "{}", set_pk_result.unwrap_err().0);

        let channel = sender.add_channel(receiver_addr, &mut rng);

        let tag = sender.get_tag(&channel, &mut accsvr, &mut rng).unwrap();

        // Tag should be valid
        let verif_result = verify(receiver_addr, &tag, &accsvr.get_verifying_key());
        assert!(verif_result.is_ok(), "{}", verif_result.unwrap_err().0);
    }
}
