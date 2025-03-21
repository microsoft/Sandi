// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use sender_tag::SenderTag;
use tag_verifier::VerificationError;

pub mod accountability_server;
pub mod batch_ndleq;
pub mod epochs;
pub mod gaussian;
pub mod nizqdleq;
pub mod receiver;
pub mod sender;
pub mod sender_records;
pub mod sender_tag;
pub mod serialization;
pub mod tag;
pub mod tag_verifier;
pub mod utils;

// private modules
mod spin_lock;
mod time_provider;

pub fn verify_tag(receiver_addr: &str, verifying_key: &[u8], tag: &[u8]) -> Result<u8, String> {
    let full_tag = SenderTag::from_slice(tag)?;

    let verif_result = tag_verifier::verify(receiver_addr, &full_tag, verifying_key);

    match verif_result {
        Ok(reputation) => return Ok(reputation),
        Err(VerificationError(err_msg)) => return Err(format!("Verification failed: {}", err_msg)),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        accountability_server::{AccServerParams, AccountabilityServer},
        sender::Sender,
    };
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn issue_tag_test() {
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
        let mut sender = Sender::new("sender1", &mut rng);
        let set_pk_result = accsvr.set_sender_epk(&sender.epk, &sender.handle);
        assert!(set_pk_result.is_ok(), "{}", set_pk_result.unwrap_err().0);

        // Ask for a tag
        let receiver_addr = "receiver";
        let channel = sender.add_channel(receiver_addr, &mut rng);

        let tag = sender.get_tag(&channel, &mut accsvr, &mut rng).unwrap();

        // Verify tag
        let vk = accsvr.get_verifying_key();
        let verif_result = tag_verifier::verify(&receiver_addr, &tag, &vk);
        assert!(verif_result.is_ok());

        // Sender should have no reports
        let sender_opt = accsvr.sender_records.get_sender_by_handle("sender1");
        assert!(sender_opt.is_some());
        assert_eq!(sender_opt.unwrap().reported_tags.len(), 0);

        // Report tag
        let report_result = accsvr.report(&tag.report_tag);
        assert!(report_result.is_ok(), "{:?}", report_result.unwrap_err());
        let sender_opt = accsvr.sender_records.get_sender_by_handle("sender1");
        assert!(sender_opt.is_some());
        // Sender should have one report now
        assert_eq!(sender_opt.unwrap().reported_tags.len(), 1);

        // Update scores
        accsvr.update_scores(&mut rng);

        // Sender should have one token now
        let sender_opt = accsvr.sender_records.get_sender_by_handle("sender1");
        assert!(sender_opt.is_some());
        assert_eq!(sender_opt.unwrap().tokens.len(), 1);
    }
}
