use sender_tag::SenderTag;
use tag_verifier::VerificationError;

pub mod accountability_server;
pub mod batch_ndleq;
pub mod nizqdleq;
pub mod sender;
pub mod sender_records;
pub mod sender_tag;
pub mod serialization;
pub mod tag;
pub mod tag_verifier;
pub mod utils;

pub fn verify_tag(
    receiver_handle: &str,
    message: &str,
    verifying_key: &Vec<u8>,
    tag: &Vec<u8>,
) -> Result<i32, String> {
    let full_tag = SenderTag::from_vec(tag);
    match full_tag {
        Ok(full_tag) => {
            let verif_result = tag_verifier::verify(
                receiver_handle,
                message,
                &full_tag.tag,
                &full_tag.randomness,
                &full_tag.proof,
                &full_tag.r_big,
                verifying_key,
            );
            match verif_result {
                Ok(score) => return Ok(score),
                Err(VerificationError(err_msg)) => {
                    return Err(format!("Verification failed: {}", err_msg))
                }
            }
        }
        Err(e) => return Err(format!("Failed to deserialize tag: {}", e)),
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
                maximum_score: 100,
                report_threashold: 10,
                epoch_duration: 24,
                tag_duration: 2,
            },
            &mut rng,
        );
        let sender = Sender::new("sender1", &mut rng);
        accsvr.set_sender_pk(&sender.epk, &sender.handle);

        // Ask for a tag
        let msg = "This is a test message";
        let receiver_handle = "receiver";
        let tag = sender
            .get_tag(msg, receiver_handle, &accsvr, &mut rng)
            .unwrap();

        // Verify tag
        let vk = accsvr.get_verifying_key();
        let verif_result = tag_verifier::verify(
            &receiver_handle,
            &msg,
            &tag.tag,
            &tag.randomness,
            &tag.proof,
            &tag.r_big,
            &vk,
        );
        assert!(verif_result.is_ok());

        // Sender should have no reports
        let sender_opt = accsvr.sender_records.get_sender_by_handle("sender1");
        assert!(sender_opt.is_some());
        assert_eq!(sender_opt.unwrap().reported_tags.len(), 0);

        // Report tag
        let report_result = accsvr.report(tag.tag, tag.proof, tag.r_big);
        assert!(report_result.is_ok());
        let sender_opt = accsvr.sender_records.get_sender_by_handle("sender1");
        assert!(sender_opt.is_some());
        // Sender should have one report now
        assert_eq!(sender_opt.unwrap().reported_tags.len(), 1);

        // Update scores
        accsvr.update_scores();

        // Sender should have one token now
        let sender_opt = accsvr.sender_records.get_sender_by_handle("sender1");
        assert!(sender_opt.is_some());
        assert_eq!(sender_opt.unwrap().tokens.len(), 1);
    }
}
