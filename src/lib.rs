pub mod accountability_server;
pub mod nizqdleq;
pub mod sender;
pub mod sender_records;
pub mod tag;
pub mod tag_verifier;
pub mod utils;
pub mod batch_ndleq;

pub fn test() {}

pub fn prove() {}

#[cfg(test)]
mod tests {
    use crate::{accountability_server::AccountabilityServer, sender::Sender};
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn issue_tag_test() {
        let mut rng = OsRng;
        let mut accsvr = AccountabilityServer::new(100, 10, &mut rng);
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
        let verif_result =
            tag_verifier::verify(&receiver_handle, &msg, &tag.0, &tag.1, &tag.2, &tag.3, &vk);
        assert!(verif_result.is_ok());

        // Sender should have no reports
        let sender_opt = accsvr.sender_records.get_sender_by_handle("sender1");
        assert!(sender_opt.is_some());
        assert_eq!(sender_opt.unwrap().reported_tags.len(), 0);

        // Report tag
        let report_result = accsvr.report(tag.0, tag.2, tag.3);
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
