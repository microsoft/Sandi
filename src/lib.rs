pub mod accountability_server;
pub mod blind_token;
pub mod nizqdleq;
pub mod sender;
pub mod sender_ids;
pub mod tag;
pub mod tag_verifier;
mod utils;

pub fn test() {}

pub fn prove() {}

#[cfg(test)]
mod tests {
    use crate::{
        accountability_server::AccountabilityServer, sender::Sender,
        sender_ids::clear_sender_records,
    };
    use rand::rngs::OsRng;
    use serial_test::serial;

    use super::*;

    #[test]
    #[serial]
    fn issue_tag_test() {
        let mut rng = OsRng;
        let accsvr = AccountabilityServer::new(100, 10, &mut rng);
        let sender = Sender::new("sender1");

        // Ask for a tag
        let msg = "This is a test message";
        let receiver_handle = "receiver";
        let tag = sender.get_tag(msg, receiver_handle, &accsvr, &mut rng);

        // Verify tag
        let vk = accsvr.get_verifying_key();
        let verif_result = tag_verifier::verify(receiver_handle, msg, &tag.0, &tag.1, &vk);
        assert!(verif_result.is_ok());

        // Sender should have no reports
        let sender_opt = sender_ids::get_sender_by_handle("sender1");
        assert!(sender_opt.is_some());
        assert_eq!(sender_opt.unwrap().reported_tags.len(), 0);

        // Report tag
        let report_result = accsvr.report(&tag.0);
        assert!(report_result.is_ok());

        // Update scores
        accsvr.update_scores();

        // Sender should have one report now
        let sender_opt = sender_ids::get_sender_by_handle("sender1");
        assert!(sender_opt.is_some());
        assert_eq!(sender_opt.unwrap().reported_tags.len(), 1);

        clear_sender_records();
    }
}
