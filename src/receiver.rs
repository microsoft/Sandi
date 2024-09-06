use std::collections::HashMap;

use crate::accountability_server::AccountabilityServer;
use crate::{epochs, sender_tag::SenderTag};
use crate::time_provider::{TimeProvider, DefaultTimeProvider};

#[derive(Clone)]
pub struct ReceiverParams {
    // Timestamp until which the receiver is locked for reporting
    pub report_lock_period: i64,

    // Duration of the lock period in epochs
    pub epoch_duration: i64,
}

pub struct Receiver {
    pub reports: HashMap<[u8;32], Vec<SenderTag>>,

    // Timestamp until which the receiver is locked for reporting
    report_lock: i64,

    // Duration of the lock period in epochs
    receiver_params: ReceiverParams,

    // Time provider
    pub(crate) time_provider: Box<dyn TimeProvider>,
}

impl Receiver {
    pub fn new(receiver_params: &ReceiverParams) -> Self {
        Receiver {
            reports: HashMap::new(),
            report_lock: 0,
            receiver_params: receiver_params.clone(),
            time_provider: Box::new(DefaultTimeProvider {}),
        }
    }

    pub(crate) fn new_with_time_provider(receiver_params: &ReceiverParams, time_provider: Box<dyn TimeProvider>) -> Self {
        Receiver {
            reports: HashMap::new(),
            report_lock: 0,
            receiver_params: receiver_params.clone(),
            time_provider,
        }
    }

    pub(crate) fn can_report_tag(&mut self, tag: &[u8]) -> Result<(SenderTag, [u8; 32]), String> {
        let full_tag = SenderTag::from_slice(tag)?;

        // Tag expired?
        let now = self.time_provider.get_current_time();
        if full_tag.report_tag.tag.exp_timestamp < now {
            return Err("Tag is expired".to_string());
        }

        let vks = full_tag.vks.compress().to_bytes();
        let reports = self.reports.entry(vks).or_insert(Vec::new());
        for report in reports {
            if report.report_tag.tag.signature == full_tag.report_tag.tag.signature {
                return Err("Tag already reported".to_string());
            }
        }

        // Are we in the lock period?
        if now < self.report_lock {
            return Err("Reporting is locked".to_string());
        }

        Ok((full_tag, vks))
    }

    fn set_report_lock(&mut self) {
        let now = self.time_provider.get_current_time();
        // Set the lock period
        self.report_lock = epochs::get_lock_timestamp(now, self.receiver_params.report_lock_period, self.receiver_params.epoch_duration);
    }

    pub fn report(&mut self, tag: &[u8], acc_server: &mut AccountabilityServer) -> Result<(), String> {
        let (full_tag, vks) = self.can_report_tag(tag)?;
        let report_tag = full_tag.report_tag.clone();
        self.reports.entry(vks).and_modify(|reps| reps.push(full_tag));

        let report_result = acc_server.report(&report_tag);
        match report_result {
            Ok(_) => {
                self.set_report_lock();
                Ok(())
            },
            Err(e) => Err(e.0),
        }
    }

}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use crate::{accountability_server::{AccServerParams, AccountabilityServer}, sender::Sender};

    use super::*;

    static mut MOCK_TIME: i64 = 0;

    struct MockTimeProvider {}

    impl TimeProvider for MockTimeProvider {
        fn get_current_time(&self) -> i64 {
            unsafe { MOCK_TIME }
        }
    }

    #[test]
    fn test_can_report_tag() {
        let mut rng = OsRng;

        unsafe {
            MOCK_TIME = 1601729494; // 2020-10-03 12:24:54 UTC
        }

        let mut acc_server = AccountabilityServer::new_with_time_provider(
            AccServerParams {
                maximum_score: 100.0,
                report_threshold: 10,
                epoch_start: 1601535600, // 2020-10-01 00:00:00 UTC
                epoch_duration: 24,
                tag_duration: 2,
                max_vks_per_epoch: 5,
                compute_reputation: None,
                noise_distribution: None,
            }, &mut rng, Box::new(MockTimeProvider {})
        );

        let mut sender = Sender::new("sender", &mut rng);
        let channel = sender.add_channel("receiver", &mut rng);
        acc_server.set_sender_epk(&sender.epk, "sender").unwrap();

        let tag = sender.get_tag(&channel, &mut acc_server, &mut rng).unwrap();

        let serialized_tag = tag.to_vec();

        let params = ReceiverParams {
            report_lock_period: 2,
            epoch_duration: 24,
        };
        let mut receiver = Receiver::new_with_time_provider(&params, Box::new(MockTimeProvider {}));

        let result = receiver.can_report_tag(&serialized_tag);
        assert_eq!(result.is_ok(), true);

        // After 3 days the tag should be expired
        unsafe {
            MOCK_TIME = 1601909494; // 2020-10-05 12:24:54 UTC
        }

        let result = receiver.can_report_tag(&serialized_tag);
        assert_eq!(result.is_err(), true);
        assert_eq!(result.unwrap_err(), "Tag is expired");

        // Get a new tag
        sender.generate_new_epoch_keys(&mut rng);
        acc_server.set_sender_epk(&sender.epk, "sender").unwrap();

        let tag = sender.get_tag(&channel, &mut acc_server, &mut rng).unwrap();
        let serialized_tag = tag.to_vec();

        let result = receiver.can_report_tag(&serialized_tag);
        assert_eq!(result.is_ok(), true);

        // Report it
        let result = receiver.report(&serialized_tag, &mut acc_server);
        assert_eq!(result.is_ok(), true);

        // Try to report it again
        let result = receiver.report(&serialized_tag, &mut acc_server);
        assert_eq!(result.is_err(), true);
        assert_eq!(result.unwrap_err(), "Tag already reported");

        unsafe {
            // New time within the lock period
            MOCK_TIME = 1602003600; // 2020-10-06 16:00:00 UTC
        }

        // Get a new tag
        sender.generate_new_epoch_keys(&mut rng);
        acc_server.set_sender_epk(&sender.epk, "sender").unwrap();
        
        let tag = sender.get_tag(&channel, &mut acc_server, &mut rng).unwrap();
        let serialized_tag = tag.to_vec();

        // Try to report
        let result = receiver.report(&serialized_tag, &mut acc_server);
        assert_eq!(result.is_err(), true);
        assert_eq!(result.unwrap_err(), "Reporting is locked");
    }
}
