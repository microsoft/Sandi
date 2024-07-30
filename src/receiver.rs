use std::collections::HashMap;
use chrono::Utc;

use crate::sender_tag::SenderTag;


pub struct Receiver {
    pub reports: HashMap<[u8;32], Vec<SenderTag>>,

    // Timestamp until which the receiver is locked for reporting
    report_lock: i64,

    // Duration of the lock period in epochs
    report_lock_period: i64,
}

impl Receiver {
    pub fn new(report_lock_period: i64) -> Self {
        Receiver {
            reports: HashMap::new(),
            report_lock: 0,
            report_lock_period,
        }
    }

    pub fn can_report_tag(&mut self, tag: &[u8]) -> Result<(), String> {
        let full_tag = SenderTag::from_slice(tag).unwrap();

        // Tag expired?
        let now = Utc::now().timestamp();
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

        self.reports.entry(vks).and_modify(|reps| reps.push(full_tag));

        // Are we in the lock period?
        if now < self.report_lock {
            return Err("Reporting is locked".to_string());
        }

        // Set the lock period
        // Need to use epochs utility to compute the lock timestamp
        self.report_lock = 0;

        Ok(())
    }

}
