use std::collections::HashMap;

use crate::{tag::Tag, utils::G};
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::{CryptoRng, RngCore};

// Alias for a sender ID
pub type SenderId = [u8; 16];
// Alias for a token
pub type Token = (Scalar, RistrettoPoint);

#[derive(Clone)]
pub(crate) struct SenderRecord {
    pub id: SenderId,
    pub handles: Vec<String>,
    pub epk: RistrettoPoint,
    pub score: i32,
    pub report_count: Vec<i32>,
    pub reported_tags: HashMap<Vec<u8>, Tag>,
    pub tokens: Vec<Token>,
}

pub(crate) struct SenderRecords {
    pub records: HashMap<SenderId, SenderRecord>,
    pub ids: HashMap<String, SenderId>,
}

impl SenderRecord {
    pub fn new<R>(handle: &str, num_epochs: usize, rng: &mut R) -> SenderRecord
    where
        R: RngCore + CryptoRng,
    {
        let mut sender_id = [0u8; 16];
        rng.fill_bytes(&mut sender_id);
        let epk = G();

        SenderRecord {
            id: sender_id,
            handles: vec![handle.to_string()],
            epk: epk,
            score: 100,
            report_count: vec![0; num_epochs + 1],
            reported_tags: HashMap::new(),
            tokens: Vec::new(),
        }
    }
}

impl SenderRecords {
    pub(crate) fn new() -> SenderRecords {
        SenderRecords {
            records: HashMap::new(),
            ids: HashMap::new(),
        }
    }

    pub(crate) fn get_sender_by_handle(&self, handle: &str) -> Option<SenderRecord> {
        let sender_id = self.ids.get(handle)?;
        let sender = self.records.get(sender_id)?;

        return Some(sender.clone());
    }

    pub(crate) fn get_sender_by_id(&self, id: &SenderId) -> Option<SenderRecord> {
        let sender = self.records.get(id)?;

        return Some(sender.clone());
    }

    pub(crate) fn set_sender(&mut self, sender_record: SenderRecord) {
        for handle in &sender_record.handles {
            self.ids
                .entry(handle.clone())
                .and_modify(|e| *e = sender_record.id.clone())
                .or_insert(sender_record.id.clone());
        }

        self.records
            .entry(sender_record.id)
            .and_modify(|e| {
                e.handles = sender_record.handles.clone();
                e.score = sender_record.score;
                e.reported_tags = sender_record.reported_tags.clone();
                e.tokens = sender_record.tokens.clone();
                e.report_count = sender_record.report_count.clone();
            })
            .or_insert(sender_record);
    }

    // Iterate over all senders, executing the given function
    pub(crate) fn for_each<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut SenderRecord),
    {
        for (_, sender) in &mut self.records {
            f(sender);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_insert() {
        let mut rng = OsRng;
        let sender = SenderRecord::new("sender1", 2, &mut rng);
        let id1 = sender.id.clone();
        let mut sr = SenderRecords::new();
        sr.set_sender(sender);
        assert_eq!(sr.records.len(), 1);

        let sender = SenderRecord::new("sender2", 2, &mut rng);
        let id2 = sender.id.clone();
        sr.set_sender(sender);
        assert_eq!(sr.records.len(), 2);

        let found = sr.get_sender_by_id(&id1);
        assert!(found.is_some());

        let found = sr.get_sender_by_id(&id2);
        assert!(found.is_some());

        let found = sr.get_sender_by_handle("sender1");
        assert!(found.is_some());

        let found = sr.get_sender_by_handle("sender2");
        assert!(found.is_some());
    }

    #[test]
    fn test_insert_with_handles() {
        let mut rng = OsRng;
        let mut sender = SenderRecord::new("sender3", 2, &mut rng);
        sender.handles.push("sender4".to_string());
        sender.handles.push("sender5".to_string());
        let id1 = sender.id.clone();
        let mut sr = SenderRecords::new();
        sr.set_sender(sender);
        assert_eq!(sr.records.len(), 1);
        assert_eq!(sr.ids.len(), 3);

        let found = sr.get_sender_by_id(&id1);
        assert!(found.is_some());

        let found = sr.get_sender_by_handle("sender3");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, id1);

        let found = sr.get_sender_by_handle("sender4");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, id1);

        let found = sr.get_sender_by_handle("sender5");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, id1);
    }
}
