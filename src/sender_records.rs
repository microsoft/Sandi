use std::{collections::HashMap, sync::Arc};

use crate::{spin_lock::{Spinlock, SpinlockGuard}, tag::Tag};
use curve25519_dalek::RistrettoPoint;
use rand::{CryptoRng, RngCore};

// Alias for a sender ID
pub type SenderId = [u8; 8];
// Alias for a token
pub type Token = ([u8; 8], RistrettoPoint);

#[derive(Clone)]
pub(crate) struct SenderRecord {
    pub id: SenderId,
    pub handles: Vec<String>,
    pub epk: Option<RistrettoPoint>,
    pub epk_epoch: i64,
    pub vks_keys: HashMap<i64, Vec<[u8; 32]>>,
    pub score: f64,
    pub b_param: f64,
    pub report_count: Vec<i32>,
    pub reported_tags: HashMap<[u8; 64], Tag>,
    pub tokens: Vec<Token>,
    pub(crate) lock: Arc<Spinlock>,
}

pub(crate) struct SenderRecords {
    pub records: HashMap<SenderId, SenderRecord>,
    pub ids: HashMap<String, SenderId>,
}

pub (crate) struct SenderRecordError(pub String);

impl SenderRecord {
    pub fn new<R>(handle: &str, num_epochs: usize, initial_score: f64, rng: &mut R) -> SenderRecord
    where
        R: RngCore + CryptoRng,
    {
        let mut sender_id = SenderId::default();
        rng.fill_bytes(&mut sender_id);

        SenderRecord {
            id: sender_id,
            handles: vec![handle.to_string()],
            epk: None,
            epk_epoch: 0,
            vks_keys: HashMap::new(),
            score: initial_score,
            b_param: 1.0,
            report_count: vec![0; num_epochs + 1],
            reported_tags: HashMap::new(),
            tokens: Vec::new(),
            lock: Arc::new(Spinlock::new()),
        }
    }

    pub fn get_vks_key_count(&self, epoch: i64) -> usize {
        match self.vks_keys.get(&epoch) {
            Some(vks_keys) => vks_keys.len(),
            None => 0,
        }
    }

    pub fn add_vks_key(&mut self, epoch: i64, vks_key: &[u8]) {
        if !self.vks_keys.contains_key(&epoch) {
            self.vks_keys.insert(epoch, vec![]);
        }

        let vks_keys_opt = self.vks_keys.get_mut(&epoch);
        match vks_keys_opt {
            None => { panic!("Epoch not found"); }
            Some(vks_keys) => {
                let mut vks_arr: [u8; 32] = [0; 32];
                vks_arr.copy_from_slice(vks_key);
                vks_keys.push(vks_arr);
            }
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

    pub(crate) fn set_sender_epk(&mut self, sender_id: &SenderId, epoch: i64, epk: RistrettoPoint) -> Result<(), SenderRecordError> {
        // First find the sender
        let sender_rec = self.records.get_mut(sender_id);
        match sender_rec
        {
            None => return Err(SenderRecordError("Sender not found".to_string())),
            Some(sender) => {
                let _sender_lock = SpinlockGuard::new(sender.lock.clone());
                if sender.epk_epoch == epoch {
                    return Err(SenderRecordError("EPK already exists for this epoch".to_string()));
                }

                sender.epk_epoch = epoch;
                sender.epk = Some(epk);
                Ok(())
            }
        }
    }

    pub(crate) fn get_sender_epk(&self, sender_id: &SenderId, epoch: i64) -> Option<RistrettoPoint> {
        // First find the sender
        let sender_rec = self.records.get(sender_id);
        match sender_rec
        {
            None => None,
            Some(sender) => {
                if sender.epk_epoch == epoch {
                    return sender.epk.clone();
                }
                None
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn set_sender_epk_byhandle(&mut self, handle: &str, epoch: i64, epk: RistrettoPoint) -> Result<(), SenderRecordError> {
        // First find the sender
        let sender_id = self.ids.get(handle).cloned();
        if let Some(id) = sender_id {
            self.set_sender_epk(&id, epoch, epk)
        } else {
            return Err(SenderRecordError("Sender not found".to_string()))
        }
    }

    #[allow(dead_code)]
    pub(crate) fn add_vks_key(&mut self, sender_id: &SenderId, epoch: i64, vks_key: [u8;32]) -> Result<(), SenderRecordError> {
        // First find the sender
        let sender_rec = self.records.get_mut(sender_id);
        match sender_rec
        {
            None => return Err(SenderRecordError("Sender not found".to_string())),
            Some(sender) => {
                let _sender_lock = SpinlockGuard::new(sender.lock.clone());
                if !sender.vks_keys.contains_key(&epoch) {
                    sender.vks_keys.insert(epoch, vec![]);
                }

                let vks_keys_opt = sender.vks_keys.get_mut(&epoch);
                match vks_keys_opt {
                    None => return Err(SenderRecordError("VKs keys not found".to_string())),
                    Some(vks_keys) => {
                        vks_keys.push(vks_key);
                        Ok(())
                    }
                }
            }
        }
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
        let sender = SenderRecord::new("sender1", 2, 100.0, &mut rng);
        let id1 = sender.id.clone();
        let mut sr = SenderRecords::new();
        sr.set_sender(sender);
        assert_eq!(sr.records.len(), 1);

        let sender = SenderRecord::new("sender2", 2, 100.0, &mut rng);
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
        let mut sender = SenderRecord::new("sender3", 2, 100.0, &mut rng);
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
