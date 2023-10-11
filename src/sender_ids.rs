use std::{collections::HashMap, sync::Mutex};

use crate::tag::Tag;
use lazy_static::lazy_static;
use rand::{CryptoRng, RngCore};

lazy_static! {
    static ref SENDER_RECORDS: Mutex<HashMap<[u8; 16], SenderRecord>> = Mutex::new(HashMap::new());
    static ref SENDER_IDS: Mutex<HashMap<String, [u8; 16]>> = Mutex::new(HashMap::new());
}

pub type SenderId = [u8; 16];

#[derive(Clone)]
pub(crate) struct SenderRecord {
    pub id: SenderId,
    pub handles: Vec<String>,
    pub score: i32,
    pub reported_tags: Vec<Tag>,
}

impl SenderRecord {
    pub fn new<R>(handle: &str, rng: &mut R) -> SenderRecord
    where
        R: RngCore + CryptoRng,
    {
        let mut sender_id = [0u8; 16];
        rng.fill_bytes(&mut sender_id);

        SenderRecord {
            id: sender_id,
            handles: vec![handle.to_string()],
            score: 100,
            reported_tags: vec![],
        }
    }
}

pub(crate) fn get_sender_by_handle(handle: &str) -> Option<SenderRecord> {
    let ids = SENDER_IDS.lock().unwrap();
    let records = SENDER_RECORDS.lock().unwrap();
    let sender_id = ids.get(handle)?;
    let sender = records.get(sender_id)?;

    return Some(sender.clone());
}

pub(crate) fn get_sender_by_id(id: &SenderId) -> Option<SenderRecord> {
    let records = SENDER_RECORDS.lock().unwrap();
    let sender = records.get(id)?;

    return Some(sender.clone());
}

pub(crate) fn set_sender(sender_record: SenderRecord) {
    let mut ids = SENDER_IDS.lock().unwrap();
    let mut records = SENDER_RECORDS.lock().unwrap();

    for handle in &sender_record.handles {
        ids.entry(handle.clone())
            .and_modify(|e| *e = sender_record.id.clone())
            .or_insert(sender_record.id.clone());
    }

    records
        .entry(sender_record.id)
        .and_modify(|e| {
            e.handles = sender_record.handles.clone();
            e.score = sender_record.score;
            e.reported_tags = sender_record.reported_tags.clone();
        })
        .or_insert(sender_record);
}

pub(crate) fn clear_sender_records() {
    SENDER_RECORDS.lock().unwrap().clear();
    SENDER_IDS.lock().unwrap().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_insert() {
        let mut rng = OsRng;
        let sender = SenderRecord::new("sender1", &mut rng);
        let id1 = sender.id.clone();
        set_sender(sender);
        assert_eq!(SENDER_RECORDS.lock().unwrap().len(), 1);

        let sender = SenderRecord::new("sender2", &mut rng);
        let id2 = sender.id.clone();
        set_sender(sender);
        assert_eq!(SENDER_RECORDS.lock().unwrap().len(), 2);

        let found = get_sender_by_id(&id1);
        assert!(found.is_some());

        let found = get_sender_by_id(&id2);
        assert!(found.is_some());

        let found = get_sender_by_handle("sender1");
        assert!(found.is_some());

        let found = get_sender_by_handle("sender2");
        assert!(found.is_some());

        clear_sender_records();
    }

    #[test]
    #[serial]
    fn test_insert_with_handles() {
        let mut rng = OsRng;
        let mut sender = SenderRecord::new("sender3", &mut rng);
        sender.handles.push("sender4".to_string());
        sender.handles.push("sender5".to_string());
        let id1 = sender.id.clone();
        set_sender(sender);
        assert_eq!(SENDER_RECORDS.lock().unwrap().len(), 1);
        assert_eq!(SENDER_IDS.lock().unwrap().len(), 3);

        let found = get_sender_by_id(&id1);
        assert!(found.is_some());

        let found = get_sender_by_handle("sender3");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, id1);

        let found = get_sender_by_handle("sender4");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, id1);

        let found = get_sender_by_handle("sender5");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, id1);

        clear_sender_records();
    }
}
