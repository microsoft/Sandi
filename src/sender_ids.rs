use std::{collections::HashMap, sync::Mutex};

use crate::tag::Tag;
use lazy_static::lazy_static;

lazy_static! {
    static ref SENDER_ID_RECORDS: Mutex<HashMap<[u8; 16], SenderRecord>> =
        Mutex::new(HashMap::new());
}

pub type SenderId = [u8; 16];

#[derive(Clone)]
pub(crate) struct SenderRecord {
    pub id: SenderId,
    pub handles: Vec<String>,
    pub score: i32,
    pub reported_tags: Vec<Tag>,
}

pub(crate) fn get_sender(handle: &str) -> Option<SenderRecord> {
    let records = SENDER_ID_RECORDS.lock().unwrap();
    let handle_str = handle.to_string();
    for record in records.values() {
        if record.handles.contains(&handle_str) {
            return Some(record.clone());
        }
    }

    None
}

pub(crate) fn set_sender(sender_record: SenderRecord) {
    let mut records = SENDER_ID_RECORDS.lock().unwrap();
    records
        .entry(sender_record.id)
        .and_modify(|e| {
            e.handles = sender_record.handles.clone();
            e.score = sender_record.score;
            e.reported_tags = sender_record.reported_tags.clone();
        })
        .or_insert(sender_record);
}
