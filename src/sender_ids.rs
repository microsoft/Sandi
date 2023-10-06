use std::{sync::Mutex, collections::HashMap};

use crate::tag::Tag;
use lazy_static::lazy_static;

lazy_static! {
    static ref SENDER_ID_RECORDS: Mutex<HashMap<[u8; 16], SenderRecord>> = Mutex::new(HashMap::new());
}

pub type SenderId = [u8; 16];

#[derive(Clone)]
pub (crate) struct SenderRecord {
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
