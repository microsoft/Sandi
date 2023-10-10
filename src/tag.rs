use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Tag {
    pub commitment: Vec<u8>,
    pub exp_timestamp: i64,
    pub score: i32,
    pub enc_sender_id: Vec<u8>,
    pub sender_handle: String,
    pub signature: Vec<u8>,
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.signature == other.signature
    }
}
