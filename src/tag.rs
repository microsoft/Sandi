
#[derive(Clone)]
pub struct Tag {
    pub commitment: Vec<u8>,
    pub exp_timestamp: i64,
    pub score: i32,
    pub enc_sender_id: Vec<u8>,
    pub sender_handle: String,
    pub signature: [u8; 64],
}

