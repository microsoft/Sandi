
#[derive(Clone)]
pub struct Tag {
    pub commitment: [u8; 32],
    pub exp_timestamp: u64,
    pub score: i32,
    pub sender_id_ct: Vec<u8>,
    pub sender_handle: String,
    pub signature: [u8; 64],
}

