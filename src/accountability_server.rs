use rand::{RngCore, CryptoRng};
use crate::{sender_ids::get_sender, utils::encrypt};

pub struct AccountabilityServer {
    secret_key: [u8; 32],
}

impl AccountabilityServer {
    pub fn new<R>(rng: &mut R) -> AccountabilityServer
    where
        R: RngCore + CryptoRng,
    {
        let mut secret_key = [0u8; 32];
        rng.fill_bytes(&mut secret_key);

        AccountabilityServer { secret_key }
    }

    pub fn issue_tag(&self, commitment: Vec<u8>, sender_handle: &str) {
        // First, we need to check if the sender_handle is valid
        let sender = get_sender(sender_handle).expect("Sender handle not found");

        // Then, we encrypt the sender ID
        let mut encrypted_sender_id = sender.id.clone();
        encrypt(&self.secret_key, &mut encrypted_sender_id);

        // Then, we sign tag information
        
    }
}
