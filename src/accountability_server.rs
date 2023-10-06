use rand::{RngCore, CryptoRng};
use chrono::{ Utc, Duration };
use ed25519_dalek::{ SigningKey, Signature, Signer };
use crate::{sender_ids::get_sender, utils::encrypt};

pub struct AccountabilityServer {
    enc_secret_key: [u8; 32],
    signing_key: SigningKey,
}

impl AccountabilityServer {
    pub fn new<R>(rng: &mut R) -> AccountabilityServer
    where
        R: RngCore + CryptoRng,
    {
        let mut enc_secret_key = [0u8; 32];
        rng.fill_bytes(&mut enc_secret_key);

        let signing_key = SigningKey::generate(rng);

        AccountabilityServer { enc_secret_key, signing_key }
    }

    pub fn issue_tag(&self, commitment: Vec<u8>, sender_handle: &str, tag_duration: u32) {
        // First, we need to check if the sender_handle is valid
        let sender = get_sender(sender_handle).expect("Sender handle not found");

        // Then, we encrypt the sender ID
        let mut encrypted_sender_id = sender.id.clone();
        encrypt(&self.enc_secret_key, &mut encrypted_sender_id);

        // Get expiration date for the tag
        // tag_duration is in hours
        let expiration_date = Utc::now().timestamp() + Duration::hours(tag_duration as i64).num_seconds();

        // Then, we sign tag information
        let mut data_to_sign = Vec::new();
        data_to_sign.extend(commitment);
        data_to_sign.extend_from_slice(expiration_date.to_be_bytes().as_slice());
        data_to_sign.extend_from_slice(&encrypted_sender_id);
    }
}
