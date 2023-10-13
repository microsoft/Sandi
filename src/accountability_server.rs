use crate::sender_ids::{SenderRecord, get_sender_id, SenderId, get_sender_by_id};
use crate::tag::Tag;
use crate::utils::{cipher_block_size, decrypt, verify_signature, SignatureVerificationError};
use crate::{sender_ids::get_sender_by_handle, sender_ids::set_sender, utils::encrypt};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use std::cmp;
use std::collections::HashMap;
use std::sync::Mutex;
use itertools::Itertools;

lazy_static! {
    static ref UNPROCESSED_REPORTED_TAGS: Mutex<HashMap<Vec<u8>, Tag>> = Mutex::new(HashMap::new());
}

pub struct AccountabilityServer {
    enc_secret_key: [u8; 32],
    signing_key: SigningKey,
    maximum_score: i32,
    reputation_threashold: i32,
}

pub struct ReportError(String);

impl AccountabilityServer {
    pub fn new<R>(maximum_score: i32, reputation_threashold: i32, rng: &mut R) -> AccountabilityServer
    where
        R: RngCore + CryptoRng,
    {
        let mut enc_secret_key = [0u8; 32];
        rng.fill_bytes(&mut enc_secret_key);

        let signing_key = SigningKey::generate(rng);

        AccountabilityServer {
            enc_secret_key,
            signing_key,
            maximum_score,
            reputation_threashold,
        }
    }

    pub fn issue_tag(&self, commitment: &Vec<u8>, sender_handle: &str, tag_duration: u32) -> Tag {
        // First, we need to check if the sender_handle is valid
        let mut sender_opt = get_sender_by_handle(sender_handle);
        if sender_opt.is_none() {
            let mut rng = OsRng;
            let sender = SenderRecord::new(sender_handle, &mut rng);
            set_sender(sender.clone());
            sender_opt = Some(sender);
        }

        let sender = sender_opt.expect("Sender should exist");

        // Check sender id size
        if sender.id.len() % cipher_block_size() != 0 {
            panic!(
                "Sender id size is not a multiple of {} bytes",
                cipher_block_size()
            );
        }

        // Then, we encrypt the sender ID
        let mut encrypted_sender_id = sender.id.clone();
        encrypt(&self.enc_secret_key, &mut encrypted_sender_id);

        // Get expiration date for the tag
        // tag_duration is in hours
        let expiration_date =
            Utc::now().timestamp() + Duration::hours(tag_duration as i64).num_seconds();

        // Then, we sign tag information
        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(&commitment);
        data_to_sign.extend_from_slice(expiration_date.to_be_bytes().as_slice());
        data_to_sign.extend_from_slice(sender.score.to_be_bytes().as_slice());
        data_to_sign.extend_from_slice(&encrypted_sender_id);
        data_to_sign.extend_from_slice(sender_handle.as_bytes());

        let signature = self.signing_key.sign(&data_to_sign);

        // Finally, we create the tag
        let tag = Tag {
            commitment: commitment.clone(),
            exp_timestamp: expiration_date,
            score: sender.score,
            enc_sender_id: encrypted_sender_id.to_vec(),
            sender_handle: sender_handle.to_string(),
            signature: signature.to_vec(),
        };

        tag
    }

    pub fn get_verifying_key(&self) -> Vec<u8> {
        let vk = self.signing_key.verifying_key();
        vk.to_bytes().to_vec()
    }

    pub fn report(&self, tag: &Tag) -> Result<(), ReportError> {
        // Check if tag is expired
        if tag.exp_timestamp < Utc::now().timestamp() {
            return Err(ReportError("Tag is expired".to_string()));
        }

        // Verify if tag is included
        let sender_opt = get_sender_by_handle(&tag.sender_handle);
        match sender_opt {
            Some(sender) => {
                if sender.reported_tags.contains(tag) || UNPROCESSED_REPORTED_TAGS.lock().unwrap().contains_key(&tag.signature) {
                    // Tag is already reported, no need to do anything
                    return Ok(())
                }

                let verifying_key = self.signing_key.verifying_key();
                let signature_result = verify_signature(tag, &verifying_key);
                match signature_result {
                    Ok(_) => {
                        // Verify the encrypted sender ID
                        let mut decrypted_sender_id = tag.enc_sender_id.clone();
                        decrypt(&self.enc_secret_key, &mut decrypted_sender_id);

                        if decrypted_sender_id != sender.id {
                            return Err(ReportError("Invalid encrypted sender ID".to_string()));
                        }

                        // Tag is valid, so we add it to the unprocessed tags
                        UNPROCESSED_REPORTED_TAGS
                            .lock()
                            .unwrap()
                            .insert(tag.signature.clone(), tag.clone());
                    }
                    Err(SignatureVerificationError(err_msg)) => {
                        return Err(ReportError(format!(
                            "Error verifying signature: {}",
                            err_msg
                        )));
                    }
                }
            }
            None => {
                return Err(ReportError("Sender handle is not registered".to_string()));
            }
        }

        Ok(())
    }

    pub fn update_scores(&self) {
        let mut unprocessed_tags = UNPROCESSED_REPORTED_TAGS.lock().unwrap();
        let sender_tags: HashMap<SenderId, Vec<Tag>> = unprocessed_tags
            .iter()
            .map(|(_, tag)| {
                let sender_id = get_sender_id(&tag.sender_handle).unwrap();
                (sender_id, tag.clone())
            })
            .into_group_map();

        // Update sender scores
        for (sender_id, tags) in sender_tags.iter() {
            let mut sender = get_sender_by_id(sender_id).unwrap();

            // Update sender score
            let mut score = sender.score;
            for tag in tags.iter() {
                score = cmp::max(score - 1, 0);
            }
            sender.score = score;

            // Add tags to reported tags
            sender.reported_tags.extend(tags.iter().cloned());

            // Update sender
            set_sender(sender);
        }

        unprocessed_tags.clear();
    }
}

#[cfg(test)]
mod tests {
    use crate::{sender::Sender, sender_ids::clear_sender_records};
    use serial_test::serial;

    use super::*;

    #[test]
    #[serial]
    fn update_scores_test() {
        let mut rng = OsRng;
        let server = AccountabilityServer::new(1000, 10, &mut rng);

        // Initialize senders
        let mut senders: Vec<Sender> = Vec::new();
        for i in 0..10 {
            let sender_handle = format!("sender{}", i);
            senders.push(Sender::new(&sender_handle));
        }

        // Get tags
        let mut tags: Vec<(Tag, Vec<u8>)> = Vec::new();
        for idx in 0..1000 {
            // Get a random sender
            let sender_idx = rng.next_u32() as usize % 10;
            tags.push(senders[sender_idx].get_tag("This is the message", "receiver", &server, &mut rng));
        }

        // Report tags
        for tag in tags {
            let result = server.report(&tag.0);
            assert!(result.is_ok());
        }

        assert!(!UNPROCESSED_REPORTED_TAGS.lock().unwrap().is_empty());

        // Update scores
        server.update_scores();

        assert!(UNPROCESSED_REPORTED_TAGS.lock().unwrap().is_empty());

        clear_sender_records();
    }
}