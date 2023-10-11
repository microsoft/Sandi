use std::cmp;

use crate::sender_ids::SenderRecord;
use crate::tag::Tag;
use crate::utils::{cipher_block_size, decrypt, verify_signature, SignatureVerificationError};
use crate::{sender_ids::get_sender_by_handle, sender_ids::set_sender, utils::encrypt};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};

pub struct AccountabilityServer {
    enc_secret_key: [u8; 32],
    signing_key: SigningKey,
}

pub struct ReportError(String);

impl AccountabilityServer {
    pub fn new<R>(rng: &mut R) -> AccountabilityServer
    where
        R: RngCore + CryptoRng,
    {
        let mut enc_secret_key = [0u8; 32];
        rng.fill_bytes(&mut enc_secret_key);

        let signing_key = SigningKey::generate(rng);

        AccountabilityServer {
            enc_secret_key,
            signing_key,
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
                if sender.reported_tags.contains(tag) {
                    return Err(ReportError("Tag is already reported".to_string()));
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

                        // Tag is valid, so we add it to the reported tags and reduce the score
                        let mut new_sender = sender.clone();
                        new_sender.reported_tags.push(tag.clone());
                        new_sender.score = cmp::max(0, new_sender.score - 1);
                        set_sender(new_sender);
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
}
