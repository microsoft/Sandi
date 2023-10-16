use crate::sender_ids::{get_sender_by_id, get_sender_id, SenderId, SenderRecord};
use crate::tag::Tag;
use crate::utils::{cipher_block_size, decrypt, verify_signature, SignatureVerificationError, get_random_scalar, G, basepoint_order};
use crate::{sender_ids::get_sender_by_handle, sender_ids::set_sender, utils::encrypt};
use chrono::{Duration, Utc};
use curve25519_dalek::RistrettoPoint;
use ed25519_dalek::{Signer, SigningKey};
use itertools::Itertools;
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use std::cmp;
use std::collections::HashMap;
use std::sync::Mutex;

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
    pub fn new<R>(
        maximum_score: i32,
        reputation_threashold: i32,
        rng: &mut R,
    ) -> AccountabilityServer
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

    pub fn set_sender_pk(&self, epk: &RistrettoPoint, sender_handle: &str) {
        let sender_opt = get_sender_by_handle(sender_handle);
        match sender_opt {
            Some(mut sender) => {
                sender.epk = epk.clone();
                set_sender(sender);
            }
            None => {
                let mut rng = OsRng;
                let mut sender = SenderRecord::new(sender_handle, &mut rng);
                sender.epk = epk.clone();
                set_sender(sender);
            }
        }
    }

    pub fn issue_tag<R>(&self, commitment: &Vec<u8>, sender_handle: &str, tag_duration: u32, rng: &mut R) -> Tag
    where 
        R: RngCore + CryptoRng, {
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

        // s is random scalar
        let s = get_random_scalar(rng);

        // G'
        let new_basepoint = s * G();
        // X
        let x_big = s * sender.epk;
        // n, r
        let n = get_random_scalar(rng);
        let r = get_random_scalar(rng);

        // Q
        let hashed_n = RistrettoPoint::hash_from_bytes::<Sha512>(n.as_bytes());
        let q_big = r * hashed_n;

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
        data_to_sign.extend_from_slice(basepoint_order().as_bytes()); // q
        data_to_sign.extend_from_slice(G().compress().as_bytes()); // G
        data_to_sign.extend_from_slice(q_big.compress().as_bytes()); // Q
        data_to_sign.extend_from_slice(new_basepoint.compress().as_bytes()); // G'
        data_to_sign.extend_from_slice(x_big.compress().as_bytes()); // X

        let signature = self.signing_key.sign(&data_to_sign);

        // Finally, we create the tag
        let tag = Tag {
            commitment: commitment.clone(),
            exp_timestamp: expiration_date,
            score: sender.score,
            enc_sender_id: encrypted_sender_id.to_vec(),
            basepoint_order: basepoint_order(),
            basepoint: G(),
            q_big,
            g_prime: new_basepoint,
            x_big,
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

        // Verify if tag is already reported, pending
        if UNPROCESSED_REPORTED_TAGS
            .lock()
            .unwrap()
            .contains_key(&tag.signature)
        {
            return Ok(());
        }

        // Verify tag signature
        let verifying_key = self.signing_key.verifying_key();
        let signature_result = verify_signature(tag, &verifying_key);
        match signature_result {
            Ok(_) => {}
            Err(SignatureVerificationError(err_msg)) => {
                return Err(ReportError(format!(
                    "Error verifying signature: {}",
                    err_msg
                )));
            }
        }

        if tag.enc_sender_id.len() != 16 {
            return Err(ReportError("Invalid sender id".to_string()));
        }
        let mut decrypted_sender_id = tag.enc_sender_id.clone();
        decrypt(&self.enc_secret_key, &mut decrypted_sender_id);
        let mut sender_id = [0u8; 16];
        sender_id.copy_from_slice(&decrypted_sender_id[..16]);

        let sender_opt = get_sender_by_id(&sender_id);
        match sender_opt {
            Some(sender) => {
                if sender.reported_tags.contains(tag) {
                    // Tag is already reported, no need to do anything
                    return Ok(());
                }

                // Tag is valid, so we add it to the unprocessed tags
                UNPROCESSED_REPORTED_TAGS
                    .lock()
                    .unwrap()
                    .insert(tag.signature.clone(), tag.clone());
            }
            None => {
                return Err(ReportError("Invalid sender".to_string()));
            }
        }

        Ok(())
    }

    fn update_score(
        current_score: i32,
        reported_tag_count: i32,
        maximum_score: i32,
        score_threashold: i32,
    ) -> i32 {
        if reported_tag_count >= score_threashold {
            return current_score - reported_tag_count + score_threashold;
        } else if reported_tag_count < score_threashold && current_score >= 0 {
            return cmp::min(current_score + 1, maximum_score);
        } else {
            assert!(reported_tag_count < score_threashold && current_score < 0);
            return cmp::min(current_score - reported_tag_count + score_threashold, 0);
        }
    }

    pub fn update_scores(&self) {
        let mut unprocessed_tags = UNPROCESSED_REPORTED_TAGS.lock().unwrap();

        // Group unprocessed tags by sender
        let sender_tags: HashMap<SenderId, Vec<Tag>> = unprocessed_tags
            .iter()
            .map(|(_, tag)| {
                let mut decrypted_sender_id = tag.enc_sender_id.clone();
                decrypt(&self.enc_secret_key, &mut decrypted_sender_id);
                let mut sender_id = [0u8; 16];
                sender_id.copy_from_slice(&decrypted_sender_id[..16]);
                (sender_id, tag.clone())
            })
            .into_group_map();

        // Update sender scores
        for (sender_id, tags) in sender_tags.iter() {
            let mut sender = get_sender_by_id(sender_id).unwrap();

            // Update sender score
            sender.score = AccountabilityServer::update_score(
                sender.score,
                tags.len() as i32,
                self.maximum_score,
                self.reputation_threashold,
            );

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
            senders.push(Sender::new(&sender_handle, &mut rng));
        }

        // Get tags
        let mut tags: Vec<Tag> = Vec::new();
        for _idx in 0..1000 {
            // Get a random sender
            let sender_idx = rng.next_u32() as usize % 10;
            tags.push(senders[sender_idx].get_tag(
                "This is the message",
                "receiver",
                &server,
                &mut rng,
            ).0);
        }

        // Report tags
        for tag in tags {
            let result = server.report(&tag);
            assert!(result.is_ok());
        }

        assert!(!UNPROCESSED_REPORTED_TAGS.lock().unwrap().is_empty());

        // Update scores
        server.update_scores();

        assert!(UNPROCESSED_REPORTED_TAGS.lock().unwrap().is_empty());

        clear_sender_records();
    }

    #[test]
    fn update_score_test() {
        let current_score = 100;
        let reported_tag_count = 10;
        let maximum_score = 100;
        let score_threashold = 10;
        let new_score = AccountabilityServer::update_score(
            current_score,
            reported_tag_count,
            maximum_score,
            score_threashold,
        );
        // current - 10 + 10 = 100
        assert_eq!(new_score, 100);

        let current_score = 100;
        let reported_tag_count = 11;
        let maximum_score = 100;
        let score_threashold = 10;
        let new_score = AccountabilityServer::update_score(
            current_score,
            reported_tag_count,
            maximum_score,
            score_threashold,
        );
        // current - 11 + 10 = 99
        assert_eq!(new_score, 99);

        let current_score = -10;
        let reported_tag_count = 20;
        let maximum_score = 100;
        let score_threashold = 10;
        let new_score = AccountabilityServer::update_score(
            current_score,
            reported_tag_count,
            maximum_score,
            score_threashold,
        );
        // current - 20 + 10 = -20
        assert_eq!(new_score, -20);

        let current_score = 100;
        let reported_tag_count = 9;
        let maximum_score = 100;
        let score_threashold = 10;
        let new_score = AccountabilityServer::update_score(
            current_score,
            reported_tag_count,
            maximum_score,
            score_threashold,
        );
        // Reported tags do not reach threshold and score cannot grow
        assert_eq!(new_score, 100);

        let current_score = 90;
        let reported_tag_count = 9;
        let maximum_score = 100;
        let score_threashold = 10;
        let new_score = AccountabilityServer::update_score(
            current_score,
            reported_tag_count,
            maximum_score,
            score_threashold,
        );
        // Reported tags do not reach threshold and score can grow
        assert_eq!(new_score, 91);

        let current_score = -10;
        let reported_tag_count = 9;
        let maximum_score = 100;
        let score_threashold = 10;
        let new_score = AccountabilityServer::update_score(
            current_score,
            reported_tag_count,
            maximum_score,
            score_threashold,
        );
        // Reported tags do not reach threshold and score can grow
        assert_eq!(new_score, -9);
    }
}
