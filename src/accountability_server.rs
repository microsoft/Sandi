use crate::nizqdleq;
use crate::sender_records::{SenderRecord, SenderRecords};
use crate::tag::Tag;
use crate::utils::{
    basepoint_order, cipher_block_size, concat_id_and_scalars, decrypt, encrypt, random_scalar,
    verify_signature, SignatureVerificationError, G,
};
use chrono::{Duration, Utc};
use curve25519_dalek::{RistrettoPoint, Scalar};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use std::cmp;

pub struct AccountabilityServer {
    enc_secret_key: [u8; 32],
    signing_key: SigningKey,
    maximum_score: i32,
    reputation_threashold: i32,
    pub(crate) sender_records: SenderRecords,
}

#[derive(Debug)]
pub struct AccSvrError(pub String);

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
        let sender_records = SenderRecords::new();

        AccountabilityServer {
            enc_secret_key,
            signing_key,
            maximum_score,
            reputation_threashold,
            sender_records,
        }
    }

    pub fn set_sender_pk(&mut self, epk: &RistrettoPoint, sender_handle: &str) {
        let sender_opt = self.sender_records.get_sender_by_handle(sender_handle);
        match sender_opt {
            Some(mut sender) => {
                sender.epk = epk.clone();
                self.sender_records.set_sender(sender);
            }
            None => {
                let mut rng = OsRng;
                let mut sender = SenderRecord::new(sender_handle, &mut rng);
                sender.epk = epk.clone();
                self.sender_records.set_sender(sender);
            }
        }
    }

    pub fn issue_tag<R>(
        &self,
        commitment: &Vec<u8>,
        sender_handle: &str,
        tag_duration: u32,
        rng: &mut R,
    ) -> Result<Tag, AccSvrError>
    where
        R: RngCore + CryptoRng,
    {
        // First, we need to check if the sender_handle is valid
        let sender_opt = self.sender_records.get_sender_by_handle(sender_handle);
        if sender_opt.is_none() {
            return Err(AccSvrError("Sender not found".to_string()));
        }
        let sender = sender_opt.unwrap();

        // Check sender id size
        if sender.id.len() % cipher_block_size() != 0 {
            return Err(AccSvrError(format!(
                "Sender id size is not a multiple of {} bytes",
                cipher_block_size()
            )));
        }

        // s is random scalar
        let s = random_scalar(rng);

        // G'
        let g_prime = s * G();

        // X
        let x_big = s * sender.epk;

        // n, r
        let n = random_scalar(rng);
        let r = random_scalar(rng);

        // Q
        let hashed_n = RistrettoPoint::hash_from_bytes::<Sha512>(n.as_bytes());
        let q_big = r * hashed_n;

        // Then, we encrypt the sender ID, n and r
        let mut encrypted_sender_id = concat_id_and_scalars(&sender.id, &n, &r);
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
        data_to_sign.extend_from_slice(basepoint_order().as_bytes()); // q
        data_to_sign.extend_from_slice(G().compress().as_bytes()); // G
        data_to_sign.extend_from_slice(q_big.compress().as_bytes()); // Q
        data_to_sign.extend_from_slice(g_prime.compress().as_bytes()); // G'
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
            g_prime,
            x_big,
            signature: signature.to_vec(),
        };

        Ok(tag)
    }

    pub fn get_verifying_key(&self) -> Vec<u8> {
        let vk = self.signing_key.verifying_key();
        vk.to_bytes().to_vec()
    }

    pub fn report(
        &mut self,
        tag: Tag,
        proof: (Scalar, Scalar),
        r_big: RistrettoPoint,
    ) -> Result<(), AccSvrError> {
        // Check if tag is expired
        if tag.exp_timestamp < Utc::now().timestamp() {
            return Err(AccSvrError("Tag is expired".to_string()));
        }

        // Verify tag signature
        let verifying_key = self.signing_key.verifying_key();
        let signature_result = verify_signature(&tag, &verifying_key);
        match signature_result {
            Ok(_) => {}
            Err(SignatureVerificationError(err_msg)) => {
                return Err(AccSvrError(format!(
                    "Error verifying signature: {}",
                    err_msg
                )));
            }
        }

        // Verify NIZQDLEQ
        let nizqdleq_result = nizqdleq::verify(
            &tag.basepoint_order,
            &tag.g_prime,
            &proof,
            &tag.x_big,
            &tag.q_big,
            &r_big,
        );
        if !nizqdleq_result {
            return Err(AccSvrError("Invalid NIZQDLEQ proof".to_string()));
        }

        // Sender Id + n + r
        let scalar_length = Scalar::ONE.as_bytes().len();
        if tag.enc_sender_id.len() != 16 + 2 * scalar_length {
            return Err(AccSvrError("Invalid sender id".to_string()));
        }

        let mut decrypted_sender_id = tag.enc_sender_id.clone();
        decrypt(&self.enc_secret_key, &mut decrypted_sender_id);
        let mut sender_id = [0u8; 16];
        sender_id.copy_from_slice(&decrypted_sender_id[..16]);
        let mut n_buff = [0u8; 32];
        n_buff.copy_from_slice(&decrypted_sender_id[16..48]);
        let n = Scalar::from_canonical_bytes(n_buff).unwrap();
        let mut r_buff = [0u8; 32];
        r_buff.copy_from_slice(&decrypted_sender_id[48..]);
        let r = Scalar::from_canonical_bytes(r_buff).unwrap();
        let inv_r = r.invert();

        let sigma = inv_r * r_big;

        let sender_opt = self.sender_records.get_sender_by_id(&sender_id);
        match sender_opt {
            Some(mut sender) => {
                if sender.reported_tags.contains_key(&tag.signature) {
                    // Tag is already reported, no need to do anything
                    return Ok(());
                }

                // Tag is valid, so we add it to the unprocessed tags
                sender.reported_tags.insert(tag.signature.clone(), tag);
                sender.tokens.push((n, sigma));
                sender.report_count += 1;

                self.sender_records.set_sender(sender);
            }
            None => {
                return Err(AccSvrError("Sender not found".to_string()));
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

    pub fn update_scores(&mut self) {
        self.sender_records.for_each(|sender| {
            sender.score = AccountabilityServer::update_score(
                sender.score,
                sender.report_count,
                self.maximum_score,
                self.reputation_threashold,
            );

            sender.report_count = 0;

            // Get rid of expired tags
            let mut expired_tags: Vec<Vec<u8>> = Vec::new();
            for (signature, tag) in &sender.reported_tags {
                if tag.exp_timestamp < Utc::now().timestamp() {
                    expired_tags.push(signature.clone());
                }
            }
            for signature in expired_tags {
                sender.reported_tags.remove(&signature);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sender::Sender;

    #[test]
    fn update_scores_test() {
        let mut rng = OsRng;
        let mut server = AccountabilityServer::new(1000, 10, &mut rng);

        // Initialize senders
        let mut senders: Vec<Sender> = Vec::new();
        for i in 0..10 {
            let sender_handle = format!("sender{}", i);
            let sender = Sender::new(&sender_handle, &mut rng);
            server.set_sender_pk(&sender.epk, &sender_handle);
            senders.push(sender);
        }

        // Get tags
        let mut tags: Vec<(Tag, Vec<u8>, (Scalar, Scalar), RistrettoPoint)> = Vec::new();
        for idx in 0..1000 {
            // Get a random sender
            let sender_idx = idx as usize % 10;
            tags.push(
                senders[sender_idx]
                    .get_tag("This is the message", "receiver", &server, &mut rng)
                    .unwrap(),
            );
        }

        // Before the report the count should be 0
        for sender in &server.sender_records.records {
            assert_eq!(sender.1.report_count, 0);
            assert_eq!(sender.1.reported_tags.len(), 0);
            assert_eq!(sender.1.tokens.len(), 0);
        }

        // Report tags
        for tag in tags {
            let result = server.report(tag.0, tag.2, tag.3);
            assert!(result.is_ok(), "{:?}", result.unwrap_err());
        }

        // After the report the count should be 100
        for sender in &server.sender_records.records {
            assert_eq!(sender.1.report_count, 100);
            assert_eq!(sender.1.reported_tags.len(), 100);
            assert_eq!(sender.1.tokens.len(), 100);
        }

        // Update scores
        server.update_scores();

        // After updateing scores the count should be 0 again
        for sender in &server.sender_records.records {
            assert_eq!(sender.1.report_count, 0);
            assert_eq!(sender.1.reported_tags.len(), 100);
            assert_eq!(sender.1.tokens.len(), 100);
        }
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
