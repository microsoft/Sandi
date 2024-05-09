use crate::gaussian::{Gaussian, NoiseDistribution};
use crate::nizqdleq;
use crate::sender_records::{SenderRecord, SenderRecords, SenderId};
use crate::tag::Tag;
use crate::utils::{
    basepoint_order, concat_id_and_scalars, decrypt, encrypt,
    random_scalar, verify_signature, SignatureVerificationError, G,
};
use crate::epochs::get_start_of_day;
use chrono::Duration;
use curve25519_dalek::{RistrettoPoint, Scalar};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use rand_distr::Distribution;
use sha2::Sha512;

// Provides ability to manipulate time for testing purposes
pub(crate) trait TimeProvider {
    fn get_current_time(&self) -> i64;
}

pub struct AccountabilityServer {
    enc_secret_key: [u8; 32],
    signing_key: SigningKey,
    params: AccServerParams,
    pub(crate) sender_records: SenderRecords,
    time_provider: Box<dyn TimeProvider>,
}

pub struct AccServerParams {
    // Maximum score a sender can have
    pub maximum_score: f32,
    // Report threshold to affect score
    pub report_threashold: i32,
    // Timestamp of the epoch start
    pub epoch_start: i64,
    // Epoch duration in hours
    pub epoch_duration: usize,
    // Tag duration in epochs
    pub tag_duration: usize,
    // Optional function to compute score category
    pub compute_score: Option<fn(f32, f32) -> i8>,
    // Optional distribution for differential privacy
    pub noise_distribution: Option<Box<Gaussian>>,
}

// The default implementation will return the correct time
pub(crate) struct DefaultTimeProvider {}

// Default function for computing score
fn compute_score(sender_score: f32, max_score: f32) -> i8 {
    // We will have 5 categores: 0, 1, 2, 3, 4
    // 0: score <= max_score / 5
    // 1: score > max_score / 5 && score <= 2 * max_score / 5
    // 2: score > 2 * max_score / 5 && score <= 3 * max_score / 5
    // 3: score > 3 * max_score / 5 && score <= 4 * max_score / 5
    // 4: score > 4 * max_score / 5
    if sender_score < 0.0 {
        return 0;
    }

    let category = sender_score / (max_score / 5.0);
    if category < 1.0 {
        return 0;
    }
    if category < 2.0 {
        return 1;
    }
    if category < 3.0 {
        return 2;
    }
    if category < 4.0 {
        return 3;
    }

    return 4;
}

#[derive(Debug)]
pub struct AccSvrError(pub String);

impl AccountabilityServer {
    pub fn new<R>(params: AccServerParams, rng: &mut R) -> AccountabilityServer
    where
        R: RngCore + CryptoRng,
    {
        let tp = Box::new(DefaultTimeProvider {});
        AccountabilityServer::new_with_time_provider(params, rng, tp)
    }

    pub(crate) fn new_with_time_provider<R>(
        params: AccServerParams,
        rng: &mut R,
        time_provider: Box<dyn TimeProvider>,
    ) -> AccountabilityServer
    where
        R: RngCore + CryptoRng,
    {
        let mut enc_secret_key = [0u8; 32];
        rng.fill_bytes(&mut enc_secret_key);

        let signing_key = SigningKey::generate(rng);
        let sender_records = SenderRecords::new();

        // If noise distribution is provided, verify it is maxed at -1.0
        if let Some(dist) = params.noise_distribution.as_ref() {
            assert!(dist.max().is_some(), "Noise distribution must have a max value");
            assert!(dist.max().unwrap() == -1.0, "Noise distribution must be maxed at -1.0");
        }

        AccountabilityServer {
            enc_secret_key,
            signing_key,
            params,
            sender_records,
            time_provider,
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
                let mut sender =
                    SenderRecord::new(sender_handle, self.params.tag_duration, self.params.maximum_score, &mut rng);
                sender.epk = epk.clone();
                self.sender_records.set_sender(sender);
            }
        }
    }

    fn compute_score(&self, sender: &SenderRecord) -> i8 {
        match self.params.compute_score {
            Some(f) => f(sender.score, self.params.maximum_score),
            None => compute_score(sender.score, self.params.maximum_score),
        }
    }

    pub fn issue_tag<R>(
        &self,
        commitment_hr: &Vec<u8>,
        commitment_vks: &Vec<u8>,
        sender_handle: &str,
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

        // s is random scalar
        let s = random_scalar(rng);

        // G'
        let g_prime = s * G();

        // X
        let x_big = s * sender.epk;

        // n, r
        let mut n = [0u8; 8];
        rng.fill_bytes(&mut n);
        let r = random_scalar(rng);

        // Q
        let hashed_n = RistrettoPoint::hash_from_bytes::<Sha512>(&n);
        let q_big = r * hashed_n;

        // Then, we encrypt the sender ID, n and r
        let mut encrypted_sender_id = concat_id_and_scalars(&sender.id, &n, &r);
        encrypt(&self.enc_secret_key, &mut encrypted_sender_id);

        // Get expiration date for the tag
        // Compute as epoch duration in hours * tag duration in epochs
        let expiration_date = self.time_provider.get_current_time()
            + Duration::hours((self.params.tag_duration * self.params.epoch_duration) as i64)
                .num_seconds();

        // Compute score category
        let score = self.compute_score(&sender);

        // Then, we sign tag information
        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(&commitment_hr);
        data_to_sign.extend_from_slice(&commitment_vks);
        data_to_sign.extend_from_slice(expiration_date.to_be_bytes().as_slice());
        data_to_sign.extend_from_slice(score.to_be_bytes().as_slice());
        data_to_sign.extend_from_slice(&encrypted_sender_id);
        data_to_sign.extend_from_slice(basepoint_order().as_bytes()); // q
        data_to_sign.extend_from_slice(G().compress().as_bytes()); // G
        data_to_sign.extend_from_slice(q_big.compress().as_bytes()); // Q
        data_to_sign.extend_from_slice(g_prime.compress().as_bytes()); // G'
        data_to_sign.extend_from_slice(x_big.compress().as_bytes()); // X

        let signature = self.signing_key.sign(&data_to_sign);

        // Finally, we create the tag
        let tag = Tag {
            commitment_hr: commitment_hr.clone(),
            commitment_vks: commitment_vks.clone(),
            exp_timestamp: expiration_date,
            score: self.compute_score(&sender),
            enc_sender_id: encrypted_sender_id.to_vec(),
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
        let utc_now = self.time_provider.get_current_time();
        if tag.exp_timestamp < utc_now {
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
            &basepoint_order(),
            &tag.g_prime,
            &tag.x_big,
            &tag.q_big,
            &r_big,
            &proof,
        );
        if !nizqdleq_result {
            return Err(AccSvrError("Invalid NIZQDLEQ proof".to_string()));
        }

        // Sender Id + n + r
        let scalar_length = Scalar::ONE.as_bytes().len();
        if tag.enc_sender_id.len() != 8 + scalar_length + 8 {
            return Err(AccSvrError("Invalid sender id".to_string()));
        }

        let mut decrypted_sender_id = tag.enc_sender_id.clone();
        decrypt(&self.enc_secret_key, &mut decrypted_sender_id);
        // Order is: r | n | ID
        let mut sender_id = SenderId::default();
        sender_id.copy_from_slice(&decrypted_sender_id[40..48]);
        let mut n = [0u8; 8];
        n.copy_from_slice(&decrypted_sender_id[32..40]);
        let mut r_buff = [0u8; 32];
        r_buff.copy_from_slice(&decrypted_sender_id[0..32]);
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

                // Obtain the counter index for the tag.
                // The counter index is the number of epochs ago the tag was issued
                let issue_date = tag.exp_timestamp
                    - (self.params.epoch_duration as i64 * 3600 * self.params.tag_duration as i64);

                // We'll assume epochs start at the beginning of the day
                let epoch_start = get_start_of_day(utc_now);
                let mut start_period = epoch_start - self.params.tag_duration as i64 * 3600 * 24;
                let mut end_period = start_period + 3600 * 24;
                let mut counter_idx = self.params.tag_duration;
                for _ in 0..=self.params.tag_duration {
                    if issue_date >= start_period && issue_date <= end_period {
                        break;
                    }
                    start_period += 3600 * 24;
                    end_period += 3600 * 24;
                    counter_idx -= 1;
                }

                // Tag is valid, so we add it to the unprocessed tags
                sender.reported_tags.insert(tag.signature.clone(), tag);
                sender.tokens.push((n, sigma));
                sender.report_count[counter_idx] += 1;

                self.sender_records.set_sender(sender);
            }
            None => {
                return Err(AccSvrError("Sender not found".to_string()));
            }
        }

        Ok(())
    }

    fn update_score(
        current_score: f32,
        reported_tag_count: i32,
        maximum_score: f32,
        report_threashold: i32,
        b: f32,
    ) -> f32 {
        if reported_tag_count >= report_threashold {
            return current_score - (reported_tag_count - report_threashold) as f32;
        } else if reported_tag_count < report_threashold && current_score >= 0.0 {
            return (current_score + b).min(maximum_score);
        } else {
            assert!(reported_tag_count < report_threashold && current_score < 0.0);
            return (current_score - (reported_tag_count - report_threashold) as f32).min(0.0);
        }
    }

    pub fn update_scores<R>(&mut self, rng: &mut R)
    where R: RngCore + CryptoRng {
        self.sender_records.for_each(|sender| {
            let mut report_count = sender.report_count[0] as f32;
        
            // Add noise if necessary
            if let Some(dist) = self.params.noise_distribution.as_ref() {
                let noise = dist.sample(rng);
                report_count += noise;
            }

            sender.score = AccountabilityServer::update_score(
                sender.score,
                report_count as i32,
                self.params.maximum_score,
                self.params.report_threashold,
                sender.b_param,
            );

            // Shift all values to the left
            for i in 0..(sender.report_count.len() - 1) {
                sender.report_count[i] = sender.report_count[i + 1];
            }
            let rep_count = sender.report_count.len() - 1;
            sender.report_count[rep_count] = 0;

            // Get rid of expired tags
            let mut expired_tags: Vec<Vec<u8>> = Vec::new();
            for (signature, tag) in &sender.reported_tags {
                if tag.exp_timestamp < self.time_provider.get_current_time() {
                    expired_tags.push(signature.clone());
                }
            }
            for signature in expired_tags {
                sender.reported_tags.remove(&signature);
            }
        });
    }
}

impl TimeProvider for DefaultTimeProvider {
    fn get_current_time(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }
}

#[cfg(test)]
mod tests {
    use chrono::{NaiveDateTime, TimeZone, Utc};
    use curve25519_dalek::ristretto::CompressedRistretto;
    use hmac::{Hmac, Mac};
    use rand::Rng;
    use sha2::Sha256;

    use super::*;
    use crate::{sender::Sender, sender_tag::SenderTag};

    static mut MOCK_TIME: i64 = 0;

    struct MockTimeProvider {}

    impl TimeProvider for MockTimeProvider {
        fn get_current_time(&self) -> i64 {
            unsafe { MOCK_TIME }
        }
    }

    #[test]
    fn update_scores_test() {
        let mut rng = OsRng;
        let mut server = AccountabilityServer::new(
            AccServerParams {
                maximum_score: 1000.0,
                report_threashold: 10,
                epoch_duration: 24,
                tag_duration: 2,
                compute_score: None,
                noise_distribution: None,
            },
            &mut rng,
        );

        // Initialize senders
        let mut senders: Vec<Sender> = Vec::new();
        for i in 0..10 {
            let sender_handle = format!("sender{}", i);
            let sender = Sender::new(&sender_handle, &mut rng);
            server.set_sender_pk(&sender.epk, &sender_handle);
            senders.push(sender);
        }

        // Get tags
        let mut tags: Vec<SenderTag> = Vec::new();
        for idx in 0..1000 {
            // Get a random sender
            let sender_idx = idx as usize % 10;
            tags.push(
                senders[sender_idx]
                    .get_tag("receiver", &server, &mut rng)
                    .unwrap(),
            );
        }

        // Before the report the count should be 0
        for sender in &server.sender_records.records {
            assert_eq!(sender.1.report_count[0], 0);
            assert_eq!(sender.1.reported_tags.len(), 0);
            assert_eq!(sender.1.tokens.len(), 0);
        }

        // Report tags
        for tag in tags {
            let result = server.report(tag.tag, tag.proof, tag.r_big);
            assert!(result.is_ok(), "{:?}", result.unwrap_err());
        }

        // After the report the count should be 100
        for sender in &server.sender_records.records {
            assert_eq!(sender.1.report_count[0], 100);
            assert_eq!(sender.1.reported_tags.len(), 100);
            assert_eq!(sender.1.tokens.len(), 100);
        }

        // Update scores
        server.update_scores(&mut rng);

        // After updateing scores the count should be 0 again
        for sender in &server.sender_records.records {
            assert_eq!(sender.1.report_count[0], 0);
            assert_eq!(sender.1.reported_tags.len(), 100);
            assert_eq!(sender.1.tokens.len(), 100);
        }
    }

    #[test]
    fn update_score_test() {
        let current_score = 100.0;
        let reported_tag_count = 10;
        let maximum_score = 100.0;
        let score_threashold = 10;
        let new_score = AccountabilityServer::update_score(
            current_score,
            reported_tag_count,
            maximum_score,
            score_threashold,
            1.0,
        );
        // current - 10 + 10 = 100
        assert_eq!(new_score, 100.0);

        let current_score = 100.0;
        let reported_tag_count = 11;
        let maximum_score = 100.0;
        let score_threashold = 10;
        let new_score = AccountabilityServer::update_score(
            current_score,
            reported_tag_count,
            maximum_score,
            score_threashold,
            1.0,
        );
        // current - 11 + 10 = 99
        assert_eq!(new_score, 99.0);

        let current_score = -10.0;
        let reported_tag_count = 20;
        let maximum_score = 100.0;
        let score_threashold = 10;
        let new_score = AccountabilityServer::update_score(
            current_score,
            reported_tag_count,
            maximum_score,
            score_threashold,
            1.0,
        );
        // current - 20 + 10 = -20
        assert_eq!(new_score, -20.0);

        let current_score = 100.0;
        let reported_tag_count = 9;
        let maximum_score = 100.0;
        let score_threashold = 10;
        let new_score = AccountabilityServer::update_score(
            current_score,
            reported_tag_count,
            maximum_score,
            score_threashold,
            1.0,
        );
        // Reported tags do not reach threshold and score cannot grow
        assert_eq!(new_score, 100.0);

        let current_score = 90.0;
        let reported_tag_count = 9;
        let maximum_score = 100.0;
        let score_threashold = 10;
        let new_score = AccountabilityServer::update_score(
            current_score,
            reported_tag_count,
            maximum_score,
            score_threashold,
            1.0,
        );
        // Reported tags do not reach threshold and score can grow
        assert_eq!(new_score, 91.0);

        let current_score = -10.0;
        let reported_tag_count = 9;
        let maximum_score = 100.0;
        let score_threashold = 10;
        let new_score = AccountabilityServer::update_score(
            current_score,
            reported_tag_count,
            maximum_score,
            score_threashold,
            1.0,
        );
        // Reported tags do not reach threshold and score can grow
        assert_eq!(new_score, -9.0);
    }

    #[test]
    fn issue_tag_test() {
        let mut rng = OsRng;
        let mut accsvr = AccountabilityServer::new(
            AccServerParams {
                maximum_score: 100.0,
                report_threashold: 10,
                epoch_duration: 24,
                tag_duration: 2,
                compute_score: None,
                noise_distribution: None,
            },
            &mut rng,
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(&[0u8; 32]).unwrap();
        mac.update("receiver".as_bytes());
        let commitment_hr = mac.finalize();

        let mut mac = Hmac::<Sha256>::new_from_slice(&[1u8; 32]).unwrap();
        let vks = CompressedRistretto::from_slice(&[2u8; 32]).unwrap().decompress().unwrap();
        mac.update(vks.compress().as_bytes());
        let commitment_vks = mac.finalize();

        let sender = Sender::new("sender1", &mut rng);
        accsvr.set_sender_pk(&sender.epk, &sender.handle);

        let tag_res = accsvr.issue_tag(&commitment_hr.into_bytes().to_vec(), &commitment_vks.into_bytes().to_vec(), &sender.handle, &mut rng);
        assert!(tag_res.is_ok());

        let tag = tag_res.unwrap();

        let binary: heapless::Vec<u8, 350> = postcard::to_vec(&tag).unwrap();
        assert_eq!(binary.len(), 282);
    }

    #[test]
    fn expiration_date_test() {
        let tag_duration = 2;
        let epoch_duration = 24;
        let tag_hours = tag_duration * epoch_duration;
        let seconds = Duration::hours(tag_hours).num_seconds();

        // Get expiration date for the tag
        // Compute as epoch duration in hours * tag duration in epochs
        let dt = Utc.from_utc_datetime(
            &NaiveDateTime::parse_from_str("2015-09-05 14:00:00", "%Y-%m-%d %H:%M:%S").unwrap(),
        );
        let expiration_date = dt.timestamp() + seconds;
        let edt = Utc.from_utc_datetime(
            &NaiveDateTime::parse_from_str("2015-09-07 14:00:00", "%Y-%m-%d %H:%M:%S").unwrap(),
        );
        assert_eq!(expiration_date, edt.timestamp());
    }

    #[test]
    fn compute_score_with_epochs_test() {
        let mut rng = OsRng;
        let time_provider = Box::new(MockTimeProvider {});

        let mut acc_svr = AccountabilityServer::new_with_time_provider(
            AccServerParams {
                maximum_score: 100.0,
                report_threashold: 10,
                epoch_duration: 24,
                tag_duration: 2,
                compute_score: None,
                noise_distribution: None,
            },
            &mut rng,
            time_provider,
        );

        let sender = Sender::new("sender1", &mut rng);
        acc_svr.set_sender_pk(&sender.epk, &sender.handle);

        // Get tags
        let mut tags: Vec<SenderTag> = Vec::new();

        // UTC now will be the timestamp of a specific UTC date
        let utc_now = Utc
            .from_utc_datetime(
                &NaiveDateTime::parse_from_str("2015-09-07 14:30:00", "%Y-%m-%d %H:%M:%S").unwrap(),
            )
            .timestamp();

        // Starting range is 3 days ago
        let starting_range = utc_now - 3 * 24 * 3600;
        // Ending range is now minus 10 minutes
        let ending_range = utc_now;

        // Generate tags with random timestamps
        for _ in 0..1000 {
            let timestamp = rng.gen_range(starting_range..ending_range);
            unsafe { MOCK_TIME = timestamp };
            tags.push(
                sender
                    .get_tag("receiver", &acc_svr, &mut rng)
                    .unwrap(),
            );
        }

        // Report tags. Time should be the correct one noe
        unsafe { MOCK_TIME = utc_now };
        let mut expired_tags = 0;
        for tag in tags {
            let result = acc_svr.report(tag.tag, tag.proof, tag.r_big);
            match result {
                Ok(_) => {}
                Err(AccSvrError(err_msg)) => {
                    if err_msg != "Tag is expired" {
                        panic!("Error reporting tag: {}", err_msg);
                    }
                    expired_tags += 1;
                }
            }
        }

        // After the report each count should be at least bigger than zero
        println!("Expired tags: {}", expired_tags);
        for sender in &acc_svr.sender_records.records {
            for i in 0..sender.1.report_count.len() {
                println!("Report count: {}", sender.1.report_count[i]);
                assert!(sender.1.report_count[i] > 0);
            }
        }
    }

    #[test]
    fn compute_score_category_test()
    {
        let score = compute_score(0.0, 100.0);
        assert_eq!(score, 0);

        let score = compute_score(19.0, 100.0);
        assert_eq!(score, 0);

        let score = compute_score(20.0, 100.0);
        assert_eq!(score, 1);

        let score = compute_score(39.0, 100.0);
        assert_eq!(score, 1);

        let score = compute_score(40.0, 100.0);
        assert_eq!(score, 2);

        let score = compute_score(59.0, 100.0);
        assert_eq!(score, 2);

        let score = compute_score(60.0, 100.0);
        assert_eq!(score, 3);

        let score = compute_score(79.0, 100.0);
        assert_eq!(score, 3);

        let score = compute_score(80.0, 100.0);
        assert_eq!(score, 4);

        let score = compute_score(99.0, 100.0);
        assert_eq!(score, 4);

        let score = compute_score(100.0, 100.0);
        assert_eq!(score, 4);

        let score = compute_score(-10.0, 100.0);
        assert_eq!(score, 0);
    }

    #[test]
    fn custom_score_function_test() {
        let params = AccServerParams {
            maximum_score: 100.0,
            report_threashold: 10,
            epoch_duration: 24,
            tag_duration: 2,
            compute_score: Some(|score, _| {
                if score < 0.0 {
                    return 0;
                }
                if score < 50.0 {
                    return 1;
                }
                if score < 100.0 {
                    return 2;
                }
                return 3;
            }),
            noise_distribution: None,
        };

        let score = params.compute_score.unwrap()(0.0, 100.0);
        assert_eq!(score, 1);

        let score = params.compute_score.unwrap()(49.0, 100.0);
        assert_eq!(score, 1);

        let score = params.compute_score.unwrap()(50.0, 100.0);
        assert_eq!(score, 2);

        let score = params.compute_score.unwrap()(99.0, 100.0);
        assert_eq!(score, 2);

        let score = params.compute_score.unwrap()(100.0, 100.0);
        assert_eq!(score, 3);
    }

    #[test]
    #[should_panic]
    fn invalid_noise_distribution_nomax_test() {
        let params = AccServerParams {
            maximum_score: 100.0,
            report_threashold: 10,
            epoch_duration: 24,
            tag_duration: 2,
            compute_score: None,
            noise_distribution: Some(Box::new(Gaussian::new(0.0, 1.0).unwrap())),
        };

        let mut rng = OsRng;

        let _ = AccountabilityServer::new(
            params,
            &mut rng,
        );
    }

    #[test]
    #[should_panic]
    fn invalid_noise_distribution_maxnotminusone_test() {
        let params = AccServerParams {
            maximum_score: 100.0,
            report_threashold: 10,
            epoch_duration: 24,
            tag_duration: 2,
            compute_score: None,
            noise_distribution: Some(Box::new(Gaussian::new_max(0.0, 1.0, 0.0).unwrap())),
        };

        let mut rng = OsRng;

        let _ = AccountabilityServer::new(
            params,
            &mut rng,
        );
    }

    #[test]
    fn valid_noise_distribution_test() {
        let params = AccServerParams {
            maximum_score: 100.0,
            report_threashold: 10,
            epoch_duration: 24,
            tag_duration: 2,
            compute_score: None,
            noise_distribution: Some(Box::new(Gaussian::new_max(0.0, 1.0, -1.0).unwrap())),
        };

        let mut rng = OsRng;

        let _ = AccountabilityServer::new(
            params,
            &mut rng,
        );
    }
}
