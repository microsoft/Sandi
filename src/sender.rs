use curve25519_dalek::{RistrettoPoint, Scalar};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::{
    accountability_server::{AccSvrError, AccountabilityServer},
    nizqdleq,
    sender_tag::{ReportTag, SenderTag},
    utils::{basepoint_order, G},
};

pub struct Sender {
    pub handle: String,
    pub epk: RistrettoPoint,
    esk: Scalar,
    channels: Vec<SenderChannel>,
}

#[derive(Clone)]
pub struct SenderChannel {
    pub receiver_addr: String,
    pub vks: RistrettoPoint,
    pub sks: Scalar,
}

#[derive(Debug)]
pub struct SenderError(String);

impl Sender {
    pub fn new<R>(handle: &str, rng: &mut R) -> Sender
    where
        R: CryptoRng + RngCore,
    {
        let (epk, esk) = Sender::generate_keypair(rng);

        Sender {
            handle: handle.to_owned(),
            esk,
            epk,
            channels: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn get_channels(&self, receiver_addr: &str) -> Vec<&SenderChannel> {
        let mut channels = Vec::new();

        for channel in &self.channels {
            if channel.receiver_addr == receiver_addr {
                channels.push(channel);
            }
        }

        channels
    }

    pub fn add_channel<R>(&mut self, receiver_addr: &str, rng: &mut R) -> SenderChannel
    where
        R: CryptoRng + RngCore,
    {
        let (vks, sks) = Sender::generate_keypair(rng);

        let channel = SenderChannel {
            receiver_addr: receiver_addr.to_owned(),
            vks,
            sks,
        };

        self.channels.push(channel.clone());
        channel
    }

    pub fn generate_new_epoch_keys<R>(&mut self, rng: &mut R)
    where
        R: CryptoRng + RngCore,
    {
        let (epk, esk) = Sender::generate_keypair(rng);

        self.epk = epk;
        self.esk = esk;
    }

    fn generate_keypair<R>(rng: &mut R) -> (RistrettoPoint, Scalar)
    where
        R: CryptoRng + RngCore,
    {
        let mut sk_buff = [0u8; 32];
        rng.fill_bytes(&mut sk_buff);
        let sk = Scalar::from_bytes_mod_order(sk_buff);
        let pk = G() * sk;

        (pk, sk)
    }

    pub fn get_tag<R>(
        &self,
        channel: &SenderChannel,
        accountability_server: &mut AccountabilityServer,
        rng: &mut R,
    ) -> Result<SenderTag, SenderError>
    where
        R: RngCore + CryptoRng,
    {
        let mut randomness_hr = [0u8; 32];
        rng.fill_bytes(&mut randomness_hr);
        let mut mac = Hmac::<Sha256>::new_from_slice(&randomness_hr).unwrap();
        mac.update(channel.receiver_addr.as_bytes());
        let commitment_hr = mac.finalize();

        let mut randomness_vks = [0u8; 32];
        rng.fill_bytes(&mut randomness_vks);
        let mut mac = Hmac::<Sha256>::new_from_slice(&randomness_vks).unwrap();
        mac.update(channel.vks.compress().as_bytes());
        let commitment_vks = mac.finalize();

        let tag_res =
            accountability_server.issue_tag(&commitment_hr.into_bytes().to_vec(), &commitment_vks.into_bytes().to_vec(), &self.handle, rng);

        match tag_res {
            Ok(tag) => {
                // Check if X is valid
                let new_x = self.esk * tag.g_prime;
                if new_x != tag.x_big {
                    return Err(SenderError("Invalid tag: X does not match".to_string()));
                }
                let r_big = self.esk * tag.q_big;
                let z = nizqdleq::prove(
                    &basepoint_order(),
                    &tag.g_prime,
                    &tag.x_big,
                    &tag.q_big,
                    &r_big,
                    &self.esk,
                    rng,
                );

                let report_tag = ReportTag {
                    tag,
                    proof: z,
                    r_big,
                };

                Ok(SenderTag {
                    report_tag,
                    randomness_hr,
                    randomness_vks,
                    vks: channel.vks,
                })
            }
            Err(AccSvrError(err_msg)) => Err(SenderError(err_msg)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountability_server::{AccServerParams, AccountabilityServer};
    use rand::rngs::OsRng;

    #[test]
    fn get_tag_test() {
        let mut rng = OsRng;
        let mut accsvr = AccountabilityServer::new(
            AccServerParams {
                maximum_score: 100.0,
                report_threshold: 10,
                epoch_start: 0,
                epoch_duration: 24,
                tag_duration: 2,
                max_vks_per_epoch: 5,
                compute_reputation: None,
                noise_distribution: None,
            },
            &mut rng,
        );
        let mut sender = Sender::new("Alice", &mut rng);
        let set_pk_result = accsvr.set_sender_epk(&sender.epk, &sender.handle);
        assert!(set_pk_result.is_ok(), "{}", set_pk_result.unwrap_err().0);

        let channel = sender.add_channel("Bob", &mut rng);

        let tag_opt = sender.get_tag(&channel, &mut accsvr, &mut rng);
        assert!(tag_opt.is_ok());

        let _tag = tag_opt.unwrap();
    }
}
