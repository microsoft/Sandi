use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    accountability_server::{AccSvrError, AccountabilityServer}, nizqdleq, sender_tag::{ReportTag, SenderTag}, tag::Tag, utils::{basepoint_order, G}
};

#[derive(Serialize, Deserialize)]
pub struct Sender {
    pub handle: String,
    pub epk: RistrettoPoint,
    esk: Scalar,
    channels: Vec<SenderChannel>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SenderChannel {
    pub receiver_addr: String,
    pub vks: RistrettoPoint,
    pub sks: Scalar,
}

#[derive(Debug)]
pub struct SenderError(pub String);

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

    pub fn get_channels(&self, receiver_addr: &str) -> Vec<&SenderChannel> {
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

        let vks_bytes = channel.vks.compress().to_bytes();
        match tag_res {
            Ok(tag) => {
                return self.get_tag_from_as_tag(tag, randomness_hr, randomness_vks, &vks_bytes, rng);
            }
            Err(AccSvrError(err_msg)) => Err(SenderError(err_msg)),
        }
    }

    pub fn get_tag_from_as_tag<R>(&self, tag: Tag, randomness_hr: [u8; 32], randomness_vks: [u8; 32], vks: &[u8], rng: &mut R) -> Result<SenderTag, SenderError>
    where 
        R: RngCore + CryptoRng,
    {
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

        let vks_res = CompressedRistretto::from_slice(vks);
        match vks_res {
            Ok(vks) => {
                let vsk_decompressed = vks.decompress();
                match vsk_decompressed {
                    Some(vks) => {
                        Ok(SenderTag {
                            report_tag,
                            randomness_hr,
                            randomness_vks,
                            vks
                        })
                    },
                    None => Err(SenderError("Failed to decompress vks".to_string())),
                }
            }
            Err(_) => Err(SenderError("Failed to decompress vks".to_string())),
        }
    }

    // Serialize the Sender object to a byte array
    pub fn to_bytes(&self) -> Vec<u8> {
        let result = serde_json::to_vec(self);
        result.unwrap()
    }

    // Deserialize a Sender object from a byte array
    pub fn from_slice(bytes: &[u8]) -> Result<Sender, SenderError> {
        let result = serde_json::from_slice(bytes);
        match result {
            Ok(sender) => Ok(sender),
            Err(err) => Err(SenderError(err.to_string())),
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

    #[test]
    fn serialization_test() {
        let mut rng = OsRng;
        let sender = Sender::new("Alice", &mut rng);
        let bytes = sender.to_bytes();
        let sender2 = Sender::from_slice(&bytes).unwrap();
        assert_eq!(sender.handle, sender2.handle);
        assert_eq!(sender.epk, sender2.epk);
        assert_eq!(sender.esk, sender2.esk);
        assert_eq!(sender.channels.len(), sender2.channels.len());
    }
}
