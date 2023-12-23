#![allow(deprecated)]
use std::array::TryFromSliceError;

use crate::{sender_records::SenderId, tag::Tag};
use aes::{
    cipher::{
        generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyIvInit,
        KeySizeUser,
    },
    Aes256,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use curve25519_dalek::{
    constants::{BASEPOINT_ORDER, RISTRETTO_BASEPOINT_POINT},
    RistrettoPoint, Scalar,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use rand::{CryptoRng, RngCore};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub fn random_scalar<R>(rng: &mut R) -> Scalar
where
    R: RngCore + CryptoRng,
{
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}

#[allow(non_snake_case)]
pub fn G() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

pub fn basepoint_order() -> Scalar {
    BASEPOINT_ORDER
}

pub fn random_point<R>(rng: &mut R) -> RistrettoPoint
where
    R: RngCore + CryptoRng,
{
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    RistrettoPoint::hash_from_bytes::<sha2::Sha512>(&bytes)
}

pub fn encrypt(key: &[u8], message: &mut [u8])
{
    if key.len() != Aes256::key_size() {
        panic!("Key size is not {} bytes", Aes256::key_size());
    }
    if (message.len() % Aes256::block_size()) != 0 {
        panic!(
            "Message size is not a multiple of {} bytes",
            Aes256::block_size()
        );
    }
    if message.len() <= Aes256::block_size() {
        panic!(
            "Message size is not greater than {} bytes",
            Aes256::block_size()
        );
    }

    let msg_length = message.len() - Aes256::block_size();

    // Get a message slice that does not include the last block
    let enc_message = &mut message[..msg_length];

    // IV will always be zero
    let iv = [0u8; 16];

    let mut cipher = Aes256CbcEnc::new_from_slices(key, &iv).unwrap();

    for block in enc_message.chunks_mut(Aes256::block_size()) {
        cipher.encrypt_block_mut(GenericArray::from_mut_slice(block));
    }
}

pub fn decrypt(key: &[u8], ciphertext: &mut [u8]) {
    if key.len() != Aes256::key_size() {
        panic!("Key size is not {} bytes", Aes256::key_size());
    }
    if (ciphertext.len() % Aes256::block_size()) != 0 {
        panic!(
            "Ciphertext size is not a multiple of {} bytes",
            Aes256::block_size()
        );
    }
    if ciphertext.len() <= Aes256::block_size() {
        panic!(
            "Ciphertext size is not greater than {} bytes",
            Aes256::block_size()
        );
    }

    let iv = [ 0u8; 16 ];
    let mut cipher = Aes256CbcDec::new_from_slices(key, &iv).unwrap();

    for block in ciphertext.chunks_mut(Aes256::block_size()) {
        cipher.decrypt_block_mut(GenericArray::from_mut_slice(block));
    }
}

pub fn cipher_block_size() -> usize {
    Aes256::block_size()
}

pub struct SignatureVerificationError(pub String);

pub fn verify_signature(
    tag: &Tag,
    verifying_key: &VerifyingKey,
) -> Result<(), SignatureVerificationError> {
    // Verify if signature is valid
    let mut data_to_sign = Vec::new();
    data_to_sign.extend_from_slice(&tag.commitment);
    data_to_sign.extend_from_slice(tag.exp_timestamp.to_be_bytes().as_slice());
    data_to_sign.extend_from_slice(tag.score.to_be_bytes().as_slice());
    data_to_sign.extend_from_slice(&tag.enc_sender_id);
    data_to_sign.extend_from_slice(basepoint_order().as_bytes());
    data_to_sign.extend_from_slice(G().compress().as_bytes());
    data_to_sign.extend_from_slice(tag.q_big.compress().as_bytes());
    data_to_sign.extend_from_slice(tag.g_prime.compress().as_bytes());
    data_to_sign.extend_from_slice(tag.x_big.compress().as_bytes());

    let sigbytes: [u8; 64] = tag.signature[..64]
        .try_into()
        .map_err(|_| SignatureVerificationError("Invalid signature".to_string()))?;

    let signature = Signature::from_bytes(&sigbytes);

    verifying_key
        .verify(&data_to_sign, &signature)
        .map_err(|_| SignatureVerificationError("Invalid signature".to_string()))?;

    Ok(())
}

pub fn verifying_key_from_vec(vk: &Vec<u8>) -> Result<VerifyingKey, String> {
    if vk.len() != PUBLIC_KEY_LENGTH {
        return Err(format!(
            "Verifying key size is not {} bytes",
            PUBLIC_KEY_LENGTH
        ));
    }

    let vkbytes: [u8; PUBLIC_KEY_LENGTH] = vk[..PUBLIC_KEY_LENGTH]
        .try_into()
        .map_err(|e: TryFromSliceError| format!("Invalid verifying key: {}", e.to_string()))?;

    let verifying_key =
        VerifyingKey::from_bytes(&vkbytes).map_err(|_| "Invalid verifying key".to_string())?;

    Ok(verifying_key)
}

pub fn concat_id_and_scalars(id: &SenderId, n: &[u8; 8], r: &Scalar) -> Vec<u8> {
    // Order will be: r | n | ID
    let mut result = Vec::new();
    result.extend_from_slice(r.as_bytes());
    result.extend_from_slice(n);
    result.extend_from_slice(id);
    result
}

pub fn get_start_of_day(timestamp: i64) -> i64 {
    // Get UTC DateTimne frin timestamp
    let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(timestamp, 0), Utc);

    // Get start of day
    let date_part = dt.naive_utc();
    let start_of_day = date_part.date().and_hms(0, 0, 0).and_utc();
    start_of_day.timestamp()
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn test_random_scalar() {
        let mut rng = OsRng;
        let scalar1 = random_scalar(&mut rng);
        let scalar2 = random_scalar(&mut rng);
        assert_ne!(scalar1, scalar2);
    }

    #[test]
    fn test_encrypt() {
        let key = [0u8; 32];
        let mut message = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x01, 0x03, 0x04,
        ];
        let mut message2 = [0x0u8; 32];
        // Copy the clear text message into message2
        message2.copy_from_slice(&message);

        encrypt(&key, message.as_mut());
        // message is now encrypted
        assert_ne!(message, message2);

        decrypt(&key, message.as_mut());

        // message is now decrypted. Compare only the first 16 bytes
        assert_eq!(message[..16], message2[..16]);
    }

    #[test]
    fn test_encrypt_multiblock() {
        let key = [0u8; 32];
        let mut message = [
            0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x00, 0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0f, 0x00, 0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0f, 0x00, 0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0f, 0x00, 0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06,
        ];
        let mut message2 = [0x0u8; 64];
        // Copy the clear text message into message2
        message2.copy_from_slice(&message);

        encrypt(&key, message.as_mut());
        // message is now encrypted. Compare only the first 48 bytes
        assert_ne!(message[..48], message2[..48]);

        decrypt(&key, message.as_mut());
        // message is now decrypted. Compare only the first 48 bytes
        assert_eq!(message[..48], message2[..48]);
    }

    #[test]
    fn test_concat_id() {
        let id = SenderId::default();
        let n = [1u8; 8];
        let r = Scalar::from_bytes_mod_order([2u8; 32]);
        let result = concat_id_and_scalars(&id, &n, &r);
        assert_eq!(result.len(), 48);
        // r
        assert_eq!(result[..32].to_vec(), r.as_bytes().to_vec());
        // n
        assert_eq!(result[32..40], n);
        // id
        assert_eq!(result[40..48], id);
        assert!(result.len() % cipher_block_size() == 0);
    }
}
