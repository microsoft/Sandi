#![allow(deprecated)]
use aes::{
    cipher::{
        generic_array::GenericArray, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit,
        KeySizeUser,
    },
    Aes256,
};
use curve25519_dalek::{
    constants::{BASEPOINT_ORDER, RISTRETTO_BASEPOINT_POINT},
    RistrettoPoint, Scalar,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use rand::{CryptoRng, RngCore};
use rand_chacha::rand_core::OsRng;

use crate::{sender_records::SenderId, tag::Tag};

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
    R: RngCore + CryptoRng, {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    RistrettoPoint::hash_from_bytes::<sha2::Sha512>(&bytes)
}

pub fn encrypt(key: &[u8], message: &mut [u8]) {
    if key.len() != Aes256::key_size() {
        panic!("Key size is not {} bytes", Aes256::key_size());
    }
    if (message.len() % Aes256::block_size()) != 0 {
        panic!(
            "Message size is not a multiple of {} bytes",
            Aes256::block_size()
        );
    }

    let cipher = Aes256::new_from_slice(key).unwrap();
    for block in message.chunks_mut(Aes256::block_size()) {
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
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

    let cipher = Aes256::new_from_slice(key).unwrap();
    for block in ciphertext.chunks_mut(Aes256::block_size()) {
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
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
    data_to_sign.extend_from_slice(tag.basepoint_order.as_bytes());
    data_to_sign.extend_from_slice(tag.basepoint.compress().as_bytes());
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
        .map_err(|_| "Invalid verifying key".to_string())?;

    let verifying_key =
        VerifyingKey::from_bytes(&vkbytes).map_err(|_| "Invalid verifying key".to_string())?;

    Ok(verifying_key)
}

pub fn concat_id_and_scalars(id: &SenderId, s1: &Scalar, s2: &Scalar) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(id);
    result.extend_from_slice(s1.as_bytes());
    result.extend_from_slice(s2.as_bytes());
    result
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
            0x0f, 0x01,
        ];
        let mut message2 = [0x0u8; 16];
        // Copy the clear text message into message2
        message2.copy_from_slice(&message);

        encrypt(&key, message.as_mut());
        // message is now encrypted
        assert_ne!(message, message2);

        decrypt(&key, message.as_mut());
        // message is now decrypted
        assert_eq!(message, message2);
    }

    #[test]
    fn test_encrypt_multiblock() {
        let key = [0u8; 32];
        let mut message = [
            0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x00, 0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x00,
        ];
        let mut message2 = [0x0u8; 32];
        // Copy the clear text message into message2
        message2.copy_from_slice(&message);

        encrypt(&key, message.as_mut());
        // message is now encrypted
        assert_ne!(message, message2);

        decrypt(&key, message.as_mut());
        // message is now decrypted
        assert_eq!(message, message2);
    }

    #[test]
    fn test_concat_id() {
        let id = [0u8; 16];
        let s1 = Scalar::from_bytes_mod_order([1u8; 32]);
        let s2 = Scalar::from_bytes_mod_order([2u8; 32]);
        let result = concat_id_and_scalars(&id, &s1, &s2);
        assert_eq!(result.len(), 80);
        assert_eq!(result[..16], id);
        assert_eq!(result[16..48].to_vec(), s1.as_bytes().to_vec());
        assert_eq!(result[48..80].to_vec(), s2.as_bytes().to_vec());
        assert!(result.len() % cipher_block_size() == 0);
    }
}
