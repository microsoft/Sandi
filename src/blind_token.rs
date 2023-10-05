use curve25519_dalek::{Scalar, RistrettoPoint};
use rand::{RngCore, CryptoRng};
use sha2::Sha512;

use crate::{utils::{ random_scalar, G }, nizqdleq::prove};


pub fn generate_key_pair<R>(rng: &mut R) -> (Scalar, RistrettoPoint)
where
    R: RngCore + CryptoRng,
{
    let secret_key = random_scalar(rng);
    let public_key = G() * secret_key;

    return (secret_key, public_key);
}

pub fn get_random_blinded<R>(rng: &mut R) -> ([u8; 32], Scalar, RistrettoPoint)
where
    R: RngCore + CryptoRng,
{
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    let r = random_scalar(rng);
    let hashed_nonce = RistrettoPoint::hash_from_bytes::<Sha512>(&nonce);
    let blinded_message = hashed_nonce * r;

    return (nonce, r, blinded_message);
}

pub fn sign<R>(blinded_message: RistrettoPoint, secret_key: Scalar, public_key: RistrettoPoint, rng: &mut R) -> (RistrettoPoint, (Scalar, Scalar))
where
    R: RngCore + CryptoRng,
{
    let signed_message = blinded_message * secret_key;
    let proof = prove(blinded_message, signed_message, secret_key, public_key, rng);

    return (signed_message, proof);
}

pub fn unblind(blinded: RistrettoPoint, r: Scalar) -> RistrettoPoint {
    return blinded * r.invert();
}

pub fn verify(nonce: [u8; 32], signature: RistrettoPoint, secret_key: Scalar) -> bool {
    if nonce.len() != 32 {
        panic!("Nonce must be 32 bytes long");
    }

    let message = RistrettoPoint::hash_from_bytes::<Sha512>(&nonce);
    let signed_message = message * secret_key;

    return signed_message == signature;
}
