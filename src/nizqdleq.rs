use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::{RngCore, CryptoRng};
use sha2::{Digest, Sha256};

use crate::utils::G;

#[allow(non_snake_case)]
pub fn prove<R>(message: RistrettoPoint, signature: RistrettoPoint, secret_key: Scalar, public_key: RistrettoPoint, rng: &mut R) -> (Scalar, Scalar)
where
    R: RngCore + CryptoRng,
{
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let randomness = Scalar::from_bytes_mod_order(bytes);

    let A = G() * randomness;
    let B = message * randomness;

    let mut hasher = Sha256::new();
    hasher.update(public_key.compress().as_bytes());
    hasher.update(message.compress().as_bytes());
    hasher.update(signature.compress().as_bytes());
    hasher.update(A.compress().as_bytes());
    hasher.update(B.compress().as_bytes());
    let hashed_points = hasher.finalize();
    let challenge = Scalar::from_bytes_mod_order(hashed_points.try_into().unwrap());
    let chall_sk = challenge * secret_key;
    let response = randomness - chall_sk;

    return (challenge, response);
}

#[allow(non_snake_case)]
pub fn verify(proof: (Scalar, Scalar), message: RistrettoPoint, signature: RistrettoPoint, public_key: RistrettoPoint) -> bool {
    let (challenge, response) = proof;
    let A = G() * response + public_key * challenge;
    let B = message * response + signature * challenge;

    let mut hasher = Sha256::new();
    hasher.update(public_key.compress().as_bytes());
    hasher.update(message.compress().as_bytes());
    hasher.update(signature.compress().as_bytes());
    hasher.update(A.compress().as_bytes());
    hasher.update(B.compress().as_bytes());
    let hashed_points = hasher.finalize();
    let challenge2 = Scalar::from_bytes_mod_order(hashed_points.try_into().unwrap());

    return challenge == challenge2;
}

#[cfg(test)]
mod tests {
    use sha2::Sha512;

    use crate::utils::random_scalar;

    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn test_correct_proof() {
        let mut rng = rand::thread_rng();
        let message = RistrettoPoint::hash_from_bytes::<Sha512>(b"hello world");
        let secret_key = random_scalar(&mut rng);
        let signature = message * secret_key;
        let public_key = G() * secret_key;

        let proof = prove(message, signature, secret_key, public_key, &mut rng);
        let result = verify(proof, message, signature, public_key);

        assert_eq!(result, true);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_incorrect_proof() {
        let mut rng = rand::thread_rng();
        let message = RistrettoPoint::hash_from_bytes::<Sha512>(b"hello world");
        let secret_key = random_scalar(&mut rng);
        let signature = G() * random_scalar(&mut rng);
        let public_key = G() * secret_key;

        let proof = prove(message, signature, secret_key, public_key, &mut rng);
        let result = verify(proof, message, signature, public_key);

        assert_eq!(result, false);
    }
}
