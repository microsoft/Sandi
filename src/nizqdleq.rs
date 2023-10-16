pub(crate) use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::utils::G;

#[allow(non_snake_case)]
pub fn prove<R>(
    order: Scalar, // q
    basepoint: RistrettoPoint, // G'
    message: RistrettoPoint, // X
    signature: RistrettoPoint, // Q
    public_key: RistrettoPoint, // R
    secret_key: Scalar, // esk
    rng: &mut R,
) -> (Scalar, Scalar)
where
    R: RngCore + CryptoRng,
{
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let randomness = Scalar::from_bytes_mod_order(bytes);

    let A = basepoint * randomness;
    let B = message * randomness;

    let mut hasher = Sha256::new();
    hasher.update(order.as_bytes());                 // q
    hasher.update(basepoint.compress().as_bytes());  // G'
    hasher.update(message.compress().as_bytes());    // X
    hasher.update(signature.compress().as_bytes());  // Q
    hasher.update(public_key.compress().as_bytes()); // R
    hasher.update(A.compress().as_bytes());          // A
    hasher.update(B.compress().as_bytes());          // B
    let hashed_points = hasher.finalize();
    let challenge = Scalar::from_bytes_mod_order(hashed_points.try_into().unwrap());
    let chall_sk = challenge * secret_key;
    let response = randomness - chall_sk;

    // c, s
    return (challenge, response);
}

#[allow(non_snake_case)]
pub fn verify(
    order: Scalar, // q
    basepoint: RistrettoPoint, // G'
    proof: (Scalar, Scalar), // z
    message: RistrettoPoint, // X
    signature: RistrettoPoint, // Q
    public_key: RistrettoPoint, // R
) -> bool {
    let (challenge, response) = proof;
    let A = G() * response + public_key * challenge;
    let B = message * response + signature * challenge;

    let mut hasher = Sha256::new();
    hasher.update(order.as_bytes());                  // q
    hasher.update(basepoint.compress().as_bytes());   // G'
    hasher.update(message.compress().as_bytes());     // X
    hasher.update(signature.compress().as_bytes());   // Q
    hasher.update(public_key.compress().as_bytes());  // R
    hasher.update(A.compress().as_bytes());           // A
    hasher.update(B.compress().as_bytes());           // B
    let hashed_points = hasher.finalize();
    let challenge2 = Scalar::from_bytes_mod_order(hashed_points.try_into().unwrap());

    return challenge == challenge2;
}

#[cfg(test)]
mod tests {
    use sha2::Sha512;

    use crate::utils::{random_scalar, basepoint_order};

    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn test_correct_proof() {
        let mut rng = rand::thread_rng();
        let order = basepoint_order();
        let basepoint = G();
        let message = RistrettoPoint::hash_from_bytes::<Sha512>(b"hello world");
        let secret_key = random_scalar(&mut rng);
        let signature = message * secret_key;
        let public_key = basepoint * secret_key;

        let proof = prove(order, basepoint, message, signature, public_key, secret_key, &mut rng);
        let result = verify(order, basepoint, proof, message, signature, public_key);

        assert_eq!(result, true);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_incorrect_proof() {
        let mut rng = rand::thread_rng();
        let order = basepoint_order();
        let basepoint = G();
        let message = RistrettoPoint::hash_from_bytes::<Sha512>(b"hello world");
        let secret_key = random_scalar(&mut rng);
        let signature = basepoint * random_scalar(&mut rng);
        let public_key = basepoint * secret_key;

        let proof = prove(order, basepoint, message, signature, public_key, secret_key, &mut rng);
        let result = verify(order, basepoint, proof, message, signature, public_key);

        assert_eq!(result, false);
    }
}
