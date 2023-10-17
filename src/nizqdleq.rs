pub(crate) use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

pub fn prove<R>(
    q: &Scalar,               // q
    g_prime: &RistrettoPoint, // G'
    x_big: &RistrettoPoint,   // X
    q_big: &RistrettoPoint,   // Q
    r_big: &RistrettoPoint,   // R
    esk: &Scalar,             // esk
    rng: &mut R,
) -> (Scalar, Scalar)
where
    R: RngCore + CryptoRng,
{
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let k = Scalar::from_bytes_mod_order(bytes); // k

    // A = G' * k
    let a_big = k * g_prime;
    // B = Q * k
    let b_big = k * q_big;

    let mut hasher = Sha256::new();
    hasher.update(q.as_bytes()); // q
    hasher.update(g_prime.compress().as_bytes()); // G'
    hasher.update(x_big.compress().as_bytes()); // X
    hasher.update(q_big.compress().as_bytes()); // Q
    hasher.update(r_big.compress().as_bytes()); // R
    hasher.update(a_big.compress().as_bytes()); // A
    hasher.update(b_big.compress().as_bytes()); // B
    let hashed_points = hasher.finalize();
    let c = Scalar::from_bytes_mod_order(hashed_points.try_into().unwrap());
    let c_sk = c * esk;
    let s = k - c_sk;

    // c, s
    return (c, s);
}

pub fn verify(
    q: &Scalar,               // q
    g_prime: &RistrettoPoint, // G'
    z: &(Scalar, Scalar),     // z
    x_big: &RistrettoPoint,   // X
    q_big: &RistrettoPoint,   // Q
    r_big: &RistrettoPoint,   // R
) -> bool {
    let (c, s) = z; // c, s
                    // A' = G' * s + X * c
    let a_prime = s * g_prime + c * x_big;
    // B' = Q * s + R * c
    let b_prime = s * q_big + c * r_big;

    let mut hasher = Sha256::new();
    hasher.update(q.as_bytes()); // q
    hasher.update(g_prime.compress().as_bytes()); // G'
    hasher.update(x_big.compress().as_bytes()); // X
    hasher.update(q_big.compress().as_bytes()); // Q
    hasher.update(r_big.compress().as_bytes()); // R
    hasher.update(a_prime.compress().as_bytes()); // A'
    hasher.update(b_prime.compress().as_bytes()); // B'
    let hashed_points = hasher.finalize();
    let new_c = Scalar::from_bytes_mod_order(hashed_points.try_into().unwrap());

    return *c == new_c;
}
