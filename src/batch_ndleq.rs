use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_chacha::ChaCha20Rng;
use rand::{CryptoRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use crate::{nizqdleq, utils::{basepoint_order}};

#[derive(Debug)]
pub struct BatchNdleqError(pub String);

pub fn prove<T>(x_big: &RistrettoPoint, y_big: &RistrettoPoint, p_arr: &T, q_arr: &T, esk: &Scalar) -> Result<(Scalar, Scalar), BatchNdleqError>
where
    T: AsRef<[RistrettoPoint]>, {
    let len_p = p_arr.as_ref().len();
    let len_q = q_arr.as_ref().len();
    if len_p != len_q {
        return Err(BatchNdleqError("Length of P and Q arrays must be equal".to_string()));
    }

    let mut hasher = Sha256::new();
    hasher.update(x_big.compress().as_bytes()); // X
    hasher.update(y_big.compress().as_bytes()); // Y

    for i in 0..len_p {
        let p = p_arr.as_ref()[i];
        let q = q_arr.as_ref()[i];
        hasher.update(p.compress().as_bytes()); // P
        hasher.update(q.compress().as_bytes()); // Q
    }

    let hash_result = hasher.finalize();
    let seed: [u8; 32] = hash_result.try_into().unwrap();

    let mut rng = ChaCha20Rng::from_seed(seed);
    let coeffs = (0..len_p).map(|_| {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Scalar::from_bytes_mod_order(bytes)
    }).collect::<Vec<_>>();
    let mut m_big = coeffs[0] * p_arr.as_ref()[0];
    let mut z_big = coeffs[0] * q_arr.as_ref()[0];
    for i in 1..len_p {
        let p = p_arr.as_ref()[i];
        let q = q_arr.as_ref()[i];
        let m = coeffs[i] * p;
        let z = coeffs[i] * q;
        m_big += m;
        z_big += z;
    }

    let bporder = basepoint_order();
    let proof = nizqdleq::prove(&bporder, x_big, y_big, &m_big, &z_big, esk, &mut rng);
    
    Ok(proof)
}

pub fn verify<T>(x_big: &RistrettoPoint, y_big: &RistrettoPoint, p_arr: &T, q_arr: &T, proof: &(Scalar, Scalar)) -> bool
where 
    T: AsRef<[RistrettoPoint]>, {

    let len_p = p_arr.as_ref().len();
    let len_q = q_arr.as_ref().len();
    if len_p != len_q {
        return false;
    }

    let mut hasher = Sha256::new();
    hasher.update(x_big.compress().as_bytes()); // X
    hasher.update(y_big.compress().as_bytes()); // Y

    for i in 0..len_p {
        let p = p_arr.as_ref()[i];
        let q = q_arr.as_ref()[i];
        hasher.update(p.compress().as_bytes()); // P
        hasher.update(q.compress().as_bytes()); // Q
    }

    let hash_result = hasher.finalize();
    let seed: [u8; 32] = hash_result.try_into().unwrap();

    let mut rng = ChaCha20Rng::from_seed(seed);
    let coeffs = (0..len_p).map(|_| {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Scalar::from_bytes_mod_order(bytes)
    }).collect::<Vec<_>>();
    let mut m_big = coeffs[0] * p_arr.as_ref()[0];
    let mut z_big = coeffs[0] * q_arr.as_ref()[0];
    for i in 1..len_p {
        let p = p_arr.as_ref()[i];
        let q = q_arr.as_ref()[i];
        let m = coeffs[i] * p;
        let z = coeffs[i] * q;
        m_big += m;
        z_big += z;
    }

    let bporder = basepoint_order();
    let result = nizqdleq::verify(&bporder, x_big, proof, y_big, &m_big, &z_big);
    result
}

#[cfg(test)]
mod tests {
    use crate::utils::{random_point, random_scalar};

    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_batch_ndleq() {
        let mut rng = OsRng;
        let sk = random_scalar(&mut rng);
        let x_big = random_point(&mut rng);
        let y_big = sk * x_big;

        let p_arr = vec![random_point(&mut rng), random_point(&mut rng)];
        let mut q_arr = Vec::new();
        for p in p_arr.iter() {
            q_arr.push(sk * *p);
        }

        let result = prove(&x_big, &y_big, &p_arr, &q_arr, &sk);
        assert!(result.is_ok());

        let proof = result.unwrap();
        let result = verify(&x_big, &y_big, &p_arr, &q_arr, &proof);
        assert!(result);
    }
}