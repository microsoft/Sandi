pub mod nizqdleq;
pub mod blind_token;
pub mod accountability_server;
pub mod sender_ids;
mod utils;
pub mod tag;

use curve25519_dalek::{RistrettoPoint, Scalar};
use sha2::Sha512;


pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub fn test() {
    //let scalar = curve25519_dalek::scalar::Scalar::
    let point = RistrettoPoint::hash_from_bytes::<Sha512>(b"hello world");
    println!("Hello, world! {:?}", point);

    let scalar = Scalar::from(1u8);
    let point2 = point * scalar;
    println!("Hello, world! {:?}", point2);
}

pub fn prove() {
    let message = RistrettoPoint::hash_from_bytes::<Sha512>(b"hello world");
    let signature = RistrettoPoint::hash_from_bytes::<Sha512>(b"hello world 2");
    let secret_key = Scalar::from(2u8);
    let public_key = RistrettoPoint::hash_from_bytes::<Sha512>(b"hello world 3");
    let mut rng = rand::thread_rng();
    nizqdleq::prove(message, signature, secret_key, public_key, &mut rng);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

    #[test]
    fn test_test() {
        test();
    }
}
