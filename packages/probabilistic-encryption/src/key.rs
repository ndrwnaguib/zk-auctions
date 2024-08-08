use num_bigint::BigUint;

/// Generic trait for operations on a public key.
pub trait PublicKey {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<BigUint>;
}

/// Generic trait for operations on a private key.
pub trait PrivateKey {
    fn decrypt(&self, ciphertext: &[BigUint]) -> Vec<u8>;
}
