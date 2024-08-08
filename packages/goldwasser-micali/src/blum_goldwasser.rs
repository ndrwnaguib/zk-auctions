use crate::errors::{Error};
use crate::key::{PublicKey, PrivateKey};
use crate::number;
use crate::prime;

use bitvec::order::Msb0;
use bitvec::vec::BitVec;
use bitvec::slice::BitSlice;
use num_bigint::{BigUint, BigInt, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::One;
use rand::thread_rng;
use std::ops::{Div, BitXor};

/// Represents the public key of the Blum-Goldwasser scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlumGoldwasserPublicKey {
    n: BigUint
}

/// Represents the private key of the Blum-Goldwasser scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlumGoldwasserPrivateKey {
    p: BigUint,
    q: BigUint,
    a: BigInt,
    b: BigInt
}

impl BlumGoldwasserPublicKey {
    pub fn n(&self) -> &BigUint {
        &self.n
    }
}

impl PublicKey for BlumGoldwasserPublicKey {
    /// Encryption algorithm.
    /// 
    /// # Arguments
    ///
    /// * `plaintext` - Plaintext to encrypt.
    /// 
    /// # Reference
    /// 
    /// See algorithm 8.56 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
    fn encrypt(&self, plaintext: &[u8]) -> Vec<BigUint> {
        let two = BigUint::from(2usize);

        /*
        Calculation of h should be like:
        let k = self.n.bits() - 1;
        let h = BigUint::from_usize(k).unwrap().bits() - 1;

        However, I will fix its value so that each u8 is evenly partitioned.
        Otherwise, the result of the decryption does not match the input plaintext.
        I don't know what implications this has on the security of the scheme.
        */

        let h = 4usize;

        let mut x = find_quadratic_residue_mod(&self.n);
        let mask = BigUint::from(h.pow(2) - 1);

        let mut ciphertext = Vec::with_capacity(8 * plaintext.len());
        let bits = BitVec::<Msb0, u8>::from_vec(plaintext.to_vec());

        let mut chunks = bits.chunks(h);
        while let Some(chunk) = chunks.next() {
            x = x.modpow(&two, &self.n);
            let p = &x & &mask;            
            let m = to_biguint(chunk);
            let c = p.bitxor(&m);
            ciphertext.push(c);
        }

        x = x.modpow(&two, &self.n);
        ciphertext.push(x);
        ciphertext
    }
}

impl BlumGoldwasserPrivateKey {
    pub fn p(&self) -> &BigUint {
        &self.p
    }

    pub fn q(&self) -> &BigUint {
        &self.q
    }

    pub fn a(&self) -> &BigInt {
        &self.a
    }

    pub fn b(&self) -> &BigInt {
        &self.b
    }
}

impl PrivateKey for BlumGoldwasserPrivateKey {
    /// Decryption algorithm.
    /// 
    /// # Arguments
    ///
    /// * `ciphertext` - Ciphertext to decrypt.
    /// 
    /// # Reference
    /// 
    /// See algorithm 8.56 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
    fn decrypt(&self, ciphertext: &[BigUint]) -> Vec<u8> {
        let one = BigUint::one();
        let two = BigUint::from(2usize);
        let four = BigUint::from(4usize);

        let n = &self.p * &self.q;
        /*
        let k = n.bits() - 1;
        let h = BigUint::from_usize(k).unwrap().bits() - 1;
        */
        let h = 4usize;
        
        let mask = BigUint::from(h.pow(2) - 1);
        match ciphertext.last() {
            None => Vec::new(),
            Some(xtplus1) => {
                let len = ciphertext.len() - 1;
                let t = BigUint::from(len);
                let d1 = (&self.p + &one).div_floor(&four).modpow(&(&t + &one), &(&self.p - &one));
                let d2 = (&self.q + &one).div_floor(&four).modpow(&(&t + &one), &(&self.q - &one));
                let u = xtplus1.modpow(&d1, &self.p).to_bigint().unwrap();
                let v = xtplus1.modpow(&d2, &self.q).to_bigint().unwrap();

                let _p = self.p.to_bigint().unwrap();
                let _q = self.q.to_bigint().unwrap();
                let _n = n.to_bigint().unwrap();
                let mut x = (v * &self.a * _p + u * &self.b * _q).mod_floor(&_n).to_biguint().unwrap();

                let mut bits: BitVec<Msb0, u8> = BitVec::new();
                for c in &ciphertext[..len] {
                    x = x.modpow(&two, &n);
                    let p = &x & &mask;
                    let m = p.bitxor(c);

                    let bit_vec = to_bitvec(&m);
                    let chunk = bit_vec.split_at(bit_vec.len() - h); 
                    for bit in chunk.1 { bits.push(*bit); }
                }
                let plaintext: Vec<u8> = bits.into_vec();
                plaintext
            }
        }
    }
}

/// Generates public and private keys.
/// 
/// # Arguments
///
/// * `byte_size` - Size of public key in bytes.
/// 
/// # Reference
/// 
/// See algorithm 8.55 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
pub fn generate_keys(byte_size: u64) -> Result<(BlumGoldwasserPublicKey, BlumGoldwasserPrivateKey), Error> {
    if byte_size < 2 {
        Err(Error::LengthPublicKeyModulus)
    } else {
        let p_bits = 8 * byte_size.div(2);
        let q_bits = 8 * (byte_size - byte_size.div(2));

        let (p, q) = generate_primes(p_bits, q_bits);

        match number::extended_euclidean_algorithm(&p, &q) {
            None => Err(Error::CouldNotGenerateKeys),
            Some((a, b)) => {
                let n = &p * &q;
                let public_key = BlumGoldwasserPublicKey { n };
                let private_key = BlumGoldwasserPrivateKey { p, q, a, b };
                Ok((public_key, private_key))
            }
        }
    }
}

/// Generates primes `p` and `q` for private/public key generation.
/// 
/// # Arguments
///
/// * `p_bits` - Number of bits for prime `p`.
/// * `q_bits` - Number of bits for prime `q`.
/// 
/// # Reference
/// 
/// See algorithm 8.55 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
/// 
/// # Panics
/// 
/// Panics if either `p_bits` or `q_bits` is `< 2`.
fn generate_primes(p_bits: u64, q_bits: u64) -> (BigUint, BigUint) {
    fn generate_prime_congruente_3mod4(bit_size: u64) -> BigUint {
        let three = BigUint::from(3usize);
        let four = BigUint::from(4usize);
        let mut prime = prime::generate_prime(bit_size);
        while prime.mod_floor(&four) != three {
            prime = prime::generate_prime(bit_size);
        }
        prime
    }

    let p = generate_prime_congruente_3mod4(p_bits);

    let mut q = generate_prime_congruente_3mod4(q_bits);
    while p == q {
        q = generate_prime_congruente_3mod4(q_bits);
    }

    (p, q)
}

/// Finds a quadratic residue modulo `n`.
/// 
/// # Arguments
///
/// * `n` - Modulo `n`.
/// 
/// # Reference
/// 
/// See algorithm 8.55 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
fn find_quadratic_residue_mod(n: &BigUint) -> BigUint {
    let mut rng = thread_rng();
    let r = rng.gen_biguint_range(&BigUint::one(), &n); 
    r.modpow(&BigUint::from(2usize), n)
}

/// Converts a `BitSlice` into a `BigUint`.
/// 
/// # Arguments
///
/// * `bits` - input `BitSlice`.
fn to_biguint(bits: &BitSlice<Msb0, u8>) -> BigUint {
    let n = bits.iter().fold(0usize, |acc, bit| {
        acc*2 + if *bit { 1 } else { 0 } 
    });

    BigUint::from(n)
}

/// Converts a `BigUint` into a `BitVec`.
/// 
/// # Arguments
///
/// * `number` - input `BigUint`.
fn to_bitvec(number: &BigUint) -> BitVec<Msb0, u8> {
    BitVec::<Msb0, u8>::from_vec(number.to_bytes_be())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::key::{PublicKey, PrivateKey};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_encrypt_decrypt(plaintext in prop::array::uniform32(0u8..)) {
            match generate_keys(8) {
                Ok((public_key, private_key)) => {
                    let cyphertext = public_key.encrypt(&plaintext);
                    let decrypted_plaintext = private_key.decrypt(&cyphertext); 

                    prop_assert_eq!(decrypted_plaintext, plaintext)
                },
                _  => prop_assert_eq!(false, true)
            };
        }

        #[test]
        fn test_generate_primes(bit_size in 8u64..32) {
            let three = BigUint::from(3usize);
            let four = BigUint::from(4usize);
            
            let (p, q) = generate_primes(bit_size, bit_size);

            prop_assert_ne!(&p, &q);
            prop_assert_eq!(p.mod_floor(&four) == three, true);
            prop_assert_eq!(q.mod_floor(&four) == three, true);
        }

        #[test]
        fn test_to_biguint_to_bitvec(arr in prop::array::uniform8(0u8..1u8)) {
            let mut bits = BitVec::with_capacity(8);
            arr.iter().for_each(|&bit| bits.push(bit == 1u8));

            let to_number = to_biguint(&bits);
            let to_bits = to_bitvec(&to_number);

            prop_assert_eq!(to_bits, bits);
        }
    }
}
