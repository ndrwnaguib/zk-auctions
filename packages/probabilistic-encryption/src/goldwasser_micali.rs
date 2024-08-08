use crate::errors::Error;
use crate::key::{PrivateKey, PublicKey};
use crate::number;
use crate::prime;

use bitvec::order::Msb0;
use bitvec::vec::BitVec;
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::One;
use rand::thread_rng;
use std::ops::Div;

/// Represents the public key of the Goldwasser-Micali scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoldwasserMicaliPublicKey {
    n: BigUint,
    y: BigUint,
}

impl GoldwasserMicaliPublicKey {
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    pub fn y(&self) -> &BigUint {
        &self.y
    }
}

impl PublicKey for GoldwasserMicaliPublicKey {
    /// Encryption algorithm.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Plaintext to encrypt.
    ///
    /// # Reference
    ///
    /// See algorithm 8.51 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
    fn encrypt(&self, plaintext: &[u8]) -> Vec<BigUint> {
        let one = BigUint::one();
        let two = BigUint::from(2usize);

        let mut rng = thread_rng();
        let mut ciphertext = Vec::with_capacity(8 * plaintext.len());
        let bits = BitVec::<Msb0, u8>::from_vec(plaintext.to_vec());

        for m in bits {
            let x = rng.gen_biguint_range(&one, &self.n);
            let x_square_mod = x.modpow(&two, &self.n);

            let c = if m {
                (&self.y.mod_floor(&self.n) * x_square_mod).mod_floor(&self.n)
            } else {
                x_square_mod
            };
            ciphertext.push(c);
        }
        ciphertext
    }
}

/// Represents the private key of the Goldwasser-Micali scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoldwasserMicaliPrivateKey {
    p: BigUint,
    q: BigUint,
}

impl GoldwasserMicaliPrivateKey {
    pub fn p(&self) -> &BigUint {
        &self.p
    }

    pub fn q(&self) -> &BigUint {
        &self.q
    }
}

impl PrivateKey for GoldwasserMicaliPrivateKey {
    /// Decryption algorithm.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Ciphertext to decrypt.
    ///
    /// # Reference
    ///
    /// See algorithm 8.51 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
    fn decrypt(&self, ciphertext: &[BigUint]) -> Vec<u8> {
        let mut bits: BitVec<Msb0, u8> = BitVec::with_capacity(ciphertext.len());

        for c in ciphertext {
            let m = !matches!(number::jacobi_symbol(c, &self.p), number::JacobiSymbol::One);
            bits.push(m);
        }
        let plaintext: Vec<u8> = bits.into();
        plaintext
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
/// See algorithm 8.50 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
pub fn generate_keys(
    byte_size: u64,
) -> Result<(GoldwasserMicaliPublicKey, GoldwasserMicaliPrivateKey), Error> {
    if byte_size < 2 {
        Err(Error::LengthPublicKeyModulus)
    } else {
        let p_bits = 8 * byte_size.div(2);
        let q_bits = 8 * (byte_size - byte_size.div(2));

        let (p, q) = generate_primes(p_bits, q_bits);

        match find_pseudosquare_mod(&p, &q) {
            None => Err(Error::CouldNotGenerateKeys),
            Some(y) => {
                let n = &p * &q;
                let public_key = GoldwasserMicaliPublicKey { n, y };
                let private_key = GoldwasserMicaliPrivateKey { p, q };

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
/// See algorithm 8.50 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
fn generate_primes(p_bits: u64, q_bits: u64) -> (BigUint, BigUint) {
    let p = prime::generate_prime(p_bits);
    let mut q = prime::generate_prime(q_bits);

    while p == q {
        q = prime::generate_prime(q_bits);
    }

    (p, q)
}

/// Finds a pseudosquare modulo `p * q`.
///
/// # Arguments
///
/// * `p` - Prime `p`.
/// * `q` - Prime `q`.
///
/// # Reference
///
/// See remark 8.54 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
fn find_pseudosquare_mod(p: &BigUint, q: &BigUint) -> Option<BigUint> {
    let a = find_quadratic_nonresidue_mod(p);
    let b = find_quadratic_nonresidue_mod(q);

    let crt = vec![(&a, p), (&b, q)];
    number::gauss_algorithm_for_crt(&crt)
}

/// Finds a quadratic non-residue modulo `n`.
///
/// # Arguments
///
/// * `n` - Module `n`.
///
/// # Reference
///
/// See remark 8.54 in "Handbook of Applied Cryptography" by Alfred J. Menezes et al.
fn find_quadratic_nonresidue_mod(n: &BigUint) -> BigUint {
    let mut rng = thread_rng();

    loop {
        let a = rng.gen_biguint_range(&BigUint::one(), n);

        match number::jacobi_symbol(&a, n) {
            number::JacobiSymbol::MinusOne => break a,
            _ => continue,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::key::{PrivateKey, PublicKey};
    use num_traits::ToPrimitive;
    use proptest::prelude::*;

    fn strategy_for_prime(lower_bound: usize, upper_bound: usize) -> impl Strategy<Value = usize> {
        let sieve = primal::Sieve::new(upper_bound);
        (lower_bound..upper_bound).prop_filter("is_prime", move |&n| sieve.is_prime(n))
    }

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
        fn test_find_quadratic_nonresidue_mod(n in strategy_for_prime(3, 1_000_000)) {
            fn is_quadratic_residue_module(a: usize, n: usize) -> bool {
                let mut b = 1usize;
                let mut result = false;
                while !result && b < n {
                    result = b.pow(2).mod_floor(&n) == a;
                    b += 1;
                }
                result
            }

            let a = find_quadratic_nonresidue_mod(&BigUint::from(n));
            prop_assert_eq!(false, is_quadratic_residue_module(a.to_usize().unwrap(), n))
        }
    }
}
