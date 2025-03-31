// Goldwasser-Micali Encryption and its AND variance
// Support 32-bit unsigned integers as plaintext

use crate::number::get_strong_prime;
use num_bigint::BigInt;
use num_traits::{One, Zero};
use rand::{rngs::StdRng, Rng, SeedableRng};

const AND_SIZE_FACTOR: usize = 40;

/* the following generator is created to match the original implementation of
 * `getNextRandom`, there is a good chance that it will be replaced */
pub struct StrainRandomGenerator {
    counter: u64,
}

impl StrainRandomGenerator {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    pub fn get_next_random(&mut self, n: &BigInt) -> BigInt {
        self.counter += 1;
        n - BigInt::from(self.counter)
    }
}

impl Default for StrainRandomGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/**/

pub struct Keys {
    pub pub_key: BigInt,
    // TODO: this is only made `pub` for the tests
    pub priv_key: (BigInt, BigInt),
}

pub fn generate_keys(prime_size: Option<u64>) -> Keys {
    let prime_size = prime_size.unwrap_or(/* default value */ 768u64);
    // TODO: add a rand seed

    let mut p = get_strong_prime(prime_size, None, None);
    while p.clone() % BigInt::from(4u16) != BigInt::from(3u16) {
        p = get_strong_prime(prime_size, None, None);
    }

    let mut q = get_strong_prime(prime_size, None, None);
    while q.clone() % BigInt::from(4u16) != BigInt::from(3u16) {
        q = get_strong_prime(prime_size, None, None);
    }

    let n = p.clone() * q.clone();
    Keys { pub_key: n, priv_key: (p, q) }
}

static mut MY_COUNTER: u64 = 0;

pub fn get_next_random(n: &BigInt) -> BigInt {
    unsafe {
        MY_COUNTER += 1;
        n - BigInt::from(MY_COUNTER)
    }
}

pub fn encrypt_bit_gm(bit: &BigInt, n: &BigInt) -> BigInt {
    let r = get_next_random(&(n - BigInt::one()));
    (r.clone() * r.clone() * &(n - BigInt::one()).modpow(bit, n)) % n
}

pub fn encrypt_bit_gm_coin(bit: &BigInt /* only 0 or 1 */, n: &BigInt, r: BigInt) -> BigInt {
    assert!(r >= BigInt::zero() && r < *n);
    (r.clone() * r.clone() * &(n - BigInt::one()).modpow(bit, n)) % n
}

pub fn encrypt_gm(number: &BigInt, pub_key: &BigInt) -> Vec<BigInt> {
    let bits_str = format!("{:032b}", number);
    bits_str
        .chars()
        .map(|bit| encrypt_bit_gm(&BigInt::from(bit.to_digit(2).unwrap()), pub_key))
        .collect()
}

pub fn decrypt_bit_gm(c: &BigInt, sk_gm: &BigInt, n: &BigInt) -> u8 {
    if c.modpow(sk_gm, n) == BigInt::one() {
        0
    } else {
        1
    }
}

pub fn decrypt_gm(cipher_numbers: &[BigInt], priv_key: &(BigInt, BigInt)) -> Option<BigInt> {
    let (p, q) = priv_key;
    let n = p * q;

    let sk_gm: BigInt = ((p.clone() - 1) * (q.clone() - 1)) / 4;

    let bits_str: String = cipher_numbers
        .iter()
        .map(|c| decrypt_bit_gm(c, &sk_gm, &n)) // Decrypt each number to a bit
        .map(|bit| if bit == 1 { '1' } else { '0' }) // Convert BigInt to '1' or '0'
        .collect();

    Some(BigInt::from(u32::from_str_radix(&bits_str, 2).unwrap()))
}

pub fn encrypt_bit_and(bit: u8, pub_key: &BigInt) -> Vec<BigInt> {
    let mut rng = StdRng::from_entropy();
    if bit == 1 {
        (0..AND_SIZE_FACTOR).map(|_| encrypt_bit_gm(&BigInt::zero(), pub_key)).collect()
    } else {
        (0..AND_SIZE_FACTOR)
            .map(|_| encrypt_bit_gm(&BigInt::from(rng.gen_range(0..=1)), pub_key))
            .collect()
    }
}

pub fn decrypt_bit_and(cipher: &Vec<BigInt>, priv_key: &(BigInt, BigInt)) -> u8 {
    let (p, q) = priv_key;
    let sk_gm: BigInt = ((p.clone() - 1) * (q.clone() - 1)) / 4;
    let n = p.clone() * q.clone();

    for c in cipher {
        if decrypt_bit_gm(c, &sk_gm, &n) == 1u8 {
            return 0;
        }
    }
    1
}

pub fn dot_mod(cipher1: &[BigInt], cipher2: &[BigInt], n: &BigInt) -> Vec<BigInt> {
    cipher1.iter().zip(cipher2).map(|(c1, c2)| ((c1) * (c2)) % n).collect()
}

pub fn embed_bit_and(bit_cipher: &BigInt, pub_key: &BigInt, r: &[BigInt]) -> Vec<BigInt> {
    let n = pub_key;
    let mut rng = StdRng::from_entropy();

    (0..AND_SIZE_FACTOR)
        .map(|i| {
            if rng.gen_range(0..=1) == 1 {
                encrypt_bit_gm_coin(&BigInt::zero(), n, r[i].clone())
            } else {
                encrypt_bit_gm_coin(&BigInt::zero(), n, r[i].clone()) * bit_cipher * (n - 1) % n
            }
        })
        .collect()
}

pub fn embed_and(cipher: &[BigInt], pub_key: &BigInt, r: &[Vec<BigInt>]) -> Vec<Vec<BigInt>> {
    cipher
        .iter()
        .enumerate()
        .map(|(i, bit_cipher)| embed_bit_and(bit_cipher, pub_key, &r[i]))
        .collect()
}

pub fn encrypt_gm_coin(mpz_number: &BigInt, pub_key: &BigInt, r: &[BigInt]) -> Vec<BigInt> {
    let bits_str = format!("{:032b}", mpz_number);

    (0..32)
        .map(|i| {
            encrypt_bit_gm_coin(
                &BigInt::from(bits_str.chars().nth(i).unwrap().to_digit(2).unwrap()),
                pub_key,
                r[i].clone(),
            )
        })
        .collect()
}

#[cfg(test)] // This module is included only during testing
mod tests {
    use super::*;
    use crate::number::Jacobi;
    use std::time::Instant;

    #[test]
    fn test_gen_keys() {
        println!("test_gen_keys:");
        let iters = 1;
        for _ in 0..iters {
            let keys = generate_keys(None);

            let n = keys.pub_key;

            assert_eq!((n.clone() - BigInt::one()).jacobi(&n), 1);
        }
        println!("test_gen_keys pass");
    }

    #[test]
    fn test_gm_enc_dec() {
        let iters = 1;
        println!("test_gm_enc_dec:");

        let keys = generate_keys(None);
        let n = keys.pub_key;

        let mut rng = StdRng::from_entropy();

        for _ in 0..iters {
            let num: BigInt = BigInt::from(rng.gen::<u32>());
            let mut cipher = encrypt_gm(&num, &n);

            // Re-encryption
            for _ in 0..3 {
                cipher = cipher
                    .iter()
                    .map(|c| (c * encrypt_gm(&BigInt::zero(), &n)[0].clone()) % &n)
                    .collect();
            }

            let decrypted = decrypt_gm(&cipher, &keys.priv_key);

            assert!(decrypted.is_some());
            assert_eq!(decrypted.unwrap(), num);
        }

        println!("test_gm_enc_dec pass");
    }

    #[test]
    fn test_gm_homo() {
        let iters = 1;
        println!("test_gm_homo:");

        for _ in 0..iters {
            let keys = generate_keys(None);
            let n = keys.pub_key;
            let priv_key = keys.priv_key;

            let c0 = encrypt_bit_gm(&BigInt::zero(), &n);
            let c1 = encrypt_bit_gm(&BigInt::one(), &n);

            // XOR tests
            assert_eq!(
                decrypt_gm(&[c0.clone() * c1.clone() % n.clone()], &priv_key),
                Some(BigInt::one())
            );
            assert_eq!(
                decrypt_gm(&[c0.clone() * c0.clone() % n.clone()], &priv_key),
                Some(BigInt::zero())
            );
            assert_eq!(
                decrypt_gm(&[c1.clone() * c1.clone() % n.clone()], &priv_key),
                Some(BigInt::zero())
            );

            // Flip tests
            assert_eq!(
                decrypt_gm(&[c0.clone() * (n.clone() - 1) % n.clone()], &priv_key),
                Some(BigInt::one())
            );
            assert_eq!(
                decrypt_gm(&[c1.clone() * (n.clone() - 1) % n.clone()], &priv_key),
                Some(BigInt::zero())
            );
        }

        println!("test_gm_homo pass");
    }

    #[test]
    fn test_gm_bit_and() {
        println!("test_gm_bit_and:");

        let keys = generate_keys(None);
        let n = keys.pub_key;
        let priv_key = keys.priv_key;

        let mut enc_times = Vec::new();
        let mut dec_times = Vec::new();

        for _ in 0..10 {
            let start = Instant::now();
            let cipher0 = encrypt_bit_and(0u8, &n);
            enc_times.push(start.elapsed().as_secs_f64());

            let start = Instant::now();
            let cipher1 = encrypt_bit_and(1u8, &n);
            enc_times.push(start.elapsed().as_secs_f64());

            let start = Instant::now();
            let bit0 = decrypt_bit_and(&cipher0, &priv_key);
            dec_times.push(start.elapsed().as_secs_f64());

            let start = Instant::now();
            let bit1 = decrypt_bit_and(&cipher1, &priv_key);
            dec_times.push(start.elapsed().as_secs_f64());

            assert_eq!(bit0, 0u8);
            assert_eq!(bit1, 1u8);

            assert_eq!(
                decrypt_bit_and(&dot_mod(&cipher0, &encrypt_bit_and(1u8, &n), &n), &priv_key),
                0u8
            );
            assert_eq!(
                decrypt_bit_and(&dot_mod(&cipher0, &encrypt_bit_and(0u8, &n), &n), &priv_key),
                0u8
            );
            assert_eq!(
                decrypt_bit_and(&dot_mod(&cipher1, &encrypt_bit_and(1u8, &n), &n), &priv_key),
                1u8
            );
        }

        let enc_avg = enc_times.iter().sum::<f64>() / enc_times.len() as f64;
        let enc_std_dev = (enc_times.iter().map(|&x| (x - enc_avg).powi(2)).sum::<f64>()
            / enc_times.len() as f64)
            .sqrt()
            / enc_avg
            * 100.0;
        let dec_avg = dec_times.iter().sum::<f64>() / dec_times.len() as f64;
        let dec_std_dev = (dec_times.iter().map(|&x| (x - dec_avg).powi(2)).sum::<f64>()
            / dec_times.len() as f64)
            .sqrt()
            / dec_avg
            * 100.0;

        println!("EncAnd avg: {:.2}s, rel.std.dev.: {:.2}%", 32.0 * enc_avg, enc_std_dev);
        println!("DecAnd avg: {:.2}s, rel.std.dev.: {:.2}%", 32.0 * dec_avg, dec_std_dev);
    }

    // TODO: fix the following test--in particular, decide the missing `r`.
    // #[test]
    // fn test_embed_bit_and() {
    //     let iters = 10;
    //     println!("test_embed_bit_and:");

    //     let keys = generate_keys(None);
    //     let n = &keys.pub_key;
    //     let priv_key = &keys.priv_key;
    //     let mut rng = StdRng::from_entropy();

    //     for _ in 0..iters {
    //         let bit: u8 = rng.gen_range(0..=1);
    //         let cipher = encrypt_bit_gm(bit, &n);

    //         let cipher_and = embed_bit_and(&cipher, &n);
    //         assert_eq!(decrypt_bit_and(&cipher_and, priv_key), bit.to_string());
    //     }

    //     println!("test_embed_bit_and pass");
    // }
}
