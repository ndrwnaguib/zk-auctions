// Goldwasser-Micali Encryption and its AND variance
// Support 32-bit unsigned integers as plaintext

use rand::{rngs::StdRng, Rng, SeedableRng};
use rug::rand::RandState;
use rug::Integer;

const AND_SIZE_FACTOR: usize = 40;

/* the following generator is created to match the original implementation of
 * `getNextRandom`, there is a good chance that it will be replaced */
pub struct StrainRandomGenerator {
    counter: u64,
}

impl StrainRandomGenerator {
    // Create a new RandomGenerator with an initial counter value
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    // Get the next random number based on `n`
    pub fn get_next_random(&mut self, n: &Integer) -> Integer {
        self.counter += 1;
        n - Integer::from(self.counter)
    }
}

/**/

struct Keys {
    pub pub_key: Integer,
    // TODO: this is only made `pub` for the tests
    pub priv_key: (Integer, Integer),
}

pub fn generate_keys(prime_size: Option<u32>) -> Keys {
    let prime_size = prime_size.unwrap_or(/* default value */ 768);
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let mut rand_state = RandState::new();
    rand_state.seed(&Integer::from(rng.gen::<u64>()));

    // TODO: write a function that generates strong primes based on Silverman's
    // “FAST GENERATION OF RANDOM, STRONG RSA PRIMES”
    let mut p = Integer::from(Integer::random_bits(prime_size, &mut rand_state));
    while (p % 4 != 3).into() {
        p = Integer::from(Integer::random_bits(prime_size, &mut rand_state));
    }

    // TODO: write a function that generates strong primes based on Silverman's
    // “FAST GENERATION OF RANDOM, STRONG RSA PRIMES”

    let mut q = Integer::from(Integer::random_bits(prime_size, &mut rand_state));
    while (q % 4 != 3).into() {
        q = Integer::from(Integer::random_bits(prime_size, &mut rand_state));
    }

    let n = p * q;
    Keys { pub_key: n, priv_key: (p, q) }
}

static mut MY_COUNTER: u64 = 0;

pub fn get_next_random(n: Integer) -> Integer {
    unsafe {
        MY_COUNTER += 1;
        n - Integer::from(MY_COUNTER)
    }
}

pub fn encrypt_bit_gm(bit: u8, n: Integer) -> Integer {
    let r = get_next_random(n - 1);

    let m = if bit == 1 { n - 1 } else { Integer::from(0) };
    (r * r * m.pow_mod(&Integer::from(1), &n).unwrap()) % n
}

pub fn encrypt_bit_gm_coin(bit: u8, n: Integer, r: Integer) -> Integer {
    assert!(r >= 0 && r <= n - 1);

    let m = if bit == 1 { n - 1 } else { Integer::from(0) };
    (r * r * m.pow_mod(&Integer::from(1), &n).unwrap()) % n
}

pub fn encrypt_gm(number: u32, pub_key: Integer) -> Vec<Integer> {
    let bits_str = format!("{:032b}", number);
    bits_str.chars().map(|bit| encrypt_bit_gm(bit.to_digit(2).unwrap() as u8, pub_key)).collect()
}

pub fn decrypt_bit_gm(c: Integer, sk_gm: Integer, n: Integer) -> u8 {
    if c.pow_mod(&sk_gm, &n).unwrap() == Integer::from(1) {
        0
    } else {
        1
    }
}

pub fn decrypt_gm(cipher_numbers: &[Integer], priv_key: (Integer, Integer)) -> Option<u32> {
    let (p, q) = priv_key;
    let n = p * q;
    let sk_gm = ((p - 1) * (q - 1)) / 4;

    let mut bits_str = String::new();
    for c in cipher_numbers {
        if (*c) >= n || c.jacobi(&n) != 1 {
            return None;
        }
        bits_str.push_str(&decrypt_bit_gm(c.clone(), sk_gm, n).to_string());
    }
    Some(u32::from_str_radix(&bits_str, 2).unwrap())
}

pub fn encrypt_bit_and(bit: u8, pub_key: Integer) -> Vec<Integer> {
    let mut rng = StdRng::from_entropy();
    if bit == 1 {
        (0..AND_SIZE_FACTOR).map(|_| encrypt_bit_gm(0, pub_key)).collect()
    } else {
        (0..AND_SIZE_FACTOR).map(|_| encrypt_bit_gm(rng.gen_range(0..=1), pub_key)).collect()
    }
}

pub fn decrypt_bit_and(cipher: &Vec<Integer>, priv_key: (Integer, Integer)) -> u8 {
    let (p, q) = priv_key;
    let n = p * q;
    let sk_gm = ((p - 1) * (q - 1)) / 4;

    for c in cipher {
        if decrypt_bit_gm(c.clone(), sk_gm, n) == 1 {
            return 0;
        }
    }
    1
}

pub fn dot_mod(cipher1: &[Integer], cipher2: &[Integer], n: Integer) -> Vec<Integer> {
    cipher1.iter().zip(cipher2).map(|(c1, c2)| ((*c1) * (*c2)) % n).collect()
}

pub fn embed_bit_and(bit_cipher: Integer, pub_key: Integer, r: &[Integer]) -> Vec<Integer> {
    let n = pub_key;
    let mut rng = StdRng::from_entropy();

    (0..AND_SIZE_FACTOR)
        .map(|i| {
            if rng.gen_range(0..=1) == 1 {
                encrypt_bit_gm_coin(0, n, r[i].clone())
            } else {
                encrypt_bit_gm_coin(0, n, r[i].clone()) * bit_cipher * (n - 1) % n
            }
        })
        .collect()
}

pub fn embed_and(cipher: &[Integer], pub_key: Integer, r: &[Vec<Integer>]) -> Vec<Vec<Integer>> {
    cipher
        .iter()
        .enumerate()
        .map(|(i, bit_cipher)| embed_bit_and(bit_cipher.clone(), pub_key, &r[i]))
        .collect()
}

pub fn encrypt_gm_coin(mpz_number: u32, pub_key: Integer, r: &[Integer]) -> Vec<Integer> {
    let bits_str = format!("{:032b}", mpz_number);

    (0..32)
        .map(|i| {
            encrypt_bit_gm_coin(
                bits_str.chars().nth(i).unwrap().to_digit(2).unwrap() as u8,
                pub_key,
                r[i].clone(),
            )
        })
        .collect()
}

#[cfg(test)] // This module is included only during testing
mod tests {
    use super::*;

    #[test]
    fn test_gen_keys() {
        println!("test_gen_keys:");
        let iters = 10;
        for _ in 0..iters {
            let keys = generate_keys();

            let n = &keys.pub_key;
            let (p, q) = &keys.priv_key;

            assert_eq!(n.jacobi(n - 1), 1);
        }
        println!("test_gen_keys pass");
    }

    #[test]
    fn test_gm_enc_dec(iters: usize) {
        println!("test_gm_enc_dec:");

        let keys = generate_keys();
        let n = &keys.pub_key;
        let (p, q) = &keys.priv_key;

        let mut rng = StdRng::from_entropy();

        for _ in 0..iters {
            let num: Integer = rng.gen::<u32>().into();
            let mut cipher = encrypt_gm(&num, n);

            // Re-encryption
            for _ in 0..3 {
                cipher =
                    cipher.iter().map(|c| (c * encrypt_gm(&Integer::from(0), n)[0]) % n).collect();
            }

            let decrypted = decrypt_gm(&cipher, &(p.clone(), q.clone()));

            assert!(decrypted.is_some());
            assert_eq!(decrypted.unwrap(), num);
        }

        println!("test_gm_enc_dec pass");
    }

    #[test]
    fn test_gm_homo(iters: usize) {
        println!("test_gm_homo:");

        for _ in 0..iters {
            let keys = generate_keys();
            let n = &keys.pub_key;
            let priv_key = &keys.priv_key;

            let c0 = encrypt_bit_gm(0, n);
            let c1 = encrypt_bit_gm(1, n);

            // XOR tests
            assert_eq!(decrypt_gm(&[c0[0] * c1[0] % n], priv_key), Some(1.into()));
            assert_eq!(decrypt_gm(&[c0[0] * c0[0] % n], priv_key), Some(0.into()));
            assert_eq!(decrypt_gm(&[c1[0] * c1[0] % n], priv_key), Some(0.into()));

            // Flip tests
            assert_eq!(decrypt_gm(&[c0[0] * (n - 1) % n], priv_key), Some(1.into()));
            assert_eq!(decrypt_gm(&[c1[0] * (n - 1) % n], priv_key), Some(0.into()));
        }

        println!("test_gm_homo pass");
    }

    #[test]
    fn test_gm_bit_and() {
        println!("test_gm_bit_and:");

        let keys = generate_keys();
        let n = &keys.pub_key;
        let priv_key = &keys.priv_key;

        let mut enc_times = Vec::new();
        let mut dec_times = Vec::new();

        for _ in 0..10 {
            let start = Instant::now();
            let cipher0 = encrypt_bit_and("0", n);
            enc_times.push(start.elapsed().as_secs_f64());

            let start = Instant::now();
            let cipher1 = encrypt_bit_and("1", n);
            enc_times.push(start.elapsed().as_secs_f64());

            let start = Instant::now();
            let bit0 = decrypt_bit_and(&cipher0, priv_key);
            dec_times.push(start.elapsed().as_secs_f64());

            let start = Instant::now();
            let bit1 = decrypt_bit_and(&cipher1, priv_key);
            dec_times.push(start.elapsed().as_secs_f64());

            assert_eq!(bit0, "0");
            assert_eq!(bit1, "1");

            // AND tests
            assert_eq!(
                decrypt_bit_and(&dot_mod(&cipher0, &encrypt_bit_and("1", n), n), priv_key),
                "0"
            );
            assert_eq!(
                decrypt_bit_and(&dot_mod(&cipher0, &encrypt_bit_and("0", n), n), priv_key),
                "0"
            );
            assert_eq!(
                decrypt_bit_and(&dot_mod(&cipher1, &encrypt_bit_and("1", n), n), priv_key),
                "1"
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

    #[test]
    fn test_embed_bit_and(iters: usize) {
        println!("test_embed_bit_and:");

        let keys = generate_keys();
        let n = &keys.pub_key;
        let priv_key = &keys.priv_key;
        let mut rng = StdRng::from_entropy();

        for _ in 0..iters {
            let bit: u8 = rng.gen_range(0..=1);
            let cipher = encrypt_bit_gm(bit as u32, n);

            let cipher_and = embed_bit_and(&cipher, n);
            assert_eq!(decrypt_bit_and(&cipher_and, priv_key), bit.to_string());
        }

        println!("test_embed_bit_and pass");
    }
}
