// Goldwasser-Micali Encryption and its AND variance
// Support 32-bit unsigned integers as plaintext

use rand::{rngs::StdRng, Rng, SeedableRng};
use rug::{ops::Pow, Assign, Integer, RandState};

const AND_SIZE_FACTOR: usize = 40;

struct Keys {
    pub_key: Integer,
    priv_key: (Integer, Integer),
}

fn generate_keys(prime_size: u32) -> Keys {
    let mut rng = StdRng::from_entropy();
    let mut p = Integer::from(Integer::random_bits(prime_size, &mut rng));
    while (&p % 4 != 3).into() {
        p = Integer::from(Integer::random_bits(prime_size, &mut rng));
    }

    let mut q = Integer::from(Integer::random_bits(prime_size, &mut rng));
    while (&q % 4 != 3).into() {
        q = Integer::from(Integer::random_bits(prime_size, &mut rng));
    }

    let n = &p * &q;
    Keys { pub_key: n.clone(), priv_key: (p, q) }
}

static mut MY_COUNTER: u64 = 0;

fn get_next_random(n: &Integer) -> Integer {
    unsafe {
        MY_COUNTER += 1;
        n - Integer::from(MY_COUNTER)
    }
}

fn encrypt_bit_gm(bit: u8, n: &Integer) -> Integer {
    let r = get_next_random(&(n - 1));

    let m = if bit == 1 { n - 1 } else { Integer::from(0) };
    (&r * &r * m.pow_mod(&Integer::from(1), n).unwrap()) % n
}

fn encrypt_gm(number: u32, pub_key: &Integer) -> Vec<Integer> {
    let bits_str = format!("{:032b}", number);
    bits_str.chars().map(|bit| encrypt_bit_gm(bit.to_digit(2).unwrap() as u8, pub_key)).collect()
}

fn decrypt_bit_gm(c: &Integer, sk_gm: &Integer, n: &Integer) -> u8 {
    if c.pow_mod(&sk_gm, n).unwrap() == Integer::from(1) {
        0
    } else {
        1
    }
}

fn decrypt_gm(cipher_numbers: &[Integer], priv_key: &(Integer, Integer)) -> Option<u32> {
    let (p, q) = priv_key;
    let n = p * q;
    let sk_gm = ((p - 1) * (q - 1)) / 4;

    let mut bits_str = String::new();
    for c in cipher_numbers {
        if c >= &n || c.jacobi(&n) != 1 {
            return None;
        }
        bits_str.push_str(&decrypt_bit_gm(c, &sk_gm, &n).to_string());
    }
    Some(u32::from_str_radix(&bits_str, 2).unwrap())
}

fn quad_residue(c: &Integer, priv_key: &(Integer, Integer)) -> bool {
    let (p, q) = priv_key;
    let n = p * q;
    let sk_gm = ((p - 1) * (q - 1)) / 4;
    c.jacobi(&n) == 1 && c.pow_mod(&sk_gm, &n).unwrap() == 1
}

fn encrypt_bit_and(bit: u8, pub_key: &Integer) -> Vec<Integer> {
    let mut rng = StdRng::from_entropy();
    if bit == 1 {
        (0..AND_SIZE_FACTOR).map(|_| encrypt_bit_gm(0, pub_key)).collect()
    } else {
        (0..AND_SIZE_FACTOR).map(|_| encrypt_bit_gm(rng.gen_range(0..=1), pub_key)).collect()
    }
}

fn decrypt_bit_and(cipher: &[Integer], priv_key: &(Integer, Integer)) -> u8 {
    let (p, q) = priv_key;
    let n = p * q;
    let sk_gm = ((p - 1) * (q - 1)) / 4;

    for c in cipher {
        if decrypt_bit_gm(c, &sk_gm, &n) == 1 {
            return 0;
        }
    }
    1
}

fn dot_mod(cipher1: &[Integer], cipher2: &[Integer], n: &Integer) -> Vec<Integer> {
    cipher1.iter().zip(cipher2).map(|(c1, c2)| (c1 * c2) % n).collect()
}

fn embed_bit_and(bit_cipher: &Integer, pub_key: &Integer, r: &[Integer]) -> Vec<Integer> {
    let n = pub_key;
    let mut rng = StdRng::from_entropy();

    (0..AND_SIZE_FACTOR)
        .map(|i| {
            if rng.gen_range(0..=1) == 1 {
                encrypt_bit_gm_coin(0, n, &r[i])
            } else {
                encrypt_bit_gm_coin(0, n, &r[i]) * bit_cipher * (n - 1) % n
            }
        })
        .collect()
}

fn embed_and(cipher: &[Integer], pub_key: &Integer, r: &[Vec<Integer>]) -> Vec<Vec<Integer>> {
    cipher
        .iter()
        .enumerate()
        .map(|(i, bit_cipher)| embed_bit_and(bit_cipher, pub_key, &r[i]))
        .collect()
}

fn encrypt_bit_gm_coin(bit: u8, n: &Integer, r: &Integer) -> Integer {
    assert!(*r >= 0 && *r <= n - 1);

    let m = if bit == 1 { n - 1 } else { Integer::from(0) };
    (r * r * m.pow_mod(&Integer::from(1), n).unwrap()) % n
}

fn encrypt_gm_coin(mpz_number: u32, pub_key: &Integer, r: &[Integer]) -> Vec<Integer> {
    let bits_str = format!("{:032b}", mpz_number);

    (0..32)
        .map(|i| {
            encrypt_bit_gm_coin(
                bits_str.chars().nth(i).unwrap().to_digit(2).unwrap() as u8,
                pub_key,
                &r[i],
            )
        })
        .collect()
}
