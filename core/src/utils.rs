use crate::number::Jacobi;
use num_bigint::{BigInt, RandBigInt};
use num_traits::Zero;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::gm::{decrypt_bit_and, get_next_random};

type InnerMap = HashMap<u32, BigInt>;
type NestedMap = HashMap<u32, InnerMap>;
type StrainProofComplexType = HashMap<u32, (NestedMap, NestedMap)>;

type SimpleMap = HashMap<u32, u32>;
type BigIntMatrix = Vec<Vec<BigInt>>;
type PermutationComplexType = (SimpleMap, NestedMap, BigIntMatrix);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StrainProof {
    MEPermutations((HashMap<u32, u32>, HashMap<u32, HashMap<u32, BigInt>>)),
    AMPermutations((HashMap<u32, u32>, Vec<Vec<BigInt>>)),
    HashInput(StrainProofComplexType),
}

pub fn divm(a: &BigInt, b: &BigInt, n: &BigInt) -> BigInt {
    let b_inv = b.modinv(n).unwrap();
    (a * b_inv) % n
}

pub fn get_rand_jn1(n: &BigInt, rng: Option<ChaCha20Rng>) -> BigInt {
    let mut rng = rng.unwrap_or(/* default value */ ChaCha20Rng::from_entropy());
    loop {
        let r = rng.gen_bigint_range(&BigInt::zero(), n);

        if r.jacobi(n) == 1 {
            return r;
        }
    }
}

pub fn set_rand_seed(num_list: &[BigInt]) -> ChaCha20Rng {
    let mut hasher = Sha256::new();

    for x in num_list {
        hasher.update(x.to_bytes_be().1);
    }

    let hash_result = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash_result[..32]); // SHA256 output is 32 bytes
    ChaCha20Rng::from_seed(seed)
    // Non-thread-safe seeding
}

fn hash_flat_recursive(hasher: &mut Sha256, obj: &dyn Hashable) {
    obj.hash_flat(hasher);
}

pub trait Hashable {
    fn hash_flat(&self, hasher: &mut Sha256);
}

impl Hashable for BigInt {
    fn hash_flat(&self, hasher: &mut Sha256) {
        hasher.update(self.to_string().as_bytes());
    }
}

impl Hashable for u32 {
    fn hash_flat(&self, hasher: &mut Sha256) {
        hasher.update(self.to_string().as_bytes());
    }
}

impl<T: Hashable> Hashable for Vec<T> {
    fn hash_flat(&self, hasher: &mut Sha256) {
        for item in self {
            hash_flat_recursive(hasher, item);
        }
    }
}

impl<K: Hashable, V: Hashable> Hashable for HashMap<K, V> {
    fn hash_flat(&self, hasher: &mut Sha256) {
        for (key, value) in self {
            hash_flat_recursive(hasher, key);
            hash_flat_recursive(hasher, value);
        }
    }
}

impl<T1: Hashable, T2: Hashable> Hashable for (T1, T2) {
    fn hash_flat(&self, hasher: &mut Sha256) {
        hash_flat_recursive(hasher, &self.0);
        hash_flat_recursive(hasher, &self.1);
    }
}

pub fn hash_flat<T: Hashable>(input: &T) -> u64 {
    let mut hasher = Sha256::new();
    input.hash_flat(&mut hasher);
    u64::from_le_bytes(hasher.finalize().to_vec()[..8].try_into().unwrap())
}

pub fn bigint_to_seed(bigint: &BigInt) -> [u8; 32] {
    // Convert BigInt to bytes
    let bytes = bigint.to_signed_bytes_le();

    // Hash the bytes to 32 bytes using SHA-256
    let hash = Sha256::digest(&bytes);

    // Convert hash output to a 32-byte array
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);
    seed
}

pub fn compute_permutation(res: &[Vec<BigInt>], n: &BigInt) -> PermutationComplexType {
    let seed = get_next_random(n);
    let permutation_desc = permute(res.len() as u32, &seed);

    let mut output_permutation = HashMap::new();
    let mut reencrypt_factors = Vec::new();

    for (i, res_i) in res.iter().enumerate() {
        let mut rs = Vec::new();
        let mut and_encryptions = HashMap::new();

        for (j, res_ij) in res_i.iter().enumerate() {
            let r = get_next_random(n);
            rs.push(r.clone());
            let rsquare = r.modpow(&BigInt::from(2), n);
            let reencryption = (rsquare * res_ij) % n;
            and_encryptions.insert(j as u32, reencryption);
        }

        output_permutation.insert(permutation_desc[&(i as u32)], and_encryptions);
        reencrypt_factors.push(rs);
    }

    (permutation_desc, output_permutation, reencrypt_factors)
}

pub fn permute(length: u32, seed_bigint: &BigInt) -> HashMap<u32, u32> {
    let seed = bigint_to_seed(seed_bigint);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut permutation: HashMap<u32, u32> = (0..length).map(|i| (i, i)).collect();

    for i in 0..(length - 1) {
        let index = rng.gen_range(i..length);
        let value_i = permutation[&i];
        let value_index = permutation[&index];

        permutation.insert(i, value_index);
        permutation.insert(index, value_i);
    }

    permutation
}

pub fn rand32(n: &BigInt) -> Vec<BigInt> {
    let mut result = Vec::new();
    for _ in 0..32 {
        result.push(get_next_random(n));
    }
    result
}

/// Decrypts a single bit from a ciphertext using the private key.
/// # Arguments
/// * `cipher` - A vector of BigInts representing the ciphertext.
/// * `priv_key` - A tuple containing the private key (BigInt, BigInt
/// # Returns
/// The decrypted bit as a u8 (0 or 1).
/// # Examples
/// ```
/// let cipher = vec![BigInt::from(12345), BigInt::from(
/// 67890)];
/// let priv_key = (BigInt::from(11111), BigInt::from(
/// 22222));
/// let decrypted_bit = decrypt_bit_and(&cipher, &priv_key);
/// assert!(decrypted_bit == 0 || decrypted_bit == 1);
/// ```
pub fn compare_leq_honest(eval_res: &Vec<Vec<BigInt>>, priv_key: &(BigInt, BigInt)) -> bool {
    let mut one_cnt = 0;
    for cipher in eval_res {
        if decrypt_bit_and(cipher, priv_key) == 1 {
            one_cnt += 1;
        }
    }

    assert!(one_cnt <= 1);
    one_cnt == 0
}
