use crate::number::Jacobi;
use num_bigint::{BigInt, RandBigInt};
use num_traits::{One, Zero};
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::gm::{decrypt_bit_and, dot_mod, embed_and, encrypt_bit_gm_coin, StrainRandomGenerator};

/// Called by supplier 1, who bids number1
/// Compare number1 vs number2 without revealing number1
/// Encrypts the result with pub_key_j for later decryption by supplier 2
fn gm_eval_honest(
    number1: &BigInt,
    cipher_i: &Vec<BigInt>,
    cipher_j: &Vec<BigInt>,
    pub_key_j: &BigInt,
    rand1: &Vec<Vec<BigInt>>,
    rand2: &Vec<Vec<BigInt>>,
    rand3: &Vec<Vec<BigInt>>,
    rand4: &Vec<Vec<BigInt>>,
) -> Vec<Vec<BigInt>> {
    assert_eq!(cipher_j.len(), 32);

    let neg_cipher_i: Vec<BigInt> =
        cipher_i.iter().map(|x| x * (pub_key_j - BigInt::one()) % pub_key_j).collect();
    let c_neg_xor = dot_mod(&neg_cipher_i, &cipher_j, pub_key_j);

    let cipher_i_and = embed_and(&cipher_i, pub_key_j, rand1);
    let cipher_j_and = embed_and(&cipher_j, pub_key_j, rand2);
    let neg_cipher_i_and = embed_and(&neg_cipher_i, pub_key_j, rand3);
    let c_neg_xor_and = embed_and(&c_neg_xor, pub_key_j, rand4);

    let mut res = Vec::new();
    for l in 0..32 {
        let mut temp = dot_mod(&cipher_j_and[l], &neg_cipher_i_and[l], pub_key_j);
        for u in 0..l {
            temp = dot_mod(&temp, &c_neg_xor_and[u], pub_key_j);
        }
        res.push(temp);
    }

    let mut rng = rand::thread_rng();
    res.shuffle(&mut rng);
    res
}

/// Called by supplier 2, w.r.t. the document of gm_eval_honest
/// Returns True if myNumber <= otherNumber
///                 (number2 <= number1)
fn compare_leq_honest(eval_res: &Vec<Vec<BigInt>>, priv_key: &(BigInt, BigInt)) -> bool {
    let mut one_cnt = 0;
    for cipher in eval_res {
        if decrypt_bit_and(cipher, priv_key) == 1 {
            one_cnt += 1;
        }
    }

    assert!(one_cnt <= 1);
    one_cnt == 0
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

impl Hashable for usize {
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

fn hash_flat<T: Hashable>(input: &T) -> u64 {
    let mut hasher = Sha256::new();
    input.hash_flat(&mut hasher);
    u64::from_le_bytes(hasher.finalize().to_vec()[..8].try_into().unwrap())
}

/// j is 1 and i is 2...
/// Called by supplier 1.
/// Returns a proof to the judge that Dec(cipher_ij, pub_key_j) = Dec(cipher_i, pub_key_i)
/// without revealing plaintexts
fn proof_eval(
    cipher_i: &Vec<BigInt>,
    cipher_j: &Vec<BigInt>,
    cipher_ij: &Vec<BigInt>,
    number1: BigInt,
    pub_key_i: &BigInt,
    pub_key_j: &BigInt,
    r1: &Vec<BigInt>,
    r12: &Vec<BigInt>,
    sound_param: usize,
) -> (Vec<Vec<Vec<BigInt>>>, Vec<Vec<(BigInt, BigInt, BigInt)>>) {
    assert_eq!(cipher_i.len(), 32);
    assert_eq!(cipher_j.len(), 32);

    let bits_v = format!("{:032b}", number1);

    // the following lines differ from the original Python implementation
    let mut strain_rng = StrainRandomGenerator::new();

    // Generate coins_delta, coins_gamma, and coins_gamma2
    let mut coins_delta = vec![vec![BigInt::zero(); sound_param]; 32];
    let mut coins_gamma = vec![vec![BigInt::zero(); sound_param]; 32];
    let mut coins_gamma2 = vec![vec![BigInt::zero(); sound_param]; 32];

    let mut rng = StdRng::from_entropy();
    for l in 0..32 {
        for m in 0..sound_param {
            coins_delta[l][m] = BigInt::from(rng.gen_range(0..2));
            coins_gamma[l][m] = strain_rng.get_next_random(&(pub_key_i - BigInt::one()));
            coins_gamma2[l][m] = strain_rng.get_next_random(&(pub_key_j - BigInt::one()));
        }
    }

    // Encrypt coins using GM scheme
    let gamma: Vec<Vec<BigInt>> = coins_delta
        .iter()
        .enumerate()
        .map(|(l, delta_row)| {
            delta_row
                .iter()
                .enumerate()
                .map(|(m, delta)| encrypt_bit_gm_coin(delta, pub_key_i, coins_gamma[l][m].clone()))
                .collect()
        })
        .collect();

    let gamma2: Vec<Vec<BigInt>> = coins_delta
        .iter()
        .enumerate()
        .map(|(l, delta_row)| {
            delta_row
                .iter()
                .enumerate()
                .map(|(m, delta)| encrypt_bit_gm_coin(delta, pub_key_j, coins_gamma2[l][m].clone()))
                .collect()
        })
        .collect();

    /* the non-interactive version of `P^EVAL`*/
    let p_eval = vec![
        gamma.clone(),
        gamma2.clone(),
        /* to ensure all are enclosed in Vec<Vec<BigInt>> */
        vec![cipher_i.clone()],
        vec![cipher_j.clone()],
        vec![cipher_ij.clone()],
        /**/
    ];
    let h = hash_flat(&p_eval);

    let mut rng_seed = StdRng::seed_from_u64(h);

    let plaintext_and_coins: Vec<Vec<(BigInt, BigInt, BigInt)>> = (0..32)
        .map(|l| {
            (0..sound_param)
                .map(|m| {
                    if rng_seed.gen::<u8>() % 2 == 0 {
                        (
                            coins_delta[l][m].clone(),
                            coins_gamma[l][m].clone(),
                            coins_gamma2[l][m].clone(),
                        )
                    } else {
                        (
                            &coins_delta[l][m]
                                ^ BigInt::from(
                                    bits_v.chars().nth(l).unwrap().to_digit(10).unwrap(),
                                ),
                            (&coins_gamma[l][m] * &r1[l]) % pub_key_i,
                            (&coins_gamma2[l][m] * &r12[l]) % pub_key_j,
                        )
                    }
                })
                .collect()
        })
        .collect();

    (p_eval, plaintext_and_coins)
}

/// Called by the judge to verify proof; returns result if pass or None on failure
fn verify_eval(
    p_eval: Vec<Vec<Vec<BigInt>>>,
    plaintext_and_coins: Vec<Vec<(BigInt, BigInt, BigInt)>>,
    n1: &BigInt,
    n2: &BigInt,
    sound_param: usize,
) -> Option<()> {
    let (gamma, gamma2, cipher_i, cipher_j, cipher_ij) =
        (&p_eval[0], &p_eval[1], &p_eval[2], &p_eval[3], &p_eval[4]);

    let h = hash_flat(&p_eval);
    let mut rng_seed = StdRng::seed_from_u64(h);

    for l in 0..32 {
        assert_eq!(plaintext_and_coins[l].len(), sound_param);
        for m in 0..sound_param {
            let (plaintext, coins_gamma, coins_gamma2) = &plaintext_and_coins[l][m];
            if rng_seed.gen::<u8>() % 2 == 0 {
                let detc1 = encrypt_bit_gm_coin(plaintext, n1, coins_gamma.clone());
                let detc2 = encrypt_bit_gm_coin(plaintext, n2, coins_gamma2.clone());
                if detc1 != gamma[l][m] || detc2 != gamma2[l][m] {
                    return None;
                }
            } else {
                let product1 = (&gamma[l][m] * &cipher_i[0][l]/* this 0 is the result of the extra enclosing happened in `p_eval`*/)
                    % n1;
                let product2 = (&gamma2[l][m] * &cipher_ij[0][l]) % n2;
                if encrypt_bit_gm_coin(plaintext, n1, coins_gamma.clone()) != product1
                    || encrypt_bit_gm_coin(plaintext, n2, coins_gamma2.clone()) != product2
                {
                    return None;
                }
            }
        }
    }
    Some(())
}

fn get_rand_jn1(n: &BigInt, rng: Option<ChaCha20Rng>) -> BigInt {
    let mut rng = rng.unwrap_or(/* default value */ ChaCha20Rng::from_entropy());
    loop {
        let r = rng.gen_bigint_range(&BigInt::zero(), &n);

        if r.jacobi(&n) == 1 {
            return r;
        }
    }
}

fn set_rand_seed(num_list: &[BigInt]) -> ChaCha20Rng {
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

fn proof_dlog_eq(
    sigma: &BigInt,
    y: &BigInt,
    n: &BigInt,
    iters: Option<usize>,
) -> Vec<(BigInt, BigInt, BigInt)> {
    let iters = iters.unwrap_or(/* default value */ 10);

    let mut p_dlog = Vec::new();
    let z = n - BigInt::one();

    let y_pow_sigma = y.modpow(sigma, n);
    let z_pow_sigma = z.modpow(sigma, n);

    for i in 0..iters {
        let r = get_rand_jn1(n, None);

        let t1 = y.modpow(&r, n);
        let t2 = z.modpow(&r, n);

        let rng = set_rand_seed(&[
            y.clone(),
            z.clone(),
            y_pow_sigma.clone(),
            z_pow_sigma.clone(),
            t1.clone(),
            t2.clone(),
            BigInt::from(i),
        ]);

        let c = get_rand_jn1(n, Some(rng));
        let s = r + (c * sigma);

        p_dlog.push((t1, t2, s));
    }

    p_dlog
}

fn verify_dlog_eq(
    n: &BigInt,
    y: &BigInt,
    y_pow_r: &BigInt,
    z_pow_r: &BigInt,
    p_dlog: &[(BigInt, BigInt, BigInt)],
    k: Option<usize>,
) -> bool {
    let k = k.unwrap_or(/* default value */ 10);
    if p_dlog.len() < k {
        println!("Insufficient number of rounds");
        return false;
    }

    println!("Sufficient number of rounds test: Passed");

    let z = n - BigInt::one();

    for (i, proof) in p_dlog.iter().take(k).enumerate() {
        let (t1, t2, s) = proof;
        let rng = set_rand_seed(&[
            y.clone(),
            z.clone(),
            y_pow_r.clone(),
            z_pow_r.clone(),
            t1.clone(),
            t2.clone(),
            BigInt::from(i),
        ]);

        let c = get_rand_jn1(n, Some(rng));

        if y.modpow(s, n) != t1 * y_pow_r.modpow(&c, n) % n {
            return false;
        }

        if z.modpow(s, n) != t2 * z_pow_r.modpow(&c, n) % n {
            return false;
        }
    }
    true
}

#[cfg(test)] // This module is included only during testing
mod tests {
    use super::*;
    use crate::gm::{
        decrypt_bit_gm, decrypt_gm, dot_mod, embed_and, embed_bit_and, encrypt_bit_and,
        encrypt_bit_gm, encrypt_gm, encrypt_gm_coin, generate_keys, get_next_random,
    };
    use num_traits::ToPrimitive;
    use std::collections::HashMap;
    use std::time::Instant;

    enum StrainProof {
        MEPermutations((HashMap<usize, usize>, HashMap<usize, HashMap<usize, BigInt>>)),
        AMPermutations((HashMap<usize, usize>, Vec<Vec<BigInt>>)),
        HashInput(
            HashMap<
                usize,
                (HashMap<usize, HashMap<usize, BigInt>>, HashMap<usize, HashMap<usize, BigInt>>),
            >,
        ),
    }

    fn divm(a: &BigInt, b: &BigInt, n: &BigInt) -> BigInt {
        let b_inv = b.modinv(n).unwrap();
        (a * b_inv) % n
    }

    fn standard_deviation(data: &[f64], mean: f64) -> f64 {
        (data.iter().map(|value| (value - mean).powi(2)).sum::<f64>() / data.len() as f64).sqrt()
    }

    fn rand32(n: &BigInt) -> Vec<BigInt> {
        let mut result = Vec::new();
        for _ in 0..32 {
            result.push(get_next_random(n));
        }
        result
    }

    fn generate_rand_matrix(n: &BigInt, rows: usize, cols: usize) -> Vec<Vec<BigInt>> {
        let mut matrix = Vec::new();
        for _ in 0..rows {
            let mut row = Vec::new();
            for _ in 0..cols {
                row.push(get_next_random(n));
            }
            matrix.push(row);
        }
        matrix
    }

    fn compute_proof_shuffle(res: &[Vec<BigInt>], n2: &BigInt) -> HashMap<usize, StrainProof> {
        let (ae_permutation_desc, ae_permutation, ae_reencrypt_factors) =
            compute_permutation(res, n2);

        let challenges_length = 40;
        let mut am_permutations = HashMap::new();
        let mut me_permutations = HashMap::new();

        for i in 0..challenges_length {
            let am = compute_permutation(res, n2);
            am_permutations.insert(i as usize, am.clone());
            let (am_permutation_desc, am_permutation, am_reencrypt_factors) = am;

            let mut me_permutation_desc = HashMap::new();
            let mut me_permutation = HashMap::new();
            let mut me_reencrypt_factors = HashMap::new();
            for j in 0..res.len() {
                me_permutation_desc.insert(am_permutation_desc[&j], ae_permutation_desc[&j]);
            }

            for j in 0..res.len() {
                let mut rs = HashMap::new();
                let mut and_encryptions = HashMap::new();
                for k in 0..challenges_length {
                    let r1: &BigInt = &ae_reencrypt_factors[j][k];
                    let r2: &BigInt = &am_reencrypt_factors[j][k];
                    let r: BigInt = divm(r1, r2, n2);
                    rs.insert(k as usize, r.clone());
                    let rsquare = r.modpow(&BigInt::from(2), n2);
                    let reencryption = (rsquare * &am_permutation[&j][&k]) % n2;
                    and_encryptions.insert(k as usize, reencryption);
                }
                me_permutation.insert(me_permutation_desc[&j].clone(), and_encryptions);
                me_reencrypt_factors.insert(j as usize, rs);
            }
            me_permutations
                .insert(i as usize, (me_permutation_desc, me_permutation, me_reencrypt_factors));
        }

        let mut proof: HashMap<usize, StrainProof> = HashMap::new();
        let mut hash_input = HashMap::new();
        hash_input.insert(0 as usize, (ae_permutation.clone(), HashMap::new()));
        for i in 0..challenges_length {
            hash_input.insert(
                (i + 1) as usize,
                (am_permutations[&i].1.clone(), me_permutations[&i].1.clone()),
            );
        }
        let h = hash_flat(&hash_input);
        let bitstring =
            format!("{:0256b}", BigInt::from_bytes_be(num_bigint::Sign::Plus, &h.to_be_bytes()));

        proof.insert(0 as usize, StrainProof::HashInput(hash_input));
        for i in 0..challenges_length {
            if bitstring.chars().nth(i).unwrap() == '0' {
                let (am_perm_desc, am_reencrypt_factors) =
                    (&am_permutations[&i].0, &am_permutations[&i].2); /* plucking the first and third elements of the returned tuple */
                proof.insert(
                    i + 1 as usize,
                    StrainProof::AMPermutations((
                        am_perm_desc.clone(),
                        am_reencrypt_factors.clone(),
                    )),
                );
            } else {
                let (me_perm_desc, me_reencrypt_factors) =
                    (&me_permutations[&i].0, &me_permutations[&i].2);
                proof.insert(
                    i + 1 as usize,
                    StrainProof::MEPermutations((
                        me_perm_desc.clone(),
                        me_reencrypt_factors.clone(),
                    )),
                );
            }
        }

        proof
    }

    fn compute_permutation(
        res: &[Vec<BigInt>],
        n: &BigInt,
    ) -> (HashMap<usize, usize>, HashMap<usize, HashMap<usize, BigInt>>, Vec<Vec<BigInt>>) {
        let seed = get_next_random(n);
        let permutation_desc = permute(res.len(), &seed);

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
                and_encryptions.insert(j, reencryption);
            }

            output_permutation.insert(permutation_desc[&i], and_encryptions);
            reencrypt_factors.push(rs);
        }

        (permutation_desc, output_permutation, reencrypt_factors)
    }

    fn bigint_to_seed(bigint: &BigInt) -> [u8; 32] {
        // Convert BigInt to bytes
        let bytes = bigint.to_signed_bytes_le();

        // Hash the bytes to 32 bytes using SHA-256
        let hash = Sha256::digest(&bytes);

        // Convert hash output to a 32-byte array
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash);
        seed
    }

    fn permute(length: usize, seed_bigint: &BigInt) -> HashMap<usize, usize> {
        let seed = bigint_to_seed(&seed_bigint);
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut permutation: HashMap<usize, usize> = (0..length).map(|i| (i, i)).collect();

        for i in 0..(length - 1) {
            let index = rng.gen_range(i..length);
            let value_i = permutation[&i];
            let value_index = permutation[&index];

            permutation.insert(i, value_index);
            permutation.insert(index, value_i);
        }

        permutation
    }

    fn verify_shuffle(
        proof: &HashMap<usize, StrainProof>,
        n2: &BigInt,
        res: &[Vec<BigInt>],
    ) -> bool {
        let challenges_length = 40;
        let StrainProof::HashInput(hash_input) = &proof[&0] else { todo!() };

        let h = hash_flat(hash_input);
        let bitstring =
            format!("{:0256b}", BigInt::from_bytes_be(num_bigint::Sign::Plus, &h.to_be_bytes()));

        let ae_permutation = &hash_input[&0].0;
        let mut am_permutations = HashMap::new();
        let mut me_permutations = HashMap::new();

        for i in 0..challenges_length {
            let (am_permutation, me_permutation) = &hash_input[&(i + 1)];
            am_permutations.insert(i, am_permutation.clone());
            me_permutations.insert(i, me_permutation.clone());
        }

        let mut success = true;

        for (i, bit) in bitstring.chars().enumerate().take(challenges_length) {
            if bit == '0' {
                // Open A-M permutation
                if let Some(StrainProof::AMPermutations((am_perm_desc, am_reencrypt_factors))) =
                    &proof.get(&(i + 1))
                {
                    for j in 0..am_perm_desc.len() {
                        for k in 0..challenges_length {
                            let lhs = &am_permutations[&i][&am_perm_desc[&j]][&k];
                            let r = &am_reencrypt_factors[j][k];
                            let rsquare = r.modpow(&BigInt::from(2), n2);
                            let rhs = (rsquare * &res[j][k]) % n2;
                            if lhs != &rhs {
                                success = false;
                            }
                        }
                    }
                }
            } else {
                // Open M-E permutation
                if let Some(StrainProof::MEPermutations((me_perm_desc, me_reencrypt_factors))) =
                    &proof.get(&(i + 1))
                {
                    for j in 0..me_perm_desc.len() {
                        for k in 0..challenges_length {
                            let lhs = &ae_permutation[&me_perm_desc[&j]][&k];
                            let r: &BigInt = &me_reencrypt_factors[&j][&k];
                            let rsquare = r.modpow(&BigInt::from(2), n2);
                            let rhs = (rsquare * &me_permutations[&i][&j][&k]) % n2;
                            if lhs != &rhs {
                                success = false;
                            }
                        }
                    }
                }
            }
        }

        success
    }

    fn verify_proof_enc(proof: Vec<Vec<Vec<BigInt>>>) -> bool {
        let n1 = &proof[0][0][0];

        let c1: &Vec<BigInt> = &proof[1][0];

        let r1t4s: &Vec<Vec<BigInt>> = &proof[2];

        let h = hash_flat(r1t4s);
        let bitstring =
            format!("{:0256b}", BigInt::from_bytes_be(num_bigint::Sign::Plus, &h.to_be_bytes()));

        let mut success = true;

        for (i, bit) in bitstring.chars().enumerate().take(40) {
            let q = if bit == '1' { 1 } else { 0 };

            let proof_per_bit: &Vec<BigInt> =
                &proof[i + 3 /* this is how proof is structured */][0];

            for (j, c1_val) in c1.iter().enumerate() {
                let a = &r1t4s[i][j];
                let rhs = (a * c1_val.modpow(&BigInt::from(2 * q), n1)) % n1;

                let r = &proof_per_bit[j];
                let lhs = r.modpow(&BigInt::from(4), n1);

                if lhs != rhs {
                    success = false;
                }
            }
        }

        success
    }

    fn compute_proof_enc(c1: Vec<BigInt>, n1: &BigInt, r1: &[BigInt]) -> Vec<Vec<Vec<BigInt>>> {
        let mut rng = rand::thread_rng();

        let mut r1s: Vec<Vec<BigInt>> = Vec::new();
        let mut r1t4s: Vec<Vec<BigInt>> = Vec::new();

        for _ in 0..40 {
            let mut r1s_per_bit: Vec<BigInt> = Vec::new();
            let mut r1t4s_per_bit: Vec<BigInt> = Vec::new();

            for _ in &c1 {
                let r_1 = rng.gen_bigint_range(&BigInt::zero(), n1);
                r1s_per_bit.push(r_1.clone());
                r1t4s_per_bit.push(r_1.modpow(&BigInt::from(4), n1));
            }

            r1s.push(r1s_per_bit);
            r1t4s.push(r1t4s_per_bit);
        }

        let h = hash_flat(&r1t4s);
        let bitstring =
            format!("{:0256b}", BigInt::from_bytes_be(num_bigint::Sign::Plus, &h.to_be_bytes()));

        let mut proof: Vec<Vec<Vec<BigInt>>> = Vec::new();
        proof.push(vec![vec![n1.clone()]]);
        proof.push(vec![c1.clone()]);
        proof.push(r1t4s.clone());

        for (i, bit) in bitstring.chars().enumerate().take(40) {
            let mut proof_per_bit: Vec<BigInt> = Vec::new();
            let q = if bit == '1' { BigInt::one() } else { BigInt::zero() };

            for j in 0..c1.len() {
                let r = (&r1[j].modpow(&q, n1) * &r1s[i][j]) % n1;
                proof_per_bit.push(r);
            }

            proof.push(vec![proof_per_bit]);
        }

        proof
    }

    #[test]
    fn strain_main() {
        let keys1 = generate_keys(None);
        let n1 = &keys1.pub_key;
        let keys2 = generate_keys(None);
        let n2 = &keys2.pub_key;

        let mut rng = rand::thread_rng();
        let v1 = rng.gen_bigint_range(&BigInt::from(0u32), &(BigInt::from(1u32) << 31));
        let r1 = rand32(n1);
        let c1 = encrypt_gm_coin(&v1, n1, &r1);

        let v2 = rng.gen_bigint_range(&BigInt::from(0u32), &(BigInt::from(1u32) << 31));
        let r2 = rand32(n2);
        let c2 = encrypt_gm_coin(&v2, n2, &r2);

        let r12 = rand32(n2);
        println!("Encryption timings...");
        let mut timings = Vec::new();

        let mut c12 = None;
        timings.extend((0..10).map(|_| {
            let start_time = Instant::now();
            c12 = Some(encrypt_gm_coin(&v1, n2, &r12));
            start_time.elapsed().as_secs_f64()
        }));

        let avg = timings.iter().sum::<f64>() / timings.len() as f64;
        let rstd = 100.0
            * (timings.iter().map(|t| (t - avg).powi(2)).sum::<f64>() / timings.len() as f64)
                .sqrt()
            / avg;
        println!("Avg: {:.3}ms, rel. std. dev.: {:.2}%", avg * 1000.0, rstd);

        println!("Decryption timings...");
        let mut decrypt_timings = Vec::new();
        for _ in 0..10 {
            let start_time = Instant::now();
            decrypt_gm(&encrypt_gm_coin(&v1, n2, &r12), &keys2.priv_key);
            decrypt_timings.push(start_time.elapsed().as_secs_f64());
        }
        let avg = decrypt_timings.iter().sum::<f64>() / decrypt_timings.len() as f64;
        let rstd = 100.0
            * (decrypt_timings.iter().map(|t| (t - avg).powi(2)).sum::<f64>()
                / decrypt_timings.len() as f64)
                .sqrt()
            / avg;
        println!("Avg: {:.2}ms, rel. std. dev.: {:.2}%", avg * 1000.0, rstd);

        println!("Eval computation timings...");
        let mut eval_timings = Vec::new();
        let rand1 = generate_rand_matrix(n2, 32, 128);
        let rand2 = generate_rand_matrix(n2, 32, 128);
        let rand3 = generate_rand_matrix(n2, 32, 128);
        let rand4 = generate_rand_matrix(n2, 32, 128);

        let mut eval_res = None;
        for _ in 0..10 {
            let start_time = Instant::now();
            eval_res = Some(gm_eval_honest(
                &v1,
                &c12.as_ref().unwrap(),
                &c2,
                n2,
                &rand1,
                &rand2,
                &rand3,
                &rand4,
            ));
            eval_timings.push(start_time.elapsed().as_secs_f64());
        }
        let avg = eval_timings.iter().sum::<f64>() / eval_timings.len() as f64;
        let rstd = 100.0
            * (eval_timings.iter().map(|t| (t - avg).powi(2)).sum::<f64>()
                / eval_timings.len() as f64)
                .sqrt()
            / avg;
        println!("avg: {:.2}s, rel. std. dev.: {:.2}%", avg, rstd);

        assert_eq!((v2 <= v1), compare_leq_honest(&eval_res.unwrap(), &keys2.priv_key));
    }

    #[test]
    fn test_gm_eval_honest() {
        let keys1 = generate_keys(None);
        let n1 = &keys1.pub_key;

        let mut rng = rand::thread_rng();
        let v1 = rng.gen_bigint_range(&BigInt::from(0u32), &(BigInt::from(1u32) << 31));
        let r1 = rand32(n1);
        let c1 = encrypt_gm_coin(&v1, n1, &r1);

        let v2 = rng.gen_bigint_range(&BigInt::from(0u32), &(BigInt::from(1u32) << 31));
        let r2 = rand32(n1);
        let c2 = encrypt_gm_coin(&v2, n1, &r2);

        let rand1 = generate_rand_matrix(n1, 32, 128);
        let rand2 = generate_rand_matrix(n1, 32, 128);
        let rand3 = generate_rand_matrix(n1, 32, 128);
        let rand4 = generate_rand_matrix(n1, 32, 128);

        let eval_res = gm_eval_honest(&v1, &c1, &c2, n1, &rand1, &rand2, &rand3, &rand4);

        assert_eq!((v2 <= v1), compare_leq_honest(&eval_res, &keys1.priv_key), "Evaluation failed");
    }

    #[test]
    fn test_proof_eval() {
        println!("test_proof_eval");

        // Generate two key pairs.
        let keys1 = generate_keys(None);
        let n1 = &keys1.pub_key;
        let (p1, q1) = keys1.priv_key;

        let keys2 = generate_keys(None);
        let n2 = &keys2.pub_key;
        let (p2, q2) = keys2.priv_key;

        println!("test honest model");
        let iters = 1;
        let mut rng = rand::thread_rng();

        for i in 0..iters {
            println!("i = {}", i);

            let v1: BigInt = rng.gen_bigint_range(&BigInt::from(0u32), &(BigInt::from(1u32) << 31));
            let start_time = Instant::now();
            let cipher_i = encrypt_gm(&v1, n1);
            let r1 = rand32(n1);
            println!("Enc elapsed: {:?}", start_time.elapsed());

            let v2: BigInt = rng.gen_bigint_range(&BigInt::from(0u32), &(BigInt::from(1u32) << 31));
            let cipher_j = encrypt_gm(&v2, n2);

            let cipher_ij = encrypt_gm(&v1, n2);
            let r12 = rand32(n2);

            let start_time = Instant::now();
            let (p_eval, plaintext_and_coins) = proof_eval(
                &cipher_i,
                &cipher_j,
                &cipher_ij,
                v1.clone(),
                n1,
                n2,
                &r1,
                &r12,
                40, /* soundness parameter */
            );
            println!("p_eval elapsed: {:?}", start_time.elapsed());

            let start_time = Instant::now();
            let eval_res =
                Some(verify_eval(p_eval.clone(), plaintext_and_coins.clone(), n1, n2, 40));
            println!("verify eval elapsed: {:?}", start_time.elapsed());

            assert!(eval_res.is_some(), "Proof verification failed");

            // The bit-flipping tests are commented out as in the original Python code.
            /*
            // Example for flipping one bit (if you wish to test failures):
            let bit_to_flip = 1 << rng.gen_range(0, 31);
            let v1_flipped = &v1 ^ BigInt::from(bit_to_flip);
            let cipher_ij_flipped = encrypt_gm(&v1_flipped, n2);

            let (P_eval_x1, plaintext_and_coins_x1) = proof_eval(&cipher_i, &cipher_j, &cipher_ij, v1_flipped.clone(), n1, n2);
            let (P_eval_x2, plaintext_and_coins_x2) = proof_eval(&cipher_i, &cipher_j, &cipher_ij_flipped, v1.clone(), n1, n2);
            let (P_eval_x3, plaintext_and_coins_x3) = proof_eval(&cipher_i, &cipher_j, &cipher_ij_flipped, v1_flipped, n1, n2);
            assert!(verify_eval(P_eval_x1, plaintext_and_coins_x1, n1, n2).is_none());
            assert!(verify_eval(P_eval_x2, plaintext_and_coins_x2, n1, n2).is_none());
            assert!(verify_eval(P_eval_x3, plaintext_and_coins_x3, n1, n2).is_none());
            */
        }
        println!("test_proof_eval pass");
    }

    #[test]
    fn test_dlog_eq() {
        let keys = generate_keys(None);
        let n = keys.pub_key;
        let z = n.clone() - BigInt::one();
        let (p, q) = keys.priv_key;

        let mut rng = rand::thread_rng();
        let r = rng.gen_bigint_range(&BigInt::zero(), &((p - 1) * (q - 1)));
        let y = rng.gen_bigint_range(&BigInt::zero(), &n);

        let y_pow_r = y.modpow(&r, &n);
        let z_pow_r = z.modpow(&r, &n);

        // Proof computation timings
        println!("Proof DLOG computation timings...");
        let mut timings = Vec::new();
        for _ in 0..10 {
            let start_time = Instant::now();
            let p_dlog = proof_dlog_eq(&r, &y, &n, Some(40 as usize));
            timings.push(start_time.elapsed().as_secs_f64());
        }
        let avg = timings.iter().sum::<f64>() / timings.len() as f64;
        let rstd = standard_deviation(&timings, avg) / avg;
        println!("avg: {:.2}ms, rel.std.dev.: {:.2}%", avg * 1000.0, rstd * 100.0);

        // Verification computation timings
        println!("Verify DLOG computation timings...");
        let mut verify_timings = Vec::new();
        let p_dlog = proof_dlog_eq(&r, &y, &n, Some(40 as usize)); // Reuse generated proof
        for _ in 0..10 {
            let start_time = Instant::now();
            assert!(verify_dlog_eq(&n, &y, &y_pow_r, &z_pow_r, &p_dlog, Some(40 as usize)));
            verify_timings.push(start_time.elapsed().as_secs_f64());
        }
        let avg_verify = verify_timings.iter().sum::<f64>() / verify_timings.len() as f64;
        let rstd_verify = standard_deviation(&verify_timings, avg_verify) / avg_verify;
        println!("avg: {:.2}ms, rel.std.dev.: {:.2}%", avg_verify * 1000.0, rstd_verify * 100.0);
    }

    #[test]
    fn test_shuffle_verify() {
        let keys1 = generate_keys(None);
        let n1 = keys1.pub_key;
        let (p1, q1) = keys1.priv_key;

        let keys2 = generate_keys(None);
        let n2 = keys2.pub_key;
        let (p2, q2) = keys2.priv_key;

        let mut rng = rand::thread_rng();
        let v1 = rng.gen_bigint_range(&BigInt::from(0), &BigInt::from(2u32.pow(31)));
        let r1 = rand32(&n1);
        let c1 = encrypt_gm_coin(&v1, &n1, &r1);

        let v2 = rng.gen_bigint_range(&BigInt::from(0), &BigInt::from(2u32.pow(31)));
        let r2 = rand32(&n2);
        let c2 = encrypt_gm_coin(&v2, &n2, &r2);

        let r12 = rand32(&n2);
        let c12 = encrypt_gm_coin(&v1, &n2, &r12);

        let mut rand1 = Vec::new();
        let mut rand2 = Vec::new();
        let mut rand3 = Vec::new();
        let mut rand4 = Vec::new();

        for _ in 0..32 {
            let mut x = Vec::new();
            let mut y = Vec::new();
            let mut x2 = Vec::new();
            let mut y2 = Vec::new();
            for _ in 0..128 {
                x.push(get_next_random(&n2));
                y.push(get_next_random(&n2));
                x2.push(get_next_random(&n2));
                y2.push(get_next_random(&n2));
            }
            rand1.push(x);
            rand2.push(y);
            rand3.push(x2);
            rand4.push(y2);
        }

        let res = gm_eval_honest(&v1, &c12, &c2, &n2, &rand1, &rand2, &rand3, &rand4);
        /* TODO: can the vector coming from `res` be empty? */
        assert_eq!(v2 <= v1, compare_leq_honest(&res, &(p2.clone(), q2.clone())));

        // Compute proof of shuffle
        let proof = compute_proof_shuffle(&res, &n2);

        // Timing for verifying shuffle
        let mut timings = Vec::new();
        println!("VerifyShuffle timings...");
        for _ in 0..10 {
            let start_time = Instant::now();
            let success = verify_shuffle(&proof, &n2, &res);
            timings.push(start_time.elapsed().as_secs_f64());
            assert!(success, "verify_shuffle failed");
        }

        // Compute and print timing statistics
        let avg = timings.iter().copied().sum::<f64>() / timings.len() as f64;
        let rstd = 100.0
            * (timings.iter().map(|t| (t - avg).powi(2)).sum::<f64>() / timings.len() as f64)
                .sqrt()
            / avg;
        println!("Avg: {:.3}ms, rel. std. dev.: {:.2}%", avg * 1000.0, rstd);
    }

    #[test]
    fn test_proof_enc() {
        let mut compute_timings = Vec::new();
        let mut verify_timings = Vec::new();

        println!("ProofEnc timings...");

        for _ in 0..10 {
            let keys1 = generate_keys(None);
            let n1 = &keys1.pub_key;
            let v1 = BigInt::from(rand::thread_rng().gen_range(0..(1 << 31 - 1)));
            let r1 = rand32(n1);
            let c1 = encrypt_gm_coin(&v1, n1, &r1);

            let start_time = Instant::now();
            let proof = compute_proof_enc(c1, n1, &r1);
            compute_timings.push(start_time.elapsed().as_secs_f64());

            let start_time = Instant::now();
            assert!(verify_proof_enc(proof));
            verify_timings.push(start_time.elapsed().as_secs_f64());
        }

        let avg_compute: f64 = compute_timings.iter().sum::<f64>() / compute_timings.len() as f64;
        let std_compute: f64 = standard_deviation(&compute_timings, avg_compute);
        println!("Avg: {:.3}ms rel. std. dev.: {:.2}%", avg_compute * 1000.0, std_compute);

        let avg_verify: f64 = verify_timings.iter().sum::<f64>() / verify_timings.len() as f64;
        let std_verify: f64 = standard_deviation(&verify_timings, avg_verify);
        println!(
            "VerifyProofEnc timings... Avg: {:.3}ms rel. std. dev.: {:.2}%",
            avg_verify * 1000.0,
            std_verify
        );
    }
}
