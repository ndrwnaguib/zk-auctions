use num_bigint::{BigInt, RandBigInt};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::gm::{dot_mod, embed_and, encrypt_bit_gm_coin, StrainRandomGenerator};
use crate::utils::{
    compute_permutation, divm, get_rand_jn1, hash_flat, set_rand_seed, StrainProof,
};
use num_traits::{One, Zero};

use crate::protocols::strain::soundness::StrainSecurityParams;

/// Configuration struct for the Strain protocol
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StrainConfig {
    pub challenges_length: u32,
    pub bit_length: usize,
    pub default_dlog_iters: u32,
    pub modpow_exponent: u32,
}

impl Default for StrainConfig {
    fn default() -> Self {
        Self { challenges_length: 40, bit_length: 32, default_dlog_iters: 10, modpow_exponent: 4 }
    }
}

impl StrainConfig {
    /// Create a new StrainConfig with custom parameters
    pub fn new(
        challenges_length: u32,
        bit_length: usize,
        default_dlog_iters: u32,
        modpow_exponent: u32,
    ) -> Self {
        Self { challenges_length, bit_length, default_dlog_iters, modpow_exponent }
    }

    /// Create a low-security configuration (fast, for testing)
    pub fn low_security() -> Self {
        Self { challenges_length: 40, bit_length: 32, default_dlog_iters: 10, modpow_exponent: 4 }
    }
}

/// Trait defining the bidder's verification operations in the Strain protocol
pub trait StrainBidder {
    /// Compute proof of encryption
    fn compare_proof_enc(
        &self,
        c1: Vec<BigInt>,
        n1: &BigInt,
        r1: &[BigInt],
    ) -> Vec<Vec<Vec<BigInt>>>;

    /// Generate proof of evaluation
    fn proof_eval(
        &self,
        cipher_i: &Vec<BigInt>,
        cipher_j: &Vec<BigInt>,
        cipher_ij: &Vec<BigInt>,
        number1: BigInt,
        pub_key_i: &BigInt,
        pub_key_j: &BigInt,
        r1: &Vec<BigInt>,
        r12: &Vec<BigInt>,
    ) -> (Vec<Vec<Vec<BigInt>>>, Vec<Vec<(BigInt, BigInt, BigInt)>>);

    /// Generate proof of discrete logarithm equality
    fn proof_dlog_eq(
        &self,
        sigma: &BigInt,
        y: &BigInt,
        n: &BigInt,
    ) -> Vec<(BigInt, BigInt, BigInt)>;

    /// Compute proof of shuffle
    fn compute_proof_shuffle(&self, res: &[Vec<BigInt>], n2: &BigInt) -> HashMap<u32, StrainProof>;

    /// Evaluate GM encryption honestly
    fn gm_eval_honest(
        &self,
        number1: &BigInt,
        cipher_i: &Vec<BigInt>,
        cipher_j: &Vec<BigInt>,
        pub_key_j: &BigInt,
        rand1: &Vec<Vec<BigInt>>,
        rand2: &Vec<Vec<BigInt>>,
        rand3: &Vec<Vec<BigInt>>,
        rand4: &Vec<Vec<BigInt>>,
    ) -> Vec<Vec<BigInt>>;

    /// Verify proof of encryption
    fn verify_proof_enc(&self, proof: Vec<Vec<Vec<BigInt>>>) -> bool;

    /// Verify proof of discrete logarithm equality
    fn verify_dlog_eq(
        &self,
        n: &BigInt,
        y: &BigInt,
        y_pow_r: &BigInt,
        z_pow_r: &BigInt,
        p_dlog: &[(BigInt, BigInt, BigInt)],
        k: Option<usize>,
    ) -> bool;

    /// Verify proof of shuffle
    fn verify_shuffle(
        &self,
        proof: &HashMap<u32, StrainProof>,
        n2: &BigInt,
        res: &[Vec<BigInt>],
    ) -> bool;
}

pub struct Bidder {
    config: StrainConfig,
    soundness_params: StrainSecurityParams,
}

impl Bidder {
    /// Create a new bidder instance with default configuration
    pub fn new() -> Self {
        Self { 
            config: StrainConfig::default(),
            soundness_params: StrainSecurityParams::default(),
        }
    }

    /// Create a new bidder instance with custom configuration
    pub fn with_config(config: StrainConfig, soundness_params: StrainSecurityParams) -> Self {
        Self { config, soundness_params }
    }
}

impl Default for Bidder {
    fn default() -> Self {
        Self::new()
    }
}

impl StrainBidder for Bidder {
    fn compare_proof_enc(
        &self,
        c1: Vec<BigInt>,
        n1: &BigInt,
        r1: &[BigInt],
    ) -> Vec<Vec<Vec<BigInt>>> {
        let mut rng = rand::thread_rng();

        let mut r1s: Vec<Vec<BigInt>> = Vec::new();
        let mut r1t4s: Vec<Vec<BigInt>> = Vec::new();

        for _ in 0..self.config.challenges_length {
            let mut r1s_per_bit: Vec<BigInt> = Vec::new();
            let mut r1t4s_per_bit: Vec<BigInt> = Vec::new();

            for _ in &c1 {
                let r_1 = rng.gen_bigint_range(&BigInt::zero(), n1);
                r1s_per_bit.push(r_1.clone());
                r1t4s_per_bit.push(r_1.modpow(&BigInt::from(self.config.modpow_exponent), n1));
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

        for (i, bit) in bitstring.chars().enumerate().take(self.config.challenges_length as usize) {
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

    fn proof_eval(
        &self,
        cipher_i: &Vec<BigInt>,
        cipher_j: &Vec<BigInt>,
        cipher_ij: &Vec<BigInt>,
        number1: BigInt,
        pub_key_i: &BigInt,
        pub_key_j: &BigInt,
        r1: &Vec<BigInt>,
        r12: &Vec<BigInt>,
    ) -> (Vec<Vec<Vec<BigInt>>>, Vec<Vec<(BigInt, BigInt, BigInt)>>) {
        assert_eq!(cipher_i.len(), self.config.bit_length);
        assert_eq!(cipher_j.len(), self.config.bit_length);

        let bits_v = format!("{number1:032b}");

        // the following lines differ from the original Python implementation
        let mut strain_rng = StrainRandomGenerator::new();

        // Generate coins_delta, coins_gamma, and coins_gamma2
        let mut coins_delta =
            vec![vec![BigInt::zero(); self.soundness_params.sound_param]; self.config.bit_length];
        let mut coins_gamma =
            vec![vec![BigInt::zero(); self.soundness_params.sound_param]; self.config.bit_length];
        let mut coins_gamma2 =
            vec![vec![BigInt::zero(); self.soundness_params.sound_param]; self.config.bit_length];

        let mut rng = StdRng::from_entropy();
        for l in 0..self.config.bit_length {
            for m in 0..self.soundness_params.sound_param {
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
                    .map(|(m, delta)| {
                        encrypt_bit_gm_coin(delta, pub_key_i, coins_gamma[l][m].clone())
                    })
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
                    .map(|(m, delta)| {
                        encrypt_bit_gm_coin(delta, pub_key_j, coins_gamma2[l][m].clone())
                    })
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

        let plaintext_and_coins: Vec<Vec<(BigInt, BigInt, BigInt)>> = (0..self.config.bit_length)
            .map(|l| {
                (0..self.soundness_params.sound_param)
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

    fn proof_dlog_eq(
        &self,
        sigma: &BigInt,
        y: &BigInt,
        n: &BigInt
    ) -> Vec<(BigInt, BigInt, BigInt)> {
        let iters = self.config.default_dlog_iters;

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

    fn compute_proof_shuffle(&self, res: &[Vec<BigInt>], n2: &BigInt) -> HashMap<u32, StrainProof> {
        let (ae_permutation_desc, ae_permutation, ae_reencrypt_factors) =
            compute_permutation(res, n2);

        let challenges_length = self.config.challenges_length;
        let mut am_permutations = HashMap::new();
        let mut me_permutations = HashMap::new();

        for i in 0..challenges_length {
            let am = compute_permutation(res, n2);
            am_permutations.insert(i, am.clone());
            let (am_permutation_desc, am_permutation, am_reencrypt_factors) = am;

            let mut me_permutation_desc = HashMap::new();
            let mut me_permutation = HashMap::new();
            let mut me_reencrypt_factors = HashMap::new();
            for j in 0..res.len() {
                me_permutation_desc
                    .insert(am_permutation_desc[&(j as u32)], ae_permutation_desc[&(j as u32)]);
            }

            for j in 0..res.len() {
                let mut rs = HashMap::new();
                let mut and_encryptions = HashMap::new();
                for k in 0..challenges_length {
                    let r1: &BigInt = &ae_reencrypt_factors[j][k as usize];
                    let r2: &BigInt = &am_reencrypt_factors[j][k as usize];
                    let r: BigInt = divm(r1, r2, n2);
                    rs.insert(k, r.clone());
                    let rsquare = r.modpow(&BigInt::from(2), n2);
                    let reencryption = (rsquare * &am_permutation[&(j as u32)][&{ k }]) % n2;
                    and_encryptions.insert(k, reencryption);
                }
                me_permutation.insert(me_permutation_desc[&(j as u32)], and_encryptions);
                me_reencrypt_factors.insert(j as u32, rs);
            }
            me_permutations.insert(i, (me_permutation_desc, me_permutation, me_reencrypt_factors));
        }

        let mut proof: HashMap<u32, StrainProof> = HashMap::new();
        let mut hash_input = HashMap::new();
        hash_input.insert(0_u32, (ae_permutation.clone(), HashMap::new()));
        for i in 0..challenges_length {
            hash_input
                .insert(i + 1, (am_permutations[&i].1.clone(), me_permutations[&i].1.clone()));
        }
        let h = hash_flat(&hash_input);
        let bitstring =
            format!("{:0256b}", BigInt::from_bytes_be(num_bigint::Sign::Plus, &h.to_be_bytes()));

        proof.insert(0_u32, StrainProof::HashInput(hash_input));
        for i in 0..challenges_length {
            if bitstring.chars().nth(i.try_into().unwrap()).unwrap() == '0' {
                let (am_perm_desc, am_reencrypt_factors) =
                    (&am_permutations[&i].0, &am_permutations[&i].2); /* plucking the first and third elements of the returned tuple */
                proof.insert(
                    i + 1_u32,
                    StrainProof::AMPermutations((
                        am_perm_desc.clone(),
                        am_reencrypt_factors.clone(),
                    )),
                );
            } else {
                let (me_perm_desc, me_reencrypt_factors) =
                    (&me_permutations[&i].0, &me_permutations[&i].2);
                proof.insert(
                    i + 1_u32,
                    StrainProof::MEPermutations((
                        me_perm_desc.clone(),
                        me_reencrypt_factors.clone(),
                    )),
                );
            }
        }

        proof
    }

    fn gm_eval_honest(
        &self,
        number1: &BigInt,
        cipher_i: &Vec<BigInt>,
        cipher_j: &Vec<BigInt>,
        pub_key_j: &BigInt,
        rand1: &Vec<Vec<BigInt>>,
        rand2: &Vec<Vec<BigInt>>,
        rand3: &Vec<Vec<BigInt>>,
        rand4: &Vec<Vec<BigInt>>,
    ) -> Vec<Vec<BigInt>> {
        assert_eq!(cipher_j.len(), self.config.bit_length);

        let neg_cipher_i: Vec<BigInt> =
            cipher_i.iter().map(|x| x * (pub_key_j - BigInt::one()) % pub_key_j).collect();
        let c_neg_xor = dot_mod(&neg_cipher_i, cipher_j, pub_key_j);

        let cipher_i_and = embed_and(cipher_i, pub_key_j, rand1);
        let cipher_j_and = embed_and(cipher_j, pub_key_j, rand2);
        let neg_cipher_i_and = embed_and(&neg_cipher_i, pub_key_j, rand3);
        let c_neg_xor_and = embed_and(&c_neg_xor, pub_key_j, rand4);

        let mut res = Vec::new();
        for l in 0..self.config.bit_length {
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

    fn verify_proof_enc(&self, proof: Vec<Vec<Vec<BigInt>>>) -> bool {
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

    fn verify_dlog_eq(
        &self,
        n: &BigInt,
        y: &BigInt,
        y_pow_r: &BigInt,
        z_pow_r: &BigInt,
        p_dlog: &[(BigInt, BigInt, BigInt)],
        k: Option<usize>,
    ) -> bool {
        let k = k.unwrap_or(/* default value */ 10) as usize;
        if p_dlog.len() < k {
            // println!("Insufficient number of rounds");
            return false;
        }

        // println!("Sufficient number of rounds test: Passed");

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

    fn verify_shuffle(
        &self,
        proof: &HashMap<u32, StrainProof>,
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

        for (i, bit) in bitstring.chars().enumerate().take(challenges_length as usize) {
            if bit == '0' {
                // Open A-M permutation
                if let Some(StrainProof::AMPermutations((am_perm_desc, am_reencrypt_factors))) =
                    &proof.get(&((i as u32) + 1))
                {
                    for j in 0..am_perm_desc.len() {
                        for k in 0..challenges_length {
                            let lhs = &am_permutations[&(i as u32)][&am_perm_desc[&(j as u32)]][&k];
                            let r: &_ = &am_reencrypt_factors[j][k as usize];
                            let rsquare = r.modpow(&BigInt::from(2), n2);
                            let rhs = (rsquare * &res[j][k as usize]) % n2;
                            if lhs != &rhs {
                                success = false;
                            }
                        }
                    }
                }
            } else {
                // Open M-E permutation
                if let Some(StrainProof::MEPermutations((me_perm_desc, me_reencrypt_factors))) =
                    &proof.get(&((i as u32) + 1))
                {
                    for j in 0..me_perm_desc.len() {
                        for k in 0..challenges_length {
                            let lhs = &ae_permutation[&me_perm_desc[&(j as u32)]][&k];
                            let r: &BigInt = &me_reencrypt_factors[&(j as u32)][&k];
                            let rsquare = r.modpow(&BigInt::from(2), n2);
                            let rhs =
                                (rsquare * &me_permutations[&(i as u32)][&(j as u32)][&k]) % n2;
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
}
