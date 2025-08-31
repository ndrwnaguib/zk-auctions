use num_bigint::BigInt;
use std::collections::HashMap;

use crate::utils::{get_rand_jn1, hash_flat, set_rand_seed, StrainProof};
use num_traits::One;

/// Trait defining the bidder's verification operations in the Strain protocol
pub trait StrainBidder {
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

/// Default implementation of the Bidder trait
pub struct Bidder;

impl Bidder {
    /// Create a new default bidder instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for Bidder {
    fn default() -> Self {
        Self::new()
    }
}

impl StrainBidder for Bidder {
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
