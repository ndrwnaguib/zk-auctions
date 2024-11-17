use rand::{rngs::StdRng, Rng, SeedableRng};
use rug::Integer;
use sha2::{Digest, Sha256};

use crate::gm::{
    decrypt_bit_and, decrypt_bit_gm, decrypt_gm, dot_mod, embed_and, embed_bit_and,
    encrypt_bit_and, encrypt_bit_gm, encrypt_bit_gm_coin, encrypt_gm, generate_keys,
};

/// Called by supplier 1, who bids number1
/// Compare number1 vs number2 without revealing number1
/// Encrypts the result with pub_key2 for later decryption by supplier 2
fn gm_eval_honest(
    number1: u32,
    cipher1: &Vec<Integer>,
    cipher2: &Vec<Integer>,
    pub_key2: &Integer,
    rand1: &[Integer],
    rand2: &[Integer],
    rand3: &[Integer],
    rand4: &[Integer],
) -> Vec<Integer> {
    assert_eq!(cipher2.len(), 32);
    let n = pub_key2.clone();

    let neg_cipher1: Vec<Integer> = cipher1.iter().map(|x| x * (&n - 1) % &n).collect();
    let c_neg_xor = dot_mod(&neg_cipher1, &cipher2, n);

    let cipher1_and = embed_and(&cipher1, pub_key2, rand1);
    let cipher2_and = embed_and(cipher2, pub_key2, rand2);
    let neg_cipher1_and = embed_and(&neg_cipher1, pub_key2, rand3);
    let c_neg_xor_and = embed_and(&c_neg_xor, pub_key2, rand4);

    let mut res = Vec::new();
    for l in 0..32 {
        let mut temp = dot_mod(&cipher2_and[l], &neg_cipher1_and[l], &n);
        for u in 0..l {
            temp = dot_mod(&temp, &c_neg_xor_and[u], &n);
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
fn compare_leq_honest(eval_res: &Vec<Integer>, priv_key: &Integer) -> bool {
    let mut one_cnt = 0;
    for cipher in eval_res {
        if decrypt_bit_and(cipher, priv_key) == "1" {
            one_cnt += 1;
        }
    }

    assert!(one_cnt <= 1);
    one_cnt == 0
}

/// Returns the hash value of a nested list structure
fn hash_flat(num_list: &Vec<Integer>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    fn hash_flat_recursively(h: &mut Sha256, obj: &Integer) {
        h.update(obj.to_string().as_bytes());
    }

    for num in num_list {
        hash_flat_recursively(&mut hasher, num);
    }
    hasher.finalize().to_vec()
}

/// j is 1 and i is 2...
/// Called by supplier 1.
/// Returns a proof to the judge that Dec(cipher12, pub_key2) = Dec(cipher1, pub_key1)
/// without revealing plaintexts
fn proof_eval(
    cipher1: &Vec<Integer>,
    cipher2: &Vec<Integer>,
    cipher12: &Vec<Integer>,
    number1: u32,
    pub_key1: &Integer,
    pub_key2: &Integer,
    r1: &Vec<Integer>,
    r12: &Vec<Integer>,
    sound_param: usize,
) -> (Vec<Vec<Vec<Integer>>>, Vec<Vec<(Integer, Integer, Integer)>>) {
    assert_eq!(cipher1.len(), 32);
    assert_eq!(cipher2.len(), 32);

    let bits_v = format!("{:032b}", number1);

    // Generate coins_delta, coins_gamma, and coins_gamma2
    let mut coins_delta = vec![vec![Integer::from(0); sound_param]; 32];
    let mut coins_gamma = vec![vec![Integer::from(0); sound_param]; 32];
    let mut coins_gamma2 = vec![vec![Integer::from(0); sound_param]; 32];

    let mut rng = StdRng::from_entropy();
    for l in 0..32 {
        for m in 0..sound_param {
            coins_delta[l][m] = Integer::from(rng.gen::<u8>() % 2);
            coins_gamma[l][m] = Integer::from(getNextRandom(pub_key1 - 1));
            coins_gamma2[l][m] = Integer::from(getNextRandom(pub_key2 - 1));
        }
    }

    // Encrypt coins using GM scheme
    let gamma: Vec<Vec<Integer>> = coins_delta
        .iter()
        .enumerate()
        .map(|(l, delta_row)| {
            delta_row
                .iter()
                .enumerate()
                .map(|(m, delta)| {
                    encrypt_bit_gm_coin(delta.clone(), pub_key1, coins_gamma[l][m].clone())
                })
                .collect()
        })
        .collect();

    let gamma2: Vec<Vec<Integer>> = coins_delta
        .iter()
        .enumerate()
        .map(|(l, delta_row)| {
            delta_row
                .iter()
                .enumerate()
                .map(|(m, delta)| {
                    encrypt_bit_gm_coin(delta.clone(), pub_key2, coins_gamma2[l][m].clone())
                })
                .collect()
        })
        .collect();

    let p_eval =
        vec![gamma.clone(), gamma2.clone(), cipher1.clone(), cipher2.clone(), cipher12.clone()];
    let h = hash_flat(&p_eval.concat().concat());

    let mut rng_seed = StdRng::seed_from_u64(u64::from_le_bytes(h[..8].try_into().unwrap()));

    let plaintext_and_coins: Vec<Vec<(Integer, Integer, Integer)>> = (0..32)
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
                                ^ Integer::from(
                                    bits_v.chars().nth(l).unwrap().to_digit(10).unwrap(),
                                ),
                            (&coins_gamma[l][m] * &r1[l]) % pub_key1,
                            (&coins_gamma2[l][m] * &r12[l]) % pub_key2,
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
    p_eval: Vec<Vec<Vec<Integer>>>,
    plaintext_and_coins: Vec<Vec<(Integer, Integer, Integer)>>,
    n1: &Integer,
    n2: &Integer,
    sound_param: usize,
) -> Option<()> {
    let (gamma, gamma2, cipher1, cipher2, cipher12) =
        (&p_eval[0], &p_eval[1], &p_eval[2], &p_eval[3], &p_eval[4]);

    let h = hash_flat(&p_eval.concat().concat());
    let mut rng_seed = StdRng::seed_from_u64(u64::from_le_bytes(h[..8].try_into().unwrap()));

    for l in 0..32 {
        assert_eq!(plaintext_and_coins[l].len(), sound_param);
        for m in 0..sound_param {
            let (plaintext, coins_gamma, coins_gamma2) = &plaintext_and_coins[l][m];
            if rng_seed.gen::<u8>() % 2 == 0 {
                let detc1 = encrypt_bit_gm_coin(plaintext.clone(), n1, coins_gamma.clone());
                let detc2 = encrypt_bit_gm_coin(plaintext.clone(), n2, coins_gamma2.clone());
                if detc1 != gamma[l][m] || detc2 != gamma2[l][m] {
                    return None;
                }
            } else {
                let product1 = (&gamma[l][m] * &cipher1[l]) % n1;
                let product2 = (&gamma2[l][m] * &cipher12[l]) % n2;
                if encrypt_bit_gm_coin(plaintext.clone(), n1, coins_gamma.clone()) != product1
                    || encrypt_bit_gm_coin(plaintext.clone(), n2, coins_gamma2.clone()) != product2
                {
                    return None;
                }
            }
        }
    }
    Some(())
}

#[cfg(test)] // This module is included only during testing
mod tests {
    use super::*;

    fn rand32(n: &BigUint) -> Vec<BigUint> {
        let mut result = Vec::new();
        for _ in 0..32 {
            result.push(get_next_random(n));
        }
        result
    }

    fn generate_rand_matrix(n: &BigUint, rows: usize, cols: usize) -> Vec<Vec<BigUint>> {
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

    #[test]
    fn strain_main() {
        let keys1 = generate_keys();
        let n1 = &keys1.pub_key;
        let keys2 = generate_keys();
        let n2 = &keys2.pub_key;

        let mut rng = thread_rng();
        let v1 = rng.gen_biguint_range(&BigUint::from(0u32), &(BigUint::from(1u32) << 31));
        let r1 = rand32(n1);
        let c1 = encrypt_gm_coin(&v1, n1, &r1);

        let v2 = rng.gen_biguint_range(&BigUint::from(0u32), &(BigUint::from(1u32) << 31));
        let r2 = rand32(n2);
        let c2 = encrypt_gm_coin(&v2, n2, &r2);

        let r12 = rand32(n2);
        println!("Encryption timings...");
        let mut timings = Vec::new();
        for _ in 0..10 {
            let start_time = Instant::now();
            let _c12 = encrypt_gm_coin(&v1, n2, &r12);
            timings.push(start_time.elapsed().as_secs_f64());
        }
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

        for _ in 0..10 {
            let start_time = Instant::now();
            let eval_res = gm_eval_honest(&v1, &c2, n2, &rand1, &rand2, &rand3, &rand4);
            eval_timings.push(start_time.elapsed().as_secs_f64());
        }
        let avg = eval_timings.iter().sum::<f64>() / eval_timings.len() as f64;
        let rstd = 100.0
            * (eval_timings.iter().map(|t| (t - avg).powi(2)).sum::<f64>()
                / eval_timings.len() as f64)
                .sqrt()
            / avg;
        println!("avg: {:.2}s, rel. std. dev.: {:.2}%", avg, rstd);

        assert_eq!(
            (v2 <= v1),
            compare_leq_honest(
                &gm_eval_honest(&v1, &c2, n2, &rand1, &rand2, &rand3, &rand4),
                &keys2.priv_key
            )
        );
    }

    #[test]
    fn test_gm_eval_honest() {
        let keys1 = generate_keys();
        let n1 = &keys1.pub_key;

        let mut rng = thread_rng();
        let v1 = rng.gen_biguint_range(&BigUint::from(0u32), &(BigUint::from(1u32) << 31));
        let r1 = rand32(n1);
        let c1 = encrypt_gm_coin(&v1, n1, &r1);

        let v2 = rng.gen_biguint_range(&BigUint::from(0u32), &(BigUint::from(1u32) << 31));
        let r2 = rand32(n1);
        let c2 = encrypt_gm_coin(&v2, n1, &r2);

        let rand1 = generate_rand_matrix(n1, 32, 128);
        let rand2 = generate_rand_matrix(n1, 32, 128);
        let rand3 = generate_rand_matrix(n1, 32, 128);
        let rand4 = generate_rand_matrix(n1, 32, 128);

        let eval_res = gm_eval_honest(&v1, &c2, n1, &rand1, &rand2, &rand3, &rand4);

        assert_eq!((v2 <= v1), compare_leq_honest(&eval_res, &keys1.priv_key), "Evaluation failed");
    }

    #[test]
    fn test_proof_eval() {
        let keys = generate_keys();
        let n = &keys.pub_key;

        let mut rng = thread_rng();
        let v1 = rng.gen_biguint_range(&BigUint::from(0u32), &(BigUint::from(1u32) << 31));
        let r1 = rand32(n);
        let c1 = encrypt_gm_coin(&v1, n, &r1);

        let rand1 = generate_rand_matrix(n, 32, 128);
        let rand2 = generate_rand_matrix(n, 32, 128);
        let rand3 = generate_rand_matrix(n, 32, 128);
        let rand4 = generate_rand_matrix(n, 32, 128);

        let eval_res = gm_eval_honest(&v1, &c1, n, &rand1, &rand2, &rand3, &rand4);

        let proof = proof_eval(&eval_res, &keys.priv_key, n);
        assert!(verify_eval(&eval_res, &proof, n), "Proof verification failed");
    }

    #[test]
    fn test_proof_dlog_eq() {
        let keys = generate_keys();
        let n = &keys.pub_key;

        let mut rng = thread_rng();
        let r1 = rand32(n);
        let r2 = rand32(n);

        let v = rng.gen_biguint_range(&BigUint::from(0u32), &(BigUint::from(1u32) << 31));
        let c1 = encrypt_gm_coin(&v, n, &r1);
        let c2 = encrypt_gm_coin(&v, n, &r2);

        let proof = proof_dlog_eq(&v, &r1, &r2, n);

        assert!(
            verify_dlog_eq(&c1, &c2, &proof, n),
            "Discrete logarithm equality proof verification failed"
        );
    }

    #[test]
    fn test_proof_shuffle() {
        let keys = generate_keys();
        let n = &keys.pub_key;

        let mut rng = thread_rng();
        let v = rand32(n);

        let c = v.iter().map(|val| encrypt_gm(val, n)).collect::<Vec<BigUint>>();

        let shuffled = {
            let mut s = c.clone();
            s.shuffle(&mut rng);
            s
        };

        let (proof, perm, rand_vals) = compute_proof_shuffle(&c, &shuffled, n);

        assert!(verify_shuffle(&c, &shuffled, &proof, n), "Shuffle proof verification failed");

        for (i, val) in v.iter().enumerate() {
            let decrypted = decrypt_gm(&shuffled[perm[i]], &keys.priv_key);
            assert_eq!(decrypted, *val, "Shuffled value does not match original");
        }
    }

    #[test]
    fn test_proof_enc() {
        let keys = generate_keys();
        let n = &keys.pub_key;

        let mut rng = thread_rng();
        let v = rng.gen_biguint_range(&BigUint::from(0u32), &(BigUint::from(1u32) << 31));
        let r = rand32(n);
        let c = encrypt_gm_coin(&v, n, &r);

        let proof = compute_proof_enc(&v, &r, n);

        assert!(verify_proof_enc(&c, &proof, n), "Encryption proof verification failed");
    }
}
