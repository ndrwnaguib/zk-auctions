use rand::{rngs::StdRng, Rng, SeedableRng};
use rug::{Integer, RandState};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

mod GM;

use GM::{
    decrypt_bit_and, decrypt_bit_gm, decrypt_gm, dot_mod, embed_and, embed_bit_and,
    encrypt_bit_and, encrypt_bit_gm, encrypt_gm, generate_keys,
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
    let c_neg_xor = dot_mod(&neg_cipher1, cipher2, &n);

    let cipher1_and = embed_and(cipher1, pub_key2, rand1);
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
