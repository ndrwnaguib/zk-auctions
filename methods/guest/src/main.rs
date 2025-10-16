const CHALLENGES: usize = 16;
use num_bigint::{BigInt, RandBigInt};
use num_traits::{One, Zero};
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, Rng, SeedableRng};
use risc0_zkvm::guest::env;
use std::collections::HashMap;
use zk_auctions_core::gm::{
    dot_mod, embed_and, encrypt_bit_gm_coin, encrypt_gm, encrypt_gm_coin, generate_keys, Keys,
    StrainRandomGenerator,
};

use zk_auctions_core::utils::{
    compute_permutation, divm, get_rand_jn1, hash_flat, rand32, set_rand_seed, StrainProof,
};

fn main() {
    eprintln!("[zkvm-guest] Starting main function");
    let mut rng = rand::thread_rng();

    eprintln!("[zkvm-guest] Generating keys_j");
    let keys_j: Keys = generate_keys(None);
    let (p_j, q_j): &(BigInt, BigInt) = &keys_j.priv_key;
    let n_j: BigInt = keys_j.pub_key;
    eprintln!("[zkvm-guest] Keys generated, n_j bit length: {}", n_j.bits());

    // Generate a second random value for v2.
    // let v_j: BigInt = rng.gen_bigint_range(&BigInt::from(0u32), &(BigInt::from(1u32) << 31));
    let v_j: BigInt = BigInt::from(5000);

    // Read inputs from the environment.
    eprintln!("[zkvm-guest] Reading inputs from environment");
    let (c_i, n_i, r_i): (Vec<BigInt>, BigInt, Vec<BigInt>) = env::read();
    eprintln!("[zkvm-guest] Read c_i (len: {}), n_i (bits: {}), r_i (len: {})", c_i.len(), n_i.bits(), r_i.len());
    let (sigma, sound_param): (BigInt, u32) = env::read();
    eprintln!("[zkvm-guest] Read sigma and sound_param: {}", sound_param);
    let (rand1, rand2, rand3, rand4): (
        Vec<Vec<BigInt>>,
        Vec<Vec<BigInt>>,
        Vec<Vec<BigInt>>,
        Vec<Vec<BigInt>>,
    ) = env::read();
    eprintln!("[zkvm-guest] Read random values");

    eprintln!("[zkvm-guest] Computing proof_eval");
    let r_j: Vec<BigInt> = rand32(&n_j);
    let c_j_proofeval = encrypt_gm(&v_j, &n_j);
    let c_ji = encrypt_gm(&v_j, &n_i);
    let r_ji = rand32(&n_i);
    let (proof_eval, plaintext_and_coins) = proof_eval(
        &c_j_proofeval,
        &c_i,
        &c_ji,
        /* this should be v_i */
        v_j.clone(),
        &n_j,
        &n_i,
        &r_j,
        &r_ji,
        sound_param as usize,
    );
    eprintln!("[zkvm-guest] proof_eval completed");

    eprintln!("[zkvm-guest] Computing proof_enc");
    let c_j_proofenc = encrypt_gm_coin(&v_j.clone(), &n_j, &r_j);
    let proof_enc: Vec<Vec<Vec<BigInt>>> = compute_proof_enc(c_j_proofenc, &n_j, &r_j);
    eprintln!("[zkvm-guest] proof_enc completed");

    eprintln!("[zkvm-guest] Computing proof_dlog");
    let z_j = n_j.clone() - BigInt::one();
    let r_j_dlog = rng.gen_bigint_range(&BigInt::zero(), &((p_j - 1) * (q_j - 1)));
    let y_j = rng.gen_bigint_range(&BigInt::zero(), &n_j);

    let y_pow_r = y_j.modpow(&r_j_dlog, &n_j);
    let z_pow_r = z_j.modpow(&r_j_dlog, &n_j);

    let proof_dlog = proof_dlog_eq(&r_j_dlog, &y_j, &n_j, Some(sound_param));
    eprintln!("[zkvm-guest] proof_dlog completed");

    eprintln!("[zkvm-guest] Computing gm_eval_honest");
    let r_ji = rand32(&n_i);
    let c_ji = encrypt_gm_coin(&v_j, &n_i, &r_ji);
    let res = gm_eval_honest(&v_j, &c_ji, &c_i, &n_i, &rand1, &rand2, &rand3, &rand4);
    eprintln!("[zkvm-guest] gm_eval_honest completed, res length: {}", res.len());
    //let proof_shuffle = compute_proof_shuffle(&res, &n_i);
    let proof_shuffle: HashMap<u32, StrainProof> = HashMap::new();
    eprintln!("[zkvm-guest] Using empty proof_shuffle");

    /* only seen by auctioneer */
    eprintln!("[zkvm-guest] Writing private data");
    let private_data = (&proof_eval, &plaintext_and_coins);
    env::write(&private_data);

    eprintln!("[zkvm-guest] Committing public results");
    let public_results =
        (n_j.clone(), proof_enc, (proof_dlog, y_j, y_pow_r, z_pow_r), (proof_shuffle, res));

    // Single commit
    env::commit(&public_results);
    eprintln!("[zkvm-guest] Main function completed successfully");
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

    let bits_v = format!("{number1:032b}");

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

fn proof_dlog_eq(
    sigma: &BigInt,
    y: &BigInt,
    n: &BigInt,
    iters: Option<u32>,
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

fn compute_proof_shuffle(res: &[Vec<BigInt>], n2: &BigInt) -> HashMap<u32, StrainProof> {
    let (ae_permutation_desc, ae_permutation, ae_reencrypt_factors) = compute_permutation(res, n2);

    let challenges_length = 40;
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
        hash_input.insert(i + 1, (am_permutations[&i].1.clone(), me_permutations[&i].1.clone()));
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
                StrainProof::AMPermutations((am_perm_desc.clone(), am_reencrypt_factors.clone())),
            );
        } else {
            let (me_perm_desc, me_reencrypt_factors) =
                (&me_permutations[&i].0, &me_permutations[&i].2);
            proof.insert(
                i + 1_u32,
                StrainProof::MEPermutations((me_perm_desc.clone(), me_reencrypt_factors.clone())),
            );
        }
    }

    proof
}

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
    let c_neg_xor = dot_mod(&neg_cipher_i, cipher_j, pub_key_j);

    let cipher_i_and = embed_and(cipher_i, pub_key_j, rand1);
    let cipher_j_and = embed_and(cipher_j, pub_key_j, rand2);
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
