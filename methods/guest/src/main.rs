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

use zk_auctions_core::protocols::strain::bidder::{Bidder, StrainBidder};

fn main() {
    eprintln!("[zkvm-guest] Starting main function");
    let mut rng = rand::thread_rng();

    eprintln!("[zkvm-guest] Generating keys_j");
    let keys_j: Keys = generate_keys(None);
    let (p_j, q_j): &(BigInt, BigInt) = &keys_j.priv_key;
    let n_j: BigInt = keys_j.pub_key;
    eprintln!("[zkvm-guest] Keys generated, n_j bit length: {}", n_j.bits());

    // Generate a second random value for v2.
    //let v_j: BigInt = rng.gen_bigint_range(&BigInt::from(0u32), &(BigInt::from(1u32) << 31));
    let v_j: BigInt = BigInt::from(5000);
    eprintln!("[zkvm-guest] Second bidder's bid v_j = {}", v_j);

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
    let bidder = Bidder::new();
    let (proof_eval, plaintext_and_coins) = bidder.proof_eval(
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
    let proof_enc: Vec<Vec<Vec<BigInt>>> = bidder.compute_proof_enc(c_j_proofenc, &n_j, &r_j);
    eprintln!("[zkvm-guest] proof_enc completed");

    eprintln!("[zkvm-guest] Computing proof_dlog");
    let z_j = n_j.clone() - BigInt::one();
    let r_j_dlog = rng.gen_bigint_range(&BigInt::zero(), &((p_j - 1) * (q_j - 1)));
    let y_j = rng.gen_bigint_range(&BigInt::zero(), &n_j);

    let y_pow_r = y_j.modpow(&r_j_dlog, &n_j);
    let z_pow_r = z_j.modpow(&r_j_dlog, &n_j);

    let proof_dlog = bidder.proof_dlog_eq(&r_j_dlog, &y_j, &n_j, Some(sound_param));
    eprintln!("[zkvm-guest] proof_dlog completed");

    eprintln!("[zkvm-guest] Computing gm_eval_honest");
    let r_ji = rand32(&n_i);
    let c_ji = encrypt_gm_coin(&v_j, &n_i, &r_ji);
    let res = bidder.gm_eval_honest(&v_j, &c_ji, &c_i, &n_i, &rand1, &rand2, &rand3, &rand4);
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
