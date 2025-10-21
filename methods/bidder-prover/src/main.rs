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
    eprintln!("");
    let mut rng = rand::thread_rng();
    let guest_id: String = env::read();
    let prefix = format!("[({})-zkvm-bidder-prover-guest]", guest_id);
    eprintln!("{} Starting main function", prefix);

    // Read inputs from the environment.
    eprintln!("{} Reading inputs from environment for bidder j", prefix);
    let (n_j, r_j, v_j, p_j, q_j): (BigInt, Vec<BigInt>, BigInt, BigInt, BigInt) = env::read();
    eprintln!("{} Reading inputs from environment for bidder i", prefix);
    let (c_i, n_i, r_i): (Vec<BigInt>, BigInt, Vec<BigInt>) = env::read();
    eprintln!(
        "{} Read c_i (len: {}), n_i (bits: {}), r_i (len: {})",
        prefix,
        c_i.len(),
        n_i.bits(),
        r_i.len()
    );
    let (sigma, sound_param): (BigInt, u32) = env::read();
    eprintln!("{} Read sigma and sound_param: {}", prefix, sound_param);
    let (rand1, rand2, rand3, rand4): (
        Vec<Vec<BigInt>>,
        Vec<Vec<BigInt>>,
        Vec<Vec<BigInt>>,
        Vec<Vec<BigInt>>,
    ) = env::read();
    eprintln!("{} Read random values", prefix);

    eprintln!("{} Computing proof_eval", prefix);
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
    eprintln!("{} proof_eval completed", prefix);

    eprintln!("{} Computing proof_enc", prefix);
    let c_j_proofenc = encrypt_gm_coin(&v_j.clone(), &n_j, &r_j);
    let proof_enc: Vec<Vec<Vec<BigInt>>> = bidder.compute_proof_enc(c_j_proofenc, &n_j, &r_j);
    eprintln!("{} proof_enc completed", prefix);

    eprintln!("{} Computing proof_dlog", prefix);
    let z_j = n_j.clone() - BigInt::one();
    let r_j_dlog = rng.gen_bigint_range(&BigInt::zero(), &((p_j - 1) * (q_j - 1)));
    let y_j = rng.gen_bigint_range(&BigInt::zero(), &n_j);

    let y_pow_r = y_j.modpow(&r_j_dlog, &n_j);
    let z_pow_r = z_j.modpow(&r_j_dlog, &n_j);

    let proof_dlog = bidder.proof_dlog_eq(&r_j_dlog, &y_j, &n_j, Some(sound_param));
    eprintln!("{} proof_dlog completed", prefix);

    eprintln!("{} Computing gm_eval_honest", prefix);
    let r_ji = rand32(&n_i);
    let c_ji = encrypt_gm_coin(&v_j, &n_i, &r_ji);
    let res = bidder.gm_eval_honest(&v_j, &c_ji, &c_i, &n_i, &rand1, &rand2, &rand3, &rand4);
    eprintln!("{} gm_eval_honest completed, res length: {}", prefix, res.len());
    //let proof_shuffle = compute_proof_shuffle(&res, &n_i);
    let proof_shuffle: HashMap<u32, StrainProof> = HashMap::new();
    eprintln!("{} Using empty proof_shuffle", prefix);

    /* only seen by auctioneer */
    eprintln!("{} Writing private data", prefix);
    let private_data = (&proof_eval, &plaintext_and_coins);
    env::write(&private_data);

    eprintln!("{} Committing public results", prefix);
    let public_results =
        (n_j.clone(), proof_enc, (proof_dlog, y_j, y_pow_r, z_pow_r), (proof_shuffle, res));

    // Single commit
    env::commit(&public_results);
    eprintln!("{} Main function completed successfully", prefix);
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
