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

use zk_auctions_core::protocols::strain::auctioneer::{Auctioneer, StrainAuctioneer};
use zk_auctions_core::protocols::strain::bidder::{Bidder, StrainBidder};
use zk_auctions_core::utils::{
    compute_permutation, divm, get_rand_jn1, hash_flat, rand32, set_rand_seed, StrainProof,
};

fn main() {
    eprintln!("r0vm-strain-auction:bidder-prove: Starting bidder-prover main function");
    let mut rng = rand::thread_rng();
    let bidder = Bidder::new();
    eprintln!("r0vm-strain-auction:bidder-prove: Created new bidder instance");

    // Read inputs from the environment.
    eprintln!("r0vm-strain-auction:bidder-prove: Reading inputs from environment");
    let (
        c_j_proofeval,
        n_j,
        r_j,
        v_j,
        p_j,
        q_j,
        c_i,
        n_i,
        r_i
    ): (
        Vec<BigInt>,
        BigInt,
        Vec<BigInt>,
        BigInt,
        BigInt,
        BigInt,
        Vec<BigInt>,
        BigInt,
        Vec<BigInt>
    ) = env::read();
    let (rand1, rand2, rand3, rand4): (
        Vec<Vec<BigInt>>,
        Vec<Vec<BigInt>>,
        Vec<Vec<BigInt>>,
        Vec<Vec<BigInt>>,
    ) = env::read();
    eprintln!("r0vm-strain-auction:bidder-prove: Successfully read all inputs from environment");

    eprintln!("r0vm-strain-auction:bidder-prove: Generating random values and encrypting");
    //let c_j_proofeval = encrypt_gm(&v_j, &n_j);
    let c_ji = encrypt_gm(&v_j, &n_i);
    let r_ji = rand32(&n_i);
    eprintln!("r0vm-strain-auction:bidder-prove: Computing proof_eval");
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
    );
    eprintln!("r0vm-strain-auction:bidder-prove: Completed proof_eval computation");

    eprintln!("r0vm-strain-auction:bidder-prove: Computing proof_enc");
    let c_j_proofenc = encrypt_gm_coin(&v_j.clone(), &n_j, &r_j);
    let proof_enc: Vec<Vec<Vec<BigInt>>> = bidder.compare_proof_enc(c_j_proofenc, &n_j, &r_j);
    eprintln!("r0vm-strain-auction:bidder-prove: Completed proof_enc computation");

    eprintln!("r0vm-strain-auction:bidder-prove: Computing discrete logarithm proof");
    let z_j = n_j.clone() - BigInt::one();
    let r_j_dlog = rng.gen_bigint_range(&BigInt::zero(), &((p_j - 1) * (q_j - 1)));
    let y_j = rng.gen_bigint_range(&BigInt::zero(), &n_j);

    let y_pow_r = y_j.modpow(&r_j_dlog, &n_j);
    let z_pow_r = z_j.modpow(&r_j_dlog, &n_j);

    let proof_dlog = bidder.proof_dlog_eq(&r_j_dlog, &y_j, &n_j);
    eprintln!("r0vm-strain-auction:bidder-prove: Completed discrete logarithm proof");

    eprintln!("r0vm-strain-auction:bidder-prove: Computing GM evaluation");
    eprintln!("r0vm-strain-auction:bidder-prove: Generating GM random values");
    let r_ji = rand32(&n_i);
    eprintln!("r0vm-strain-auction:bidder-prove: Completed GM Encryption");
    let c_ji = encrypt_gm_coin(&v_j, &n_i, &r_ji);
    eprintln!("r0vm-strain-auction:bidder-prove: Evaluating GM");
    let res = bidder.gm_eval_honest(&v_j, &c_ji, &c_i, &n_i, &rand1, &rand2, &rand3, &rand4);
    eprintln!("r0vm-strain-auction:bidder-prove: Completed GM evaluation");
    //let proof_shuffle = bidder.compute_proof_shuffle(&res, &n_i);

    eprintln!("r0vm-strain-auction:bidder-prove: Writing private data to environment");
    /* only seen by auctioneer */
    let private_data = (&proof_eval, &plaintext_and_coins);
    env::write(&private_data);

    eprintln!("r0vm-strain-auction:bidder-prove: Preparing public results");
    let public_results = (
        n_j.clone(),
        n_i.clone(),
        c_j_proofeval.clone(),
        c_i.clone(),
        proof_enc,
        (proof_dlog, y_j, y_pow_r, z_pow_r),
        //(proof_shuffle, res),
        (res),
    );

    eprintln!("r0vm-strain-auction:bidder-prove: Committing public results");
    // Single commit
    env::commit(&public_results);
    eprintln!("r0vm-strain-auction:bidder-prove: Successfully completed bidder-prover execution");
}
