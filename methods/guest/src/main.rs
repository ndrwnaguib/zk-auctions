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
use zk_auctions_protocols::strain::{Strain, StrainProtocol};

fn main() {
    let mut rng = rand::thread_rng();
    let strain_protocol = StrainProtocol::new(StrainConfig::low_security());

    let keys_j: Keys = generate_keys(None);
    let (p_j, q_j): &(BigInt, BigInt) = &keys_j.priv_key;
    let n_j: BigInt = keys_j.pub_key;

    // Generate a second random value for v2.
    let v_j: BigInt = rng.gen_bigint_range(&BigInt::from(0u32), &(BigInt::from(1u32) << 31));

    // Read inputs from the environment.
    let (c_i, n_i, r_i): (Vec<BigInt>, BigInt, Vec<BigInt>) = env::read();
    let (sigma, sound_param): (BigInt, u32) = env::read();
    let (rand1, rand2, rand3, rand4): (
        Vec<Vec<BigInt>>,
        Vec<Vec<BigInt>>,
        Vec<Vec<BigInt>>,
        Vec<Vec<BigInt>>,
    ) = env::read();

    let r_j: Vec<BigInt> = rand32(&n_j);
    let c_j_proofeval = encrypt_gm(&v_j, &n_j);
    let c_ji = encrypt_gm(&v_j, &n_i);
    let r_ji = rand32(&n_i);
    let (proof_eval, plaintext_and_coins) = strain_protocol.proof_eval(
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

    let c_j_proofenc = encrypt_gm_coin(&v_j.clone(), &n_j, &r_j);
    let proof_enc: Vec<Vec<Vec<BigInt>>> = strain_protocol.compare_proof_enc(c_j_proofenc, &n_j, &r_j);

    let z_j = n_j.clone() - BigInt::one();
    let r_j_dlog = rng.gen_bigint_range(&BigInt::zero(), &((p_j - 1) * (q_j - 1)));
    let y_j = rng.gen_bigint_range(&BigInt::zero(), &n_j);

    let y_pow_r = y_j.modpow(&r_j_dlog, &n_j);
    let z_pow_r = z_j.modpow(&r_j_dlog, &n_j);

    let proof_dlog = strain_protocol.proof_dlog_eq(&r_j_dlog, &y_j, &n_j, Some(sound_param));

    let r_ji = rand32(&n_i);
    let c_ji = encrypt_gm_coin(&v_j, &n_i, &r_ji);
    let res = strain_protocol.gm_eval_honest(&v_j, &c_ji, &c_i, &n_i, &rand1, &rand2, &rand3, &rand4);
    let proof_shuffle = strain_protocol.compute_proof_shuffle(&res, &n_i);

    /* only seen by auctioneer */
    let private_data = (&proof_eval, &plaintext_and_coins);
    env::write(&private_data);

    let public_results =
        (n_j.clone(), proof_enc, (proof_dlog, y_j, y_pow_r, z_pow_r), (proof_shuffle, res));

    // Single commit
    env::commit(&public_results);
}
