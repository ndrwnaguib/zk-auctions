use num_bigint::BigInt;
use risc0_zkvm::guest::env;
use std::collections::HashMap;
use zk_auctions_core::protocols::strain::{Auctioneer, StrainAuctioneer};
use zk_auctions_core::utils::StrainProof;

fn main() {
    // Read inputs from the environment
    let (
        n_j,
        n_i,
        c_j,
        c_i,
        proof_enc,
        (proof_dlog, y_j, y_pow_r, z_pow_r),
        (proof_shuffle, res),
        proof_eval,
        plaintext_and_coins,
        sound_param,
    ): (
        BigInt,
        BigInt,
        Vec<BigInt>,
        Vec<BigInt>,
        Vec<Vec<Vec<BigInt>>>,
        (Vec<(BigInt, BigInt, BigInt)>, BigInt, BigInt, BigInt),
        (HashMap<u32, StrainProof>, Vec<Vec<BigInt>>),
        Vec<Vec<Vec<BigInt>>>,
        Vec<Vec<(BigInt, BigInt, BigInt)>>,
        u32,
    ) = env::read();

    // Create auctioneer instance
    let auctioneer = Auctioneer::new();

    // Verify the evaluation proof
    let eval_verification = auctioneer.verify_eval(
        proof_eval.clone(),
        plaintext_and_coins.clone(),
        &n_i,
        &n_j,
        sound_param as usize,
    );

    // Check if verification succeeded
    let is_eval_verified = match eval_verification {
        Some(_) => true,
        None => false,
    };

    // Commit the verification result
    env::commit(&is_eval_verified);
}
