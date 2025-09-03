use risc0_zkvm::guest::env;
use zk_auctions_core::protocols::strain::{Bidder, StrainSecurityParams, StrainBidder};
use zk_auctions_core::utils::{StrainProof, compare_leq_honest};
use num_bigint::BigInt;
use std::collections::HashMap;

fn main() {
    // Read the inputs from the host
    let (
        n_j,
        n_i,
        c_j,
        c_i,
        proof_enc,
        (proof_dlog, y_j, y_pow_r, z_pow_r),
        (proof_shuffle, res),
        security_param,
        priv_key_i,
        v_i,
    ): (
        BigInt,
        BigInt,
        Vec<BigInt>,
        Vec<BigInt>,
        Vec<Vec<Vec<BigInt>>>,
        (Vec<(BigInt, BigInt, BigInt)>, BigInt, BigInt, BigInt),
        (HashMap<u32, StrainProof>, Vec<Vec<BigInt>>),
        StrainSecurityParams,
        (BigInt, BigInt), // priv_key_i: (p_i, q_i)
        BigInt,           // v_i: the bid value to potentially reveal
    ) = env::read();

    // Create a bidder instance for verification
    let bidder = Bidder::new();

    // Perform all verification steps
    let mut verification_success = true;

    // 1. Verify proof_enc
    if !bidder.verify_proof_enc(proof_enc) {
        verification_success = false;
    }

    // 2. Verify dlog_eq
    if verification_success && !bidder.verify_dlog_eq(
        &n_j,
        &y_j,
        &y_pow_r,
        &z_pow_r,
        &proof_dlog,
        Some(security_param.sound_param),
    ) {
        verification_success = false;
    }

    // 3. Verify shuffle
    if verification_success && !bidder.verify_shuffle(&proof_shuffle, &n_j, &res) {
        verification_success = false;
    }

    // 4. Perform comparison if verification succeeded
    let (is_won, revealed_v_i) = if verification_success {
        // Compare the evaluation result with the private key
        let comparison_result = compare_leq_honest(&res, &priv_key_i);

        // TODO: check all together
        if comparison_result {
            // The second bidder's bid is less than or equal to the first bidder's bid
            // This means the second bidder (i) won, so reveal their v_i
            (true, Some(v_i))
        } else {
            // The second bidder's bid is greater than the first bidder's bid
            // This means the second bidder (i) lost, so don't reveal their v_i
            (false, None)
        }
    } else {
        // If verification failed, no comparison can be trusted
        (false, None)
    };

    // Commit the verification result and comparison result
    env::commit(&(verification_success, is_won, revealed_v_i));
}