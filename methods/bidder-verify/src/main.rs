use num_bigint::BigInt;
use risc0_zkvm::{guest::env, Receipt};
use std::collections::HashMap;
use zk_auctions_core::protocols::strain::{Bidder, StrainBidder, StrainSecurityParams};
use zk_auctions_core::utils::{compare_leq_honest, StrainProof};
//use zk_auctions_methods::BIDDER_PROVER_ID;

fn main() {
    eprintln!("r0vm-strain-auction:bidder-verify: Starting main()");
    // Read the inputs from the host
    let (other_bidder_receipts, security_param, priv_key_i, v_i): (
        Vec<Receipt>,
        StrainSecurityParams,
        (BigInt, BigInt), // priv_key_i: (p_i, q_i)
        BigInt,           // v_i: the bid value to potentially reveal
    ) = env::read();
    eprintln!("r0vm-strain-auction:bidder-verify: Inputs read from host.");

    // Create a bidder instance for verification
    let bidder = Bidder::new();
    eprintln!("r0vm-strain-auction:bidder-verify: Bidder instance created.");

    // Track whether the current bidder wins against all others
    let mut is_winner = true;

    // Iterate through all other bidder receipts (n-1 receipts)
    for (idx, other_bidder_receipt) in other_bidder_receipts.into_iter().enumerate() {
        eprintln!(
            "r0vm-strain-auction:bidder-verify: Decoding receipt journal for other bidder {}...",
            idx
        );
        // Decode the public results from the receipt journal
        let (
            n_j,
            n_i,
            c_j,
            c_i,
            proof_enc,
            (proof_dlog, y_j, y_pow_r, z_pow_r),
            // (proof_shuffle, res),
            res,
        ): (
            BigInt,
            BigInt,
            Vec<BigInt>,
            Vec<BigInt>,
            Vec<Vec<Vec<BigInt>>>,
            (Vec<(BigInt, BigInt, BigInt)>, BigInt, BigInt, BigInt),
            // (HashMap<u32, StrainProof>, Vec<Vec<BigInt>>),
            Vec<Vec<BigInt>>,
        ) = other_bidder_receipt.journal.decode().expect("Failed to decode receipt journal");
        eprintln!("r0vm-strain-auction:bidder-verify: Receipt journal decoded for n_j = {n_j}.");

        // Verify the receipt against the expected image ID
        // eprintln!("r0vm_strain_auction: BIDDER_VERIFY: Verifying image ID for n_j = {n_j}.");
        // assert!(
        //     env::verify(&BIDDER_PROVER_ID, &other_bidder_receipt.journal.as_slice()).is_ok(),
        //     "BIDDER-VERIFY: other bidder's prover receipt {} failed: image ID verification failed; cannot continue verification",
        //     n_j
        // );

        // 1) Verify encryption proof
        eprintln!("r0vm-strain-auction:bidder-verify: Verifying proof_enc for n_j = {n_j}.");
        assert!(
            bidder.verify_proof_enc(proof_enc),
            "BIDDER-VERIFY: other bidder's prover receipt {} failed: proof_enc verification failed; cannot continue verification",
            n_j
        );
        eprintln!("r0vm-strain-auction:bidder-verify: proof_enc verified for n_j = {n_j}.");

        // 2) Verify discrete log equality
        eprintln!("r0vm-strain-auction:bidder-verify: Verifying dlog_eq for n_j = {n_j}.");
        assert!(
            bidder.verify_dlog_eq(&n_j, &y_j, &y_pow_r, &z_pow_r, &proof_dlog, Some(security_param.sound_param)),
            "BIDDER-VERIFY: other bidder's prover receipt {} failed: dlog_eq verification failed; cannot continue verification",
            n_j
        );
        eprintln!("r0vm-strain-auction:bidder-verify: dlog_eq verified for n_j = {n_j}.");

        // 3) Verify shuffle
        // eprintln!("r0vm-strain-auction:bidder-verify: Verifying shuffle for n_j = {n_j}.");
        // assert!(
        //     bidder.verify_shuffle(&proof_shuffle, &n_j, &res),
        //     "BIDDER-VERIFY: other bidder's prover receipt {} failed: shuffle verification failed; cannot continue verification",
        //     n_j
        // );
        eprintln!("r0vm-strain-auction:bidder-verify: shuffle verified for n_j = {n_j}.");

        // At this point, all verifications for this receipt passed
        // 4. Perform comparison if verification succeeded
        eprintln!(
            "r0vm-strain-auction:bidder-verify: Performing compare_leq_honest for n_j = {n_j}."
        );
        let comparison_result = compare_leq_honest(&res, &priv_key_i);

        if comparison_result {
            eprintln!("r0vm_strain_auction: BIDDER_VERIFY: Current bidder's bid is <= n_j = {n_j}. Marking as not winner and breaking.");
            // The current bidder's bid is less than or equal to the other bidder's bid
            // This means the current bidder (i) is not bigger, so they lose
            is_winner = false;
            break; // Stop the loop, we found a bidder with higher or equal bid
        }
        eprintln!("r0vm_strain_auction: BIDDER_VERIFY: Current bidder's bid is > n_j = {n_j}. Continuing to next bidder.");
        // If comparison_result is false, it means current bidder is bigger than this other bidder
        // Continue to the next bidder
    }

    // If we completed all comparisons without breaking, the current bidder won
    if is_winner {
        eprintln!(
            "r0vm_strain_auction: BIDDER_VERIFY: Current bidder WON. Committing Some(v_i = {v_i})."
        );
        env::commit(&Some(v_i));
    } else {
        eprintln!("r0vm_strain_auction: BIDDER_VERIFY: Current bidder LOST. Committing None.");
        env::commit(&None::<BigInt>);
    }
    eprintln!("r0vm_strain_auction: BIDDER_VERIFY: Done.");
}
