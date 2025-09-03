use num_bigint::BigInt;
use risc0_zkvm::{default_prover, serde::from_slice, ExecutorEnv, Receipt};
use std::collections::HashMap;
use zk_auctions_core::protocols::strain::{StrainSecurityParams};
use zk_auctions_core::protocols::strain::VerifiedReceipt;
use zk_auctions_core::utils::StrainProof;
use zk_auctions_methods::AUCTIONEER_VERIFY_ELF;

/// Trait defining the auctioneer host operations in the Strain protocol
pub trait StrainAuctioneerHost {
    /// Verify a receipt from a bidder
    fn verify(&mut self, bidder_prover_receipt: &Receipt, private_output: &[u8]) -> bool;
}

/// AuctioneerHost represents the auctioneer in the auction system
/// The auctioneer receives receipts from bidders and verifies them using strain_id
pub struct AuctioneerHost {
    /// Registry of verified receipts keyed by "n_j|n_i"
    verified_receipts: HashMap<String, VerifiedReceipt>,
    /// Soundness parameter for ZK proof verification
    pub soundness_param: StrainSecurityParams,
}

impl Default for AuctioneerHost {
    fn default() -> Self {
        Self::new(StrainSecurityParams::default())
    }
}

impl StrainAuctioneerHost for AuctioneerHost {
    /// Verify a receipt from a bidder
    /// Returns true if verification succeeds, false otherwise
    fn verify(&mut self, bidder_prover_receipt: &risc0_zkvm::Receipt, private_output: &[u8]) -> bool {
        // First verify the receipt itself using BIDDER_PROVER_ID
        bidder_prover_receipt.verify(zk_auctions_methods::BIDDER_PROVER_ID).expect("Failed to verify the receipt"); 

        // Decode the public results from the receipt
        let (
            n_j,
            n_i,
            c_j,
            c_i,
            proof_enc,
            (proof_dlog, y_j, y_pow_r, z_pow_r),
            (proof_shuffle, res),
        ): (
            BigInt,
            BigInt,
            Vec<BigInt>,
            Vec<BigInt>,
            Vec<Vec<Vec<BigInt>>>,
            (Vec<(BigInt, BigInt, BigInt)>, BigInt, BigInt, BigInt),
            (HashMap<u32, StrainProof>, Vec<Vec<BigInt>>),
        ) = bidder_prover_receipt.journal.decode().expect("Failed to decode all the journal results");

        // Read the private output for additional verification
        let (proof_eval, plaintext_and_coins): (
            Vec<Vec<Vec<BigInt>>>,
            Vec<Vec<(BigInt, BigInt, BigInt)>>,
        ) = from_slice(private_output).expect("Failed to deserialize private data");

        // Use the auctioneer-verify guest circuit to verify the evaluation proof
        // Create the execution environment
        let env = ExecutorEnv::builder()
            .write(&(
                n_j.clone(),
                n_i.clone(),
                c_j.clone(),
                c_i.clone(),
                proof_enc.clone(),
                (proof_dlog.clone(), y_j.clone(), y_pow_r.clone(), z_pow_r.clone()),
                (proof_shuffle.clone(), res.clone()),
                proof_eval.clone(),
                plaintext_and_coins.clone(),
                self.soundness_param.sound_param,
            ))
            .expect("Failed to write inputs to ExecutorEnv")
            .build()
            .expect("Failed to build ExecutorEnv");

        // Execute the auctioneer-verify guest circuit
        let session = default_prover();
        let verification_receipt = session.prove(env, AUCTIONEER_VERIFY_ELF).expect("Failed to prove auctioneer verification").receipt;

        // Extract the verification result
        let is_eval_verified: bool = verification_receipt.journal.decode().expect("Failed to decode verification result");

        if !is_eval_verified {
            return false;
        }

        // If all verifications pass, register the verified receipt and associated keys/ciphertexts
        let info = VerifiedReceipt {
            bidder_prover_receipt: bidder_prover_receipt.clone(),
            auctioneer_verify_receipt: Some(verification_receipt.clone()),
            n_j: n_j.clone(),
            n_i: n_i.clone(),
            c_j: c_j.clone(),
            c_i: c_i.clone(),
        };

        // Use a composite key: n_j|n_i to distinguish direction of pairwise proof
        let key = format!("{}|{}", n_j, n_i);
        self.verified_receipts.insert(key, info);

        true
    }
}

impl AuctioneerHost {
    /// Create a new auctioneer host
    pub fn new(sound_param: StrainSecurityParams) -> Self {
        Self {
            verified_receipts: HashMap::new(),
            soundness_param: sound_param,
        }
    }

    /// Get information about a verified receipt keyed by "n_j|n_i"
    pub fn get_verified_receipt(&self, n_j: &BigInt, n_i: &BigInt) -> Option<&VerifiedReceipt> {
        let key = format!("{}|{}", n_j, n_i);
        self.verified_receipts.get(&key)
    }

    /// Get all verified receipts
    pub fn get_all_verified_receipts(&self) -> &HashMap<String, VerifiedReceipt> {
        &self.verified_receipts
    }

    /// Get the total number of verified receipts
    pub fn verified_receipt_count(&self) -> usize {
        self.verified_receipts.len()
    }

    /// Check if a receipt for (n_j, n_i) exists
    pub fn has_verified_receipt(&self, n_j: &BigInt, n_i: &BigInt) -> bool {
        let key = format!("{}|{}", n_j, n_i);
        self.verified_receipts.contains_key(&key)
    }

    /// Remove a verified receipt for (n_j, n_i)
    pub fn remove_verified_receipt(&mut self, n_j: &BigInt, n_i: &BigInt) -> Option<VerifiedReceipt> {
        let key = format!("{}|{}", n_j, n_i);
        self.verified_receipts.remove(&key)
    }

    /// Clear all verified receipts (useful for starting a new auction)
    pub fn clear_receipts(&mut self) {
        self.verified_receipts.clear();
    }
}
