use num_bigint::BigInt;
use risc0_zkvm::{serde::from_slice, Receipt};
use std::collections::HashMap;
use zk_auctions_core::protocols::strain::{Auctioneer, StrainAuctioneer, StrainSecurityParams};
use zk_auctions_core::protocols::strain::VerifiedReceipt;
use zk_auctions_core::utils::StrainProof;
use zk_auctions_methods::GUEST_ID;

/// AuctioneerHost represents the auctioneer in the auction system
/// The auctioneer receives receipts from bidders and verifies them using strain_id
pub struct AuctioneerHost {
    /// The auctioneer's verification instance
    auctioneer: Auctioneer,
    /// Registry of verified receipts keyed by "n_j|n_i"
    verified_receipts: HashMap<String, VerifiedReceipt>,
    /// Soundness parameter for ZK proof verification
    soundness_param: StrainSecurityParams,
}

impl Default for AuctioneerHost {
    fn default(sound_param: StrainSecurityParams) -> Self {
        Self::new(sound_param)
    }
}

impl AuctioneerHost {
    /// Create a new auctioneer host
    pub fn new(sound_param: StrainSecurityParams) -> Self {
        Self {
            auctioneer: Auctioneer::new(),
            verified_receipts: HashMap::new(),
            soundness_param: sound_param,
        }
    }

    /// Verify a receipt from a bidder
    /// Returns true if verification succeeds, false otherwise
    pub fn verify(&mut self, receipt: &risc0_zkvm::Receipt, private_output: &[u8]) -> bool {
        // First verify the receipt itself using GUEST_ID
        receipt.verify(GUEST_ID).expect("Failed to verify the receipt"); 

        // Decode the public results from the receipt
        let (
            n_j,
            n_i,
            c_j,
            c_i,
            _proof_enc,
            (_proof_dlog, _y_j, _y_pow_r, _z_pow_r),
            (_proof_shuffle, res),
        ): (
            BigInt,
            BigInt,
            Vec<BigInt>,
            Vec<BigInt>,
            Vec<Vec<Vec<BigInt>>>,
            (Vec<(BigInt, BigInt, BigInt)>, BigInt, BigInt, BigInt),
            (HashMap<u32, StrainProof>, Vec<Vec<BigInt>>),
        ) = receipt.journal.decode().expect("Failed to decode all the journal results");

        // Read the private output for additional verification
        let (proof_eval, plaintext_and_coins): (
            Vec<Vec<Vec<BigInt>>>,
            Vec<Vec<(BigInt, BigInt, BigInt)>>,
        ) = from_slice(private_output).expect("Failed to deserialize private data");

        // Verify the evaluation proof
        let eval_verification = self.auctioneer.verify_eval(
            proof_eval.clone(),
            plaintext_and_coins.clone(),
            &n_i,
            &n_j,
            self.soundness_param.sound_param, // Use the struct's sound_param
        );

        if eval_verification.is_none() {
            return false;
        }

        // If all verifications pass, register the verified receipt and associated keys/ciphertexts
        self.register_verified_receipt(&n_j, &n_i, &c_j, &c_i, &res, receipt);

        true
    }

    /// Register a verified receipt in the auctioneer's registry
    fn register_verified_receipt(
        &mut self,
        n_j: &BigInt,
        n_i: &BigInt,
        c_j: &Vec<BigInt>,
        c_i: &Vec<BigInt>,
        _encrypted_bid_res: &[Vec<BigInt>],
        receipt: &Receipt,
    ) {
        let info = VerifiedReceipt {
            receipt: receipt.clone(),
            n_j: n_j.clone(),
            n_i: n_i.clone(),
            c_j: c_j.clone(),
            c_i: c_i.clone(),
        };

        // Use a composite key: n_j|n_i to distinguish direction of pairwise proof
        let key = format!("{}|{}", n_j, n_i);
        self.verified_receipts.insert(key, info);
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
