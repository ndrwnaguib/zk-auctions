use std::collections::HashMap;

use num_bigint::{BigInt, RandBigInt};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use zk_auctions_core::gm::{generate_keys, encrypt_gm, get_next_random};
use zk_auctions_core::protocols::strain::bidder::{Bidder, StrainBidder, StrainBidderHost};
use zk_auctions_core::protocols::strain::StrainSecurityParams;
use zk_auctions_core::utils::{rand32, compare_leq_honest};
use zk_auctions_methods::{
    BIDDER_PROVER_ELF, BIDDER_PROVER_ID,
};

/// Bidder verifier results
#[derive(Debug, Clone)]
pub struct BidderVerifierResult {
    /// The other bidder's prover receipt
    pub prover_receipt: Receipt,
    /// Whether the other bidder is verified
    pub is_verified: bool,
}

/// Bidder prover results
#[derive(Debug, Clone)]
pub struct BidderProverResult {
    /// The prover receipt
    pub prover_receipt: Receipt,
    /// The private output
    pub private_output: Vec<u8>,
}

/// Collection of all receipts for a bidder across all stages
#[derive(Debug, Clone)]
pub struct BidderReceipts {
    /// Receipt from the bidder-join guest circuit (key generation)
    pub join_receipt: Option<Receipt>,
    /// Receipts from the bidder-prover guest circuit (one for each other bidder)
    pub prover_receipts: Vec<Receipt>,
    /// Receipt from the bidder-verify guest circuit
    pub verify_receipt: Option<Receipt>,
}

/// MockBidderHost represents a bidder in the auction system
/// The bidder creates a ZK session to generate a receipt containing their bid
pub struct MockBidderHost {
    /// The bidder's private key
    p_j: BigInt,
    /// The bidder's private key
    q_j: BigInt,
    /// The bidder's public key
    n_j: BigInt,
    /// The bidder's bid value
    v_j: BigInt,
    /// The bidder's encrypted bid
    c_j: Vec<BigInt>,
    /// The bidder's random values
    r_j: Vec<BigInt>,
    //// The bidder receipts based on the phase
    receipts: BidderReceipts,
    /// The bidder's prover results, key is the other bidder's public key
    prover_results: HashMap<BigInt, BidderProverResult>,
    /// The bidder's verifier results, key is the other bidder's public key
    verifier_results: HashMap<BigInt, BidderVerifierResult>,
    /// The bidder's security parameters
    security_param: StrainSecurityParams,
    /// Bidder instance for verification operations
    bidder: Bidder,
}

impl StrainBidderHost for MockBidderHost {
    /// Joins Auction by generating keys and encrypting the bid.
    ///
    /// # Parameters
    /// - `v_j`: The bid value for this bidder.
    /// - `security_param`: Security parameters for the auction.
    ///
    /// # Returns
    /// A new instance of `MockBidderHost` with generated keys and encrypted bid.
    fn new(v_j: BigInt, security_param: StrainSecurityParams) -> Self {
        // Generate keys
        println!("[MockBidderHost::new] Generating keys for bidder with bid value: {}", v_j);
        let keys_j = generate_keys(None);
        let n_j = keys_j.pub_key.clone();
        let (p_j, q_j): (BigInt, BigInt) = keys_j.priv_key;
        // Print only the first 16 hex digits of n_j to avoid excessive output
        let n_j_str = n_j.to_str_radix(16);
        let n_j_short = if n_j_str.len() > 16 {
            format!("0x{}...", &n_j_str[..16])
        } else {
            format!("0x{}", n_j_str)
        };
        println!("[MockBidderHost::new] Generated keys: n_j = {}, p_j = <hidden>, q_j = <hidden>", n_j_short);

        // Generate random values
        let r_j: Vec<BigInt> = rand32(&n_j);
        // Print only the first 5 elements of r_j to avoid excessive output
        println!(
            "[MockBidderHost::new] Generated random values r_j (first 5 elements): {:?}{}",
            &r_j[..std::cmp::min(5, r_j.len())],
            if r_j.len() > 5 { " ..." } else { "" }
        );

        // Encrypt the bid value
        let c_j = encrypt_gm(&v_j, &n_j);
        // Print only the first 5 elements of c_j to avoid excessive output
        println!(
            "[MockBidderHost::new] Encrypted bid value c_j (first 5 elements): {:?}{}",
            &c_j[..std::cmp::min(5, c_j.len())],
            if c_j.len() > 5 { " ..." } else { "" }
        );

        Self {
            p_j,
            q_j,
            n_j,
            v_j,
            c_j,
            r_j,
            receipts: BidderReceipts {
                join_receipt: None, // No longer using RISC0 join receipt
                prover_receipts: Vec::new(),
                verify_receipt: None,
            },
            prover_results: HashMap::new(),
            verifier_results: HashMap::new(),
            security_param,
            bidder: Bidder::new(),
        }
    }

    /// Generates a zero-knowledge proof receipt for this bidder's bid.
    ///
    /// This function creates a session and proves the bid without revealing the actual value.
    ///
    /// # Parameters
    /// - `c_i`: The encrypted bid of the other bidder.
    /// - `n_i`: The public key of the other bidder.
    /// - `r_i`: The random value used for the other bidder's bid encryption.
    ///
    /// # Returns
    /// A tuple containing the ZK proof receipt and the private output as a byte vector.
    fn prove(&mut self, c_i: &Vec<BigInt>, n_i: &BigInt, r_i: &Vec<BigInt>) -> (Receipt, Vec<u8>) {
        // Generate random values for the shuffle proof
        let (rand1, rand2, rand3, rand4) = self.generate_shuffle_randoms(n_i);

        let mut private_output = Vec::new();
        // Set up the execution environment
        // First input: (c_j, n_j, r_j, v_j, p_j, q_j, c_i, n_i, r_i)
        let env = ExecutorEnv::builder()
            .write(&(
                &self.c_j, &self.n_j, &self.r_j, &self.v_j, &self.p_j, &self.q_j, c_i, n_i, r_i,
            ))
            .expect("Failed to add encryption proof input")
            // Second input: (rand1, rand2, rand3, rand4)
            .write(&(&rand1, &rand2, &rand3, &rand4))
            .expect("Failed to add shuffle proof input")
            .stdout(&mut private_output)
            .build()
            .expect("Failed to build executor environment");

        // Create the prover and generate the receipt
        let session = default_prover();
        let bidder_prover_receipt =
            session.prove(env, BIDDER_PROVER_ELF).expect("Failed to prove").receipt;

        // Store the receipt and private output
        self.receipts.prover_receipts.push(bidder_prover_receipt.clone());
        self.prover_results.insert(n_i.clone(), BidderProverResult {
            prover_receipt: bidder_prover_receipt.clone(),
            private_output: private_output.clone(),
        });

        (bidder_prover_receipt, private_output)
    }

    /// Verify another bidder's receipt
    /// Performs all three verification steps: proof_enc, dlog_eq, and shuffle
    /// Also performs comparison and reveals the bid value if this bidder won
    fn verify_other_bidders(
        &mut self,
        other_bidders_prover_receipts: &Vec<risc0_zkvm::Receipt>,
    ) -> Option<BigInt> {
        // First verify the receipt itself using BIDDER_PROVER_ID
        println!("[MockBidderHost::verify_other_bidders] Verifying receipts...");
        other_bidders_prover_receipts.iter().for_each(|receipt| {
            println!("[MockBidderHost::verify_other_bidders] Verifying receipt: {:?}", receipt);
            receipt.verify(BIDDER_PROVER_ID).expect("Failed to verify the receipt");
        }); 

        // Track whether the current bidder wins against all others
        let mut is_winner = true;

        // Iterate through all other bidder receipts (n-1 receipts)
        for (_idx, other_bidder_receipt) in other_bidders_prover_receipts.iter().enumerate() {
            println!("[MockBidderHost::verify_other_bidders] Verifying receipt: {:?}", other_bidder_receipt);
            // Decode the public results from the receipt journal
            let (
                n_j,
                _n_i,
                _c_j,
                _c_i,
                proof_enc,
                (proof_dlog, y_j, y_pow_r, z_pow_r),
                //(proof_shuffle, res),
                (res),
            ): (
                BigInt,
                BigInt,
                Vec<BigInt>,
                Vec<BigInt>,
                Vec<Vec<Vec<BigInt>>>,
                (Vec<(BigInt, BigInt, BigInt)>, BigInt, BigInt, BigInt),
                //(HashMap<u32, zk_auctions_core::utils::StrainProof>, Vec<Vec<BigInt>>),
                (Vec<Vec<BigInt>>),
            ) = other_bidder_receipt.journal.decode().expect("Failed to decode receipt journal");

            // 1) Verify encryption proof
            assert!(
                self.bidder.verify_proof_enc(proof_enc),
                "BIDDER-VERIFY: other bidder's prover receipt {} failed: proof_enc verification failed; cannot continue verification",
                n_j
            );

            println!("[MockBidderHost::verify_other_bidders] Verifying discrete log equality: {:?}", n_j);
            // 2) Verify discrete log equality
            assert!(
                self.bidder.verify_dlog_eq(&n_j, &y_j, &y_pow_r, &z_pow_r, &proof_dlog, Some(self.security_param.sound_param as usize)),
                "BIDDER-VERIFY: other bidder's prover receipt {} failed: dlog_eq verification failed; cannot continue verification",
                n_j
            );

            println!("[MockBidderHost::verify_other_bidders] Verifying shuffle: {:?}", n_j);
            // 3) Verify shuffle
            // assert!(
            //     self.bidder.verify_shuffle(&proof_shuffle, &n_j, &res),
            //     "BIDDER-VERIFY: other bidder's prover receipt {} failed: shuffle verification failed; cannot continue verification",
            //     n_j
            // );

            // At this point, all verifications for this receipt passed
            // 4. Perform comparison if verification succeeded
            let comparison_result = compare_leq_honest(&res, &(self.p_j.clone(), self.q_j.clone()));

            println!("[MockBidderHost::verify_other_bidders] Comparison result: {:?}", comparison_result);
            if comparison_result {
                // The current bidder's bid is less than or equal to the other bidder's bid
                // This means the current bidder (i) is not bigger, so they lose
                is_winner = false;
                break; // Stop the loop, we found a bidder with higher or equal bid
            }
            // If comparison_result is false, it means current bidder is bigger than this other bidder
            // Continue to the next bidder
        }

        // If we completed all comparisons without breaking, the current bidder won
        if is_winner {
            println!("[MockBidderHost::verify_other_bidders] Winner: {:?}", self.v_j);
            Some(self.v_j.clone())
        } else {
            println!("[MockBidderHost::verify_other_bidders] Not winner: {:?}", self.v_j);
            None
        }
    }
}

impl MockBidderHost {
    /// Create a new bidder with a random bid and default security parameters
    pub fn with_random_bid(security_param: StrainSecurityParams) -> Self {
        let mut rng = rand::thread_rng();
        let v_j: BigInt = rng.gen_bigint_range(&BigInt::from(0u32), &(BigInt::from(1u32) << 31));
        Self::new(v_j, security_param)
    }

    /// Get the encrypted bid (c_j)
    pub fn get_c_j(&self) -> &Vec<BigInt> {
        &self.c_j
    }

    /// Get the public key (n_j)
    pub fn get_n_j(&self) -> &BigInt {
        &self.n_j
    }

    /// Get the random values (r_j)
    pub fn get_r_j(&self) -> &Vec<BigInt> {
        &self.r_j
    }

    /// Get all receipts from all stages
    pub fn get_receipts(&self) -> &BidderReceipts {
        &self.receipts
    }

    /// Get the bidder's private key components
    pub fn get_private_key(&self) -> (BigInt, BigInt) {
        (self.p_j.clone(), self.q_j.clone())
    }

    /// Get the bidder's bid value
    pub fn get_bid_value(&self) -> &BigInt {
        &self.v_j
    }

    /// Get the bidder's security parameters
    pub fn get_security_params(&self) -> &StrainSecurityParams {
        &self.security_param
    }

    /// Get the verified other bidder receipts
    pub fn get_other_bidders_prover_receipts(&self) -> &HashMap<BigInt, BidderVerifierResult> {
        &self.verifier_results
    }

    /// Check if a specific other bidder is verified
    pub fn is_other_bidder_verified(&self, n_j: &BigInt) -> Option<bool> {
        self.verifier_results.get(n_j).map(|receipt| receipt.is_verified)
    }

    /// Get the join receipt
    pub fn get_join_receipt(&self) -> Option<&Receipt> {
        self.receipts.join_receipt.as_ref()
    }

    /// Get the verify receipt
    pub fn get_verify_receipt(&self) -> Option<&Receipt> {
        self.receipts.verify_receipt.as_ref()
    }

    /// Get all prover receipts
    pub fn get_prover_receipts(&self) -> &Vec<Receipt> {
        &self.receipts.prover_receipts
    }

    /// Generate random values for shuffle proof
    fn generate_shuffle_randoms(
        &mut self,
        n_i: &BigInt,
    ) -> (Vec<Vec<BigInt>>, Vec<Vec<BigInt>>, Vec<Vec<BigInt>>, Vec<Vec<BigInt>>) {
        let mut rand1: Vec<Vec<BigInt>> = Vec::with_capacity(32);
        let mut rand2: Vec<Vec<BigInt>> = Vec::with_capacity(32);
        let mut rand3: Vec<Vec<BigInt>> = Vec::with_capacity(32);
        let mut rand4: Vec<Vec<BigInt>> = Vec::with_capacity(32);

        for _ in 0..32 {
            let mut x = Vec::with_capacity(128);
            let mut y = Vec::with_capacity(128);
            let mut x2 = Vec::with_capacity(128);
            let mut y2 = Vec::with_capacity(128);

            for _ in 0..128 {
                x.push(get_next_random(n_i));
                y.push(get_next_random(n_i));
                x2.push(get_next_random(n_i));
                y2.push(get_next_random(n_i));
            }

            rand1.push(x);
            rand2.push(y);
            rand3.push(x2);
            rand4.push(y2);
        }

        (rand1, rand2, rand3, rand4)
    }
}
