use std::collections::HashMap;

use num_bigint::{BigInt, RandBigInt};
use risc0_zkvm::serde::from_slice;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use zk_auctions_core::gm::get_next_random;
use zk_auctions_core::protocols::strain::bidder::StrainBidderHost;
use zk_auctions_core::protocols::strain::StrainSecurityParams;
use zk_auctions_methods::{
    BIDDER_JOIN_ELF, BIDDER_PROVER_ELF, BIDDER_PROVER_ID, BIDDER_VERIFY_ELF,
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

/// BidderHost represents a bidder in the auction system
/// The bidder creates a ZK session to generate a receipt containing their bid
pub struct BidderHost {
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
}

impl StrainBidderHost for BidderHost {
    /// Joins Auction by generating keys and encrypting the bid.
    ///
    /// # Parameters
    /// - `v_j`: The bid value for this bidder.
    /// - `security_param`: Security parameters for the auction.
    ///
    /// # Returns
    /// A new instance of `BidderHost` with generated keys and encrypted bid.
    fn new(v_j: BigInt, security_param: StrainSecurityParams) -> Self {
        // Use the keygen guest circuit to generate keys and encrypt the bid
        // Create the execution environment
        let mut private_output = Vec::new();
        let env = ExecutorEnv::builder()
            .write(&v_j)
            .expect("Failed to write bid value to ExecutorEnv")
            .stdout(&mut private_output)
            .build()
            .expect("Failed to build ExecutorEnv");

        // Execute the keygen guest circuit
        let session = default_prover();
        let bidder_join_receipt =
            session.prove(env, BIDDER_JOIN_ELF).expect("Failed to prove keygen").receipt;

        // Extract the results from the receipt
        // Private output contains: (p_j, q_j)
        let (p_j, q_j): (BigInt, BigInt) =
            from_slice(&private_output).expect("Failed to decode private output");
        // Journal contains: (n_j, c_j, r_j)
        let (n_j, c_j, r_j): (BigInt, Vec<BigInt>, Vec<BigInt>) =
            bidder_join_receipt.journal.decode().expect("Failed to decode keygen results");

        Self {
            p_j: BigInt::from(0),
            q_j: BigInt::from(0),
            n_j,
            v_j,
            c_j,
            r_j,
            receipts: BidderReceipts {
                join_receipt: Some(bidder_join_receipt),
                prover_receipts: Vec::new(),
                verify_receipt: None,
            },
            prover_results: HashMap::new(),
            verifier_results: HashMap::new(),
            security_param,
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
        let (rand1, rand2, rand3, rand4) = self.generate_shuffle_randoms();

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
        other_bidders_prover_receipts.iter().for_each(|receipt| {
            receipt.verify(BIDDER_PROVER_ID).expect("Failed to verify the receipt");
        }); 

        // Use the bidder-verify guest circuit to perform verification and comparison
        let env = ExecutorEnv::builder()
            .write(&(
                other_bidders_prover_receipts,
                self.security_param.clone(),
                (self.p_j.clone(), self.q_j.clone()),
                self.v_j.clone(),
            ))
            .expect("Failed to write inputs to ExecutorEnv")
            .build()
            .expect("Failed to build ExecutorEnv");

        // Execute the bidder-verify guest circuit
        let session = default_prover();
        let bidder_verify_prove_info = session
            .prove(env, BIDDER_VERIFY_ELF)
            .expect("Failed to prove bidder verification");

        let bidder_verify_receipt = bidder_verify_prove_info.receipt;

        // Extract the verification and comparison results
        let (revealed_v_i): Option<BigInt> =
            bidder_verify_receipt.journal.decode().expect("Failed to decode verification result");

        // Store the receipt
        self.receipts.verify_receipt = Some(bidder_verify_receipt);

        revealed_v_i
    }
}

impl BidderHost {
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
                x.push(get_next_random(&self.n_j));
                y.push(get_next_random(&self.n_j));
                x2.push(get_next_random(&self.n_j));
                y2.push(get_next_random(&self.n_j));
            }

            rand1.push(x);
            rand2.push(y);
            rand3.push(x2);
            rand4.push(y2);
        }

        (rand1, rand2, rand3, rand4)
    }
}
