use num_bigint::{BigInt, RandBigInt};
use risc0_zkvm::serde::from_slice;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use std::collections::HashMap;
use zk_auctions_core::gm::{encrypt_gm, generate_keys, get_next_random, Keys};
use zk_auctions_core::utils::rand32;
use zk_auctions_core::protocols::strain::VerifiedReceipt;
use zk_auctions_core::protocols::strain::{StrainSecurityParams};
use zk_auctions_core::utils::StrainProof;
use zk_auctions_methods::{BIDDER_JOIN_ELF, BIDDER_PROVER_ELF, BIDDER_PROVER_ID, BIDDER_VERIFY_ELF};

/// Trait defining the bidder host operations in the Strain protocol
pub trait StrainBidderHost {
    /// Joins Auction by generating keys and encrypting the bid.
    fn new(v_j: BigInt, security_param: StrainSecurityParams) -> Self;
    
    /// Generate a zero-knowledge proof receipt for this bidder's bid
    fn prove(&mut self, c_i: &Vec<BigInt>, n_i: &BigInt, r_i: &Vec<BigInt>) -> (Receipt, Vec<u8>);

    /// Verify another bidder's receipt and perform comparison
    fn verify_other_bidder(&mut self, other_bidder_receipt: &Receipt) -> BidderVerificationResult;
}

/// Result of verifying another bidder's receipt
#[derive(Debug, Clone)]
pub struct BidderVerificationResult {
    /// Whether the verification succeeded
    pub is_verified: bool,
    /// Whether this bidder won the comparison
    pub is_won: bool,
    /// The revealed bid value if this bidder won, None otherwise
    pub revealed_bid: Option<BigInt>,
}

/// Collection of all receipts for a bidder across all stages
#[derive(Debug, Clone)]
pub struct BidderReceipts {
    /// Receipt from the bidder-join guest circuit (key generation)
    pub bidder_join_receipt: Option<Receipt>,
    /// Receipts from the bidder-prover guest circuit (one for each other bidder)
    pub bidder_prover_receipts: Vec<Receipt>,
    /// Receipts from the bidder-verify guest circuit (one for each other bidder)
    pub bidder_verify_receipts: Vec<Receipt>,
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
    /// The bidder's security parameters
    security_param: StrainSecurityParams,
    /// Registry of verified other bidder receipts
    verified_bidders_receipts: HashMap<String, VerifiedReceipt>,
    /// Collection of all receipts from all stages
    receipts: BidderReceipts,
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
        //let mut private_output = Vec::new();
        let env = ExecutorEnv::builder()
            .write(&v_j)
            .expect("Failed to write bid value to ExecutorEnv")
            //.stdout(&mut private_output)
            .build()
            .unwrap();

        // Execute the keygen guest circuit
        let session = default_prover();
        let bidder_join_receipt = session.prove(env, BIDDER_JOIN_ELF).expect("Failed to prove keygen").receipt;

        // Extract the results from the receipt
        // Private output contains: (p_j, q_j)
        //let (p_j, c_j, q_j): (BigInt, BigInt, BigInt) = from_slice(&private_output).expect("Failed to decode private output");
        // Journal contains: (n_j, c_j, r_j)
        let (n_j, c_j, r_j): (BigInt, Vec<BigInt>, Vec<BigInt>) = bidder_join_receipt.journal.decode().expect("Failed to decode keygen results");

        // Generate keys
        // let keys_j = generate_keys(None);
        // let n_j = keys_j.pub_key;
        // let (p_j, q_j) = keys_j.priv_key;

        // // Generate random values
        // let r_j: Vec<BigInt> = rand32(&n_j);

        // // Encrypt the bid value
        // let c_j = encrypt_gm(&v_j, &n_j);

        Self {
            p_j: BigInt::from(0),
            q_j: BigInt::from(0),
            n_j,
            v_j,
            c_j,
            r_j,
            verified_bidders_receipts: HashMap::new(),
            security_param,
            receipts: BidderReceipts {
                bidder_join_receipt: None,
                bidder_prover_receipts: Vec::new(),
                bidder_verify_receipts: Vec::new(),
            },
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
    fn prove(
        &mut self,
        c_i: &Vec<BigInt>,
        n_i: &BigInt,
        r_i: &Vec<BigInt>,
    ) -> (Receipt, Vec<u8>) {
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
        let bidder_prover_receipt = session.prove(env, BIDDER_PROVER_ELF).expect("Failed to prove").receipt;

        // Store the receipt
        self.receipts.bidder_prover_receipts.push(bidder_prover_receipt.clone());

        (bidder_prover_receipt, private_output)
    }

    /// Verify another bidder's receipt
    /// Performs all three verification steps: proof_enc, dlog_eq, and shuffle
    /// Also performs comparison and reveals the bid value if this bidder won
    fn verify_other_bidder(&mut self, other_bidder_receipt: &risc0_zkvm::Receipt) -> BidderVerificationResult {
        // First verify the receipt itself using BIDDER_PROVER_ID
        other_bidder_receipt.verify(BIDDER_PROVER_ID).expect("Failed to verify the receipt");

        // Decode the public results from the receipt journal
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
        ) = other_bidder_receipt
            .journal
            .decode()
            .expect("Failed to decode receipt journal");

        // Use the bidder-verify guest circuit to perform verification and comparison
        let env = ExecutorEnv::builder()
            .write(&(
                n_j.clone(),
                n_i.clone(),
                c_j.clone(),
                c_i.clone(),
                proof_enc.clone(),
                (proof_dlog.clone(), y_j.clone(), y_pow_r.clone(), z_pow_r.clone()),
                (proof_shuffle.clone(), res.clone()),
                self.security_param.clone(),
                (self.p_j.clone(), self.q_j.clone()), // Use this bidder's private key
                self.v_j.clone(), // Use this bidder's bid value
            ))
            .expect("Failed to write inputs to ExecutorEnv")
            .build()
            .expect("Failed to build ExecutorEnv");

        // Execute the bidder-verify guest circuit
        let session = default_prover();
        let bidder_verify_receipt = session.prove(env, BIDDER_VERIFY_ELF).expect("Failed to prove bidder verification").receipt;

        // Store the receipt
        self.receipts.bidder_verify_receipts.push(bidder_verify_receipt.clone());

        // Extract the verification and comparison results
        let (verification_success, is_won, revealed_v_i): (bool, bool, Option<BigInt>) = 
            bidder_verify_receipt.journal.decode().expect("Failed to decode verification result");

        if !verification_success {
            return BidderVerificationResult {
                is_verified: false,
                is_won: false,
                revealed_bid: None,
            };
        }

        // If all verifications pass, register the verified bidder
        self.verified_bidders_receipts.insert(n_j.to_string(), VerifiedReceipt {
            bidder_prover_receipt: other_bidder_receipt.clone(),
            auctioneer_verify_receipt: None,
            n_j: n_j.clone(),
            n_i: n_i.clone(),
            c_j: c_j.clone(),
            c_i: c_i.clone(),
        });

        BidderVerificationResult {
            is_verified: true,
            is_won,
            revealed_bid: revealed_v_i,
        }
    }
}

impl BidderHost {
    /// Create a new bidder with a random bid and default security parameters
    pub fn with_random_bid(security_param: StrainSecurityParams) -> Self {
        let mut rng = rand::thread_rng();
        let v_j: BigInt = rng.gen_bigint_range(&BigInt::from(0u32), &(BigInt::from(1u32) << 31));
        Self::new(v_j, security_param)
    }

    /// Get information about a verified bidder
    pub fn get_verified_bidder(&self, n_j: &BigInt) -> Option<&VerifiedReceipt> {
        self.verified_bidders_receipts.get(&n_j.to_string())
    }

    /// Get all verified bidders
    pub fn get_all_verified_bidders(&self) -> &HashMap<String, VerifiedReceipt> {
        &self.verified_bidders_receipts
    }

    /// Get the total number of verified bidders
    pub fn verified_bidder_count(&self) -> usize {
        self.verified_bidders_receipts.len()
    }

    /// Check if a bidder with the given strain_id is verified
    pub fn is_bidder_verified(&self, n_j: &BigInt) -> bool {
        self.verified_bidders_receipts.contains_key(&n_j.to_string())
    }

    /// Remove a bidder from the verified registry
    pub fn remove_verified_bidder(&mut self, n_j: &BigInt) -> Option<VerifiedReceipt> {
        self.verified_bidders_receipts.remove(&n_j.to_string())
    }

    /// Clear all verified bidders (useful for starting a new auction)
    pub fn clear_verified_bidders(&mut self) {
        self.verified_bidders_receipts.clear();
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
