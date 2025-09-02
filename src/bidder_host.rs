use anyhow::anyhow;
use num_bigint::{BigInt, RandBigInt};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use risc0_zkvm::serde::from_slice;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use std::collections::HashMap;
use zk_auctions_core::gm::{encrypt_gm, generate_keys, get_next_random, Keys};
use zk_auctions_core::protocols::strain::VerifiedReceipt;
use zk_auctions_core::protocols::strain::{Bidder, StrainSecurityParams};
use zk_auctions_core::utils::rand32;
use zk_auctions_core::utils::StrainProof;
use zk_auctions_methods::GUEST_ID;

/// BidderHost represents a bidder in the auction system
/// The bidder creates a ZK session to generate a receipt containing their bid
pub struct BidderHost {
    /// The bidder's verification instance
    bidder: Bidder,
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
    /// The bidder's soundness parameters
    security_param: StrainSecurityParams,
    /// Registry of verified other bidder receipts
    verified_receipts: HashMap<String, VerifiedReceipt>,
}

impl Default for BidderHost {
    fn default(security_param: StrainSecurityParams) -> Self {
        let mut rng = rand::thread_rng();
        let v_j: BigInt = rng.gen_bigint_range(&BigInt::from(0u32), &(BigInt::from(1u32) << 31));
        Self::new(v_j, security_param)
    }
}

impl BidderHost {
    /// Create a new bidder with a random bid
    /// TODO: move security_param to the auctioneer host
    pub fn new(v_j: BigInt, security_param: StrainSecurityParams) -> Self {
        let keys_j = generate_keys(None);
        let n_j = keys_j.pub_key;
        let (p_j, q_j) = keys_j.priv_key;
        let r_j: Vec<BigInt> = rand32(&n_j);
        let c_j = encrypt_gm(&v_j, &n_j);

        Self {
            p_j,
            q_j,
            n_j,
            v_j,
            c_j,
            r_j,
            security_param,
            bidder: Bidder::new(),
            verified_receipts: HashMap::new(),
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
    pub fn prove(
        &mut self,
        c_i: &Vec<BigInt>,
        n_i: &BigInt,
        r_i: &Vec<BigInt>,
    ) -> (Receipt, Vec<u8>) {
        // Generate random values for the shuffle proof
        let (rand1, rand2, rand3, rand4) = self.generate_shuffle_randoms();

        let mut private_output = Vec::new();
        // Set up the execution environment
        let env = ExecutorEnv::builder()
            .write(&(
                &self.c_j, &self.n_j, &self.r_j, &self.v_j, &self.p_j, &self.q_j, c_i, n_i, r_i,
            ))
            .expect("Failed to add encryption proof input")
            .write(&(&self.security_param.sigma, &(self.security_param.sound_param as u32))) // sigma and sound_param
            .expect("Failed to add discrete-log input")
            .write(&(&rand1, &rand2, &rand3, &rand4))
            .expect("Failed to add shuffle proof input")
            .stdout(&mut private_output)
            .build()
            .expect("Failed to build executor environment");

        // Create the prover and generate the receipt
        let session = default_prover();
        let receipt = session.prove(env, GUEST_ELF).expect("Failed to prove").receipt;

        (receipt, private_output)
    }

    /// Verify another bidder's receipt
    /// Performs all three verification steps: proof_enc, dlog_eq, and shuffle
    pub fn verify_other_bidder(&mut self, receipt: &risc0_zkvm::Receipt) -> bool {
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
        ) = receipt
            .journal
            .decode()
            .map_err(|e| anyhow!("Failed to decode receipt journal: {}", e))?;

        // 1. Verify the receipt itself using GUEST_ID
        assert!(receipt.verify(GUEST_ID).is_ok(), "Failed to verify receipt for n_j = {}", n_j);

        // 2. Verify proof_enc
        assert!(
            self.bidder.verify_proof_enc(proof_enc).is_ok(),
            "Failed to verify proof_enc for n_j = {}",
            n_j
        );

        // 3. Verify dlog_eq
        assert!(
            self.bidder.verify_dlog_eq(
                &self.security_param.sigma,
                &y_j,
                &n_j,
                &y_pow_r,
                &z_pow_r,
                &proof_dlog,
                Some(self.security_param.sound_param),
            ),
            "Failed to verify dlog_eq for n_j = {}",
            n_j
        );

        // 4. Verify shuffle
        assert!(
            self.bidder.verify_shuffle(&proof_shuffle, &n_j, &res).is_ok(),
            "Failed to verify shuffle for n_j = {}",
            n_j
        );

        // If all verifications pass, register the verified bidder
        self.register_verified_bidder(&n_j, &n_i, &c_j, &c_i, receipt);

        true
    }

    /// Register a verified bidder in the registry
    fn register_verified_bidder(
        &mut self,
        n_j: &BigInt,
        n_i: &BigInt,
        c_j: &Vec<BigInt>,
        c_i: &Vec<BigInt>,
        receipt: &Receipt,
    ) {
        let bidder_info = VerifiedReceipt {
            receipt: receipt.clone(),
            n_j: n_j.clone(),
            n_i: n_i.clone(),
            c_j: c_j.clone(),
            c_i: c_i.clone(),
        };

        // Generate a unique strain_id based on the public key
        self.verified_receipts.insert(n_j.to_string(), bidder_info);
    }

    /// Get information about a verified bidder
    pub fn get_verified_bidder(&self, n_j: &BigInt) -> Option<&VerifiedReceipt> {
        self.verified_receipts.get(n_j.to_string())
    }

    /// Get all verified bidders
    pub fn get_all_verified_bidders(&self) -> &HashMap<String, VerifiedReceipt> {
        &self.verified_receipts
    }

    /// Get the total number of verified bidders
    pub fn verified_bidder_count(&self) -> usize {
        self.verified_receipts.len()
    }

    /// Check if a bidder with the given strain_id is verified
    pub fn is_bidder_verified(&self, n_j: &BigInt) -> bool {
        self.verified_receipts.contains_key(n_j.to_string())
    }

    /// Remove a bidder from the verified registry
    pub fn remove_verified_bidder(&mut self, n_j: &BigInt) -> Option<VerifiedReceipt> {
        self.verified_receipts.remove(n_j.to_string())
    }

    /// Clear all verified bidders (useful for starting a new auction)
    pub fn clear_verified_bidders(&mut self) {
        self.verified_receipts.clear();
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
