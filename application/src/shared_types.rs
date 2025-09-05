use std::time::Duration;
use num_bigint::BigInt;
use risc0_zkvm::Receipt;

/// Configuration for a bidder in the parallel auction
#[derive(Debug, Clone)]
pub struct ParallelBidderConfig {
    pub id: usize,
    pub name: String,
    pub bid_value: BigInt,
}

/// Message types for communication between threads
#[derive(Debug, Clone)]
pub enum AuctionMessage {
    // Join phase messages
    BidderJoined { bidder_id: usize, name: String },
    JoinPhaseComplete,
    
    // Evaluation phase messages
    PublicInfo { bidder_id: usize, c_i: Vec<BigInt>, n_i: BigInt, r_i: Vec<BigInt> },
    ProofGenerated { prover_id: usize, target_id: usize, receipt: Receipt, private_output: Vec<u8> },
    ProofVerified { prover_id: usize, target_id: usize, is_valid: bool },
    ReceiptReceived { from_bidder_id: usize, to_bidder_id: usize, receipt: Receipt },
    PublicKey { bidder_id: usize, public_key: Vec<u8> },
    
    // Winner selection messages
    BidderResult { bidder_id: usize, won: bool, revealed_bid: Option<BigInt> },
    WinnerAnnouncement { bidder_id: usize, winner_name: String, winner_bid: BigInt },
    AuctionComplete { winner_id: usize, winner_name: String, winner_bid: BigInt },
}

/// Result of the parallel auction process
#[derive(Debug)]
pub struct ParallelAuctionResult {
    pub winner_name: String,
    pub winner_bid: BigInt,
    pub winner_id: usize,
    pub all_bids: Vec<(usize, String, BigInt)>,
    pub execution_time: Duration,
}

