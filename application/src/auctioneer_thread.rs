use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use num_bigint::BigInt;
use risc0_zkvm::Receipt;
use zk_auctions::strain::auctioneer::AuctioneerHost;
use zk_auctions_core::protocols::strain::{StrainSecurityParams, StrainAuctioneerHost};

use crate::shared_types::{AuctionMessage, ParallelAuctionResult};
use crate::{thread_output::*, teprintln, tprintln};

/// Create communication channels for a multi-bidder auction
pub fn create_auction_channels(num_bidders: usize) -> (mpsc::Sender<AuctionMessage>, mpsc::Receiver<AuctionMessage>, Vec<mpsc::Sender<AuctionMessage>>, Vec<mpsc::Receiver<AuctionMessage>>, Vec<Vec<mpsc::Sender<AuctionMessage>>>, Vec<Vec<Arc<Mutex<mpsc::Receiver<AuctionMessage>>>>>) {
    let (bidder_tx, auctioneer_rx) = mpsc::channel::<AuctionMessage>();
    
    // Create individual channels for each bidder to receive messages from auctioneer
    let mut bidder_txs = Vec::new();
    let mut bidder_rxs = Vec::new();
    
    // Create bidder-to-bidder communication channels
    // We need shared channels between each pair of bidders
    let mut bidder_to_bidder_txs = Vec::new();
    let mut bidder_to_bidder_rxs = Vec::new();
    
    // Create channels for each bidder pair (i,j) where i != j
    // We'll create a flat list of channels and distribute them
    let mut all_channels = Vec::new();
    for i in 0..num_bidders {
        for j in 0..num_bidders {
            if i != j {
                let (tx, rx) = mpsc::channel::<AuctionMessage>();
                all_channels.push((i, j, tx, Arc::new(Mutex::new(rx))));
            }
        }
    }
    
    for i in 0..num_bidders {
        let (tx, rx) = mpsc::channel::<AuctionMessage>();
        bidder_txs.push(tx);
        bidder_rxs.push(rx);
        
        let mut other_bidder_txs = Vec::new();
        let mut other_bidder_rxs = Vec::new();
        
        for j in 0..num_bidders {
            if i != j {
                // Find the channel for (i,j) - this is where i sends to j
                let (_, _, sender, _) = all_channels.iter().find(|(from, to, _, _)| *from == i && *to == j).unwrap();
                other_bidder_txs.push(sender.clone());
                
                // Find the channel for (j,i) - this is where i receives from j
                let (_, _, _, receiver) = all_channels.iter().find(|(from, to, _, _)| *from == j && *to == i).unwrap();
                other_bidder_rxs.push(receiver.clone());
            } else {
                // Placeholder for self (won't be used)
                let (_other_tx, _other_rx) = mpsc::channel::<AuctionMessage>();
                other_bidder_txs.push(_other_tx);
                other_bidder_rxs.push(Arc::new(Mutex::new(_other_rx)));
            }
        }
        bidder_to_bidder_txs.push(other_bidder_txs);
        bidder_to_bidder_rxs.push(other_bidder_rxs);
    }
    
    (bidder_tx, auctioneer_rx, bidder_txs, bidder_rxs, bidder_to_bidder_txs, bidder_to_bidder_rxs)
}

/// Auctioneer thread that coordinates the auction
pub struct AuctioneerThread {
    pub soundness: StrainSecurityParams,
    pub bidder_txs: Vec<mpsc::Sender<AuctionMessage>>,
    pub rx: mpsc::Receiver<AuctionMessage>,
}

impl AuctioneerThread {
    pub fn new(soundness: StrainSecurityParams, bidder_txs: Vec<mpsc::Sender<AuctionMessage>>, rx: mpsc::Receiver<AuctionMessage>) -> Self {
        AuctioneerThread { 
            soundness, 
            bidder_txs, 
            rx 
        }
    }

    pub fn run(mut self, num_bidders: usize) -> ParallelAuctionResult {
        let tag = "Auctioneer";
        tprintln!(tag, "Starting auction with {} bidders", num_bidders);

        let mut auctioneer_host = AuctioneerHost::new(self.soundness);
        let mut joined_bidders: Vec<(usize, String)> = Vec::new();
        let mut all_proofs: Vec<(usize, usize, Receipt, Vec<u8>)> = Vec::new();
        let mut bidder_configs: HashMap<usize, (String, BigInt)> = HashMap::new();
        let mut public_info_store: HashMap<usize, (Vec<BigInt>, BigInt, Vec<BigInt>)> = HashMap::new();

        // PHASE 1: JOIN PHASE
        tprintln!(tag, "🚀 PHASE 1: JOIN PHASE STARTING");

        while joined_bidders.len() < num_bidders {
            tprintln!(tag, "Waiting for bidders to join...");
            if let Ok(msg) = self.rx.recv() {
                match msg {
                    AuctionMessage::BidderJoined { bidder_id, name } => {
                        let name_clone = name.clone();
                        joined_bidders.push((bidder_id, name));
                        tprintln!(tag, "Bidder {} ({}) joined", bidder_id, name_clone);
                    }
                    _ => {}
                }
            }
        }

        tprintln!(tag, "✅ PHASE 1 COMPLETE: All {} bidders joined", num_bidders);

        // Notify all bidders that join phase is complete
        tprintln!(tag, "📢 Notifying bidders that join phase is complete...");
        for bidder_tx in &self.bidder_txs {
            bidder_tx.send(AuctionMessage::JoinPhaseComplete).expect("Failed to send join phase complete message to all bidders");
        }

        // PHASE 2: EVALUATION PHASE
        tprintln!(tag, "🔐 PHASE 2: EVALUATION PHASE STARTING");

        let mut proofs_received = 0;
        let expected_proofs = num_bidders * (num_bidders - 1);

        tprintln!(tag, "⏳ 2.2: Waiting for proofs & public information to be received from all bidders...");
        while proofs_received < expected_proofs {
            if let Ok(msg) = self.rx.recv() {
                match msg {
                    AuctionMessage::ProofGenerated { prover_id, target_id, receipt, private_output } => {
                        all_proofs.push((prover_id, target_id, receipt, private_output));
                        proofs_received += 1;
                        tprintln!(
                            tag,
                            "🔒 2.2: Received proof & public information from bidder {} against bidder {} ({}/{})",
                            prover_id, target_id, proofs_received, expected_proofs
                        );
                    }
                    _ => {}
                }
            }
        }

        tprintln!(tag, "✅ 2.2 COMPLETE: All proofs received. Starting verification...");

        // Verify all proofs
        tprintln!(tag, "🔍 2.3: Verifying all {} proofs...", all_proofs.len());
        let mut verification_results: Vec<(usize, usize, bool)> = Vec::new();

        for (prover_id, target_id, receipt, private_output) in all_proofs {
            tprintln!(tag, "Verifying proof from bidder {} against bidder {}...", prover_id, target_id);
            let is_valid = auctioneer_host.verify(&receipt, &private_output);
            verification_results.push((prover_id, target_id, is_valid));

            // Notify bidders about verification results
            tprintln!(tag, "📤 2.4: Sending verification result to all bidders...");
            for bidder_tx in &self.bidder_txs {
                bidder_tx
                    .send(AuctionMessage::ProofVerified { prover_id, target_id, is_valid })
                    .expect("Failed to send verification result to all bidders");
            }

            tprintln!(
                tag,
                "Proof from bidder {} against bidder {}: {}",
                prover_id,
                target_id,
                if is_valid { "✓" } else { "✗" }
            );
        }

        tprintln!(tag, "All proofs verified.");

        // Check if all verifications passed
        let all_verified = verification_results.iter().all(|(_, _, is_valid)| *is_valid);
        if !all_verified {
            teprintln!(tag, "Some proofs failed verification!");
            panic!("Some proofs failed verification!");
        }


        tprintln!(tag, "✅ PHASE 2 COMPLETE: All verification and data sharing done");

        // PHASE 3: WINNER SELECTION
        tprintln!(tag, "🏆 PHASE 3: WINNER SELECTION STARTING");
        tprintln!(tag, "⏳ 3.1: Waiting for winner announcement from bidders...");

        // Wait for winner announcement
        let mut winner_id = 0;
        let mut winner_name = String::new();
        let mut winner_bid = BigInt::from(0u32);

        while let Ok(msg) = self.rx.recv() {
            match msg {
                AuctionMessage::WinnerAnnouncement { bidder_id, winner_name: name, winner_bid: bid } => {
                    winner_id = bidder_id;
                    winner_name = name;
                    winner_bid = bid;
                    tprintln!(tag, "📢 3.2: Received winner announcement from bidder {}: {} with bid ${}", bidder_id, winner_name, winner_bid);
                    break;
                }
                _ => {}
            }
        }

        // Announce winner to all bidders
        tprintln!(tag, "🎉 3.3: ANNOUNCING WINNER: {} (Bidder {}) with bid ${}", winner_name, winner_id, winner_bid);
        for bidder_tx in &self.bidder_txs {
            bidder_tx
                .send(AuctionMessage::AuctionComplete { winner_id, winner_name: winner_name.clone(), winner_bid: winner_bid.clone() })
                .expect("Failed to send auction complete message to all bidders");
        }

        tprintln!(tag, "🎉 AUCTION COMPLETE! Winner: {} (Bidder {}) with bid ${}", winner_name, winner_id, winner_bid);

        // Create result
        let all_bids: Vec<(usize, String, BigInt)> = bidder_configs
            .iter()
            .map(|(id, (name, bid))| (*id, name.clone(), bid.clone()))
            .collect();

        ParallelAuctionResult {
            winner_name: winner_name.clone(),
            winner_bid: winner_bid.clone(),
            winner_id,
            all_bids,
            execution_time: Duration::from_millis(100),
        }
    }
}

