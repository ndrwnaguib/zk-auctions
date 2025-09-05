use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex};

use num_bigint::BigInt;
use risc0_zkvm::Receipt;
use zk_auctions::strain::mock_bidder::MockBidderHost;
use zk_auctions_core::protocols::strain::{StrainSecurityParams, StrainBidderHost};

use crate::shared_types::{AuctionMessage, ParallelBidderConfig};
use crate::{thread_output::*, tprintln};

/// Individual bidder thread that operates independently
pub struct BidderThread {
    pub id: usize,
    pub name: String,
    pub bid_value: BigInt,
    pub soundness: StrainSecurityParams,
    pub tx: mpsc::Sender<AuctionMessage>,
    pub rx: mpsc::Receiver<AuctionMessage>,
    pub num_bidders: usize,
    pub other_bidder_txs: Vec<mpsc::Sender<AuctionMessage>>,
    pub other_bidder_rxs: Vec<Arc<Mutex<mpsc::Receiver<AuctionMessage>>>>,
}

impl BidderThread {
    pub fn new(
        config: ParallelBidderConfig, 
        soundness: StrainSecurityParams,
        bidder_tx: mpsc::Sender<AuctionMessage>,
        bidder_rx: mpsc::Receiver<AuctionMessage>,
        num_bidders: usize,
        other_bidder_txs: Vec<mpsc::Sender<AuctionMessage>>,
        other_bidder_rxs: Vec<Arc<Mutex<mpsc::Receiver<AuctionMessage>>>>
    ) -> Self {
        BidderThread {
            id: config.id,
            name: config.name,
            bid_value: config.bid_value,
            soundness,
            tx: bidder_tx,
            rx: bidder_rx,
            num_bidders,
            other_bidder_txs,
            other_bidder_rxs,
        }
    }

    pub fn run(mut self) {
        let tag = format!("Bidder {}", self.id);
        tprintln!(tag, "{} starting up with bid ${}", self.name, self.bid_value);

        // PHASE 1: JOIN PHASE
        tprintln!(tag, "🚀 PHASE 1: JOIN PHASE - {} joining auction", self.name);
        let mut bidder_host = MockBidderHost::new(self.bid_value.clone(), self.soundness);

        self.tx
            .send(AuctionMessage::BidderJoined { bidder_id: self.id, name: self.name.clone() })
            .unwrap();

        // Wait for join phase to complete
        tprintln!(tag, "{} waiting for join phase to complete...", self.name);
        while let Ok(msg) = self.rx.recv() {
            match msg {
                AuctionMessage::JoinPhaseComplete => break,
                _ => {}
            }
        }

        tprintln!(tag, "✅ PHASE 1 COMPLETE: {} join phase complete", self.name);

        // PHASE 2: EVALUATION PHASE
        tprintln!(tag, "🔐 PHASE 2: EVALUATION PHASE - {} entering evaluation phase", self.name);

        // Send public information
        let c_j = bidder_host.get_c_j();
        let n_j = bidder_host.get_n_j();
        let r_j = bidder_host.get_r_j();

        tprintln!(tag, "📤 2.1: {} sending cipher values (c_j, n_j, r_j) to other bidders...", self.name);
        // Send cipher values directly to all other bidders
        for other_bidder_tx in &self.other_bidder_txs {
            other_bidder_tx
                .send(AuctionMessage::PublicInfo { bidder_id: self.id, c_i: c_j.clone(), n_i: n_j.clone(), r_i: r_j.clone() })
                .expect("Failed to send cipher values to other bidder");
        }

        tprintln!(tag, "⏳ 2.2: {} waiting for cipher values (c_i, n_i, r_i) from other bidders...", self.name);
        // Collect public information from other bidders
        let mut other_bidders_info: HashMap<usize, (Vec<BigInt>, BigInt, Vec<BigInt>)> = HashMap::new();
        let mut proofs_generated = 0;
        let mut generated_receipts: HashMap<usize, Receipt> = HashMap::new(); // Store receipts by target_id
        let mut received_receipts: HashMap<usize, Receipt> = HashMap::new(); // Store receipts received from other bidders
        let expected_other_bidders = self.num_bidders - 1; // Each bidder expects n-1 other bidders' cipher values

        tprintln!(tag, "👂 2.2: {} listening for cipher values from other bidders...", self.name);
        
        // Listen for cipher values from other bidders using direct channels
        for other_bidder_rx in &self.other_bidder_rxs {
            if let Ok(msg) = other_bidder_rx.lock().unwrap().recv() {
                match msg {
                    AuctionMessage::PublicInfo { bidder_id, c_i, n_i, r_i } => {
                        if bidder_id != self.id {
                            other_bidders_info.insert(bidder_id, (c_i, n_i, r_i));
                            tprintln!(tag, "📥 2.2: Received cipher values (c_i, n_i, r_i) from bidder {}", bidder_id);

                            // Generate proof against this bidder
                            tprintln!(tag, "🔒 2.2: {} generating proof against bidder {}", self.name, bidder_id);
                            let (c_i, n_i, r_i) = other_bidders_info.get(&bidder_id).unwrap();
                            let (receipt, private_output) = bidder_host.prove(c_i, n_i, r_i);

                            // Store the receipt for later sending to the target bidder
                            generated_receipts.insert(bidder_id, receipt.clone());

                            tprintln!(tag, "📤 2.2: {} sending private data to auctioneer for verification", self.name);
                            self.tx
                                .send(AuctionMessage::ProofGenerated { prover_id: self.id, target_id: bidder_id, receipt, private_output })
                                .expect("Failed to send proof generated message");

                            proofs_generated += 1;
                            tprintln!(tag, "✅ 2.2: {} completed proof generation against bidder {}", self.name, bidder_id);
                            
                            // Check if we've generated all required proofs
                            if proofs_generated >= expected_other_bidders {
                                tprintln!(tag, "✅ 2.2 COMPLETE: {} generated all required proofs", self.name);
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        
        // Continue listening for auctioneer messages
        while let Ok(msg) = self.rx.recv() {
            match msg {
                AuctionMessage::ProofVerified { prover_id, target_id, is_valid } => {
                    if target_id == self.id {
                        tprintln!(tag, "📥 2.4: Received verification result from auctioneer - proof from bidder {}: {}", prover_id, if is_valid { "✓" } else { "✗" });
                        
                        // After receiving verification result, send receipt to the specific target bidder
                        tprintln!(tag, "📤 2.5: {} sending receipt to bidder {} (the target of this proof)", self.name, prover_id);
                        // Find the correct channel to send to the target bidder
                        if let Some(receipt) = generated_receipts.get(&prover_id) {
                            // Find the channel index that corresponds to the target bidder
                            let mut target_channel_index = 0;
                            for (i, _) in self.other_bidder_txs.iter().enumerate() {
                                if i == prover_id {
                                    target_channel_index = i;
                                    break;
                                }
                            }
                            
                            if let Some(target_tx) = self.other_bidder_txs.get(target_channel_index) {
                                target_tx
                                    .send(AuctionMessage::ReceiptReceived { 
                                        from_bidder_id: self.id, 
                                        to_bidder_id: prover_id, 
                                        receipt: receipt.clone() 
                                    })
                                    .expect("Failed to send receipt to target bidder");
                            }
                        }
                    }
                }
                AuctionMessage::ReceiptReceived { from_bidder_id, to_bidder_id, receipt } => {
                    if to_bidder_id == self.id {
                        tprintln!(tag, "📥 2.5: {} received receipt from bidder {}", self.name, from_bidder_id);
                        received_receipts.insert(from_bidder_id, receipt);
                        
                        // Check if we've received all expected receipts
                        if received_receipts.len() == expected_other_bidders {
                            tprintln!(tag, "✅ 2.5 COMPLETE: {} received all receipts. Starting winner selection...", self.name);
                            
                            // PHASE 3: WINNER SELECTION
                            tprintln!(tag, "🏆 PHASE 3: WINNER SELECTION - {} verifying receipts to determine winner", self.name);
                            
                            let mut is_winner = false;
                            
                            // Convert received receipts to vector for verification
                            let receipts_vec: Vec<Receipt> = received_receipts.values().cloned().collect();
                            
                            tprintln!(tag, "🔍 3.1: {} verifying all {} receipts to determine winner", self.name, receipts_vec.len());
                            
                            // Verify all receipts and determine if this bidder wins
                            match bidder_host.verify_other_bidders(&receipts_vec) {
                                Some(extracted_bid) => {
                                    tprintln!(tag, "✅ 3.1: {} successfully verified all receipts - extracted bid: ${}", self.name, extracted_bid);
                                    
                                    // If we can extract our bid value, we are the winner
                                    if extracted_bid == self.bid_value {
                                        is_winner = true;
                                        tprintln!(tag, "🎉 3.2: {} IS THE WINNER! Successfully extracted own bid value: ${}", self.name, extracted_bid);
                                        
                                        // Send winner announcement to auctioneer
                                        tprintln!(tag, "📢 3.3: {} announcing victory to auctioneer", self.name);
                                        self.tx
                                            .send(AuctionMessage::WinnerAnnouncement { 
                                                bidder_id: self.id, 
                                                winner_name: self.name.clone(), 
                                                winner_bid: self.bid_value.clone() 
                                            })
                                            .expect("Failed to send winner announcement to auctioneer");
                                    } else {
                                        tprintln!(tag, "🤔 3.2: {} extracted different bid value: ${} (expected: ${})", self.name, extracted_bid, self.bid_value);
                                    }
                                }
                                None => {
                                    tprintln!(tag, "❌ 3.1: {} failed to verify receipts or is not the winner", self.name);
                                }
                            }
                            
                            if !is_winner {
                                tprintln!(tag, "😞 3.2: {} is NOT the winner - could not extract own bid value from any receipt", self.name);
                            }
                        }
                    }
                }
                AuctionMessage::AuctionComplete { .. } => {
                    tprintln!(tag, "🏆 PHASE 3: {} received auction completion notification", self.name);
                    break;
                },
                _ => {}
            }
        }

        tprintln!(tag, "🏁 {} shutting down - auction complete", self.name);
    }
}

