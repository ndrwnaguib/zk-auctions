extern crate num_bigint;

use std::thread;

use num_bigint::BigInt;
use zk_auctions_application::auctioneer_thread::{AuctioneerThread, create_auction_channels};
use zk_auctions_application::bidder_thread::BidderThread;
use zk_auctions_application::shared_types::{ParallelAuctionResult, ParallelBidderConfig};
use zk_auctions_core::protocols::strain::StrainSecurityParams;

fn run_parallel_auction_scenario(bidder_configs: Vec<ParallelBidderConfig>) -> ParallelAuctionResult {
    let num_bidders = bidder_configs.len();
    println!("🚀 Starting PARALLEL auction with {} bidders", num_bidders);

    let start_time = std::time::Instant::now();

    // Shared soundness parameters
    let soundness = StrainSecurityParams::default();

    // Create communication channels
    let (bidder_tx, auctioneer_rx, bidder_txs, bidder_rxs, bidder_to_bidder_txs, mut bidder_to_bidder_rxs) = create_auction_channels(num_bidders);

    // Create auctioneer
    let auctioneer = AuctioneerThread::new(soundness.clone(), bidder_txs, auctioneer_rx);

    // Create bidder threads
    let mut bidder_handles = Vec::new();

    for (i, (config, bidder_rx)) in bidder_configs.into_iter().zip(bidder_rxs.into_iter()).enumerate() {
        // Get the channels for this specific bidder
        let other_bidder_txs = bidder_to_bidder_txs[i].clone();
        let other_bidder_rxs = std::mem::replace(&mut bidder_to_bidder_rxs[i], Vec::new());
        
        let bidder = BidderThread::new(config, soundness.clone(), bidder_tx.clone(), bidder_rx, num_bidders, other_bidder_txs, other_bidder_rxs);

        let handle = thread::spawn(move || {
            bidder.run();
        });
        bidder_handles.push(handle);
    }

    // Start auctioneer in a separate thread
    let auctioneer_handle = thread::spawn(move || auctioneer.run(num_bidders));

    // Wait for all threads to complete
    for handle in bidder_handles {
        handle.join().unwrap();
    }

    let result = auctioneer_handle.join().unwrap();
    let execution_time = start_time.elapsed();

    println!("⏱️  Total execution time: {:?}", execution_time);

    ParallelAuctionResult { execution_time, ..result }
}

fn main() {
    // Example: 2 bidders working in parallel
    let bidder_configs = vec![
        ParallelBidderConfig { id: 0, name: "Alice".to_string(), bid_value: BigInt::from(1000u32) },
        ParallelBidderConfig { id: 1, name: "Bob".to_string(), bid_value: BigInt::from(1500u32) },
    ];

    let result = run_parallel_auction_scenario(bidder_configs);

    println!("\n🎉 PARALLEL AUCTION COMPLETED!");
    println!("=== FINAL RESULTS ===");
    println!("Winner: {} (Bidder {}) with bid ${}", result.winner_name, result.winner_id, result.winner_bid);
    println!("Execution time: {:?}", result.execution_time);
    println!("All bids:");
    for (id, name, bid) in result.all_bids {
        println!("  Bidder {} ({}): ${}", id, name, bid);
    }
}

