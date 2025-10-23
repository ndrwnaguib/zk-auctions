use num_bigint::BigInt;
use std::thread;
use std::sync::mpsc;

use crate::host::mock_bidder_join;
use crate::host::bidders_prove_all;
use crate::host::auctioneer_verify_all;
use crate::host::bidder_verify_all;
use std::collections::HashMap;

pub mod web_server;

pub fn run_two_bidders_example() { 
    // ==================================================================================
    // PHASE 1: BIDDERS JOIN - Generate keys and encrypt bid values
    // ==================================================================================
    // Each bidder generates their own GM keypair (n_j, p_j, q_j) and encrypts their bid
    // This phase runs in parallel for all bidders to reduce total execution time
    // Output: Each bidder gets (n_j, c_j, r_j, (p_j, q_j)) where:
    //   - n_j: public key
    //   - c_j: encrypted bid value  
    //   - r_j: random values used in encryption
    //   - (p_j, q_j): private key components
    // ==================================================================================
    println!("[host] PHASE 1: Bidders Join - Generating keys and encrypting bids...");
    
    // Create channels for communication between threads
    let (tx, rx) = mpsc::channel();
    
    // Spawn first bidder thread
    let tx1 = tx.clone();
    let handle1 = thread::spawn(move || {
        let v_i: BigInt = BigInt::from(1500);
        println!("[host] Starting bidder1 thread with bid v_i = {}", v_i);
        let result = mock_bidder_join("bidder1".to_string(), v_i.clone());
        println!("[host] Bidder1 thread completed");
        tx1.send(("bidder1", v_i, result)).unwrap();
    });
    
    // Spawn second bidder thread
    let handle2 = thread::spawn(move || {
        let v_j: BigInt = BigInt::from(2000);
        println!("[host] Starting bidder2 thread with bid v_j = {}", v_j);
        let result = mock_bidder_join("bidder2".to_string(), v_j.clone());
        println!("[host] Bidder2 thread completed");
        tx.send(("bidder2", v_j, result)).unwrap();
    });
    
    // Wait for both threads to complete and collect results
    println!("[host] Waiting for both bidders to complete...");
    let mut bidder1_result = None;
    let mut bidder2_result = None;
    
    for _ in 0..2 {
        let (bidder_id, bid_value, (n, c, r, (p, q))) = rx.recv().unwrap();
        match bidder_id {
            "bidder1" => {
                bidder1_result = Some((n, c, r, (p, q), bid_value));
                println!("[host] Received bidder1 results");
            },
            "bidder2" => {
                bidder2_result = Some((n, c, r, (p, q), bid_value));
                println!("[host] Received bidder2 results");
            },
            _ => panic!("Unknown bidder ID"),
        }
    }
    
    // Join threads to ensure they're finished
    handle1.join().unwrap();
    handle2.join().unwrap();
    
    // Extract results
    let (n_1, c_1, r_1, (p_1, q_1), v_1) = bidder1_result.unwrap();
    let (n_2, c_2, r_2, (p_2, q_2), v_2) = bidder2_result.unwrap();
    // Preserve bid values for final logging before moves elsewhere
    let v1_for_log = v_1.clone();
    let v2_for_log = v_2.clone();
    
    println!("[host] First bidder's bid v_1 = {}", v_1);
    println!("[host] Second bidder's bid v_2 = {}", v_2);

    // ==================================================================================
    // PHASE 2: BIDDER PROVE - Each bidder runs bidder_prove against other bidders
    // ==================================================================================
    // Each bidder "j" runs the zkVM bidder_prove guest method with respect to bidder "i"
    // - "j" = the bidder running the proof (me)
    // - "i" = the other bidder being compared against
    // This generates zero-knowledge proofs that bidder j's bid is valid
    // Output: proof_eval, proof_enc, proof_dlog, and comparison results
    // ==================================================================================
    println!("[host] PHASE 2: Bidder Prove - Generating zero-knowledge proofs in parallel...");

    let sound_param: usize = 40;
    let sigma: BigInt = BigInt::from(40);
    println!("[host] sound_param = {} sigma = {}", sound_param, sigma);

    // Store bidder data before moving into bidders vector
    let bidder1_data = (n_1.clone(), p_1.clone(), q_1.clone());
    let bidder2_data = (n_2.clone(), p_2.clone(), q_2.clone());
    
    // Store copies for later use (not used in current implementation)
    let _p_1_copy = bidder1_data.1.clone();
    let _q_1_copy = bidder1_data.2.clone();
    
    // Prepare bidders data for parallel processing
    let bidders = vec![
        ("bidder1".to_string(), n_1, c_1, r_1, v_1, p_1, q_1),
        ("bidder2".to_string(), n_2, c_2, r_2, v_2, p_2, q_2),
    ];

    // Run Phase 2 in parallel
    let phase2_results = bidders_prove_all(bidders, sound_param, sigma);

    // ==================================================================================
    // PHASE 3: AUCTIONEER VERIFY - Verify all proof_eval from all bidders
    // ==================================================================================
    // The auctioneer verifies the evaluation proofs (proof_eval) from all bidders
    // This ensures that all bidders have provided valid zero-knowledge proofs
    // The auctioneer acts as a trusted verifier in this phase
    // Only proceed to Phase 4 if ALL verifications pass
    // ==================================================================================
    
    // Prepare bidders data for verification
    let mut bidders_data = HashMap::new();
    bidders_data.insert("bidder1".to_string(), bidder1_data);
    bidders_data.insert("bidder2".to_string(), bidder2_data);
    
    // Verify all results using the cleaner function
    if !auctioneer_verify_all(&phase2_results, &bidders_data, sound_param) {
        println!("[host] Protocol stopped due to verification failures");
        return;
    }

    // ==================================================================================
    // PHASE 4: BIDDER VERIFY ALL - Each bidder verifies other bidders' results in parallel
    // ==================================================================================
    // Each bidder verifies the proofs from other bidders using bidder_verify_all
    // This includes verifying proof_enc (encryption proof) and proof_dlog (discrete log proof)
    // This ensures mutual verification between bidders
    // Also includes the final bid comparison using compare_leq_honest
    // Each bidder determines if they are the winner by comparing against all other bidders
    // ==================================================================================
    
    // Run the comprehensive bidder verification
    let winner_results = bidder_verify_all(&phase2_results, &bidders_data, sound_param);
    
    // Final winner announcement (only show winner id and bid value if there is exactly one)
    let mut winners = Vec::new();
    for (bidder_id, is_winner) in &winner_results {
        if *is_winner {
            winners.push(bidder_id);
        }
    }
    if winners.len() == 1 {
        let winner_id = winners[0];
        let winner_bid = if winner_id == &"bidder1" { v1_for_log } else { v2_for_log };
        println!("[host] 🎉 WINNER: {} (Bid: {})", winner_id, winner_bid);
    }
}

pub fn run_n_bidders_example(bidders: Vec<(String, BigInt)>) {
    // ==================================================================================
    // N-BIDDER AUCTION PROTOCOL - Configurable bidders with names and bid values
    // ==================================================================================
    println!("[host] Starting N-Bidder Auction Protocol...");
    
    let num_bidders = bidders.len();
    let sound_param: usize = 40;
    let sigma: BigInt = BigInt::from(40);
    
    println!("[host] Running auction with {} bidders", num_bidders);
    println!("[host] sound_param = {} sigma = {}", sound_param, sigma);

    // ==================================================================================
    // PHASE 1: BIDDERS JOIN - Generate keys and encrypt bid values (parallel)
    // ==================================================================================
    println!("[host] PHASE 1: Bidders Join - Generating keys and encrypting bids for {} bidders...", num_bidders);

    let (tx, rx) = mpsc::channel();
    let mut threads = Vec::new();
    
    for (bidder_id, bid_value) in bidders {
        let tx_clone = tx.clone();
        
        let handle = thread::spawn(move || {
            println!("[host] Starting {} thread with bid v = {}", bidder_id, bid_value);
            let result = mock_bidder_join(bidder_id.clone(), bid_value.clone());
            println!("[host] {} thread completed", bidder_id);
            tx_clone.send((bidder_id, bid_value, result)).unwrap();
        });
        
        threads.push(handle);
    }
    
    // Collect results from all bidders
    let mut bidder_results = HashMap::new();
    for _ in 0..num_bidders {
        let (bidder_id, bid_value, (n, c, r, (p, q))) = rx.recv().unwrap();
        bidder_results.insert(bidder_id.clone(), (n, c, r, p, q, bid_value));
        println!("[host] Received {} results", bidder_id);
    }
    
    // Wait for all threads to complete
    for handle in threads {
        handle.join().unwrap();
    }
    
    println!("[host] PHASE 1: All {} bidders have joined successfully", num_bidders);

    // ==================================================================================
    // PHASE 2: BIDDER PROVE - Each bidder runs bidder_prove against other bidders (parallel)
    // ==================================================================================
    println!("[host] PHASE 2: Bidder Prove - Generating zero-knowledge proofs for all bidder pairs...");
    println!("[host] Expected number of proof operations: {} (n*(n-1) where n={})", num_bidders * (num_bidders - 1), num_bidders);
    
    // Prepare bidders data for parallel processing
    let mut bidders_data = Vec::new();
    let mut bidders_data_map = HashMap::new();
    
    for (bidder_id, (n, c, r, p, q, v)) in &bidder_results {
        bidders_data.push((
            bidder_id.clone(),
            n.clone(),
            c.clone(),
            r.clone(),
            v.clone(),
            p.clone(),
            q.clone(),
        ));
        bidders_data_map.insert(bidder_id.clone(), (n.clone(), p.clone(), q.clone()));
    }
    
    // Run Phase 2 in parallel
    let phase2_results = bidders_prove_all(bidders_data, sound_param, sigma);
    
    println!("[host] PHASE 2: All bidder_prove operations completed for {} bidders", num_bidders);

    // ==================================================================================
    // PHASE 3: AUCTIONEER VERIFY - Verify all proof_eval and receipts from all bidders
    // ==================================================================================
    println!("[host] PHASE 3: Auctioneer Verify - Verifying all evaluation proofs and receipts...");
    
    if !auctioneer_verify_all(&phase2_results, &bidders_data_map, sound_param) {
        println!("[host] Protocol stopped due to verification failures");
        return;
    }
    
    println!("[host] PHASE 3: All auctioneer verifications passed");

    // ==================================================================================
    // PHASE 4: BIDDER VERIFY ALL & WINNER DETERMINATION - Each bidder verifies other bidders' results
    // ==================================================================================
    println!("[host] PHASE 4: Bidder Verify All - Each bidder verifies other bidders' results in parallel...");
    
    // Run the comprehensive bidder verification
    let winner_results = bidder_verify_all(&phase2_results, &bidders_data_map, sound_param);
    
    // Final winner announcement (only show winner id and bid value if there is exactly one)
    let mut winners = Vec::new();
    for (bidder_id, is_winner) in &winner_results {
        if *is_winner {
            winners.push(bidder_id);
        }
    }
    if winners.len() == 1 {
        let winner_id = winners[0];
        let winner_bid = bidder_results.get(winner_id).unwrap().5.clone();
        println!("[host] 🎉 WINNER: {} (Bid: {})", winner_id, winner_bid);
    }
}
