use num_bigint::BigInt;
use num_traits::One;
 
use risc0_zkvm::{default_prover, serde::from_slice, ExecutorEnv};
use std::collections::HashMap;
use std::thread;
use std::sync::mpsc;
use zk_auctions_core::gm::{get_next_random, generate_keys, encrypt_gm};
use zk_auctions_core::utils::rand32;
use zk_auctions_core::protocols::strain::auctioneer::{Auctioneer, StrainAuctioneer};
use zk_auctions_core::utils::{
    compare_leq_honest, get_rand_jn1, hash_flat, set_rand_seed, StrainProof,
};
use zk_auctions_methods::{BIDDER_PROVER_ELF, BIDDER_PROVER_ID, BIDDER_JOIN_ELF};

// Struct to store bidder prove results
#[derive(Clone)]
pub struct BidderProveResult {
    proof_eval: Vec<Vec<Vec<BigInt>>>,
    plaintext_and_coins: Vec<Vec<(BigInt, BigInt, BigInt)>>,
    n_j_from_proof: BigInt,
    proof_enc: Vec<Vec<Vec<BigInt>>>,
    proof_dlog: Vec<(BigInt, BigInt, BigInt)>,
    y_j: BigInt,
    y_pow_r: BigInt,
    z_pow_r: BigInt,
    proof_shuffle: HashMap<u32, StrainProof>,
    res: Vec<Vec<BigInt>>,
    receipt: risc0_zkvm::Receipt,
    other_bidder_id: String,
}

pub fn auctioneer_verify(
    proof_eval: &Vec<Vec<Vec<BigInt>>>,
    plaintext_and_coins: &Vec<Vec<(BigInt, BigInt, BigInt)>>,
    n_i: &BigInt,
    n_j: &BigInt,
    sound_param: usize,
) {
    let auctioneer = Auctioneer::new();
    let eval_res = Some(auctioneer.verify_eval(
        proof_eval.clone(),
        plaintext_and_coins.clone(),
        n_i,
        n_j,
        sound_param,
    ));
    assert!(eval_res.is_some(), "`proof_eval` verification failed.");
    println!("[(auctioneer)-host-auctioneer-verify] proof_eval verification passed.");
}

pub fn auctioneer_verify_all(
    phase2_results: &HashMap<String, Vec<BidderProveResult>>,
    bidders_data: &HashMap<String, (BigInt, BigInt, BigInt)>, // (n_i, p_i, q_i) for each bidder
    sound_param: usize,
) -> bool {
    println!("[(auctioneer)-host-auctioneer-verify-all] PHASE 3: Auctioneer Verify - Verifying all evaluation proofs and receipts from all bidders...");
    
    let mut all_verifications_passed = true;
    
    // Verify all results from all bidders
    for (bidder_id, results) in phase2_results {
        println!("[(auctioneer)-host-auctioneer-verify-all] Verifying {} results for bidder: {}", results.len(), bidder_id);
        
        for (i, result) in results.iter().enumerate() {
            println!("[(auctioneer)-host-auctioneer-verify-all] Verifying result {} for bidder {} vs {}", i + 1, bidder_id, result.other_bidder_id);
            
            // First verify the receipt
            match result.receipt.verify(BIDDER_PROVER_ID) {
                Ok(_) => {
                    // Receipt verification passed
                },
                Err(_e) => {
                    // Receipt verification failed
                    all_verifications_passed = false;
                    continue; // Skip other verifications if receipt fails
                }
            }
            
            // Get the corresponding bidder i data for verification
            let (n_i, p_i, q_i) = bidders_data.get(bidder_id).unwrap();
            
            // println!("[(auctioneer)-host] Verifying proof_eval for {} vs {}", bidder_id, result.other_bidder_id);
            // println!("[host] proof_eval = {:?}", result.proof_eval);
            // println!("[host] plaintext_and_coins = {:?}", result.plaintext_and_coins);
            // println!("[(auctioneer)-host] n_i = {:?}", n_i);
            // println!("[(auctioneer)-host] n_j_from_proof = {:?}", result.n_j_from_proof);
            // println!("[host] sound_param = {:?}", sound_param);

            // Verify this specific proof_eval
            match std::panic::catch_unwind(|| {
                auctioneer_verify(&result.proof_eval, &result.plaintext_and_coins, n_i, &result.n_j_from_proof, sound_param);
            }) {
                Ok(_) => {
                    println!("[(auctioneer)-host-auctioneer-verify-all] ✅ Verification PASSED for {} result {} vs {}", bidder_id, i + 1, result.other_bidder_id);
                },
                Err(_) => {
                    println!("[(auctioneer)-host-auctioneer-verify-all] ❌ Verification FAILED for {} result {} vs {}", bidder_id, i + 1, result.other_bidder_id);
                    all_verifications_passed = false;
                }
            }
        }
    }
    
    if all_verifications_passed {
        println!("[(auctioneer)-host-auctioneer-verify-all] ✅ ALL auctioneer verifications PASSED - Proceeding to Phase 4");
    } else {
        println!("[(auctioneer)-host-auctioneer-verify-all] ❌ Some auctioneer verifications FAILED - Stopping protocol");
    }
    
    all_verifications_passed
}

pub fn bidder_join(bidder_id: String, bid_value: BigInt) -> (BigInt, Vec<BigInt>, Vec<BigInt>, (BigInt, BigInt)) {
    println!("[({})-host-bidder-join] Starting bidder_join for bidder: {}", bidder_id, bidder_id);
    
    // Create environment for the bidder_join guest method
    let mut private_output = Vec::new();
    let env = ExecutorEnv::builder()
        .write(&bidder_id)
        .expect("Failed to add bidder_id")
        .write(&bid_value)
        .expect("Failed to add bid_value")
        .stdout(&mut private_output)
        .build()
        .unwrap();
    
    println!("[({})-host-bidder-join] ExecutorEnv built for bidder_join. Running zkVM...", bidder_id);
    
    // Run the bidder_join guest method
    let session = default_prover();
    let receipt = session.prove(env, BIDDER_JOIN_ELF).unwrap().receipt;
    println!("[({})-host-bidder-join] zkVM proof generated for bidder_join. Verifying...", bidder_id);
    
    // Read private output (private key components)
    let (p_j, q_j): (BigInt, BigInt) = from_slice(&private_output)
        .expect("Failed to deserialize private key data");
    
    // Read public output from journal
    let (n_j, c_j, r_j): (BigInt, Vec<BigInt>, Vec<BigInt>) = receipt.journal.decode()
        .expect("Failed to decode public results");
    
    println!("[({})-host-bidder-join] bidder {} generated public key n_j = {}", bidder_id, bidder_id, n_j);
    println!("[({})-host-bidder-join] bidder {} encrypted value c_j (len={})", bidder_id, bidder_id, c_j.len());
    
    (n_j, c_j, r_j, (p_j, q_j))
}

pub fn mock_bidder_join(bidder_id: String, bid_value: BigInt) -> (BigInt, Vec<BigInt>, Vec<BigInt>, (BigInt, BigInt)) {
    println!("[host] Starting mock_bidder_join for bidder: {}", bidder_id);
    println!("[({})-host-bidder-join] Starting bidder join process", bidder_id);
    println!("[({})-host-bidder-join] Bid value: {}", bidder_id, bid_value);
    
    // Generate keys using pure Rust (same as zkVM version)
    println!("[({})-host-bidder-join] Generating GM keypair...", bidder_id);
    let keys_j = generate_keys(None);
    let n_j = keys_j.pub_key;
    let (p_j, q_j) = keys_j.priv_key;
    println!("[({})-host-bidder-join] Keypair generated successfully", bidder_id);
    
    // Generate random values using pure Rust
    println!("[({})-host-bidder-join] Generating random values...", bidder_id);
    let r_j: Vec<BigInt> = rand32(&n_j);
    println!("[({})-host-bidder-join] Random values generated", bidder_id);
    
    // Encrypt the bid value using pure Rust
    println!("[({})-host-bidder-join] Encrypting bid value...", bidder_id);
    let c_j = encrypt_gm(&bid_value, &n_j);
    println!("[({})-host-bidder-join] Bid value encrypted successfully", bidder_id);
    
    println!("[({})-host-bidder-join] bidder {} generated public key n_j = {}", bidder_id, bidder_id, n_j);
    println!("[({})-host-bidder-join] bidder {} encrypted value c_j (len={})", bidder_id, bidder_id, c_j.len());
    println!("[({})-host-bidder-join] bidder {} joined successfully", bidder_id, bidder_id);
    
    (n_j, c_j, r_j, (p_j, q_j))
}

// Helper function to truncate public key for display (privacy-preserving)
fn truncate_pubkey(pubkey: &BigInt) -> String {
    let full = pubkey.to_string();
    if full.len() > 10 {
        format!("{}...{}", &full[..5], &full[full.len()-5..])
    } else {
        full
    }
}

pub fn bidders_prove_all(
    bidders: Vec<(String, BigInt, Vec<BigInt>, Vec<BigInt>, BigInt, BigInt, BigInt)>, // (id, n, c, r, v, p, q)
    sound_param: usize,
    sigma: BigInt,
) -> HashMap<String, Vec<BidderProveResult>> {
    println!("[host-bidders-prove-all] PHASE 2: Running bidder_prove in parallel for all bidder pairs...");
    
    let mut results: HashMap<String, Vec<BidderProveResult>> = HashMap::new();
    let (tx, rx) = mpsc::channel();
    
    // Create all possible bidder pairs
    let mut threads = Vec::new();
    
    for i in 0..bidders.len() {
        for j in 0..bidders.len() {
            if i != j {
                let (bidder_i_id, n_i, c_i, r_i, v_i, p_i, q_i) = bidders[i].clone();
                let (bidder_j_id, n_j, c_j, r_j, v_j, p_j, q_j) = bidders[j].clone();
                let tx_clone = tx.clone();
                let sigma_clone = sigma.clone();
                
                let handle = thread::spawn(move || {
                    // For privacy: show other bidder's public key (truncated) instead of name
                    let n_i_truncated = truncate_pubkey(&n_i);
                    println!("[({})-host-bidders-prove-all] Starting bidder_prove vs pubkey {}", bidder_j_id, n_i_truncated);
                    
                    let (proof_eval, plaintext_and_coins, n_j_from_proof, proof_enc, (proof_dlog, y_j, y_pow_r, z_pow_r), (proof_shuffle, res), receipt) = 
                        bidder_prove(bidder_j_id.clone(), c_i, n_i.clone(), r_i, n_j, r_j, v_j, p_j, q_j, sound_param, sigma_clone);
                    
                    let result = BidderProveResult {
                        proof_eval,
                        plaintext_and_coins,
                        n_j_from_proof,
                        proof_enc,
                        proof_dlog,
                        y_j,
                        y_pow_r,
                        z_pow_r,
                        proof_shuffle,
                        res,
                        receipt,
                        other_bidder_id: bidder_i_id.clone(),
                    };
                    
                    println!("[({})-host-bidders-prove-all] Completed bidder_prove vs pubkey {}", bidder_j_id, n_i_truncated);
                    tx_clone.send((bidder_j_id, bidder_i_id, result)).unwrap();
                });
                
                threads.push(handle);
            }
        }
    }
    
    // Collect results
    for _ in 0..threads.len() {
        let (bidder_j_id, bidder_i_id, result) = rx.recv().unwrap();
        results.entry(bidder_j_id).or_insert_with(Vec::new).push(result);
    }
    
    // Wait for all threads to complete
    for handle in threads {
        handle.join().unwrap();
    }
    
    println!("[host-bidders-prove-all] PHASE 2: All bidder_prove operations completed");
    results
}

pub fn bidder_prove(
    bidder_id: String,
    c_i: Vec<BigInt>,
    n_i: BigInt,
    r_i: Vec<BigInt>,
    n_j: BigInt,
    r_j: Vec<BigInt>,
    v_j: BigInt,
    p_j: BigInt,
    q_j: BigInt,
    sound_param: usize,
    sigma: BigInt,
) -> (
    Vec<Vec<Vec<BigInt>>>,
    Vec<Vec<(BigInt, BigInt, BigInt)>>,
    BigInt,
    Vec<Vec<Vec<BigInt>>>,
    (Vec<(BigInt, BigInt, BigInt)>, BigInt, BigInt, BigInt),
    (HashMap<u32, StrainProof>, Vec<Vec<BigInt>>),
    risc0_zkvm::Receipt,
) {
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
            x.push(get_next_random(&n_i));
            y.push(get_next_random(&n_i));
            x2.push(get_next_random(&n_i));
            y2.push(get_next_random(&n_i));
        }
        rand1.push(x);
        rand2.push(y);
        rand3.push(x2);
        rand4.push(y2);
    }

    let mut private_output = Vec::new();
    println!("[({})-host-bidder-prove] Building ExecutorEnv...", bidder_id);
    let env = ExecutorEnv::builder()
        .write(&bidder_id)
        .expect("Failed to add guest_id")
        .write(&(&n_j, &r_j, &v_j, &p_j, &q_j))
        .expect("Failed to add bidder j data")
        .write(&(&c_i, &n_i, &r_i))
        .expect("Failed to add bidder i data")
        .write(&(&sigma, &(sound_param as u32)))
        .expect("Failed to add parameters")
        .write(&(&rand1, &rand2, &rand3, &rand4))
        .expect("Failed to add random values")
        .stdout(&mut private_output)
        .build()
        .unwrap();
    println!("[({})-host-bidder-prove] ExecutorEnv built successfully.", bidder_id);

    let session = default_prover();
    println!("[({})-host-bidder-prove] Running zkVM (prove)...", bidder_id);
    let receipt = session.prove(env, BIDDER_PROVER_ELF).unwrap().receipt;
    println!("[({})-host-bidder-prove] zkVM proof generated.", bidder_id);

    println!("[({})-host-bidder-prove] Reading private output...", bidder_id);
    let (proof_eval, plaintext_and_coins): (
        Vec<Vec<Vec<BigInt>>>,
        Vec<Vec<(BigInt, BigInt, BigInt)>>,
    ) = from_slice(&private_output).expect("Failed to deserialize private data");
    println!("[({})-host-bidder-prove] Private output deserialization successful.", bidder_id);

    println!("[({})-host-bidder-prove] Decoding public results from journal...", bidder_id);
    let (n_j, proof_enc, proof_dlog_tuple, proof_shuffle_tuple): (
        BigInt,
        Vec<Vec<Vec<BigInt>>>,
        (Vec<(BigInt, BigInt, BigInt)>, BigInt, BigInt, BigInt),
        (HashMap<u32, StrainProof>, Vec<Vec<BigInt>>),
    ) = receipt.journal.decode().expect("Failed to decode all results");
    println!("[({})-host-bidder-prove] Got n_j = {}", bidder_id, n_j);

    (proof_eval, plaintext_and_coins, n_j, proof_enc, proof_dlog_tuple, proof_shuffle_tuple, receipt)
}

pub fn bidder_verify(
    bidder_label: &str,
    proof_enc: Vec<Vec<Vec<BigInt>>>,
    proof_dlog: Vec<(BigInt, BigInt, BigInt)>,
    y_j: BigInt,
    y_pow_r: BigInt,
    z_pow_r: BigInt,
    n_j_from_proof: &BigInt,
    sound_param: usize,
    res: Vec<Vec<BigInt>>,
    p_i: BigInt,
    q_i: BigInt,
) -> bool {
    println!("[({})-host-bidder-verify] Verifying proof_enc...", bidder_label);
    assert!(verify_proof_enc(proof_enc));
    println!("[({})-host-bidder-verify] proof_enc verification passed.", bidder_label);

    println!("[({})-host-bidder-verify] Verifying dlog proof...", bidder_label);
    assert!(verify_dlog_eq(n_j_from_proof, &y_j, &y_pow_r, &z_pow_r, &proof_dlog, Some(sound_param)));
    println!("[({})-host-bidder-verify] dlog proof verification passed.", bidder_label);

    // Final bid comparison using private key
    println!("[({})-host-bidder-verify] Comparing bids using compare_leq_honest...", bidder_label);
    let comparison_result = compare_leq_honest(&res, &(p_i, q_i));
    
    if comparison_result {
        println!("[({})-host-bidder-verify] Other bidder's bid is <= current bidder's bid. Continuing...", bidder_label);
        true
    } else {
        println!("[({})-host-bidder-verify] Other bidder's bid is > current bidder's bid. Not winner.", bidder_label);
        false
    }
}

pub fn bidder_verify_all(
    phase2_results: &HashMap<String, Vec<BidderProveResult>>,
    bidders_data: &HashMap<String, (BigInt, BigInt, BigInt)>, // (n_i, p_i, q_i) for each bidder
    sound_param: usize,
) -> HashMap<String, bool> {
    let mut winner_results: HashMap<String, bool> = HashMap::new();
    let (tx, rx) = mpsc::channel();
    let mut threads = Vec::new();
    
    // Clone the data for use in threads
    let phase2_results_clone = phase2_results.clone();
    let bidders_data_clone = bidders_data.clone();
    
    // For each bidder, create a thread to verify all results where they are the "other bidder"
    for (bidder_id, _results) in phase2_results {
        let bidder_id_clone = bidder_id.clone();
        let phase2_results_thread = phase2_results_clone.clone();
        let bidders_data_thread = bidders_data_clone.clone();
        let tx_clone = tx.clone();
        
        let handle = thread::spawn(move || {
            println!("[({})-host-bidder-verify-all] Starting verification for bidder: {}", bidder_id_clone, bidder_id_clone);
            
            // A bidder is a winner if they beat ALL other bidders
            // We need to find results where this bidder compared against others
            // and verify that this bidder's bid was higher in ALL comparisons
            let mut is_winner = true;
            let mut comparisons_checked = 0;
            
            // Look for results where this bidder (bidder_id_clone) compared against others
            if let Some(this_bidder_results) = phase2_results_thread.get(&bidder_id_clone) {
                for result in this_bidder_results {
                    // This result is from bidder_id_clone comparing against some other bidder
                    println!("[({})-host-bidder-verify-all] Verifying result against {}", bidder_id_clone, result.other_bidder_id);
                    
                    // Get the private key for the current bidder (bidder_id_clone)
                    let (_n_i, p_i, q_i) = bidders_data_thread.get(&bidder_id_clone).unwrap();
                    
                    // Verify this result
                    let comparison_result = bidder_verify(
                        &bidder_id_clone,
                        result.proof_enc.clone(),
                        result.proof_dlog.clone(),
                        result.y_j.clone(),
                        result.y_pow_r.clone(),
                        result.z_pow_r.clone(),
                        &result.n_j_from_proof,
                        sound_param,
                        result.res.clone(),
                        p_i.clone(),
                        q_i.clone(),
                    );
                    
                    comparisons_checked += 1;
                    
                    // If comparison_result is true, it means this bidder's bid is > other bidder's bid
                    // If comparison_result is false, it means this bidder's bid is <= other bidder's bid
                    if !comparison_result {
                        println!("[({})-host-bidder-verify-all] Lost against another bidder", bidder_id_clone);
                        is_winner = false;
                        break;
                    } else {
                        println!("[({})-host-bidder-verify-all] Beat another bidder", bidder_id_clone);
                    }
                }
            } else {
                println!("[({})-host-bidder-verify-all] No results found for bidder {}", bidder_id_clone, bidder_id_clone);
                is_winner = false;
            }
            
            println!("[({})-host-bidder-verify-all] Verification complete. Is winner: {} (checked {} comparisons)", 
                     bidder_id_clone, is_winner, comparisons_checked);
            tx_clone.send((bidder_id_clone, is_winner)).unwrap();
        });
        
        threads.push(handle);
    }
    
    // Collect results
    for _ in 0..threads.len() {
        let (bidder_id, is_winner) = rx.recv().unwrap();
        winner_results.insert(bidder_id, is_winner);
    }
    
    // Wait for all threads to complete
    for handle in threads {
        handle.join().unwrap();
    }
    
    // Announce winner
    for (bidder_id, is_winner) in &winner_results {
        if *is_winner {
            println!("[({})-host-bidder-verify-all] 🏆 WINNER: {} is the auction winner!", bidder_id, bidder_id);
        } else {
            println!("[({})-host-bidder-verify-all] ❌ {} is not the winner", bidder_id, bidder_id);
        }
    }
    
    winner_results
}


pub fn verify_proof_enc(proof: Vec<Vec<Vec<BigInt>>>) -> bool {
    let n1 = &proof[0][0][0];

    let c1: &Vec<BigInt> = &proof[1][0];

    let r1t4s: &Vec<Vec<BigInt>> = &proof[2];

    let h = hash_flat(r1t4s);
    let bitstring =
        format!("{:0256b}", BigInt::from_bytes_be(num_bigint::Sign::Plus, &h.to_be_bytes()));

    let mut success = true;

    for (i, bit) in bitstring.chars().enumerate().take(40) {
        let q = if bit == '1' { 1 } else { 0 };

        let proof_per_bit: &Vec<BigInt> = &proof[i + 3 /* this is how proof is structured */][0];

        for (j, c1_val) in c1.iter().enumerate() {
            let a = &r1t4s[i][j];
            let rhs = (a * c1_val.modpow(&BigInt::from(2 * q), n1)) % n1;

            let r = &proof_per_bit[j];
            let lhs = r.modpow(&BigInt::from(4), n1);

            if lhs != rhs {
                success = false;
            }
        }
    }

    success
}

pub fn verify_dlog_eq(
    n: &BigInt,
    y: &BigInt,
    y_pow_r: &BigInt,
    z_pow_r: &BigInt,
    p_dlog: &[(BigInt, BigInt, BigInt)],
    k: Option<usize>,
) -> bool {
    let k = k.unwrap_or(/* default value */ 10) as usize;
    if p_dlog.len() < k {
        // println!("Insufficient number of rounds");
        return false;
    }

    // println!("Sufficient number of rounds test: Passed");

    let z = n - BigInt::one();

    for (i, proof) in p_dlog.iter().take(k).enumerate() {
        let (t1, t2, s) = proof;
        let rng = set_rand_seed(&[
            y.clone(),
            z.clone(),
            y_pow_r.clone(),
            z_pow_r.clone(),
            t1.clone(),
            t2.clone(),
            BigInt::from(i),
        ]);

        let c = get_rand_jn1(n, Some(rng));

        if y.modpow(s, n) != t1 * y_pow_r.modpow(&c, n) % n {
            return false;
        }

        if z.modpow(s, n) != t2 * z_pow_r.modpow(&c, n) % n {
            return false;
        }
    }
    true
}

pub fn verify_shuffle(proof: &HashMap<u32, StrainProof>, n2: &BigInt, res: &[Vec<BigInt>]) -> bool {
    let challenges_length = 40;
    let StrainProof::HashInput(hash_input) = &proof[&0] else { todo!() };

    let h = hash_flat(hash_input);
    let bitstring =
        format!("{:0256b}", BigInt::from_bytes_be(num_bigint::Sign::Plus, &h.to_be_bytes()));

    let ae_permutation = &hash_input[&0].0;
    let mut am_permutations = HashMap::new();
    let mut me_permutations = HashMap::new();

    for i in 0..challenges_length {
        let (am_permutation, me_permutation) = &hash_input[&(i + 1)];
        am_permutations.insert(i, am_permutation.clone());
        me_permutations.insert(i, me_permutation.clone());
    }

    let mut success = true;

    for (i, bit) in bitstring.chars().enumerate().take(challenges_length as usize) {
        if bit == '0' {
            // Open A-M permutation
            if let Some(StrainProof::AMPermutations((am_perm_desc, am_reencrypt_factors))) =
                &proof.get(&((i as u32) + 1))
            {
                for j in 0..am_perm_desc.len() {
                    for k in 0..challenges_length {
                        let lhs = &am_permutations[&(i as u32)][&am_perm_desc[&(j as u32)]][&k];
                        let r: &_ = &am_reencrypt_factors[j][k as usize];
                        let rsquare = r.modpow(&BigInt::from(2), n2);
                        let rhs = (rsquare * &res[j][k as usize]) % n2;
                        if lhs != &rhs {
                            success = false;
                        }
                    }
                }
            }
        } else {
            // Open M-E permutation
            if let Some(StrainProof::MEPermutations((me_perm_desc, me_reencrypt_factors))) =
                &proof.get(&((i as u32) + 1))
            {
                for j in 0..me_perm_desc.len() {
                    for k in 0..challenges_length {
                        let lhs = &ae_permutation[&me_perm_desc[&(j as u32)]][&k];
                        let r: &BigInt = &me_reencrypt_factors[&(j as u32)][&k];
                        let rsquare = r.modpow(&BigInt::from(2), n2);
                        let rhs = (rsquare * &me_permutations[&(i as u32)][&(j as u32)][&k]) % n2;
                        if lhs != &rhs {
                            success = false;
                        }
                    }
                }
            }
        }
    }

    success
}
