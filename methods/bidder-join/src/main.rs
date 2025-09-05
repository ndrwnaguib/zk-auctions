use num_bigint::{BigInt, RandBigInt};
use risc0_zkvm::guest::env;
use zk_auctions_core::gm::{encrypt_gm, generate_keys, Keys};
use zk_auctions_core::utils::rand32;


// TODO: set reserve price as a constraint
fn main() {
    eprintln!("r0vm-strain-auction:bidder-join: Starting main()");
    // Read the bid value from the environment
    eprintln!("r0vm-strain-auction:bidder-join: Reading bid value from environment");
    let v_j: BigInt = env::read();

    // Generate keys
    eprintln!("r0vm-strain-auction:bidder-join: Generating GM keypair");
    let keys_j = generate_keys(None);
    let n_j = keys_j.pub_key;
    let (p_j, q_j): &(BigInt, BigInt) = &keys_j.priv_key;

    // Generate random values
    eprintln!("r0vm-strain-auction:bidder-join: Generating random r_j values");
    let r_j: Vec<BigInt> = rand32(&n_j);

    // Encrypt the bid value
    eprintln!("r0vm-strain-auction:bidder-join: Encrypting bid value");
    let c_j = encrypt_gm(&v_j, &n_j);

    // Write private output: return the private key and the bid value
    eprintln!("r0vm-strain-auction:bidder-join: Writing private output (p_j, q_j)");
    env::write(&(p_j, q_j));

    // Commit the public results only
    eprintln!("r0vm-strain-auction:bidder-join: Committing public results (n_j, c_j, r_j)");
    eprintln!("r0vm-strain-auction:bidder-join: Done.");
    env::commit(&(n_j, c_j, r_j));
}
