use num_bigint::{BigInt, RandBigInt};
use risc0_zkvm::guest::env;
use zk_auctions_core::gm::{encrypt_gm, generate_keys, Keys};
use zk_auctions_core::utils::rand32;

// TODO: set reserve price as a constraint
fn main() {
    let bidder_id: String = env::read();
    let prefix = format!("[({})-zkvm-bidder-join-guest]", bidder_id);
    eprintln!("{} Starting main()", prefix);
    // Read the bid value from the environment
    eprintln!("{} Reading bid value from environment", prefix);
    let v_j: BigInt = env::read();

    // Generate keys
    eprintln!("{} Generating GM keypair", prefix);
    let keys_j = generate_keys(None);
    let n_j = keys_j.pub_key;
    let (p_j, q_j): &(BigInt, BigInt) = &keys_j.priv_key;

    // Generate random values
    eprintln!("{} Generating random r_j values", prefix);
    let r_j: Vec<BigInt> = rand32(&n_j);

    // Encrypt the bid value
    eprintln!("{} Encrypting bid value", prefix);
    let c_j = encrypt_gm(&v_j, &n_j);

    // Write private output: return the private key and the bid value
    eprintln!("{} Writing private output (p_j, q_j)", prefix);
    env::write(&(p_j, q_j));

    // Commit the public results only
    eprintln!("{} Committing public results (n_j, c_j, r_j)", prefix);
    env::commit(&(n_j, c_j, r_j));
    eprintln!("{} Done.", prefix);
}
