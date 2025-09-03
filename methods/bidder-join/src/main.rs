use num_bigint::{BigInt, RandBigInt};
use risc0_zkvm::guest::env;
use zk_auctions_core::gm::{encrypt_gm, generate_keys, Keys};
use zk_auctions_core::utils::rand32;

fn main() {
    // Read the bid value from the environment
    let v_j: BigInt = env::read();

    // Generate keys
    let keys_j = generate_keys(None);
    let n_j = keys_j.pub_key;
    let (p_j, q_j): &(BigInt, BigInt) = &keys_j.priv_key;

    // Generate random values
    let r_j: Vec<BigInt> = rand32(&n_j);

    // Encrypt the bid value
    let c_j = encrypt_gm(&v_j, &n_j);

    // Write private output: return the private key and the bid value
    env::write(&(p_j, q_j));

    // Commit the public results only
    env::commit(&(n_j, c_j, r_j));
}
