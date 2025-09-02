use num_bigint::BigInt;
use risc0_zkvm::Receipt;

#[derive(Debug, Clone)]
pub struct VerifiedReceipt {
    pub receipt: Receipt,
    pub n_j: BigInt,
    pub n_i: BigInt,
    pub c_j: Vec<BigInt>,
    pub c_i: Vec<BigInt>,
}

