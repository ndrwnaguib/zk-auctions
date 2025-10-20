use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

/// Struct to hold soundness parameters for ZK proofs in the Strain protocol
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StrainSecurityParams {
    /// Soundness parameter for ZK proof verification
    pub sound_param: usize,
    /// Sigma parameter for discrete logarithm proofs
    pub sigma: BigInt,
}

impl Default for StrainSecurityParams {
    fn default() -> Self {
        Self { sound_param: 40, sigma: BigInt::from(40) }
    }
}

impl StrainSecurityParams {
    /// Create new soundness parameters
    pub fn new(sound_param: usize, sigma: BigInt) -> Self {
        Self { sound_param, sigma }
    }
}
