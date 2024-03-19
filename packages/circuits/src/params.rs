use halo2_ecc::fields::FpStrategy;

use crate::strain_circuit::CircuitParams;

pub const PARAMS: CircuitParams = CircuitParams {
    strategy: FpStrategy::Simple,
    degree: 19,
    num_advice: 1,
    num_lookup_advice: 1,
    num_fixed: 1,
    lookup_bits: 18,
    limb_bits: 88,
    num_limbs: 3,
};
