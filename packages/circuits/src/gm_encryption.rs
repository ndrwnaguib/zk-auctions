#![allow(non_snake_case)]
use halo2_base::gates::circuit::builder::BaseCircuitBuilder;

use halo2_base::halo2_proofs::halo2curves::bn256::{self};
use halo2_base::utils::{ScalarField};
use halo2_base::AssignedValue;

use halo2_wasm::Halo2Wasm;
use num_bigint::BigUint;
use probabilistic_encryption::goldwasser_micali::{
    GoldwasserMicaliPrivateKey, GoldwasserMicaliPublicKey,
};
use probabilistic_encryption::key::{PrivateKey, PublicKey};
use std::cell::RefCell;

use std::rc::Rc;

use crate::consts::CONTEXT_PHASE;

type F = bn256::Fr;

pub struct GmVerificationInputs {
    gm_pk: GoldwasserMicaliPublicKey,
    gm_sk: GoldwasserMicaliPrivateKey,
    ciphertext: Vec<BigUint>,
    plaintext: Vec<u8>,
}

pub struct GmVerificationCircuit {
    gm_verification_inputs: GmVerificationInputs,
    builder: Rc<RefCell<BaseCircuitBuilder<F>>>,
}

impl GmVerificationCircuit {
    pub fn new(halo2_wasm: &Halo2Wasm, gm_verification_inputs: GmVerificationInputs) -> Self {
        GmVerificationCircuit { gm_verification_inputs, builder: Rc::clone(&halo2_wasm.circuit) }
    }

    pub fn verify_decryption(&mut self) {
        let mut builder = self.builder.borrow_mut();
        let ctx = builder.main(CONTEXT_PHASE);

        // Decrypt Ciphertext
        let expected_plaintext =
            self.gm_verification_inputs.gm_sk.decrypt(&self.gm_verification_inputs.ciphertext);

        // Load actual plaintext and expected plaintext as private inputs
        let actual_plaintext_assigned =
            ctx.load_witness(F::from_bytes_le(&self.gm_verification_inputs.plaintext));

        let expected_plaintext_assigned = ctx.load_witness(F::from_bytes_le(&expected_plaintext));

        // Constrain equality
        ctx.constrain_equal(&expected_plaintext_assigned, &actual_plaintext_assigned);
    }

    pub fn verify_encryption(&mut self) {
        let mut builder = self.builder.borrow_mut();
        let ctx = builder.main(CONTEXT_PHASE);

        // Encrypt plaintext
        let expected_ciphertext =
            self.gm_verification_inputs.gm_pk.encrypt(&self.gm_verification_inputs.plaintext);

        // Assign Private Inputs
        let actual_ciphertext_assigned = self
            .gm_verification_inputs
            .ciphertext
            .iter()
            .map(|c| ctx.load_witness(F::from_bytes_le(&c.to_bytes_le())))
            .collect::<Vec<AssignedValue<F>>>();

        let expected_ciphertext_assigned = expected_ciphertext
            .iter()
            .map(|c| ctx.load_witness(F::from_bytes_le(&c.to_bytes_le())))
            .collect::<Vec<AssignedValue<F>>>();

        // Constrain equality
        for (expected, actual) in
            expected_ciphertext_assigned.iter().zip(actual_ciphertext_assigned.iter())
        {
            ctx.constrain_equal(expected, actual);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File};

    use anyhow::{anyhow, Context, Ok, Result};
    use halo2_ecc::fields::FpStrategy;
    use halo2_wasm::{CircuitConfig, Halo2Wasm};
    use probabilistic_encryption::{goldwasser_micali, key::PublicKey};
    use serde::{Deserialize, Serialize};

    use super::{GmVerificationCircuit, GmVerificationInputs};

    #[derive(Clone, Copy, Debug, Serialize, Deserialize)]
    pub struct CircuitParams {
        strategy: FpStrategy,
        degree: u32,
        num_advice: usize,
        num_lookup_advice: usize,
        num_fixed: usize,
        lookup_bits: usize,
        limb_bits: usize,
        num_limbs: usize,
    }

    fn mock_gm_encryption() -> Result<GmVerificationInputs> {
        let plaintext = b"hello world";

        let (gm_pk, gm_sk) =
            goldwasser_micali::generate_keys(8).expect("Failed to generate GM keys!");

        let ciphertext = gm_pk.encrypt(plaintext);

        Ok(GmVerificationInputs { gm_pk, gm_sk, ciphertext, plaintext: plaintext.to_vec() })
    }

    #[test]
    fn test_gm_decryption_mock() -> Result<()> {
        let path = "configs/gm_encryption.config";
        let circuit_params: CircuitConfig = serde_json::from_reader(
            File::open(path)
                .map_err(|e| anyhow!(e))
                .with_context(|| format!("The circuit config file does not exist: {}", path))?,
        )
        .map_err(|e| anyhow!(e))
        .with_context(|| format!("Failed to read the circuit config file: {}", path))?;

        let gm_verification_inputs = mock_gm_encryption()?;

        let mut halo2_wasm = Halo2Wasm::new();

        halo2_wasm.config(circuit_params);

        let mut circuit = GmVerificationCircuit::new(&halo2_wasm, gm_verification_inputs);

        circuit.verify_decryption();

        halo2_wasm.mock();

        Ok(())
    }

    // #[test]
    // fn test_gm_encryption_mock() -> Result<()> {
    //     let path = "configs/gm_encryption.config";
    //     let circuit_params: CircuitConfig = serde_json::from_reader(
    //         File::open(path)
    //             .map_err(|e| anyhow!(e))
    //             .with_context(|| format!("The circuit config file does not exist: {}", path))?,
    //     )
    //     .map_err(|e| anyhow!(e))
    //     .with_context(|| format!("Failed to read the circuit config file: {}", path))?;

    //     let gm_verification_inputs = mock_gm_encryption()?;

    //     let mut halo2_wasm = Halo2Wasm::new();

    //     halo2_wasm.config(circuit_params);

    //     let mut circuit = GmVerificationCircuit::new(&halo2_wasm, gm_verification_inputs);

    //     circuit.verify_encryption();

    //     halo2_wasm.mock();

    //     Ok(())
    // }
}
