use std::marker::PhantomData;

use halo2_base::halo2_proofs::{
    arithmetic::Field,
    circuit::Layouter,
    halo2curves::{ff::PrimeField, secp256r1::Fp},
};
use halo2_ecc::fields::{fp, FpStrategy};
use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};

pub struct CircuitParams {
    pub strategy: FpStrategy,
    pub degree: u32,
    pub num_advice: usize,
    pub num_lookup_advice: usize,
    pub num_fixed: usize,
    pub lookup_bits: usize,
    pub limb_bits: usize,
    pub num_limbs: usize,
}

/// Assuming some params to start writing some tests based on.
pub struct StrainAuctionCircuit<F> {
    pub bid_amount: Option<F>,
    pub auction_id: Option<F>,
    pub bidder_id: Option<F>,
    pub bid_time: Option<F>,
    pub can_withdraw: bool,
    pub nonce: Option<F>, // for maybe some possible attacks
    pub signature: Option<F>,
    pub _marker: PhantomData<F>,
}

type FpChip = fp::FpConfig<Fp>;

impl<F: PrimeField> Circuit<F> for StrainAuctionCircuit<F> {
    type Config = FpChip;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        todo!()
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use halo2_base::halo2_proofs::dev::MockProver;

    #[test]
    fn test_minimum_bid_amount() {
        let circuit = StrainAuctionCircuit {
            bid_amount: 5, // Assuming the minimum bid is 10
            auction_duration: 100,
            current_time: 50,
            highest_bid: 20,
        };
        
        let mut prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
        
        assert!(prover.verify().is_err(), "Bid below minimum amount should fail");
    }

    #[test]
    fn test_auction_duration() {
        let circuit = StrainAuctionCircuit {
            bid_amount: 15,
            auction_duration: 100,
            current_time: 150, // Beyond the auction duration
            highest_bid: 10,
        };
        let mut prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();

        assert!(prover.verify().is_err(), "Bid outside auction duration should fail");
    }

    #[test]
    fn test_overbidding() {
        let circuit = StrainAuctionCircuit {
            bid_amount: 30,
            auction_duration: 100,
            current_time: 50,
            highest_bid: 20,
        };
        let mut prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();

        assert!(prover.verify().is_ok(), "Overbidding should succeed");
    }
}
