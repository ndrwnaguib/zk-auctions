use num_bigint::BigInt;
use rand::{rngs::StdRng, Rng, SeedableRng};
use risc0_zkvm::Receipt;

use crate::{gm::encrypt_bit_gm_coin, utils::hash_flat};

/// Trait defining the auctioneer host operations in the Strain protocol
/// This trait is implemented by the auctioneer host in the Strain protocol
pub trait StrainAuctioneerHost {
    /// Verify a receipt from a bidder
    fn verify(&mut self, bidder_prover_receipt: &Receipt, private_output: &[u8]) -> bool;
}

/// Trait defining the auctioneer's verification operations in the Strain protocol
pub trait StrainAuctioneer {
    /// Verify proof of evaluation
    fn verify_eval(
        &self,
        p_eval: Vec<Vec<Vec<BigInt>>>,
        plaintext_and_coins: Vec<Vec<(BigInt, BigInt, BigInt)>>,
        n1: &BigInt,
        n2: &BigInt,
        sound_param: usize,
    ) -> Option<()>;
}

/// Default implementation of the Auctioneer trait
pub struct Auctioneer;

impl Auctioneer {
    /// Create a new default auctioneer instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for Auctioneer {
    fn default() -> Self {
        Self::new()
    }
}

impl StrainAuctioneer for Auctioneer {
    fn verify_eval(
        &self,
        p_eval: Vec<Vec<Vec<BigInt>>>,
        plaintext_and_coins: Vec<Vec<(BigInt, BigInt, BigInt)>>,
        n1: &BigInt,
        n2: &BigInt,
        sound_param: usize,
    ) -> Option<()> {
        let (gamma, gamma2, cipher_i, _cipher_j, cipher_ij) =
            (&p_eval[0], &p_eval[1], &p_eval[2], &p_eval[3], &p_eval[4]);

        let h = hash_flat(&p_eval);
        let mut rng_seed = StdRng::seed_from_u64(h);

        for l in 0..32 {
            assert_eq!(plaintext_and_coins[l].len(), sound_param as usize);
            for m in 0..(sound_param as usize) {
                let (plaintext, coins_gamma, coins_gamma2) = &plaintext_and_coins[l][m];
                if rng_seed.gen::<u8>() % 2 == 0 {
                    let detc1 = encrypt_bit_gm_coin(plaintext, n1, coins_gamma.clone());
                    let detc2 = encrypt_bit_gm_coin(plaintext, n2, coins_gamma2.clone());
                    if detc1 != gamma[l][m] || detc2 != gamma2[l][m] {
                        return None;
                    }
                } else {
                    let product1 = (&gamma[l][m] * &cipher_i[0][l]/* this 0 is the result of the extra enclosing happened in `p_eval`*/)
                        % n1;
                    let product2 = (&gamma2[l][m] * &cipher_ij[0][l]) % n2;
                    if encrypt_bit_gm_coin(plaintext, n1, coins_gamma.clone()) != product1
                        || encrypt_bit_gm_coin(plaintext, n2, coins_gamma2.clone()) != product2
                    {
                        return None;
                    }
                }
            }
        }
        Some(())
    }
}
