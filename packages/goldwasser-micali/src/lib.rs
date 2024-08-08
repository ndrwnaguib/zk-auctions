//! # Probabilistic publick-key cryptography
//!
//! `probabilisticpubkey` consists of implementations for the Goldwasser-Micali
//! and Blum-Goldwasser probabilistic public-key systems. 

extern crate bitvec;

#[macro_use]
extern crate failure;
extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;
extern crate rand;

#[cfg(test)]
extern crate primal;
#[cfg(test)]
extern crate proptest;

/// Number theoric functions.
pub mod number;
/// Prime generation and primality testing functions.
pub mod prime;
/// Errors during key generation. 
pub mod errors;
/// Generic traits for operations on keys.
pub mod key;
/// Goldwasser-Micali probabilistic public-key scheme.
pub mod goldwasser_micali;
/// Blum-Goldwasser probabilistic public-key scheme.
pub mod blum_goldwasser;