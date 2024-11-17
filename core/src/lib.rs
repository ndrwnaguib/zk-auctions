use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Outputs {
    pub position: f32,
}

pub mod gm;

pub mod proofs;

