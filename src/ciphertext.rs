use serde::{Deserialize, Serialize};
use unknown_order::BigNumber;

/// Ciphertext that can be used to prove its verifiably encrypted or decrypted
#[derive(Clone, Debug, Serialize, Deserialize, Eq)]
pub struct VerifiableCipherText {
    pub(crate) u: BigNumber,
    pub(crate) v: BigNumber,
    pub(crate) e: Vec<BigNumber>,
}

impl PartialEq for VerifiableCipherText {
    fn eq(&self, other: &Self) -> bool {
        self.u == other.u
            && self.v == other.v
            && self.e.iter().zip(other.e.iter()).all(|(l, r)| l == r)
    }
}
