use serde::{Deserialize, Serialize};
use std::vec::Vec;
use unknown_order::BigNumber;

/// Proof verifiable encryption for discrete log
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifiableEncryptionProof {
    pub(crate) challenge: BigNumber,
    pub(crate) r: BigNumber,
    pub(crate) m: Vec<BigNumber>,
}
