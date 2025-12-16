// TODO: This module needs to be updated for devnet2 branch which doesn't export individual XMSS
// types The devnet2 branch only exports aggregation functions
// This module is currently not used anywhere in the codebase

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub inner: Vec<u8>,
}

impl Signature {
    pub fn new(inner: Vec<u8>) -> Self {
        Self { inner }
    }
}
