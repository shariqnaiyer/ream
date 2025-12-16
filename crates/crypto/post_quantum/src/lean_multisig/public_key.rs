// TODO: This module needs to be updated for devnet2 branch which doesn't export individual XMSS
// types The devnet2 branch only exports aggregation functions
// This module is currently not used anywhere in the codebase

use alloy_primitives::{
    FixedBytes,
    hex::{self, ToHexExt},
};
use serde::{Deserialize, Deserializer, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

/// Wrapper around XMSS public key (stubbed for devnet2)
///
/// Total size: 48 bytes
#[derive(Debug, PartialEq, Clone, Encode, Decode, TreeHash, Default, Eq, Hash, Copy)]
pub struct PublicKey {
    pub inner: FixedBytes<48>,
}

impl From<&[u8]> for PublicKey {
    fn from(value: &[u8]) -> Self {
        Self {
            inner: FixedBytes::from_slice(value),
        }
    }
}

impl PublicKey {
    pub fn new(inner: FixedBytes<48>) -> Self {
        Self { inner }
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("0x{}", self.inner.encode_hex()))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let result: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&result).map_err(serde::de::Error::custom)?;

        Ok(Self {
            inner: FixedBytes::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)?,
        })
    }
}
