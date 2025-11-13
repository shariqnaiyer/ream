pub mod converters;
pub mod fork_choice;
pub mod state_transition;

use std::collections::HashMap;

use alloy_primitives::B256;
use serde::Deserialize;

/// A leanSpec test fixture file contains a map of test IDs to test cases
pub type TestFixture<T> = HashMap<String, T>;

/// Common fields in all test fixtures
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseTestCase {
    pub network: String,
    #[serde(default)]
    pub description: Option<String>,
}

// State configuration
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateConfig {
    pub genesis_time: u64,
}

/// Block header
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

/// Checkpoint
#[derive(Debug, Deserialize)]
pub struct Checkpoint {
    pub root: B256,
    pub slot: u64,
}

/// Validator
#[derive(Debug, Deserialize)]
pub struct Validator {
    pub pubkey: String,
}

/// Block
/// Note: JSON uses both camelCase (anchorBlock) and snake_case (steps.block) formats
#[derive(Debug, Deserialize)]
pub struct Block {
    pub slot: u64,
    #[serde(alias = "proposerIndex")]
    pub proposer_index: u64,
    #[serde(alias = "parentRoot")]
    pub parent_root: B256,
    #[serde(alias = "stateRoot")]
    pub state_root: B256,
    pub body: BlockBody,
}

/// Block body
#[derive(Debug, Deserialize)]
pub struct BlockBody {
    pub attestations: DataList<Attestation>,
}

/// Attestation
#[derive(Debug, Deserialize)]
pub struct Attestation {
    #[serde(alias = "validatorId")]
    pub validator_id: u64,
    pub data: AttestationData,
}

/// Attestation data
#[derive(Debug, Deserialize)]
pub struct AttestationData {
    pub slot: u64,
    pub head: Checkpoint,
    pub target: Checkpoint,
    pub source: Checkpoint,
}

/// Generic data list wrapper
#[derive(Debug, Deserialize)]
pub struct DataList<T> {
    pub data: Vec<T>,
}

impl<T> DataList<T> {
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}
