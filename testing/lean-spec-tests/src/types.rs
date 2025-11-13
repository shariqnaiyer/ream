//! Type definitions for leanSpec test fixtures

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

/// Fork choice test case
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkChoiceTest {
    pub network: String,
    pub anchor_state: AnchorState,
    pub anchor_block: Block,
    pub steps: Vec<ForkChoiceStep>,
}

/// State transition test case
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateTransitionTest {
    pub network: String,
    pub pre: State,
    pub blocks: Vec<Block>,
    pub post: Option<StateExpectation>,
    pub expect_exception: Option<String>,
}

/// Anchor state for fork choice tests
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorState {
    pub config: StateConfig,
    pub slot: u64,
    pub latest_block_header: BlockHeader,
    pub latest_justified: Checkpoint,
    pub latest_finalized: Checkpoint,
    pub historical_block_hashes: DataList<B256>,
    pub justified_slots: DataList<u64>,
    pub validators: DataList<Validator>,
    pub justifications_roots: DataList<B256>,
    pub justifications_validators: DataList<Vec<u64>>,
}

/// Full consensus state
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub config: StateConfig,
    pub slot: u64,
    pub latest_block_header: BlockHeader,
    pub latest_justified: Checkpoint,
    pub latest_finalized: Checkpoint,
    pub historical_block_hashes: DataList<B256>,
    pub justified_slots: DataList<u64>,
    pub validators: DataList<Validator>,
    pub justifications_roots: DataList<B256>,
    pub justifications_validators: DataList<Vec<u64>>,
}

/// State configuration
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

/// Fork choice step - can be tick, block, attestation, or checks
#[derive(Debug, Deserialize)]
#[serde(tag = "stepType", rename_all = "lowercase")]
pub enum ForkChoiceStep {
    Tick {
        #[serde(default)]
        valid: Option<bool>,
        time: u64,
    },
    Block {
        valid: bool,
        checks: Option<StoreChecks>,
        block: Block,
    },
    Attestation {
        valid: bool,
        checks: Option<StoreChecks>,
        attestation: Attestation,
    },
    Checks {
        checks: StoreChecks,
    },
}

/// Store checks for fork choice validation
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreChecks {
    pub head_slot: Option<u64>,
    pub head_root: Option<B256>,
    pub time: Option<u64>,
    pub justified_checkpoint: Option<Checkpoint>,
    pub finalized_checkpoint: Option<Checkpoint>,
    pub proposer_boost_root: Option<B256>,
}

/// State expectations for state transition tests
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateExpectation {
    pub slot: Option<u64>,
    pub latest_block_header_slot: Option<u64>,
    pub latest_block_header_state_root: Option<B256>,
    pub historical_block_hashes_count: Option<usize>,
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
