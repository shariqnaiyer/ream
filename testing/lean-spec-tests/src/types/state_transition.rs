use alloy_primitives::B256;
use serde::Deserialize;

use crate::types::{Block, BlockHeader, Checkpoint, DataList, StateConfig, Validator};

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

/// State expectations for state transition tests
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateExpectation {
    pub slot: Option<u64>,
    pub latest_block_header_slot: Option<u64>,
    pub latest_block_header_state_root: Option<B256>,
    pub historical_block_hashes_count: Option<usize>,
}
