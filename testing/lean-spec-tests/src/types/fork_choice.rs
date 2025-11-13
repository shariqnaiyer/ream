use alloy_primitives::B256;
use serde::Deserialize;

use crate::types::{Attestation, Block, BlockHeader, Checkpoint, DataList, StateConfig, Validator};

/// Fork choice test case
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkChoiceTest {
    pub network: String,
    pub anchor_state: AnchorState,
    pub anchor_block: Block,
    pub steps: Vec<ForkChoiceStep>,
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
