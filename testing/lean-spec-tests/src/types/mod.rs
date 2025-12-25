pub mod fork_choice;
pub mod state_transition;
pub mod verify_signatures;

use std::collections::HashMap;

use alloy_primitives::{B256, hex};
use anyhow::{anyhow, bail};
use ream_consensus_lean::{
    attestation::{Attestation as ReamAttestation, AttestationData},
    block::{Block as ReamBlock, BlockBody as ReamBlockBody, BlockHeader as ReamBlockHeader},
    checkpoint::Checkpoint as ReamCheckpoint,
    config::Config as ReamConfig,
    validator::Validator as ReamValidator,
};
use ream_post_quantum_crypto::leansig::public_key::PublicKey;
use serde::Deserialize;
use ssz_types::VariableList;

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

/// State config for test fixtures
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StateConfig {
    pub genesis_time: u64,
}

/// Block header for test fixtures
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

/// Checkpoint for test fixtures
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    pub root: B256,
    pub slot: u64,
}

/// Validator
#[derive(Debug, Deserialize, Clone)]
pub struct Validator {
    pub pubkey: String,
    pub index: u64,
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

/// Attestation - supports both aggregate and single-validator formats
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    /// Single-validator attestation: validator ID
    #[serde(alias = "validatorId")]
    #[serde(default)]
    pub validator_id: Option<u64>,
    /// Aggregate attestation: aggregation bits showing which validators participated
    #[serde(default)]
    pub aggregation_bits: Option<DataList<bool>>,
    /// Attestation data (common to both formats)
    pub data: AttestationData,
}

/// Generic data list wrapper
#[derive(Debug, Deserialize, Clone)]
pub struct DataList<T> {
    pub data: Vec<T>,
}

/// Consensus state
#[derive(Debug, Deserialize, Clone)]
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

impl<T> DataList<T> {
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// From/TryFrom implementations for converting JSON types to ream consensus types

impl From<&StateConfig> for ReamConfig {
    fn from(config: &StateConfig) -> Self {
        ream_consensus_lean::config::Config {
            genesis_time: config.genesis_time,
        }
    }
}

impl From<&BlockHeader> for ReamBlockHeader {
    fn from(header: &BlockHeader) -> Self {
        ream_consensus_lean::block::BlockHeader {
            slot: header.slot,
            proposer_index: header.proposer_index,
            parent_root: header.parent_root,
            state_root: header.state_root,
            body_root: header.body_root,
        }
    }
}

impl From<&Checkpoint> for ReamCheckpoint {
    fn from(checkpoint: &Checkpoint) -> Self {
        ream_consensus_lean::checkpoint::Checkpoint {
            root: checkpoint.root,
            slot: checkpoint.slot,
        }
    }
}

impl TryFrom<&Validator> for ReamValidator {
    type Error = anyhow::Error;

    fn try_from(validator: &Validator) -> anyhow::Result<Self> {
        // Parse hex pubkey string
        let pubkey_hex = validator.pubkey.trim_start_matches("0x");
        let pubkey_bytes = hex::decode(pubkey_hex)
            .map_err(|err| anyhow!("Failed to decode validator pubkey hex: {err}"))?;

        // LeanSpec uses 52-byte XMSS public keys - verify the size
        if pubkey_bytes.len() != 52 {
            bail!("Expected 52-byte pubkey, got {} bytes", pubkey_bytes.len());
        }

        Ok(ReamValidator {
            public_key: PublicKey::from(&pubkey_bytes[..]),
            index: validator.index,
        })
    }
}

impl Attestation {
    /// Convert to a list of ream attestations.
    /// - For single-validator attestations: returns a single attestation
    /// - For aggregate attestations: expands into individual attestations based on aggregation_bits
    pub fn to_ream_attestations(&self) -> anyhow::Result<Vec<ReamAttestation>> {
        match (&self.validator_id, &self.aggregation_bits) {
            // Single-validator attestation
            (Some(validator_id), None) => {
                Ok(vec![ReamAttestation {
                    validator_id: *validator_id,
                    data: self.data.clone(),
                }])
            }
            // Aggregate attestation - expand based on aggregation bits
            (None, Some(aggregation_bits)) => {
                let mut attestations = Vec::new();
                for (validator_index, &participated) in aggregation_bits.data.iter().enumerate() {
                    if participated {
                        attestations.push(ReamAttestation {
                            validator_id: validator_index as u64,
                            data: self.data.clone(),
                        });
                    }
                }
                Ok(attestations)
            }
            // Invalid: both or neither field present
            _ => bail!("Attestation must have either validator_id or aggregation_bits, not both or neither"),
        }
    }
}

impl TryFrom<&Block> for ReamBlock {
    type Error = anyhow::Error;

    fn try_from(block: &Block) -> anyhow::Result<Self> {
        // Convert attestations from fixture format to ream format
        // Note: For devnet1, block body attestations use individual validator attestations.
        // Aggregate attestations (with aggregation_bits) are a newer format not yet fully supported.
        // For now, we only include attestations that are already in single-validator format.
        let mut attestations: Vec<ReamAttestation> = Vec::new();
        for attestation in &block.body.attestations.data {
            // Only include single-validator attestations, skip aggregate attestations
            if attestation.validator_id.is_some() {
                attestations.extend(attestation.to_ream_attestations()?);
            }
            // Aggregate attestations (with aggregation_bits) are skipped to maintain
            // compatibility with fixture state roots that were computed without expanding them
        }

        Ok(ReamBlock {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
            body: ReamBlockBody {
                attestations: VariableList::try_from(attestations)
                    .map_err(|err| anyhow!("Failed to create attestations VariableList: {err}"))?,
            },
        })
    }
}
