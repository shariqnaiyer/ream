//! Type converters from leanSpec JSON types to ream lean types
//!
//! Only includes converters for types that require actual transformation.
//! Simple types (Checkpoint, BlockHeader, Attestation, Block) are converted inline
//! where needed to avoid unnecessary boilerplate.

use alloy_primitives::hex;
use anyhow::{Context, Result};
use ream_consensus_lean::{config::Config, state::LeanState, validator::Validator};
use ssz_types::VariableList;

use crate::types;

/// Convert leanSpec JSON state to ream LeanState
pub fn convert_state(state: &types::AnchorState) -> Result<LeanState> {
    let validators: Vec<Validator> = state
        .validators
        .data
        .iter()
        .map(|v| convert_validator(v))
        .collect::<Result<Vec<_>>>()?;

    // Convert historical_block_hashes
    let historical_block_hashes = VariableList::from(state.historical_block_hashes.data.clone());

    // Convert justified_slots - this is a BitList in ream but Vec<u64> in leanSpec
    // We need to create a BitList where indices in the Vec are set to true
    let justified_slots = {
        if state.justified_slots.data.is_empty() {
            // Empty BitList if no justified slots
            ssz_types::BitList::with_capacity(0).map_err(|e| {
                anyhow::anyhow!("Failed to create empty BitList: {:?}", e)
            })?
        } else {
            let max_slot = state
                .justified_slots
                .data
                .iter()
                .max()
                .copied()
                .unwrap();
            let mut bitlist =
                ssz_types::BitList::with_capacity(max_slot as usize + 1).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to create BitList with capacity {}: {:?}",
                        max_slot + 1,
                        e
                    )
                })?;

            for &slot in &state.justified_slots.data {
                bitlist
                    .set(slot as usize, true)
                    .map_err(|e| anyhow::anyhow!("Failed to set bit at index {}: {:?}", slot, e))?;
            }
            bitlist
        }
    };

    // Convert justifications_roots
    let justifications_roots = VariableList::from(state.justifications_roots.data.clone());

    // Convert justifications_validators - this is a flat BitList in ream
    // but a Vec<Vec<u64>> in leanSpec (one inner Vec per root, containing validator indices)
    let justifications_validators = {
        let validator_count = validators.len();
        let total_bits = state.justifications_validators.data.len() * validator_count;

        let mut bitlist = ssz_types::BitList::with_capacity(total_bits).map_err(|e| {
            anyhow::anyhow!(
                "Failed to create BitList for justifications_validators: {:?}",
                e
            )
        })?;

        for (root_index, validator_list) in state.justifications_validators.data.iter().enumerate()
        {
            for &validator_index in validator_list {
                let flat_index = root_index * validator_count + validator_index as usize;
                bitlist.set(flat_index, true).map_err(|e| {
                    anyhow::anyhow!("Failed to set bit at flat index {}: {:?}", flat_index, e)
                })?;
            }
        }
        bitlist
    };

    Ok(LeanState {
        config: Config {
            genesis_time: state.config.genesis_time,
        },
        slot: state.slot,
        latest_block_header: ream_consensus_lean::block::BlockHeader {
            slot: state.latest_block_header.slot,
            proposer_index: state.latest_block_header.proposer_index,
            parent_root: state.latest_block_header.parent_root,
            state_root: state.latest_block_header.state_root,
            body_root: state.latest_block_header.body_root,
        },
        latest_justified: ream_consensus_lean::checkpoint::Checkpoint {
            root: state.latest_justified.root,
            slot: state.latest_justified.slot,
        },
        latest_finalized: ream_consensus_lean::checkpoint::Checkpoint {
            root: state.latest_finalized.root,
            slot: state.latest_finalized.slot,
        },
        historical_block_hashes,
        justified_slots,
        validators: VariableList::from(validators),
        justifications_roots,
        justifications_validators,
    })
}

/// Convert leanSpec JSON block to ream Block
pub fn convert_block(block: &types::Block) -> Result<ream_consensus_lean::block::Block> {
    let attestations: Vec<ream_consensus_lean::attestation::Attestation> = block
        .body
        .attestations
        .data
        .iter()
        .map(|a| ream_consensus_lean::attestation::Attestation {
            validator_id: a.validator_id,
            data: ream_consensus_lean::attestation::AttestationData {
                slot: a.data.slot,
                head: ream_consensus_lean::checkpoint::Checkpoint {
                    root: a.data.head.root,
                    slot: a.data.head.slot,
                },
                target: ream_consensus_lean::checkpoint::Checkpoint {
                    root: a.data.target.root,
                    slot: a.data.target.slot,
                },
                source: ream_consensus_lean::checkpoint::Checkpoint {
                    root: a.data.source.root,
                    slot: a.data.source.slot,
                },
            },
        })
        .collect();

    Ok(ream_consensus_lean::block::Block {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: block.state_root,
        body: ream_consensus_lean::block::BlockBody {
            attestations: VariableList::from(attestations),
        },
    })
}

/// Convert leanSpec JSON validator to ream Validator
pub fn convert_validator(validator: &types::Validator) -> Result<Validator> {
    // Parse hex pubkey string
    let pubkey_hex = validator.pubkey.trim_start_matches("0x");
    let pubkey_bytes = hex::decode(pubkey_hex).context("Failed to decode validator pubkey hex")?;

    // LeanSpec uses 52-byte XMSS public keys - verify the size
    if pubkey_bytes.len() != 52 {
        anyhow::bail!(
            "Expected 52-byte pubkey, got {} bytes",
            pubkey_bytes.len()
        );
    }

    // Validator expects a hex string for the pubkey field during deserialization
    let json_str = format!(r#"{{"pubkey":"0x{}"}}"#, pubkey_hex);

    serde_json::from_str(&json_str).context("Failed to deserialize Validator")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_validator() {
        let json_validator = types::Validator {
            pubkey: "0x4bb83259d65cd50278b7f84107f3de10cae4f80455600d29a65e595c3ecbfe4e92026d342f3016491bcb5f317855de399ab46a36".to_string(),
        };

        let result = convert_validator(&json_validator);
        assert!(
            result.is_ok(),
            "Failed to convert validator: {:?}",
            result.err()
        );
    }
}
