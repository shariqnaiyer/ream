use alloy_primitives::hex;
use anyhow::{Context, Result};
use ream_consensus_lean::{
    attestation::{Attestation, AttestationData},
    block::{Block, BlockBody, BlockHeader},
    checkpoint::Checkpoint,
    config::Config,
    state::LeanState,
    validator::Validator,
};
use ream_post_quantum_crypto::hashsig::public_key::PublicKey;
use ssz_types::VariableList;

use crate::types::fork_choice::AnchorState;

/// Convert leanSpec JSON state to ream LeanState
pub fn convert_state(state: &AnchorState) -> Result<LeanState> {
    let validators: Vec<Validator> = state
        .validators
        .data
        .iter()
        .map(convert_validator)
        .collect::<Result<Vec<_>>>()?;

    // Convert historical_block_hashes
    let historical_block_hashes = VariableList::from(state.historical_block_hashes.data.clone());

    // Convert justified_slots - this is a BitList in ream but Vec<u64> in leanSpec
    let justified_slots = {
        if state.justified_slots.data.is_empty() {
            // Empty BitList if no justified slots
            ssz_types::BitList::with_capacity(0)
                .map_err(|err| anyhow::anyhow!("Failed to create empty BitList: {err:?}"))?
        } else {
            let max_slot = state
                .justified_slots
                .data
                .iter()
                .max()
                .copied()
                .expect("Failed to get max slot");
            let mut bitlist =
                ssz_types::BitList::with_capacity(max_slot as usize + 1).map_err(|err| {
                    anyhow::anyhow!(
                        "Failed to create BitList with capacity {}: {err:?}",
                        max_slot + 1
                    )
                })?;

            for &slot in &state.justified_slots.data {
                bitlist
                    .set(slot as usize, true)
                    .map_err(|err| anyhow::anyhow!("Failed to set bit at index {slot}: {err:?}"))?;
            }
            bitlist
        }
    };

    let justifications_roots = VariableList::from(state.justifications_roots.data.clone());

    let justifications_validators = {
        let validator_count = validators.len();
        let total_bits = state.justifications_validators.data.len() * validator_count;

        let mut bitlist = ssz_types::BitList::with_capacity(total_bits).map_err(|err| {
            anyhow::anyhow!("Failed to create BitList for justifications_validators: {err:?}")
        })?;

        for (root_index, validator_list) in state.justifications_validators.data.iter().enumerate()
        {
            for &validator_index in validator_list {
                let flat_index = root_index * validator_count + validator_index as usize;
                bitlist.set(flat_index, true).map_err(|err| {
                    anyhow::anyhow!("Failed to set bit at flat index {flat_index}: {err:?}")
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
        latest_block_header: BlockHeader {
            slot: state.latest_block_header.slot,
            proposer_index: state.latest_block_header.proposer_index,
            parent_root: state.latest_block_header.parent_root,
            state_root: state.latest_block_header.state_root,
            body_root: state.latest_block_header.body_root,
        },
        latest_justified: Checkpoint {
            root: state.latest_justified.root,
            slot: state.latest_justified.slot,
        },
        latest_finalized: Checkpoint {
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
pub fn convert_block(block: &super::Block) -> Result<Block> {
    let attestations: Vec<Attestation> = block
        .body
        .attestations
        .data
        .iter()
        .map(|attestation| Attestation {
            validator_id: attestation.validator_id,
            data: AttestationData {
                slot: attestation.data.slot,
                head: Checkpoint {
                    root: attestation.data.head.root,
                    slot: attestation.data.head.slot,
                },
                target: Checkpoint {
                    root: attestation.data.target.root,
                    slot: attestation.data.target.slot,
                },
                source: Checkpoint {
                    root: attestation.data.source.root,
                    slot: attestation.data.source.slot,
                },
            },
        })
        .collect();

    Ok(Block {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: block.state_root,
        body: BlockBody {
            attestations: VariableList::from(attestations),
        },
    })
}

/// Convert leanSpec JSON validator to ream Validator
pub fn convert_validator(validator: &super::Validator) -> Result<Validator> {
    // Parse hex pubkey string
    let pubkey_hex = validator.pubkey.trim_start_matches("0x");
    let pubkey_bytes = hex::decode(pubkey_hex).context("Failed to decode validator pubkey hex")?;

    // LeanSpec uses 52-byte XMSS public keys - verify the size
    if pubkey_bytes.len() != 52 {
        anyhow::bail!("Expected 52-byte pubkey, got {} bytes", pubkey_bytes.len());
    }

    Ok(Validator {
        public_key: PublicKey::from(&pubkey_bytes[..]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_validator() {
        let json_validator = crate::types::Validator {
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
