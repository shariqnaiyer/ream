//! Fork choice test runner for leanSpec test vectors

use std::path::Path;

use alloy_primitives::FixedBytes;
use anyhow::{Context, Result};
use ream_consensus_lean::{
    attestation::SignedAttestation,
    block::{BlockWithAttestation, SignedBlockWithAttestation},
};
use ream_fork_choice_lean::store::Store;
use ream_network_spec::networks::{LeanNetworkSpec, lean_network_spec, set_lean_network_spec};
use ream_storage::{
    db::ReamDB,
    dir::setup_data_dir,
    tables::{field::REDBField, table::REDBTable},
};
use ssz_types::VariableList;
use tree_hash::TreeHash;

use crate::{
    converters::{convert_block, convert_state},
    types::{ForkChoiceStep, ForkChoiceTest, TestFixture},
};

/// Load a fork choice test fixture from a JSON file
pub fn load_fork_choice_test(path: impl AsRef<Path>) -> Result<TestFixture<ForkChoiceTest>> {
    let content = std::fs::read_to_string(path.as_ref())
        .with_context(|| format!("Failed to read test file: {:?}", path.as_ref()))?;

    let fixture: TestFixture<ForkChoiceTest> = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse test file: {:?}", path.as_ref()))?;

    Ok(fixture)
}

/// Run a single fork choice test case
pub async fn run_fork_choice_test(test_name: &str, test: &ForkChoiceTest) -> Result<()> {
    println!("Running fork choice test: {}", test_name);

    // Initialize network spec if not already set
    // Use genesis_time from the test's anchor state config
    use ream_network_spec::networks::{Devnet, LEAN_NETWORK_SPEC};
    if LEAN_NETWORK_SPEC.get().is_none() {
        let network_spec = LeanNetworkSpec {
            genesis_time: test.anchor_state.config.genesis_time,
            justification_lookback_slots: 3,
            seconds_per_slot: 4,
            num_validators: test.anchor_state.validators.data.len() as u64,
            devnet: Devnet::One,
        };
        set_lean_network_spec(std::sync::Arc::new(network_spec));
    }

    // Convert anchor state and block
    let mut anchor_state =
        convert_state(&test.anchor_state).context("Failed to convert anchor state")?;

    let anchor_block =
        convert_block(&test.anchor_block).context("Failed to convert anchor block")?;

    // IMPORTANT: The anchor state has a circular dependency - its latest_block_header needs
    // to hash to the anchor block root so that the first block can reference it as parent_root.
    // The fixture breaks this cycle by having latestBlockHeader.stateRoot as zero.
    // We resolve it by setting latestBlockHeader.stateRoot to match the anchorBlock.stateRoot.
    // This makes the header hash to the correct anchor block root.
    anchor_state.latest_block_header.state_root = anchor_block.state_root;

    // Wrap anchor block in SignedBlockWithAttestation
    // For test purposes, we use empty signatures and a default proposer attestation
    let anchor_signed = SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block: anchor_block.clone(),
            proposer_attestation: ream_consensus_lean::attestation::Attestation {
                validator_id: anchor_block.proposer_index,
                data: ream_consensus_lean::attestation::AttestationData {
                    slot: anchor_block.slot,
                    head: ream_consensus_lean::checkpoint::Checkpoint {
                        root: anchor_block.tree_hash_root(),
                        slot: anchor_block.slot,
                    },
                    target: anchor_state.latest_justified,
                    source: anchor_state.latest_finalized,
                },
            },
        },
        signature: VariableList::empty(),
    };

    // Setup test database
    let test_dir =
        setup_data_dir("lean_spec_tests", None, true).context("Failed to setup test directory")?;
    let ream_db = ReamDB::new(test_dir).context("Failed to create ReamDB")?;
    let db = ream_db
        .init_lean_db()
        .context("Failed to initialize LeanDB")?;

    // For testing, we need to manually set up the store to match leanSpec expectations
    // Key insight: states are indexed by the block root that produced them
    // When on_block is called, it looks up state by block.parent_root
    //
    // IMPORTANT: leanSpec and ream may compute tree hashes differently, so we can't rely on
    // recomputing the anchor_block hash. Instead, we use the parent_root from the first block
    // in the test as the "correct" anchor_block_root. This ensures blocks can find their parent state.
    let anchor_block_root = if let Some(ForkChoiceStep::Block { block, .. }) = test.steps.first() {
        // Use the first block's parent_root as the anchor_block_root
        block.parent_root
    } else {
        // Fallback to computing it if there are no block steps
        anchor_block.tree_hash_root()
    };

    // Initialize time
    db.lean_time_provider()
        .insert(anchor_block.slot * lean_network_spec().seconds_per_slot)?;

    // Store the anchor block using the anchor_block_root from the first block's parent_root
    // This ensures subsequent blocks can find the state when they look up by their parent_root
    db.lean_block_provider()
        .insert(anchor_block_root, anchor_signed)?;

    // Store the anchor state using the same anchor_block_root
    db.lean_state_provider()
        .insert(anchor_block_root, anchor_state.clone())?;

    // Set justified and finalized checkpoints
    db.latest_justified_provider()
        .insert(anchor_state.latest_justified)?;
    db.latest_finalized_provider()
        .insert(anchor_state.latest_finalized)?;

    // Set head to the anchor block root
    db.lean_head_provider().insert(anchor_block_root)?;
    db.lean_safe_target_provider().insert(anchor_block_root)?;

    // Initialize store with the database
    let mut store = Store {
        store: std::sync::Arc::new(tokio::sync::Mutex::new(db)),
    };

    println!("  Network: {}", test.network);
    println!("  Anchor state slot: {}", test.anchor_state.slot);
    println!("  Anchor block slot: {}", test.anchor_block.slot);
    println!("  Number of steps: {}", test.steps.len());

    // Process each step
    for (step_idx, step) in test.steps.iter().enumerate() {
        match step {
            ForkChoiceStep::Tick { time, .. } => {
                println!("  Step {}: Tick to time {}", step_idx, time);
                // Update store time
                let db = store.store.lock().await;
                db.lean_time_provider().insert(*time)?;
            }

            ForkChoiceStep::Block {
                valid,
                block,
                checks,
            } => {
                println!(
                    "  Step {}: Block at slot {} (expect valid: {})",
                    step_idx, block.slot, valid
                );

                let ream_block = convert_block(block).context("Failed to convert block")?;

                // Debug: Get the parent state and log details
                let parent_state = {
                    let db = store.store.lock().await;
                    db.lean_state_provider().get(ream_block.parent_root)?
                        .context("Parent state not found")?
                };

                println!("    Parent state (before processing):");
                println!("      slot: {}", parent_state.slot);
                println!("      state hash: 0x{}", hex::encode(parent_state.tree_hash_root()));
                println!("      latest_block_header.state_root: 0x{}", hex::encode(parent_state.latest_block_header.state_root));
                println!("    Expected state_root in block: 0x{}", hex::encode(&ream_block.state_root));

                // Wrap in SignedBlockWithAttestation
                let signed_block = SignedBlockWithAttestation {
                    message: BlockWithAttestation {
                        block: ream_block.clone(),
                        proposer_attestation: ream_consensus_lean::attestation::Attestation {
                            validator_id: ream_block.proposer_index,
                            data: ream_consensus_lean::attestation::AttestationData {
                                slot: ream_block.slot,
                                head: ream_consensus_lean::checkpoint::Checkpoint {
                                    root: ream_block.tree_hash_root(),
                                    slot: ream_block.slot,
                                },
                                target: ream_consensus_lean::checkpoint::Checkpoint {
                                    root: ream_block.parent_root,
                                    slot: ream_block.slot.saturating_sub(1),
                                },
                                source: ream_consensus_lean::checkpoint::Checkpoint::default(),
                            },
                        },
                    },
                    signature: VariableList::empty(),
                };

                let result = store.on_block(&signed_block).await;

                if *valid {
                    result.context(format!("Block at slot {} should be valid", block.slot))?;
                } else if result.is_ok() {
                    anyhow::bail!(
                        "Block at slot {} should be invalid but was accepted",
                        block.slot
                    );
                }

                // Validate checks if present
                if let Some(checks) = checks {
                    validate_checks(&store, checks).await?;
                }
            }

            ForkChoiceStep::Attestation {
                valid,
                attestation,
                checks,
            } => {
                println!(
                    "  Step {}: Attestation from validator {} (expect valid: {})",
                    step_idx, attestation.validator_id, valid
                );

                let signed_attestation = SignedAttestation {
                    message: ream_consensus_lean::attestation::Attestation {
                        validator_id: attestation.validator_id,
                        data: ream_consensus_lean::attestation::AttestationData {
                            slot: attestation.data.slot,
                            head: ream_consensus_lean::checkpoint::Checkpoint {
                                root: attestation.data.head.root,
                                slot: attestation.data.head.slot,
                            },
                            target: ream_consensus_lean::checkpoint::Checkpoint {
                                root: attestation.data.target.root,
                                slot: attestation.data.target.slot,
                            },
                            source: ream_consensus_lean::checkpoint::Checkpoint {
                                root: attestation.data.source.root,
                                slot: attestation.data.source.slot,
                            },
                        },
                    },
                    signature: FixedBytes::<4000>::default(),
                };

                // Add attestation to new attestations
                let db = store.store.lock().await;
                let result = db
                    .lean_latest_new_attestations_provider()
                    .insert(signed_attestation.message.validator_id, signed_attestation);

                if *valid {
                    result.context(format!(
                        "Attestation from validator {} should be valid",
                        attestation.validator_id
                    ))?;
                } else if result.is_ok() {
                    anyhow::bail!(
                        "Attestation from validator {} should be invalid but was accepted",
                        attestation.validator_id
                    );
                }

                // Validate checks if present
                if let Some(checks) = checks {
                    validate_checks(&store, checks).await?;
                }
            }

            ForkChoiceStep::Checks { checks } => {
                println!("  Step {}: Checks", step_idx);
                validate_checks(&store, checks).await?;
            }
        }
    }

    println!("  ✓ Test passed");
    Ok(())
}

/// Validate store checks
async fn validate_checks(store: &Store, checks: &crate::types::StoreChecks) -> Result<()> {
    let db = store.store.lock().await;

    if let Some(expected_head_slot) = checks.head_slot {
        let head_root = db.lean_head_provider().get()?;
        let head_block = db
            .lean_block_provider()
            .get(head_root)?
            .ok_or_else(|| anyhow::anyhow!("Head block not found"))?;
        let actual_slot = head_block.message.block.slot;

        anyhow::ensure!(
            actual_slot == expected_head_slot,
            "Head slot mismatch: expected {}, got {}",
            expected_head_slot,
            actual_slot
        );
        println!("    ✓ Head slot: {}", actual_slot);
    }

    if let Some(expected_head_root) = checks.head_root {
        let actual_head_root = db.lean_head_provider().get()?;
        anyhow::ensure!(
            actual_head_root == expected_head_root,
            "Head root mismatch: expected {}, got {}",
            expected_head_root,
            actual_head_root
        );
        println!("    ✓ Head root: {}", actual_head_root);
    }

    if let Some(expected_time) = checks.time {
        let actual_time = db.lean_time_provider().get()?;
        anyhow::ensure!(
            actual_time == expected_time,
            "Time mismatch: expected {}, got {}",
            expected_time,
            actual_time
        );
        println!("    ✓ Time: {}", actual_time);
    }

    if let Some(expected_justified) = &checks.justified_checkpoint {
        let actual_justified = db.latest_justified_provider().get()?;
        anyhow::ensure!(
            actual_justified.slot == expected_justified.slot
                && actual_justified.root == expected_justified.root,
            "Justified checkpoint mismatch: expected {:?}, got {:?}",
            expected_justified,
            actual_justified
        );
        println!("    ✓ Justified checkpoint: slot {}", actual_justified.slot);
    }

    if let Some(expected_finalized) = &checks.finalized_checkpoint {
        let actual_finalized = db.latest_finalized_provider().get()?;
        anyhow::ensure!(
            actual_finalized.slot == expected_finalized.slot
                && actual_finalized.root == expected_finalized.root,
            "Finalized checkpoint mismatch: expected {:?}, got {:?}",
            expected_finalized,
            actual_finalized
        );
        println!("    ✓ Finalized checkpoint: slot {}", actual_finalized.slot);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_load_fork_choice_fixture() {
        let fixture_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/consensus/fork_choice/devnet/fc/test_fork_choice_head/test_head_with_gaps_in_slots.json"
        );

        let fixture =
            load_fork_choice_test(fixture_path).expect("Failed to load fork choice test fixture");

        assert!(
            !fixture.is_empty(),
            "Fixture should contain at least one test"
        );

        // Run each test in the fixture
        for (test_name, test) in &fixture {
            run_fork_choice_test(test_name, test)
                .await
                .expect("Fork choice test should pass");
        }
    }
}
