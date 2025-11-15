use std::path::Path;

use anyhow::{Context, Result};
use ream_consensus_lean::{
    attestation::{Attestation, AttestationData, SignedAttestation},
    block::{BlockWithAttestation, SignedBlockWithAttestation},
    checkpoint::Checkpoint,
};
use ream_fork_choice_lean::store::Store;
use ream_network_spec::networks::{LeanNetworkSpec, lean_network_spec, set_lean_network_spec};
use ream_post_quantum_crypto::hashsig::signature::Signature;
use ream_storage::{
    db::ReamDB,
    dir::setup_data_dir,
    tables::{field::REDBField, table::REDBTable},
};
use ssz_types::VariableList;
use tree_hash::TreeHash;

use crate::types::{
    TestFixture,
    converters::{convert_block, convert_state},
    fork_choice::{ForkChoiceStep, ForkChoiceTest, StoreChecks},
};

/// Load a fork choice test fixture from a JSON file
pub fn load_fork_choice_test(path: impl AsRef<Path>) -> Result<TestFixture<ForkChoiceTest>> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path.as_ref())
        .with_context(|| format!("Failed to read test file: {:?}", path.as_ref().display()))?)
        .with_context(|| format!("Failed to parse test file: {:?}", path.as_ref().display()))?)
}

/// Run a single fork choice test case
pub async fn run_fork_choice_test(test_name: &str, test: &ForkChoiceTest) -> Result<()> {
    println!("Running fork choice test: {test_name}");

    // Initialize network spec if not already set
    // Use genesis_time from the test's anchor state config
    use ream_network_spec::networks::{Devnet, LEAN_NETWORK_SPEC};
    if LEAN_NETWORK_SPEC.get().is_none() {
        set_lean_network_spec(std::sync::Arc::new(LeanNetworkSpec {
            genesis_time: test.anchor_state.config.genesis_time,
            justification_lookback_slots: 3,
            seconds_per_slot: 4,
            num_validators: test.anchor_state.validators.data.len() as u64,
            devnet: Devnet::One,
        }));
    }

    // Convert anchor state and block
    let anchor_state =
        convert_state(&test.anchor_state).context("Failed to convert anchor state")?;

    let anchor_block =
        convert_block(&test.anchor_block).context("Failed to convert anchor block")?;

    // Setup test database
    let db = ReamDB::new(setup_data_dir("lean_spec_tests", None, true).context("Failed to setup test directory")?).context("Failed to create ReamDB")?
        .init_lean_db()
        .context("Failed to initialize LeanDB")?;

    // Initialize time
    db.lean_time_provider()
        .insert(anchor_block.slot * lean_network_spec().seconds_per_slot)?;

    let anchor_block_root = anchor_block.tree_hash_root();

    // Store the anchor block using this block root
    db.lean_block_provider()
        .insert(anchor_block_root, SignedBlockWithAttestation {
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
        })?;

    // Store the anchor state
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
                println!("  Step {step_idx}: Tick to time {time}");
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
                    "  Step {step_idx}: Block at slot {} (expect valid: {valid})",
                    block.slot
                );

                let ream_block = convert_block(block).context("Failed to convert block")?;

                // Advance time to the block's slot before processing
                {
                    let db = store.store.lock().await;
                    db.lean_time_provider().insert(ream_block.slot * lean_network_spec().seconds_per_slot)?;
                }

                // Get the parent state and parent block to extract the correct checkpoints
                let db = store.store.lock().await;

                let source_checkpoint = db
                    .lean_state_provider()
                    .get(ream_block.parent_root)?
                    .context(format!(
                        "Parent state not found for parent_root: {}",
                        ream_block.parent_root
                    ))?.latest_justified;

                let parent_slot = db
                    .lean_block_provider()
                    .get(ream_block.parent_root)?
                    .context(format!(
                        "Parent block not found for parent_root: {}",
                        ream_block.parent_root
                    ))?.message.block.slot;

                drop(db);

                // Wrap in SignedBlockWithAttestation
                let signed_block = SignedBlockWithAttestation {
                    message: BlockWithAttestation {
                        block: ream_block.clone(),
                        proposer_attestation: Attestation {
                            validator_id: ream_block.proposer_index,
                            data: AttestationData {
                                slot: ream_block.slot,
                                head: Checkpoint {
                                    root: ream_block.tree_hash_root(),
                                    slot: ream_block.slot,
                                },
                                target: Checkpoint {
                                    root: ream_block.parent_root,
                                    slot: parent_slot,
                                },
                                source: source_checkpoint,
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
                    "  Step {step_idx}: Attestation from validator {} (expect valid: {valid})",
                    attestation.validator_id
                );

                let signed_attestation = SignedAttestation {
                    message: Attestation {
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
                    },
                    signature: Signature::blank(),
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

                if let Some(checks) = checks {
                    validate_checks(&store, checks).await?;
                }
            }

            ForkChoiceStep::Checks { checks } => {
                println!("  Step {step_idx}: Checks");
                validate_checks(&store, checks).await?;
            }
        }
    }

    println!("Test passed");
    Ok(())
}

/// Validate store checks
async fn validate_checks(store: &Store, checks: &StoreChecks) -> Result<()> {
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
            "Head slot mismatch: expected {expected_head_slot}, got {actual_slot}"
        );

        println!("Head slot: {actual_slot}");
    }

    if let Some(expected_head_root) = checks.head_root {
        let actual_head_root = db.lean_head_provider().get()?;
        anyhow::ensure!(
            actual_head_root == expected_head_root,
            "Head root mismatch: expected {expected_head_root}, got {actual_head_root}"
        );
        println!("Head root: {actual_head_root}");
    }

    if let Some(expected_time) = checks.time {
        let actual_time = db.lean_time_provider().get()?;
        anyhow::ensure!(
            actual_time == expected_time,
            "Time mismatch: expected {expected_time}, got {actual_time}"
        );
        println!("Time: {actual_time}");
    }

    if let Some(expected_justified) = &checks.justified_checkpoint {
        let actual_justified = db.latest_justified_provider().get()?;
        anyhow::ensure!(
            actual_justified.slot == expected_justified.slot
                && actual_justified.root == expected_justified.root,
            "Justified checkpoint mismatch: expected {expected_justified:?}, got {actual_justified:?}"
        );
        println!("Justified checkpoint: slot {}", actual_justified.slot);
    }

    if let Some(expected_finalized) = &checks.finalized_checkpoint {
        let actual_finalized = db.latest_finalized_provider().get()?;
        anyhow::ensure!(
            actual_finalized.slot == expected_finalized.slot
                && actual_finalized.root == expected_finalized.root,
            "Finalized checkpoint mismatch: expected {expected_finalized:?}, got {actual_finalized:?}",
        );
        println!("Finalized checkpoint: slot {}", actual_finalized.slot);
    }

    Ok(())
}
