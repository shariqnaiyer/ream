use std::path::Path;

use anyhow::{anyhow, bail};
use ream_consensus_lean::state::LeanState;
use ream_network_spec::networks::LeanNetworkSpec;
use tracing::info;

use crate::types::{TestFixture, verify_signatures::VerifySignaturesTest};

/// Load a verify signatures test fixture from a JSON file
pub fn load_verify_signatures_test(
    path: impl AsRef<Path>,
) -> anyhow::Result<TestFixture<VerifySignaturesTest>> {
    let content = std::fs::read_to_string(path.as_ref()).map_err(|err| {
        anyhow!(
            "Failed to read test file {:?}: {err}",
            path.as_ref().display()
        )
    })?;

    let fixture: TestFixture<VerifySignaturesTest> =
        serde_json::from_str(&content).map_err(|err| {
            anyhow!(
                "Failed to parse test file {:?}: {err}",
                path.as_ref().display()
            )
        })?;

    Ok(fixture)
}

/// Run a single verify signatures test case
pub async fn run_verify_signatures_test(
    test_name: &str,
    test: VerifySignaturesTest,
) -> anyhow::Result<()> {
    info!("Running verify signatures test: {test_name}");

    // Initialize network spec if not already set
    let mut network_spec = LeanNetworkSpec::ephemery();
    network_spec.genesis_time = test.anchor_state.config.genesis_time;
    ream_network_spec::networks::set_lean_network_spec(std::sync::Arc::new(network_spec.clone()));

    // Extract values for logging before moving test
    let network = test.network.clone();

    // Determine expected result based on test name
    // Tests with "invalid" in the name should fail verification
    let should_be_valid: bool = !test_name.contains("invalid");

    // Convert the signed block with attestation from fixture format to ream format
    let signed_block = convert_signed_block(&test)?;

    // Convert anchor state
    let state = LeanState::try_from(test.anchor_state)
        .map_err(|err| anyhow!("Failed to convert anchor state: {err}"))?;

    info!("  Network: {}", network);
    info!("  Anchor state slot: {}", state.slot);
    info!(
        "  Expected result: {}",
        if should_be_valid {
            "Valid signatures"
        } else {
            "Invalid signatures"
        }
    );

    // Verify signatures
    let verification_result = signed_block.verify_signatures(&state, true);

    match (should_be_valid, verification_result) {
        (true, Ok(true)) => {
            info!("  Signature verification succeeded as expected");
            info!("Test passed");
            Ok(())
        }
        (true, Ok(false)) => {
            bail!("Signature verification returned false but should have succeeded")
        }
        (true, Err(err)) => {
            bail!("Signature verification should have succeeded but failed: {err}")
        }
        (false, Ok(true)) => {
            bail!("Signature verification succeeded but should have failed")
        }
        (false, Ok(false)) => {
            bail!("Signature verification returned false but error was expected")
        }
        (false, Err(_)) => {
            info!("Signature verification failed as expected");
            info!("Test passed");
            Ok(())
        }
    }
}

/// Convert fixture SignedBlockWithAttestation to ream format
fn convert_signed_block(
    test: &VerifySignaturesTest,
) -> anyhow::Result<ream_consensus_lean::block::SignedBlockWithAttestation> {
    use ream_consensus_lean::block::{Block, BlockWithAttestation, SignedBlockWithAttestation};
    use ssz_types::VariableList;

    // Convert block
    let block = Block::try_from(&test.signed_block_with_attestation.message.block)
        .map_err(|err| anyhow!("Failed to convert block: {err}"))?;

    // Convert proposer attestation
    #[cfg(feature = "devnet1")]
    let proposer_attestation = {
        use ream_consensus_lean::attestation::Attestation;
        let att = &test
            .signed_block_with_attestation
            .message
            .proposer_attestation;
        let validator_id = att
            .validator_id
            .ok_or_else(|| anyhow!("Proposer attestation must have validator_id"))?;

        Attestation {
            validator_id,
            data: att.data.clone(),
        }
    };

    #[cfg(feature = "devnet2")]
    let proposer_attestation = {
        use ream_consensus_lean::attestation::AggregatedAttestations;
        let att = &test
            .signed_block_with_attestation
            .message
            .proposer_attestation;
        let validator_id = att
            .validator_id
            .ok_or_else(|| anyhow!("Proposer attestation must have validator_id"))?;

        AggregatedAttestations {
            validator_id,
            data: att.data.clone(),
        }
    };

    // Convert signatures
    let mut signatures = Vec::new();

    // The new fixture format uses aggregated attestation signatures with participants and
    // proofData. The proofData contains SSZ-encoded signature bytes.
    for (attestation_idx, agg_sig) in test
        .signed_block_with_attestation
        .signature
        .attestation_signatures
        .data
        .iter()
        .enumerate()
    {
        if attestation_idx >= block.body.attestations.len() {
            break;
        }

        // Decode the hex proof data into signature bytes
        let proof_hex = agg_sig
            .proof_data
            .data
            .strip_prefix("0x")
            .unwrap_or(&agg_sig.proof_data.data);
        let proof_bytes = hex::decode(proof_hex)
            .map_err(|err| anyhow!("Failed to decode proof data hex: {err}"))?;

        // Handle dummy/placeholder proof data (0x00 means no actual signature yet)
        if proof_bytes.len() == 1 && proof_bytes[0] == 0 {
            signatures.push(ream_post_quantum_crypto::leansig::signature::Signature::blank());
            continue;
        }

        // Convert proof bytes to a signature (should already be properly sized)
        signatures
            .push(ream_post_quantum_crypto::leansig::signature::Signature::from(&proof_bytes[..]));
    }

    // Convert proposer signature
    let proposer_signature = convert_signature(
        &test
            .signed_block_with_attestation
            .signature
            .proposer_signature,
    )?;

    #[cfg(feature = "devnet1")]
    {
        // For devnet1, signature is a VariableList of all signatures
        signatures.push(proposer_signature);
        Ok(SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block,
                proposer_attestation,
            },
            signature: VariableList::try_from(signatures)
                .map_err(|err| anyhow!("Failed to create signatures VariableList: {err}"))?,
        })
    }

    #[cfg(feature = "devnet2")]
    {
        // For devnet2, signature is BlockSignatures with separate fields
        use ream_consensus_lean::block::BlockSignatures;
        Ok(SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block,
                proposer_attestation,
            },
            signature: BlockSignatures {
                attestation_signatures: VariableList::try_from(signatures).map_err(|err| {
                    anyhow!("Failed to create attestation_signatures VariableList: {err}")
                })?,
                proposer_signature,
            },
        })
    }
}

/// Convert fixture LeanSignature to ream Signature
///
/// Constructs SSZ-encoded bytes from signature components following the
/// GeneralizedXMSSSignature structure: { path, rho, hashes }
fn convert_signature(
    sig: &crate::types::verify_signatures::LeanSignature,
) -> anyhow::Result<ream_post_quantum_crypto::leansig::signature::Signature> {
    use ream_post_quantum_crypto::leansig::signature::Signature;

    // Handle empty signatures (for invalid test cases)
    if sig.path.siblings.data.is_empty() || sig.hashes.data.is_empty() {
        return Ok(Signature::blank());
    }

    // Encode path (HashTreeOpening with co_path: Vec<FieldArray<8>>)
    let mut path_bytes = vec![4, 0, 0, 0]; // offset to variable data
    for sibling in &sig.path.siblings.data {
        for &val in &sibling.data {
            path_bytes.extend_from_slice(&val.to_le_bytes());
        }
    }

    // Encode rho (FieldArray<7>) - fixed 28 bytes
    let rho_bytes: Vec<u8> = sig
        .rho
        .data
        .iter()
        .flat_map(|&val| val.to_le_bytes())
        .collect();

    // Encode hashes (Vec<FieldArray<8>>)
    let hashes_bytes: Vec<u8> = sig
        .hashes
        .data
        .iter()
        .flat_map(|hash| hash.data.iter().flat_map(|&val| val.to_le_bytes()))
        .collect();

    // Construct full SSZ bytes with offsets
    let fixed_size = 4 + 28 + 4; // offset_path + rho + offset_hashes = 36 bytes
    let offset_path = fixed_size;
    let offset_hashes = offset_path + path_bytes.len();

    let mut sig_bytes = Vec::new();
    sig_bytes.extend_from_slice(&(offset_path as u32).to_le_bytes());
    sig_bytes.extend_from_slice(&rho_bytes);
    sig_bytes.extend_from_slice(&(offset_hashes as u32).to_le_bytes());
    sig_bytes.extend_from_slice(&path_bytes);
    sig_bytes.extend_from_slice(&hashes_bytes);

    Ok(Signature::from(&sig_bytes[..]))
}
