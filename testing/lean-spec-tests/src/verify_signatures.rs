use std::path::Path;

use anyhow::{anyhow, bail};
use ream_consensus_lean::state::LeanState;
use ream_network_spec::networks::LeanNetworkSpec;
use tracing::info;
use tree_hash::TreeHash;

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
    let should_be_valid = !test_name.contains("invalid");

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

    // Log signature and attestation counts for debugging
    tracing::debug!(
        "Verification setup: {} signatures, {} block attestations, 1 proposer attestation",
        signed_block.signature.len(),
        signed_block.message.block.body.attestations.len()
    );

    // Log detailed verification parameters
    let proposer_att = &signed_block.message.proposer_attestation;
    tracing::debug!(
        "Proposer attestation: validator_id={}, slot={}, data_root={:?}",
        proposer_att.validator_id,
        proposer_att.data.slot,
        &proposer_att.data.tree_hash_root().as_slice()[..8]
    );

    tracing::debug!(
        "AttestationData full hash: {}",
        hex::encode(proposer_att.data.tree_hash_root())
    );

    if let Some(validator) = state.validators.get(proposer_att.validator_id as usize) {
        tracing::debug!(
            "Validator {} pubkey (first 50 bytes): {}",
            proposer_att.validator_id,
            hex::encode(&validator.public_key.inner.as_slice()[..50])
        );
    }

    tracing::debug!(
        "Signature first 32 bytes: {:?}",
        &signed_block.signature[0].inner.as_slice()[..32]
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
            info!("  Signature verification failed as expected");
            info!("Test passed");
            Ok(())
        }
    }
}

/// Convert fixture SignedBlockWithAttestation to ream format
fn convert_signed_block(
    test: &VerifySignaturesTest,
) -> anyhow::Result<ream_consensus_lean::block::SignedBlockWithAttestation> {
    use ream_consensus_lean::{
        attestation::Attestation,
        block::{Block, BlockWithAttestation, SignedBlockWithAttestation},
    };
    use ssz_types::VariableList;

    // Convert block
    let block = Block::try_from(&test.signed_block_with_attestation.message.block)
        .map_err(|err| anyhow!("Failed to convert block: {err}"))?;

    // Convert proposer attestation
    let proposer_attestation = {
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
        // Create a minimal valid SSZ signature that will fail cryptographic verification
        if proof_bytes.len() == 1 && proof_bytes[0] == 0 {
            signatures.push(create_dummy_signature());
            continue;
        }

        // Convert proof bytes to a signature (should already be properly sized)
        signatures.push(ream_post_quantum_crypto::leansig::signature::Signature::from(
            &proof_bytes[..],
        ));
    }

    // Add proposer signature
    signatures.push(convert_signature(
        &test
            .signed_block_with_attestation
            .signature
            .proposer_signature,
    )?);

    Ok(SignedBlockWithAttestation {
        message: BlockWithAttestation {
            block,
            proposer_attestation,
        },
        signature: VariableList::try_from(signatures)
            .map_err(|err| anyhow!("Failed to create signatures VariableList: {err}"))?,
    })
}

/// Create a minimal valid dummy signature (for placeholder attestation signatures)
///
/// Creates a signature with minimal valid SSZ structure that will fail cryptographic verification
fn create_dummy_signature() -> ream_post_quantum_crypto::leansig::signature::Signature {
    use ream_post_quantum_crypto::leansig::signature::Signature;

    // Create minimal valid SSZ structure:
    // - path with 1 sibling (32 bytes)
    // - rho (28 bytes)
    // - hashes with 1 hash (32 bytes)
    let mut sig_bytes = Vec::new();

    // Fixed part (36 bytes)
    let offset_path = 36u32;
    let offset_hashes = offset_path + 4 + 32; // 4 bytes offset + 32 bytes for 1 sibling

    sig_bytes.extend_from_slice(&offset_path.to_le_bytes());    // offset to path
    sig_bytes.extend_from_slice(&[0u8; 28]);                    // rho (all zeros)
    sig_bytes.extend_from_slice(&offset_hashes.to_le_bytes());  // offset to hashes

    // Path data (HashTreeOpening with 1 sibling)
    sig_bytes.extend_from_slice(&4u32.to_le_bytes());  // offset within path
    sig_bytes.extend_from_slice(&[0u8; 32]);           // 1 sibling (8 u32s)

    // Hashes data (1 hash)
    sig_bytes.extend_from_slice(&[0u8; 32]);           // 1 hash (8 u32s)

    // Pad to 3112 bytes
    sig_bytes.resize(3112, 0);

    Signature::from(&sig_bytes[..])
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
    let rho_bytes: Vec<u8> = sig.rho.data.iter()
        .flat_map(|&val| val.to_le_bytes())
        .collect();

    // Encode hashes (Vec<FieldArray<8>>)
    let hashes_bytes: Vec<u8> = sig.hashes.data.iter()
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

    // Ensure signature is exactly 3112 bytes (PROD config size)
    const EXPECTED_SIZE: usize = 3112;
    if sig_bytes.len() > EXPECTED_SIZE {
        bail!("Signature too large: {} bytes, expected {}", sig_bytes.len(), EXPECTED_SIZE);
    }
    sig_bytes.resize(EXPECTED_SIZE, 0);

    Ok(Signature::from(&sig_bytes[..]))
}
