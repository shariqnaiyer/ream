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
        let att = &test.signed_block_with_attestation.message.proposer_attestation;
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

    // Add signatures for block body attestations (one signature per attestation)
    // The attestation_signatures structure is: DataList<DataList<LeanSignature>>
    // where each inner DataList corresponds to one attestation
    for attestation_idx in 0..block.body.attestations.len() {
        if let Some(attestation_sig_list) = test.signed_block_with_attestation.signature.attestation_signatures.data.get(attestation_idx) {
            // For each attestation, aggregate all signatures in the list
            // For now, we'll just use the first signature if multiple exist
            if let Some(sig_data) = attestation_sig_list.data.first() {
                signatures.push(convert_signature(sig_data)?);
            }
        }
    }

    // Add proposer signature
    signatures.push(convert_signature(
        &test.signed_block_with_attestation.signature.proposer_signature,
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

/// Convert fixture LeanSignature to ream Signature
///
/// The fixture signature format contains the raw XMSS signature components.
/// We need to serialize these into the binary format expected by the leansig library.
fn convert_signature(
    sig: &crate::types::verify_signatures::LeanSignature,
) -> anyhow::Result<ream_post_quantum_crypto::leansig::signature::Signature> {
    use ream_post_quantum_crypto::leansig::signature::Signature;

    // Serialize the signature components into bytes in the format expected by leansig
    // The XMSS signature format appears to use length-prefixed variable-length arrays
    let mut signature_bytes = Vec::new();

    // Write number of siblings as u64 (8 bytes) for the path length
    let num_siblings = sig.path.siblings.data.len() as u64;
    signature_bytes.extend_from_slice(&num_siblings.to_le_bytes());

    // Serialize path siblings - each sibling needs to be 36 bytes (4-byte index + 32-byte sibling)
    for (idx, sibling) in sig.path.siblings.data.iter().enumerate() {
        // Write the sibling index as u32 (4 bytes)
        signature_bytes.extend_from_slice(&(idx as u32).to_le_bytes());
        // Write the sibling data (32 bytes)
        for &val in &sibling.data {
            signature_bytes.extend_from_slice(&val.to_le_bytes());
        }
    }

    // Serialize rho - 7 u32 values (no length prefix, fixed size)
    for &val in &sig.rho.data {
        signature_bytes.extend_from_slice(&val.to_le_bytes());
    }

    // Write number of hashes as u64 (8 bytes)
    let num_hashes = sig.hashes.data.len() as u64;
    signature_bytes.extend_from_slice(&num_hashes.to_le_bytes());

    // Serialize hashes - each hash needs to be 36 bytes (4-byte index + 32-byte hash)
    for (idx, hash) in sig.hashes.data.iter().enumerate() {
        // Write the leaf index as u32 (4 bytes)
        signature_bytes.extend_from_slice(&(idx as u32).to_le_bytes());
        // Write the hash data (32 bytes)
        for &val in &hash.data {
            signature_bytes.extend_from_slice(&val.to_le_bytes());
        }
    }

    // Pad or truncate to 3112 bytes (SIGNATURE_SIZE)
    const SIGNATURE_SIZE: usize = 3112;
    signature_bytes.resize(SIGNATURE_SIZE, 0);

    // Create signature from bytes
    Ok(Signature::from(&signature_bytes[..]))
}
