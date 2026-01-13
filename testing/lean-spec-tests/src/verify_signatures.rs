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
        hex::encode(&proposer_att.data.tree_hash_root())
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

    // The new fixture format uses aggregated attestation signatures with participants and proofData.
    // For testing purposes, we decode the proofData hex string into signature bytes.
    // Each aggregated signature corresponds to one attestation in the block.
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

        // Decode the hex proof data
        let proof_hex = agg_sig.proof_data.data.strip_prefix("0x").unwrap_or(&agg_sig.proof_data.data);
        let proof_bytes = hex::decode(proof_hex)
            .map_err(|e| anyhow!("Failed to decode proof data hex: {}", e))?;

        // For now, if proof_data is just "0x00" (1 byte), create a blank signature
        // Otherwise, we'd need to parse it as a proper signature
        if proof_bytes.len() == 1 && proof_bytes[0] == 0 {
            tracing::debug!("Skipping aggregated signature {} with dummy proof data", attestation_idx);
            signatures.push(ream_post_quantum_crypto::leansig::signature::Signature::blank());
        } else {
            // TODO: Parse actual aggregated proof data when available
            bail!("Non-trivial aggregated proof data not yet supported");
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
/// We need to convert these to the proper leansig library types and serialize using SSZ.
fn convert_signature(
    sig: &crate::types::verify_signatures::LeanSignature,
) -> anyhow::Result<ream_post_quantum_crypto::leansig::signature::Signature> {
    use ream_post_quantum_crypto::leansig::signature::Signature;

    // XMSS signature structure varies by configuration:
    // - TEST config (LOG_LIFETIME=8, DIMENSION=4): 8 siblings, 4 hashes → 424 bytes
    // - PROD config (LOG_LIFETIME=32, DIMENSION=64): 32 siblings, 64 hashes → 3112 bytes
    // Accept any configuration, but log for debugging
    let num_siblings = sig.path.siblings.data.len();
    let num_hashes = sig.hashes.data.len();

    tracing::debug!(
        "Converting signature with {} siblings and {} hashes",
        num_siblings,
        num_hashes
    );

    // Allow empty signatures for invalid test cases (they should fail verification)
    // But warn about them
    if num_siblings == 0 || num_hashes == 0 {
        tracing::warn!(
            "Empty signature structure: {} siblings and {} hashes - will use blank signature",
            num_siblings,
            num_hashes
        );
        // Return a blank signature that will fail verification
        return Ok(ream_post_quantum_crypto::leansig::signature::Signature::blank());
    }

    // Construct SSZ bytes manually following the SSZ specification for GeneralizedXMSSSignature
    // The signature structure is: GeneralizedXMSSSignature<IE, TH> {
    //   path: HashTreeOpening<TH>,    // variable length
    //   rho: IE::Randomness,           // fixed length (FieldArray<7>)
    //   hashes: Vec<TH::Domain>        // variable length (Vec<FieldArray<8>>)
    // }

    // First, encode the path (HashTreeOpening)
    // HashTreeOpening contains: co_path: Vec<FieldArray<8>>
    let mut path_bytes = Vec::new();
    // Offset points to start of variable data (right after the 4-byte offset)
    path_bytes.extend_from_slice(&4u32.to_le_bytes());
    // Encode Vec<FieldArray<8>> for siblings
    // In SSZ, Vec<T> where T is fixed-length is encoded as just the elements concatenated
    // NO length prefix! The length is implicit from the total byte length.
    for sibling in &sig.path.siblings.data {
        for &val in &sibling.data {
            path_bytes.extend_from_slice(&val.to_le_bytes());
        }
    }

    // Encode rho (FieldArray<7>) - fixed 28 bytes
    let mut rho_bytes = Vec::new();
    tracing::debug!("Rho values from fixture: {:?}", &sig.rho.data);
    for &val in &sig.rho.data {
        rho_bytes.extend_from_slice(&val.to_le_bytes());
    }

    // Encode hashes (Vec<FieldArray<8>>)
    // Same as above - no length prefix for Vec<T> where T is fixed-length
    let mut hashes_bytes = Vec::new();
    for hash in &sig.hashes.data {
        for &val in &hash.data {
            hashes_bytes.extend_from_slice(&val.to_le_bytes());
        }
    }

    // Now construct the full GeneralizedXMSSSignature bytes
    let mut sig_bytes = Vec::new();

    // Calculate offsets
    let rho_size = 7 * 4; // 7 field elements * 4 bytes each = 28 bytes
    let fixed_size = 4 + rho_size + 4; // offset_path + rho + offset_hashes = 36 bytes

    let offset_path = fixed_size;
    let offset_hashes = offset_path + path_bytes.len();

    // Write offset for path (4 bytes)
    sig_bytes.extend_from_slice(&(offset_path as u32).to_le_bytes());

    // Write rho (28 bytes, fixed)
    sig_bytes.extend_from_slice(&rho_bytes);

    // Write offset for hashes (4 bytes)
    sig_bytes.extend_from_slice(&(offset_hashes as u32).to_le_bytes());

    // Write path data (variable)
    sig_bytes.extend_from_slice(&path_bytes);

    // Write hashes data (variable)
    sig_bytes.extend_from_slice(&hashes_bytes);

    // Debug: log the detailed byte breakdown
    tracing::debug!(
        "SSZ breakdown: fixed_part={} bytes, path_data={} bytes, hashes_data={} bytes, total={}",
        36,
        path_bytes.len(),
        hashes_bytes.len(),
        sig_bytes.len()
    );

    // Dump signature bytes for debugging
    tracing::debug!(
        "Converted signature size: {} bytes",
        sig_bytes.len()
    );
    if sig_bytes.len() >= 100 {
        tracing::debug!(
            "Converted signature first 100 bytes: {}",
            sig_bytes[..100].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
        );
    }
    if sig_bytes.len() >= 200 {
        tracing::debug!(
            "Converted signature bytes 100-200: {}",
            sig_bytes[100..200].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
        );
    }

    // Using PROD config (3112 bytes)
    const EXPECTED_SIGNATURE_SIZE: usize = 3112;

    if sig_bytes.len() != EXPECTED_SIGNATURE_SIZE {
        bail!(
            "Signature size {} does not match expected size {}. For PROD config (LOG_LIFETIME=32, DIMENSION=64), signatures must be exactly 3112 bytes.",
            sig_bytes.len(),
            EXPECTED_SIGNATURE_SIZE
        );
    }

    tracing::debug!(
        "Signature is exactly {} bytes (PROD config)",
        EXPECTED_SIGNATURE_SIZE
    );

    // Create signature directly from the padded SSZ bytes
    let signature = Signature::from(&sig_bytes[..]);

    // Verify round-trip: decode the signature we just created
    tracing::debug!("Testing signature round-trip deserialization...");
    let decoded_sig = signature.as_lean_sig();
    if let Err(e) = decoded_sig {
        tracing::error!("Failed to decode signature back: {}", e);
    } else {
        tracing::debug!("Signature round-trip successful");
    }

    Ok(signature)
}
