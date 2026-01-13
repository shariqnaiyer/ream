/// Detailed verification test to trace where verification diverges

use alloy_primitives::hex;
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
struct TestCase {
    #[serde(flatten)]
    data: std::collections::HashMap<String, TestData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestData {
    anchor_state: AnchorState,
    signed_block_with_attestation: SignedBlock,
}

#[derive(Debug, Deserialize)]
struct AnchorState {
    validators: ValidatorList,
}

#[derive(Debug, Deserialize)]
struct ValidatorList {
    data: Vec<Validator>,
}

#[derive(Debug, Deserialize)]
struct Validator {
    pubkey: String,
}

#[derive(Debug, Deserialize)]
struct SignedBlock {
    message: BlockMessage,
    signature: BlockSignature,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlockMessage {
    proposer_attestation: ProposerAttestation,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProposerAttestation {
    validator_id: u64,
    data: AttestationData,
}

#[derive(Debug, Deserialize)]
struct AttestationData {
    slot: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlockSignature {
    proposer_signature: ProposerSignature,
}

#[derive(Debug, Deserialize)]
struct ProposerSignature {
    path: SignaturePath,
    rho: Rho,
    hashes: Hashes,
}

#[derive(Debug, Deserialize)]
struct SignaturePath {
    siblings: Siblings,
}

#[derive(Debug, Deserialize)]
struct Siblings {
    data: Vec<U32Array8>,
}

#[derive(Debug, Deserialize)]
struct Rho {
    data: [u32; 7],
}

#[derive(Debug, Deserialize)]
struct Hashes {
    data: Vec<U32Array8>,
}

#[derive(Debug, Deserialize)]
struct U32Array8 {
    data: [u32; 8],
}

fn encode_u32_array(arr: &[u32]) -> Vec<u8> {
    arr.iter().flat_map(|&val| val.to_le_bytes()).collect()
}

fn convert_fixture_signature_to_bytes(sig: &ProposerSignature) -> Vec<u8> {
    let mut path_bytes = Vec::new();
    path_bytes.extend_from_slice(&4u32.to_le_bytes());
    for sibling in &sig.path.siblings.data {
        path_bytes.extend_from_slice(&encode_u32_array(&sibling.data));
    }

    let rho_bytes = encode_u32_array(&sig.rho.data);

    let mut hashes_bytes = Vec::new();
    for hash in &sig.hashes.data {
        hashes_bytes.extend_from_slice(&encode_u32_array(&hash.data));
    }

    let fixed_part_size = 4 + rho_bytes.len() + 4;
    let offset_path = fixed_part_size as u32;
    let offset_hashes = offset_path + path_bytes.len() as u32;

    let mut sig_bytes = Vec::new();
    sig_bytes.extend_from_slice(&offset_path.to_le_bytes());
    sig_bytes.extend_from_slice(&rho_bytes);
    sig_bytes.extend_from_slice(&offset_hashes.to_le_bytes());
    sig_bytes.extend_from_slice(&path_bytes);
    sig_bytes.extend_from_slice(&hashes_bytes);

    sig_bytes
}

#[test]
fn test_detailed_verification_trace() {
    use leansig::serialization::Serializable;
    use ream_post_quantum_crypto::leansig::public_key::PublicKey;

    println!("\n=== Detailed Verification Trace ===\n");

    // Load fixture
    let fixture_path = "fixtures/consensus/verify_signatures/devnet/verify_signatures/test_valid_signatures/test_proposer_signature.json";
    let fixture_data = fs::read_to_string(fixture_path)
        .expect("Failed to read fixture file");
    let test_case: TestCase = serde_json::from_str(&fixture_data)
        .expect("Failed to parse fixture JSON");

    let test_data = test_case.data.values().next().expect("No test data");

    println!("Step 1: Load public key");
    let validator = &test_data.anchor_state.validators.data[1];
    let pubkey_hex = validator.pubkey.strip_prefix("0x").unwrap();
    let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
    let pubkey = PublicKey::from(&pubkey_bytes[..]);
    let lean_pubkey = pubkey.as_lean_sig().expect("Failed to deserialize public key");
    println!("  ✓ Public key loaded and deserialized");

    println!("\nStep 2: Load signature");
    let sig = &test_data.signed_block_with_attestation.signature.proposer_signature;
    let sig_bytes = convert_fixture_signature_to_bytes(sig);
    println!("  Signature size: {} bytes", sig_bytes.len());
    println!("  Num siblings: {}", sig.path.siblings.data.len());
    println!("  Num hashes: {}", sig.hashes.data.len());
    println!("  Rho: {:?}", sig.rho.data);

    type LeanSignature = <leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8 as leansig::signature::SignatureScheme>::Signature;
    let lean_signature = LeanSignature::from_bytes(&sig_bytes).expect("Failed to deserialize signature");
    println!("  ✓ Signature deserialized");

    // Re-serialize to check round-trip
    let reserialized = lean_signature.to_bytes();
    if reserialized == sig_bytes {
        println!("  ✓ Signature round-trip successful");
    } else {
        println!("  ✗ Signature round-trip failed!");
        for (i, (a, b)) in sig_bytes.iter().zip(reserialized.iter()).enumerate() {
            if a != b {
                println!("    First difference at byte {}: 0x{:02x} vs 0x{:02x}", i, a, b);
                break;
            }
        }
    }

    println!("\nStep 3: Setup verification parameters");
    let message_hex = "96fd6f2c9100832cdddd6e06ce9c7d629152716aaa9821a4fb9726db01fee3f2";
    let message_bytes = hex::decode(message_hex).unwrap();
    let message: [u8; 32] = message_bytes.try_into().unwrap();
    let epoch = 1u32;
    println!("  Message: {}", message_hex);
    println!("  Epoch: {}", epoch);

    println!("\nStep 4: Attempt verification");
    type LeanSigScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
    use leansig::signature::SignatureScheme;

    let result = LeanSigScheme::verify(&lean_pubkey, epoch, &message, &lean_signature);

    println!("  Verification result: {}", result);

    if !result {
        println!("\n=== VERIFICATION FAILED ===");
        println!("This confirms that Python-generated signatures cannot be verified by Rust.");
        println!("\nPossible causes:");
        println!("  1. Different PRF implementations");
        println!("  2. Different message encoder implementations");
        println!("  3. Different hash chain implementations");
        println!("  4. Different Merkle tree implementations");
        println!("  5. Version mismatch between Python and Rust libraries");
        println!("\nNext step: Check if there's a canonical reference implementation");
        println!("or contact leanSpec maintainers about compatibility.");
    }
}
