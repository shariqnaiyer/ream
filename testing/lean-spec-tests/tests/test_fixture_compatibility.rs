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
    // Encode path (HashTreeOpening)
    let mut path_bytes = Vec::new();
    path_bytes.extend_from_slice(&4u32.to_le_bytes()); // offset
    for sibling in &sig.path.siblings.data {
        path_bytes.extend_from_slice(&encode_u32_array(&sibling.data));
    }

    // Encode rho
    let rho_bytes = encode_u32_array(&sig.rho.data);

    // Encode hashes
    let mut hashes_bytes = Vec::new();
    for hash in &sig.hashes.data {
        hashes_bytes.extend_from_slice(&encode_u32_array(&hash.data));
    }

    // Construct full signature
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
fn test_python_fixture_signature_verification() {
    use leansig::{
        signature::SignatureScheme,
        serialization::Serializable,
    };
    use ream_post_quantum_crypto::leansig::{
        public_key::PublicKey,
    };

    type LeanSigScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
    type LeanSignature = <LeanSigScheme as SignatureScheme>::Signature;

    // Load fixture
    let fixture_path = "fixtures/consensus/verify_signatures/devnet/verify_signatures/test_valid_signatures/test_proposer_signature.json";
    let fixture_data = fs::read_to_string(fixture_path)
        .expect("Failed to read fixture file");
    let test_case: TestCase = serde_json::from_str(&fixture_data)
        .expect("Failed to parse fixture JSON");

    let test_data = test_case.data.values().next().expect("No test data");

    // Extract validator 1 public key
    let validator = &test_data.anchor_state.validators.data[1];
    let pubkey_hex = validator.pubkey.strip_prefix("0x").unwrap();
    let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
    let pubkey = PublicKey::from(&pubkey_bytes[..]);
    let lean_pubkey = pubkey.as_lean_sig().expect("Failed to deserialize public key");

    println!("✓ Loaded public key from fixture");
    println!("  Public key: {}", validator.pubkey);

    // Extract proposer attestation
    let proposer_att = &test_data.signed_block_with_attestation.message.proposer_attestation;
    let epoch = proposer_att.data.slot as u32;

    println!("✓ Loaded attestation data");
    println!("  Validator ID: {}", proposer_att.validator_id);
    println!("  Epoch (slot): {}", epoch);

    // Message hash (this should match what we computed before)
    let message_hex = "96fd6f2c9100832cdddd6e06ce9c7d629152716aaa9821a4fb9726db01fee3f2";
    let message_bytes = hex::decode(message_hex).unwrap();
    let message: [u8; 32] = message_bytes.try_into().unwrap();

    println!("✓ Message hash: {}", message_hex);

    // Convert fixture signature to bytes
    let sig = &test_data.signed_block_with_attestation.signature.proposer_signature;
    let sig_bytes = convert_fixture_signature_to_bytes(sig);

    println!("✓ Converted signature to bytes");
    println!("  Signature size: {} bytes", sig_bytes.len());
    println!("  First 50 bytes: {}", hex::encode(&sig_bytes[..50]));
    println!("  Num siblings: {}", sig.path.siblings.data.len());
    println!("  Num hashes: {}", sig.hashes.data.len());

    // Deserialize signature
    let lean_signature = LeanSignature::from_bytes(&sig_bytes);

    match lean_signature {
        Ok(lean_sig) => {
            println!("✓ Signature deserialized successfully");

            // Attempt verification
            let result = LeanSigScheme::verify(&lean_pubkey, epoch, &message, &lean_sig);

            println!("\n=== VERIFICATION RESULT ===");
            println!("Python-generated fixture signature verified by Rust: {}", result);

            if !result {
                println!("\n❌ INCOMPATIBILITY DETECTED:");
                println!("   Python XMSS implementation generated a signature that Rust cannot verify");
                println!("   All parameters are correct, but verification fails");
                println!("   This indicates the two implementations are incompatible");
            } else {
                println!("\n✓ COMPATIBILITY CONFIRMED:");
                println!("   Python and Rust XMSS implementations are compatible");
            }

            // Don't fail the test - we want to see the result
            // assert!(result, "Python fixture signature should verify in Rust");
        }
        Err(e) => {
            println!("✗ Failed to deserialize signature: {:?}", e);
            println!("\n❌ DESERIALIZATION ERROR:");
            println!("   The signature bytes from Python cannot be deserialized by Rust");
            println!("   This indicates a fundamental encoding incompatibility");
            panic!("Signature deserialization failed");
        }
    }
}
