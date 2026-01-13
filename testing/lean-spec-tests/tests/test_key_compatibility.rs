/// Test to check if Python-generated keys can be used in Rust

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

#[test]
fn test_python_key_deserialization() {
    use leansig::serialization::Serializable;
    use ream_post_quantum_crypto::leansig::public_key::PublicKey;

    // Load fixture
    let fixture_path = "fixtures/consensus/verify_signatures/devnet/verify_signatures/test_valid_signatures/test_proposer_signature.json";
    let fixture_data = fs::read_to_string(fixture_path)
        .expect("Failed to read fixture file");
    let test_case: TestCase = serde_json::from_str(&fixture_data)
        .expect("Failed to parse fixture JSON");

    let test_data = test_case.data.values().next().expect("No test data");

    println!("\n=== Python Key Deserialization Test ===\n");

    // Test all validator keys
    for (i, validator) in test_data.anchor_state.validators.data.iter().enumerate() {
        println!("Validator {}:", i);
        println!("  Python pubkey: {}", validator.pubkey);

        let pubkey_hex = validator.pubkey.strip_prefix("0x").unwrap();
        let pubkey_bytes = hex::decode(pubkey_hex).unwrap();

        println!("  Size: {} bytes", pubkey_bytes.len());

        // Try to deserialize as Rust PublicKey
        let pubkey = PublicKey::from(&pubkey_bytes[..]);

        // Convert to leansig public key
        let lean_pubkey = pubkey.as_lean_sig();

        match lean_pubkey {
            Ok(pk) => {
                println!("  ✓ Successfully deserialized");

                // Try to re-serialize
                let reserialized = pk.to_bytes();
                println!("  Reserialized size: {} bytes", reserialized.len());

                // Check if it matches
                if reserialized == pubkey_bytes {
                    println!("  ✓ Round-trip successful (bytes match)");
                } else {
                    println!("  ✗ Round-trip failed (bytes differ)");
                    println!("    Original:      {}", hex::encode(&pubkey_bytes));
                    println!("    Reserialized:  {}", hex::encode(&reserialized));

                    // Find first difference
                    for (pos, (a, b)) in pubkey_bytes.iter().zip(reserialized.iter()).enumerate() {
                        if a != b {
                            println!("    First difference at byte {}: 0x{:02x} vs 0x{:02x}", pos, a, b);
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                println!("  ✗ Failed to deserialize: {:?}", e);
                panic!("Cannot deserialize Python-generated public key");
            }
        }
        println!();
    }
}

#[test]
fn test_rust_key_generation_stability() {
    use leansig::{
        signature::SignatureScheme,
        serialization::Serializable,
    };

    type LeanSigScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;

    println!("\n=== Rust Key Generation Stability Test ===\n");

    // Generate key with fixed seed
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let (pk1, _sk1) = LeanSigScheme::key_gen(&mut rng, 0, 10);
    let pk1_bytes = pk1.to_bytes();

    println!("Key 1: 0x{}", hex::encode(&pk1_bytes));

    // Generate another key with same seed
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let (pk2, _sk2) = LeanSigScheme::key_gen(&mut rng, 0, 10);
    let pk2_bytes = pk2.to_bytes();

    println!("Key 2: 0x{}", hex::encode(&pk2_bytes));

    if pk1_bytes == pk2_bytes {
        println!("\n✓ Deterministic key generation (same seed produces same key)");
    } else {
        println!("\n✗ Non-deterministic key generation!");
    }
}
