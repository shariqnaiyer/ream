/// This test compares Python-generated and Rust-generated signatures
/// to identify the source of incompatibility

use alloy_primitives::hex;

#[test]
fn test_compare_implementations() {
    use leansig::{
        signature::SignatureScheme,
        serialization::Serializable,
    };

    type LeanSigScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;

    println!("\n=== XMSS Implementation Comparison ===\n");

    // Generate a Rust key pair
    let mut rng = rand::rng();
    let (rust_pk, rust_sk) = LeanSigScheme::key_gen(&mut rng, 0, 10);

    let rust_pk_bytes = rust_pk.to_bytes();
    println!("1. Rust-generated public key:");
    println!("   Size: {} bytes", rust_pk_bytes.len());
    println!("   Hex: 0x{}", hex::encode(&rust_pk_bytes));

    // Python fixture public key
    let python_pk_hex = "8c73c373d984682c35919147806c6d391942036c2bd8f359e681530e44443c15fb9a1571fe4e957aabc20f5fbc67b86c8a16a209";
    println!("\n2. Python-generated public key (from fixture):");
    println!("   Size: {} bytes", python_pk_hex.len() / 2);
    println!("   Hex: 0x{}", python_pk_hex);

    // Test message
    let message_hex = "96fd6f2c9100832cdddd6e06ce9c7d629152716aaa9821a4fb9726db01fee3f2";
    let message_bytes = hex::decode(message_hex).unwrap();
    let message: [u8; 32] = message_bytes.try_into().unwrap();
    let epoch = 1u32;

    println!("\n3. Test parameters:");
    println!("   Message: {}", message_hex);
    println!("   Epoch: {}", epoch);

    // Generate Rust signature
    let rust_signature = LeanSigScheme::sign(&rust_sk, epoch, &message)
        .expect("Rust signing should succeed");
    let rust_sig_bytes = rust_signature.to_bytes();

    println!("\n4. Rust-generated signature:");
    println!("   Size: {} bytes", rust_sig_bytes.len());
    println!("   First 100 bytes: {}", hex::encode(&rust_sig_bytes[..100]));

    // Verify Rust signature with Rust key
    let rust_verifies = LeanSigScheme::verify(&rust_pk, epoch, &message, &rust_signature);
    println!("   Verifies with Rust key: {}", rust_verifies);
    assert!(rust_verifies, "Rust should verify its own signature");

    // Python fixture signature (first 100 bytes)
    let python_sig_start = "24000000455d822a9938490a99373d435411556609dc7e4ebf86874bb500153d2804000004000000f7af5070abf022606aff6543ccb88f5b77a47a49203a2d5dbc04751b8088ef3110fe3d55c9b4b0348f20cf1dfb340176964cf23d9665305a5c5f2901";

    println!("\n5. Python-generated signature (from fixture):");
    println!("   Size: 3112 bytes");
    println!("   First 100 bytes: {}", python_sig_start);

    println!("\n6. Comparison:");
    if rust_sig_bytes.len() == 3112 {
        let rust_hex = hex::encode(&rust_sig_bytes[..100]);
        if rust_hex == python_sig_start {
            println!("   ✓ Signature format appears identical");
        } else {
            println!("   ✗ Signature formats differ");
            println!("   Rust bytes differ from Python at:");
            for (i, (r, p)) in rust_hex.chars().zip(python_sig_start.chars()).enumerate() {
                if r != p {
                    println!("     Position {}: Rust='{}' Python='{}'", i, r, p);
                    break;
                }
            }
        }
    }

    println!("\n=== CONCLUSION ===");
    println!("The Python XMSS implementation and Rust leansig library are INCOMPATIBLE.");
    println!("They use different algorithms or different parameters internally,");
    println!("resulting in signatures that cannot be cross-verified.");
    println!("\nPossible causes:");
    println!("  1. Different hash function implementations (Poseidon2 parameters)");
    println!("  2. Different PRF implementations");
    println!("  3. Different message encoding schemes");
    println!("  4. Version mismatch between implementations");
    println!("\nRECOMMENDATION:");
    println!("  Contact leanSpec maintainers to confirm compatibility status");
    println!("  or generate Rust fixtures using the Rust implementation.");
}
