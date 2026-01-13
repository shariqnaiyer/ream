use alloy_primitives::hex;
use ream_post_quantum_crypto::leansig::{
    public_key::PublicKey,
    signature::Signature,
};

#[test]
fn test_minimal_fixture_verification() {
    // Exact data from test_proposer_signature.json fixture

    // Public key for validator 1
    let pubkey_hex = "8c73c373d984682c35919147806c6d391942036c2bd8f359e681530e44443c15fb9a1571fe4e957aabc20f5fbc67b86c8a16a209";
    let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
    let pubkey = PublicKey::from(&pubkey_bytes[..]);

    println!("Public key loaded: {} bytes", pubkey_bytes.len());

    // Try to deserialize as leansig public key
    let lean_pubkey = pubkey.as_lean_sig();
    assert!(lean_pubkey.is_ok(), "Should deserialize public key: {:?}", lean_pubkey.err());
    let lean_pubkey = lean_pubkey.unwrap();

    println!("✓ Public key deserialized successfully");

    // Message hash (AttestationData tree_hash_root)
    let message_hex = "96fd6f2c9100832cdddd6e06ce9c7d629152716aaa9821a4fb9726db01fee3f2";
    let message_bytes = hex::decode(message_hex).unwrap();
    let message: [u8; 32] = message_bytes.try_into().unwrap();

    println!("Message: {}", hex::encode(message));

    // Epoch (slot)
    let epoch = 1u32;

    println!("Epoch: {}", epoch);

    // Signature bytes (from Python fixture, exactly 3112 bytes)
    // First 100 bytes for brevity - we'll load the full signature from file
    let sig_hex_start = "24000000455d822a9938490a99373d435411556609dc7e4ebf86874bb500153d2804000004000000f7af5070abf022606aff6543ccb88f5b77a47a49203a2d5dbc04751b8088ef3110fe3d55c9b4b0348f20cf1dfb340176964cf23d9665305a5c5f2901";

    println!("Signature starts with: {}...", &sig_hex_start[..40]);

    // For this minimal test, let's load the actual signature from the fixture JSON
    // For now, just verify the test setup works
    println!("\n=== Test Setup Complete ===");
    println!("Next step: Load full signature from fixture and attempt verification");
}

#[test]
fn test_rust_self_generated_signature() {
    use leansig::{
        signature::SignatureScheme,
        serialization::Serializable,
    };

    type LeanSigScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;

    // Generate a key pair using the same config as PROD
    let mut rng = rand::rng();
    let (pk, sk) = LeanSigScheme::key_gen(&mut rng, 0, 10);

    // Message (same as fixture)
    let message_hex = "96fd6f2c9100832cdddd6e06ce9c7d629152716aaa9821a4fb9726db01fee3f2";
    let message_bytes = hex::decode(message_hex).unwrap();
    let message: [u8; 32] = message_bytes.try_into().unwrap();

    // Sign at epoch 1
    let epoch = 1u32;
    let signature = LeanSigScheme::sign(&sk, epoch, &message).expect("Signing should succeed");

    // Verify - this should work
    let result = LeanSigScheme::verify(&pk, epoch, &message, &signature);

    println!("Rust self-generated signature verification: {}", result);
    assert!(result, "Rust should be able to verify its own signatures");

    // Print signature size
    let sig_bytes = signature.to_bytes();
    println!("Rust-generated signature size: {} bytes", sig_bytes.len());

    // Print public key
    let pk_bytes = pk.to_bytes();
    println!("Rust-generated public key size: {} bytes", pk_bytes.len());
    println!("Rust-generated public key: 0x{}", hex::encode(&pk_bytes));
}
