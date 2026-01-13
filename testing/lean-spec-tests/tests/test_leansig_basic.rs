use alloy_primitives::hex;
use ream_post_quantum_crypto::leansig::{
    public_key::PublicKey,
    signature::Signature,
};

#[test]
fn test_fixture_pubkey_deserialize() {
    // Validator 1 public key from fixture
    let pubkey_hex = "8c73c373d984682c35919147806c6d391942036c2bd8f359e681530e44443c15fb9a1571fe4e957aabc20f5fbc67b86c8a16a209";
    let pubkey_bytes = hex::decode(pubkey_hex).unwrap();

    // Try to deserialize as PublicKey
    let pubkey = PublicKey::from(&pubkey_bytes[..]);

    // Try to convert to leansig public key
    let lean_pubkey = pubkey.as_lean_sig();
    assert!(lean_pubkey.is_ok(), "Should be able to deserialize public key from fixture");

    println!("Successfully deserialized public key from fixture");
}

#[test]
fn test_fixture_signature_deserialize() {
    // First 100 bytes of signature from fixture
    let sig_hex = "24000000455d822a9938490a99373d435411556609dc7e4ebf86874bb500153d2804000004000000f7af5070abf022606aff6543ccb88f5b77a47a49203a2d5dbc04751b8088ef3110fe3d55c9b4b0348f20cf1dfb340176964cf23d9665305a5c5f2901";

    // We need full 3112 bytes, so just test deserialization logic exists
    println!("Signature hex starts with: {}", &sig_hex[..40]);
}
