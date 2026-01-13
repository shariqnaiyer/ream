use ream_post_quantum_crypto::leansig::{
    private_key::PrivateKey,
    public_key::PublicKey,
};

#[tokio::test]
async fn test_rust_generate_and_verify() {
    // Generate a key pair
    let mut rng = rand::thread_rng();
    let (public_key, private_key) = PrivateKey::generate_key_pair(&mut rng, 0, 10);

    let epoch = 1u32;
    let message = [0x96, 0xfd, 0x6f, 0x2c, 0x91, 0x00, 0x83, 0x2c,
                   0xdd, 0xdd, 0x6e, 0x06, 0xce, 0x9c, 0x7d, 0x62,
                   0x91, 0x52, 0x71, 0x6a, 0xaa, 0x98, 0x21, 0xa4,
                   0xfb, 0x97, 0x26, 0xdb, 0x01, 0xfe, 0xe3, 0xf2];

    // Sign
    let signature = private_key.sign(&message, epoch).unwrap();

    // Verify
    let result = signature.verify(&public_key, epoch, &message).unwrap();

    assert!(result, "Rust-generated signature should verify");
    println!("✓ Rust can generate and verify signatures");

    // Print public key for comparison
    println!("Generated public key: 0x{}", hex::encode(public_key.inner.as_slice()));
}
