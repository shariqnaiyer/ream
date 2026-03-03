use anyhow::anyhow;
#[cfg(feature = "devnet3")]
use lean_multisig::{
    Devnet2XmssAggregateSignature, xmss_aggregate_signatures, xmss_aggregation_setup_prover,
    xmss_aggregation_setup_verifier, xmss_verify_aggregated_signatures,
};
#[cfg(feature = "devnet3")]
use ssz::{Decode, Encode};

// ============================================================================
// devnet3: Use the stable lean-multisig API (no recursive aggregation)
// Uses the leansig wrapper types
// ============================================================================
#[cfg(feature = "devnet3")]
use crate::leansig::{public_key::PublicKey, signature::Signature};

/// Setup function for the prover side of XMSS aggregation.
#[cfg(feature = "devnet3")]
pub fn setup_prover() {
    xmss_aggregation_setup_prover();
}

/// Setup function for the verifier side of XMSS aggregation.
#[cfg(feature = "devnet3")]
pub fn setup_verifier() {
    xmss_aggregation_setup_verifier();
}

/// Aggregate multiple leansig signatures into a single proof.
#[cfg(feature = "devnet3")]
pub fn aggregate_signatures(
    public_keys: &[PublicKey],
    signatures: &[Signature],
    message: &[u8; 32],
    epoch: u32,
) -> anyhow::Result<Vec<u8>> {
    if public_keys.len() != signatures.len() {
        return Err(anyhow!(
            "Public key count ({}) does not match signature count ({})",
            public_keys.len(),
            signatures.len()
        ));
    }

    let aggregate_signature = xmss_aggregate_signatures(
        &public_keys
            .iter()
            .map(|public_key| public_key.as_lean_sig())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| anyhow!("Failed to convert public keys: {err}"))?,
        &signatures
            .iter()
            .map(|signature| signature.as_lean_sig())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| anyhow!("Failed to convert signatures: {err}"))?,
        message,
        epoch,
    )
    .map_err(|err| anyhow!("Failed to aggregate signatures: {err:?}"))?;

    Ok(aggregate_signature.as_ssz_bytes())
}

/// Verify an aggregated signature from SSZ-encoded bytes.
#[cfg(feature = "devnet3")]
pub fn verify_aggregate_signature(
    public_keys: &[PublicKey],
    message: &[u8; 32],
    aggregate_signature_bytes: &[u8],
    epoch: u32,
) -> anyhow::Result<()> {
    let aggregate_signature =
        Devnet2XmssAggregateSignature::from_ssz_bytes(aggregate_signature_bytes)
            .map_err(|err| anyhow!("Failed to decode aggregate signature: {err:?}"))?;

    xmss_verify_aggregated_signatures(
        &public_keys
            .iter()
            .map(|public_key| public_key.as_lean_sig())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| anyhow!("Failed to convert public keys: {err}"))?,
        message,
        &aggregate_signature,
        epoch,
    )
    .map_err(|err| anyhow!("Failed to verify aggregated signatures: {err}"))
}

// ============================================================================
// devnet4: Use the new lean-multisig API with recursive aggregation
// Uses lean-multisig-devnet4 types directly (XmssPublicKey, XmssSignature)
// ============================================================================

// Re-export types for use in other modules
#[cfg(feature = "devnet4")]
pub use lean_multisig_devnet4::{
    AggregatedXMSS, F, MESSAGE_LEN_FE, XmssPublicKey, XmssSecretKey, XmssSignature, xmss_key_gen,
    xmss_sign, xmss_verify,
};
#[cfg(feature = "devnet4")]
use lean_multisig_devnet4::{
    setup_prover as lean_setup_prover, setup_verifier as lean_setup_verifier, xmss_aggregate,
    xmss_verify_aggregation,
};

/// Setup function for the prover side of XMSS aggregation.
/// This initializes the aggregation bytecode and precomputes DFT twiddles.
#[cfg(feature = "devnet4")]
pub fn setup_prover() {
    lean_setup_prover();
}

/// Setup function for the verifier side of XMSS aggregation.
/// This initializes the aggregation bytecode.
#[cfg(feature = "devnet4")]
pub fn setup_verifier() {
    lean_setup_verifier();
}

/// Convert a 32-byte message to field elements for devnet4 API.
/// The devnet4 API expects messages as `[F; MESSAGE_LEN_FE]` (9 field elements).
#[cfg(feature = "devnet4")]
pub fn message_to_field_elements(message: &[u8; 32]) -> [F; MESSAGE_LEN_FE] {
    // Pack bytes into field elements (4 bytes per field element, with padding)
    let mut result: [F; MESSAGE_LEN_FE] = std::array::from_fn(|_| F::new(0));
    for (i, chunk) in message.chunks(4).enumerate() {
        if i < MESSAGE_LEN_FE {
            let mut bytes = [0u8; 4];
            bytes[..chunk.len()].copy_from_slice(chunk);
            result[i] = F::new(u32::from_le_bytes(bytes));
        }
    }
    result
}

/// Aggregate multiple XMSS signatures into a single proof.
/// This is the devnet4 version using the recursive aggregation API.
#[cfg(feature = "devnet4")]
pub fn aggregate_signatures_devnet4(
    public_keys_and_signatures: Vec<(XmssPublicKey, XmssSignature)>,
    message: &[F; MESSAGE_LEN_FE],
    slot: u32,
    log_inv_rate: usize,
) -> AggregatedXMSS {
    xmss_aggregate(&[], public_keys_and_signatures, message, slot, log_inv_rate)
}

/// Verify an aggregated signature.
#[cfg(feature = "devnet4")]
pub fn verify_aggregate_signature_devnet4(
    aggregated: &AggregatedXMSS,
    message: &[F; MESSAGE_LEN_FE],
    slot: u32,
) -> anyhow::Result<()> {
    xmss_verify_aggregation(aggregated, message, slot)
        .map(|_| ())
        .map_err(|err| anyhow!("Failed to verify aggregated signatures: {err:?}"))
}

// ============================================================================
// devnet4 only: Recursive aggregation functions
// ============================================================================

/// Result of recursive aggregation containing proof data and bytecode claim
#[cfg(feature = "devnet4")]
#[derive(Debug, Clone)]
pub struct RecursiveAggregationResult {
    /// The aggregated proof
    pub aggregated: AggregatedXMSS,
    /// Bytecode point claim data for recursive verification (if recursive)
    pub bytecode_point: Option<Vec<u8>>,
}

/// Perform recursive aggregation combining children proofs and raw XMSS signatures.
///
/// This function aggregates:
/// - `children`: Existing aggregated proofs from prior aggregation rounds
/// - `raw_xmss`: New raw XMSS signatures (public key, signature pairs)
///
/// At least one raw signature OR children proofs are required.
#[cfg(feature = "devnet4")]
pub fn recursive_aggregate(
    children: &[AggregatedXMSS],
    raw_xmss: Vec<(XmssPublicKey, XmssSignature)>,
    message: &[F; MESSAGE_LEN_FE],
    slot: u32,
    log_inv_rate: usize,
) -> anyhow::Result<RecursiveAggregationResult> {
    if raw_xmss.is_empty() && children.is_empty() {
        return Err(anyhow!(
            "At least one raw signature or children proof required for aggregation"
        ));
    }

    // Perform recursive aggregation
    let aggregated = xmss_aggregate(children, raw_xmss, message, slot, log_inv_rate);

    // Extract bytecode point if present (recursive aggregation)
    let bytecode_point = if !children.is_empty() {
        Some(Vec::new()) // TODO: Extract actual bytecode point from aggregated proof
    } else {
        None
    };

    Ok(RecursiveAggregationResult {
        aggregated,
        bytecode_point,
    })
}

/// Verify a recursively aggregated signature.
#[cfg(feature = "devnet4")]
pub fn verify_recursive_aggregation(
    aggregated: &AggregatedXMSS,
    message: &[F; MESSAGE_LEN_FE],
    slot: u32,
) -> anyhow::Result<()> {
    xmss_verify_aggregation(aggregated, message, slot)
        .map(|_| ())
        .map_err(|err| anyhow!("Failed to verify recursive aggregation: {err:?}"))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "devnet3"))]
mod tests_devnet3 {
    use rand::rng;

    use crate::{
        lean_multisig::aggregate::{
            aggregate_signatures, setup_prover, setup_verifier, verify_aggregate_signature,
        },
        leansig::private_key::PrivateKey,
    };

    #[test]
    fn test_aggregate_and_verify() {
        setup_prover();
        setup_verifier();

        let mut rng = rng();
        let message = [42u8; 32];
        let epoch = 50u32;

        let key_configs = vec![(10, 32), (20, 64), (30, 128)];

        let mut public_keys = Vec::new();
        let mut signatures = Vec::new();

        for (activation_epoch, num_active_epochs) in key_configs {
            let (pub_key, mut priv_key) =
                PrivateKey::generate_key_pair(&mut rng, activation_epoch, num_active_epochs);

            let mut iterations = 0;
            while !priv_key.get_prepared_interval().contains(&(epoch as u64))
                && iterations < (epoch - activation_epoch as u32)
            {
                priv_key.prepare_signature();
                iterations += 1;
            }

            let signature = priv_key.sign(&message, epoch).unwrap();
            assert!(signature.verify(&pub_key, epoch, &message).unwrap());

            public_keys.push(pub_key);
            signatures.push(signature);
        }

        let aggregate_signature_bytes =
            aggregate_signatures(&public_keys, &signatures, &message, epoch).unwrap();

        verify_aggregate_signature(&public_keys, &message, &aggregate_signature_bytes, epoch)
            .unwrap();
    }
}

#[cfg(all(test, feature = "devnet4"))]
mod tests_devnet4 {
    use super::*;

    #[test]
    fn test_aggregate_and_verify_devnet4() {
        setup_prover();
        setup_verifier();

        let slot = 100u32;
        let message_bytes = [42u8; 32];
        let message_fe = message_to_field_elements(&message_bytes);

        // Generate test keys
        let seed1: [u8; 20] = [1; 20];
        let seed2: [u8; 20] = [2; 20];

        let (secret_key1, pub_key1) = xmss_key_gen(seed1, 50, 150).unwrap();
        let (secret_key2, pub_key2) = xmss_key_gen(seed2, 50, 150).unwrap();

        // Sign messages
        let sig1 = xmss_sign(&mut rand::rng(), &secret_key1, &message_fe, slot).unwrap();
        let sig2 = xmss_sign(&mut rand::rng(), &secret_key2, &message_fe, slot).unwrap();

        // Aggregate
        let aggregated = aggregate_signatures_devnet4(
            vec![(pub_key1, sig1), (pub_key2, sig2)],
            &message_fe,
            slot,
            3,
        );

        // Verify
        verify_aggregate_signature_devnet4(&aggregated, &message_fe, slot).unwrap();
    }
}
