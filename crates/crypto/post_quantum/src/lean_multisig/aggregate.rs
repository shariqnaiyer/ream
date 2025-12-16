use anyhow::anyhow;
use lean_multisig::{
    Devnet2XmssAggregateSignature, XmssAggregateError, xmss_aggregate_signatures,
    xmss_aggregation_setup_prover, xmss_aggregation_setup_verifier,
    xmss_verify_aggregated_signatures,
};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

use super::errors::LeanMultisigError;
use crate::leansig::{public_key::PublicKey, signature::Signature};

/// Aggregated signature for multiple leansig signatures
///
/// This wraps the XMSS aggregate signature from the lean-multisig crate
/// and provides a fixed-size serializable format for use in the ream state.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AggregateSignature {
    /// Serialized proof bytes
    pub proof_bytes: Vec<u8>,
    /// Encoding randomness for each signature
    pub encoding_randomness: Vec<Vec<u8>>,
}

impl AggregateSignature {
    /// Create a new aggregate signature from components
    pub fn new(proof_bytes: Vec<u8>, encoding_randomness: Vec<Vec<u8>>) -> Self {
        Self {
            proof_bytes,
            encoding_randomness,
        }
    }

    /// Convert from the lean-multisig aggregate signature type
    pub fn from_devnet2(
        agg_sig: &Devnet2XmssAggregateSignature,
    ) -> Result<Self, LeanMultisigError> {
        // Convert encoding_randomness from [F; RAND_LEN_FE] to Vec<u8>
        let encoding_randomness = agg_sig
            .encoding_randomness
            .iter()
            .map(|rand_fe| {
                // Serialize the field elements to bytes
                // Each field element is 32 bits (4 bytes) for KoalaBear
                bincode::serialize(rand_fe).map_err(|err| {
                    LeanMultisigError::SerializationError(anyhow!(
                        "Failed to serialize encoding randomness: {err}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            proof_bytes: agg_sig.proof_bytes.clone(),
            encoding_randomness,
        })
    }

    /// Convert to the lean-multisig aggregate signature type
    pub fn to_devnet2(&self) -> Result<Devnet2XmssAggregateSignature, LeanMultisigError> {
        use p3_koala_bear::KoalaBear as F;

        // Deserialize encoding_randomness from Vec<u8> to [F; RAND_LEN_FE]
        const RAND_LEN_FE: usize = 7; // From leansig parameters
        let encoding_randomness = self
            .encoding_randomness
            .iter()
            .map(|bytes| {
                bincode::deserialize::<[F; RAND_LEN_FE]>(bytes).map_err(|err| {
                    LeanMultisigError::DeserializationError(anyhow!(
                        "Failed to deserialize encoding randomness: {err}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Devnet2XmssAggregateSignature {
            proof_bytes: self.proof_bytes.clone(),
            encoding_randomness,
        })
    }
}

/// Setup function for the prover side of XMSS aggregation
///
/// This precomputes necessary data structures to speed up proof generation.
/// Should be called once at startup if you plan to generate aggregate signatures.
pub fn setup_prover() {
    xmss_aggregation_setup_prover();
}

/// Setup function for the verifier side of XMSS aggregation
///
/// This precomputes necessary data structures to speed up verification.
/// Should be called once at startup if you plan to verify aggregate signatures.
pub fn setup_verifier() {
    xmss_aggregation_setup_verifier();
}

/// Aggregate multiple leansig signatures into a single proof
///
/// # Arguments
/// * `public_keys` - The public keys corresponding to each signature
/// * `signatures` - The individual signatures to aggregate
/// * `message` - The message that was signed (must be 32 bytes)
/// * `epoch` - The epoch at which the signatures were created
///
/// # Returns
/// An aggregated signature that proves all individual signatures are valid
///
/// # Errors
/// Returns an error if:
/// - The number of public keys doesn't match the number of signatures
/// - Any signature is invalid
/// - Serialization/deserialization fails
pub fn aggregate_signatures(
    public_keys: &[PublicKey],
    signatures: &[Signature],
    message: &[u8; 32],
    epoch: u32,
) -> Result<AggregateSignature, LeanMultisigError> {
    if public_keys.len() != signatures.len() {
        return Err(LeanMultisigError::AggregationError(
            XmssAggregateError::WrongSignatureCount,
        ));
    }

    // Convert ream types to lean-multisig types
    let lean_pub_keys: Vec<_> = public_keys
        .iter()
        .map(|pk| pk.as_lean_sig())
        .collect::<Result<Vec<_>, _>>()
        .map_err(LeanMultisigError::KeyGenerationFailed)?;

    let lean_signatures: Vec<_> = signatures
        .iter()
        .map(|sig| sig.as_lean_sig())
        .collect::<Result<Vec<_>, _>>()
        .map_err(LeanMultisigError::SigningFailed)?;

    // Perform aggregation using lean-multisig
    let agg_sig = xmss_aggregate_signatures(&lean_pub_keys, &lean_signatures, message, epoch)
        .map_err(LeanMultisigError::AggregationError)?;

    // Convert to ream type
    AggregateSignature::from_devnet2(&agg_sig)
}

/// Verify an aggregated signature
///
/// # Arguments
/// * `public_keys` - The public keys that were used to create the aggregate signature
/// * `message` - The message that was signed (must be 32 bytes)
/// * `aggregate_signature` - The aggregate signature to verify
/// * `epoch` - The epoch at which the signatures were created
///
/// # Returns
/// Ok(()) if the aggregate signature is valid
///
/// # Errors
/// Returns an error if:
/// - The aggregate signature is invalid
/// - Deserialization fails
/// - Proof verification fails
pub fn verify_aggregate_signature(
    public_keys: &[PublicKey],
    message: &[u8; 32],
    aggregate_signature: &AggregateSignature,
    epoch: u32,
) -> Result<(), LeanMultisigError> {
    // Convert ream types to lean-multisig types
    let lean_pub_keys: Vec<_> = public_keys
        .iter()
        .map(|pk| pk.as_lean_sig())
        .collect::<Result<Vec<_>, _>>()
        .map_err(LeanMultisigError::KeyGenerationFailed)?;

    let agg_sig = aggregate_signature.to_devnet2()?;

    // Verify using lean-multisig
    xmss_verify_aggregated_signatures(&lean_pub_keys, message, &agg_sig, epoch)
        .map_err(LeanMultisigError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use rand::rng;

    use super::*;
    use crate::leansig::private_key::PrivateKey;

    #[test]
    fn test_aggregate_and_verify() {
        // Setup (not mandatory but speeds up the first proof)
        setup_prover();
        setup_verifier();

        let mut rng = rng();
        let message = [42u8; 32];
        let epoch = 50u32;

        // Generate 3 key pairs with different lifetimes
        let key_configs = vec![(10, 32), (20, 64), (30, 128)];

        let mut public_keys = Vec::new();
        let mut signatures = Vec::new();

        for (activation_epoch, num_active_epochs) in key_configs {
            let (pub_key, mut priv_key) =
                PrivateKey::generate_key_pair(&mut rng, activation_epoch, num_active_epochs);

            // Advance the private key preparation to the signing epoch
            let mut iterations = 0;
            while !priv_key.get_prepared_interval().contains(&(epoch as u64))
                && iterations < (epoch - activation_epoch as u32)
            {
                priv_key.prepare_signature();
                iterations += 1;
            }

            let signature = priv_key.sign(&message, epoch).unwrap();

            // Verify individual signature
            assert!(signature.verify(&pub_key, epoch, &message).unwrap());

            public_keys.push(pub_key);
            signatures.push(signature);
        }

        // Aggregate signatures
        let agg_sig = aggregate_signatures(&public_keys, &signatures, &message, epoch).unwrap();

        // Verify aggregate signature
        verify_aggregate_signature(&public_keys, &message, &agg_sig, epoch).unwrap();
    }

    #[test]
    fn test_wrong_signature_count() {
        let mut rng = rng();
        let message = [42u8; 32];
        let epoch = 50u32;

        let (pub_key, mut priv_key) = PrivateKey::generate_key_pair(&mut rng, 10, 100);

        // Prepare and sign
        while !priv_key.get_prepared_interval().contains(&(epoch as u64)) {
            priv_key.prepare_signature();
        }
        let signature = priv_key.sign(&message, epoch).unwrap();

        // Try to aggregate with mismatched counts
        let result = aggregate_signatures(&[pub_key, pub_key], &[signature], &message, epoch);

        assert!(result.is_err());
        if let Err(LeanMultisigError::AggregationError(XmssAggregateError::WrongSignatureCount)) =
            result
        {
            // Expected error
        } else {
            panic!("Expected WrongSignatureCount error");
        }
    }
}
