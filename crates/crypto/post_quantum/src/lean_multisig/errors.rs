#[cfg(feature = "devnet3")]
use lean_multisig::{ProofError, XmssAggregateError};
#[cfg(feature = "devnet4")]
use lean_multisig_devnet4::ProofError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LeanMultisigError {
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(#[from] anyhow::Error),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[cfg(feature = "devnet3")]
    #[error("Verification failed: {0}")]
    VerificationFailed(#[from] ProofError),

    #[cfg(feature = "devnet4")]
    #[error("Verification failed: {0}")]
    VerificationFailedDevnet4(#[from] ProofError),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid public key size")]
    InvalidPublicKeySize,

    #[cfg(feature = "devnet3")]
    #[error("Aggregation error: {0:?}")]
    AggregationError(XmssAggregateError),

    #[cfg(feature = "devnet4")]
    #[error("Aggregation error: {0}")]
    AggregationErrorDevnet4(String),
}
