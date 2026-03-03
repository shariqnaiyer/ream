use std::hash::{Hash, Hasher};

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{
    BitList, VariableList,
    typenum::{U4096, U1048576},
};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::checkpoint::Checkpoint;

// ============================================================================
// Feature-gated signature type for attestations
// ============================================================================

/// Type alias for attestation signatures.
/// For devnet3: leansig Signature for individual validator signatures
/// For devnet4: Vec<u8> for serialized XMSS signatures
#[cfg(feature = "devnet3")]
pub type AttestationSignature = ream_post_quantum_crypto::leansig::signature::Signature;

#[cfg(feature = "devnet4")]
pub type AttestationSignature = Vec<u8>;

// Fallback for when neither feature is enabled
#[cfg(not(any(feature = "devnet3", feature = "devnet4")))]
pub type AttestationSignature = Vec<u8>;

/// Key for signature storage, combining validator ID and attestation data root.
/// Used for both gossip_signatures and aggregated_payloads maps.
#[derive(
    Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize, Encode, Decode, PartialOrd, Ord,
)]
pub struct SignatureKey {
    pub validator_id: u64,
    pub data_root: B256,
}

impl SignatureKey {
    pub fn new(validator_id: u64, attestation_data: &AttestationData) -> Self {
        Self {
            validator_id,
            data_root: attestation_data.tree_hash_root(),
        }
    }

    pub fn from_parts(validator_id: u64, data_root: B256) -> Self {
        Self {
            validator_id,
            data_root,
        }
    }
}

// ============================================================================
// devnet4 only: BytecodePointOption for recursive aggregation
// ============================================================================

/// Optional bytecode point for recursive aggregation.
/// Uses Option type - None for non-recursive, Some(bytes) for recursive.
#[cfg(feature = "devnet4")]
pub type BytecodePointOption = Option<VariableList<u8, U1048576>>;

#[cfg(feature = "devnet4")]
/// Helper trait for BytecodePointOption
pub trait BytecodePointExt {
    /// Returns true if this is a recursive aggregation proof
    fn is_recursive(&self) -> bool;
    /// Get the bytecode point data if present
    fn as_bytecode_bytes(&self) -> Option<&[u8]>;
}

#[cfg(feature = "devnet4")]
impl BytecodePointExt for BytecodePointOption {
    fn is_recursive(&self) -> bool {
        self.is_some()
    }

    fn as_bytecode_bytes(&self) -> Option<&[u8]> {
        self.as_ref().map(|bytes| bytes.as_ref())
    }
}

// ============================================================================
// devnet3: AggregatedSignatureProof without bytecode_point
// ============================================================================

#[cfg(feature = "devnet3")]
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct AggregatedSignatureProof {
    pub participants: BitList<U4096>,
    pub proof_data: VariableList<u8, U1048576>,
}

#[cfg(feature = "devnet3")]
impl AggregatedSignatureProof {
    pub fn new(participants: BitList<U4096>, proof_data: VariableList<u8, U1048576>) -> Self {
        Self {
            participants,
            proof_data,
        }
    }

    /// Get the validator IDs covered by this proof
    pub fn to_validator_indices(&self) -> Vec<u64> {
        self.participants
            .iter()
            .enumerate()
            .filter(|(_, bit)| *bit)
            .map(|(index, _)| index as u64)
            .collect()
    }
}

/// Manual Hash implementation for AggregatedSignatureProof using tree_hash_root
/// This is needed because VariableList and BitList don't implement Hash directly.
#[cfg(feature = "devnet3")]
impl Hash for AggregatedSignatureProof {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.tree_hash_root().hash(state);
    }
}

// ============================================================================
// devnet4: AggregatedSignatureProof with bytecode_point for recursive aggregation
// ============================================================================

#[cfg(feature = "devnet4")]
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AggregatedSignatureProof {
    pub participants: BitList<U4096>,
    pub proof_data: VariableList<u8, U1048576>,
    /// Serialized bytecode-point claim data from recursive aggregation.
    /// None for non-recursive (direct XMSS), Some(bytes) for recursive.
    pub bytecode_point: BytecodePointOption,
}

#[cfg(feature = "devnet4")]
impl TreeHash for AggregatedSignatureProof {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("Struct should never be packed")
    }

    fn tree_hash_packing_factor() -> usize {
        1
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        // For Option<VariableList>, hash the inner value if Some, or zero hash if None
        let bytecode_hash = match &self.bytecode_point {
            Some(bytes) => bytes.tree_hash_root(),
            None => tree_hash::Hash256::ZERO,
        };

        // Concatenate all field hashes as bytes for merkle_root
        let mut leaves = Vec::with_capacity(3 * 32);
        leaves.extend_from_slice(self.participants.tree_hash_root().as_slice());
        leaves.extend_from_slice(self.proof_data.tree_hash_root().as_slice());
        leaves.extend_from_slice(bytecode_hash.as_slice());
        tree_hash::merkle_root(&leaves, 0)
    }
}

#[cfg(feature = "devnet4")]
impl AggregatedSignatureProof {
    pub fn new(participants: BitList<U4096>, proof_data: VariableList<u8, U1048576>) -> Self {
        Self {
            participants,
            proof_data,
            bytecode_point: None,
        }
    }

    /// Create a new recursive aggregation proof with bytecode point
    pub fn new_recursive(
        participants: BitList<U4096>,
        proof_data: VariableList<u8, U1048576>,
        bytecode_point: VariableList<u8, U1048576>,
    ) -> Self {
        Self {
            participants,
            proof_data,
            bytecode_point: Some(bytecode_point),
        }
    }

    /// Returns true if this is a recursive aggregation proof
    pub fn is_recursive(&self) -> bool {
        self.bytecode_point.is_some()
    }

    /// Get the validator IDs covered by this proof
    pub fn to_validator_indices(&self) -> Vec<u64> {
        self.participants
            .iter()
            .enumerate()
            .filter(|(_, bit)| *bit)
            .map(|(index, _)| index as u64)
            .collect()
    }
}

/// Manual Hash implementation for AggregatedSignatureProof using tree_hash_root
/// This is needed because VariableList and BitList don't implement Hash directly.
#[cfg(feature = "devnet4")]
impl Hash for AggregatedSignatureProof {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.tree_hash_root().hash(state);
    }
}

// ============================================================================
// Common types (shared between devnet3 and devnet4)
// ============================================================================

/// Attestation content describing the validator's observed chain view.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, Hash)]
pub struct AttestationData {
    pub slot: u64,
    pub head: Checkpoint,
    pub target: Checkpoint,
    pub source: Checkpoint,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct AggregatedAttestations {
    pub validator_id: u64,
    pub data: AttestationData,
}

impl AggregatedAttestation {
    /// Return the attested slot.
    pub fn slot(&self) -> u64 {
        self.message.slot
    }

    /// Return the attested head checkpoint.
    pub fn head(&self) -> Checkpoint {
        self.message.head
    }

    /// Return the attested target checkpoint.
    pub fn target(&self) -> Checkpoint {
        self.message.target
    }

    /// Return the attested source checkpoint.
    pub fn source(&self) -> Checkpoint {
        self.message.source
    }
}

/// Validator attestation bundled with its signature.
#[cfg(feature = "devnet3")]
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct SignedAttestation {
    pub validator_id: u64,
    pub message: AttestationData,
    /// signature over attestation message only as it would be aggregated later in attestation
    pub signature: AttestationSignature,
}

/// Validator attestation bundled with its signature.
#[cfg(feature = "devnet4")]
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedAttestation {
    pub validator_id: u64,
    pub message: AttestationData,
    /// signature over attestation message only as it would be aggregated later in attestation
    pub signature: AttestationSignature,
}

#[cfg(feature = "devnet4")]
impl TreeHash for SignedAttestation {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Container
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("Struct should never be packed")
    }

    fn tree_hash_packing_factor() -> usize {
        1
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        // Concatenate all field hashes as bytes for merkle_root
        let mut leaves = Vec::with_capacity(3 * 32);
        leaves.extend_from_slice(self.validator_id.tree_hash_root().as_slice());
        leaves.extend_from_slice(self.message.tree_hash_root().as_slice());
        // For Vec<u8>, use merkle_root directly
        leaves.extend_from_slice(tree_hash::merkle_root(&self.signature, 0).as_slice());
        tree_hash::merkle_root(&leaves, 0)
    }
}

/// Aggregated attestation consisting of participation bits and message.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct AggregatedAttestation {
    /// U4096 = VALIDATOR_REGISTRY_LIMIT
    pub aggregation_bits: BitList<U4096>,
    pub message: AttestationData,
}

/// Aggregated attestation bundled with aggregated signatures.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct SignedAggregatedAttestation {
    pub data: AttestationData,
    pub proof: AggregatedSignatureProof,
}
