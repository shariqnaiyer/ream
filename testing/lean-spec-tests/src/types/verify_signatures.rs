use serde::Deserialize;

use crate::types::{Attestation, Block, DataList, State};

/// Verify signatures test case
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifySignaturesTest {
    pub network: String,
    pub anchor_state: State,
    pub signed_block_with_attestation: SignedBlockWithAttestation,
}

/// Signed block with attestation from fixture
#[derive(Debug, Deserialize)]
pub struct SignedBlockWithAttestation {
    pub message: BlockWithAttestation,
    pub signature: SignatureData,
}

/// Block with proposer attestation
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockWithAttestation {
    pub block: Block,
    pub proposer_attestation: Attestation,
}

/// Signature data containing proposer and attestation signatures
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureData {
    pub attestation_signatures: DataList<AggregatedAttestationSignature>,
    pub proposer_signature: LeanSignature,
}

/// Aggregated attestation signature with participants and proof data
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregatedAttestationSignature {
    pub participants: DataList<bool>, // Bitfield indicating which validators participated
    pub proof_data: ProofData,
}

/// Proof data for aggregated signatures
#[derive(Debug, Deserialize)]
pub struct ProofData {
    pub data: String, // Hex string like "0x00"
}

/// XMSS signature structure
#[derive(Debug, Deserialize)]
pub struct LeanSignature {
    pub path: SignaturePath,
    pub rho: U32Array7,
    pub hashes: DataList<U32Array8>,
}

/// Signature path containing siblings
#[derive(Debug, Deserialize)]
pub struct SignaturePath {
    pub siblings: DataList<U32Array8>,
}

/// Array of 7 u32 values (for rho)
#[derive(Debug, Deserialize)]
pub struct U32Array7 {
    pub data: [u32; 7],
}

/// Array of 8 u32 values (for hash values)
#[derive(Debug, Deserialize)]
pub struct U32Array8 {
    pub data: [u32; 8],
}
