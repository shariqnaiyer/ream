//! Devnet5 multi-message (Type-2) signature aggregation wrappers.
//!
//! Thin bridge over the `lean-multisig` (rev `8fcbd779`) native Type-1/Type-2
//! recursive aggregation API, exposed to ream as byte-oriented helpers that
//! operate on ream's `PublicKey` / `Signature` wrappers.
//!
//! Proof shapes (mirrors `leanSpec`'s `xmss/aggregation.py`):
//! - **Type-1**: many validators over one message `(attestation data root, slot)` or `(block root,
//!   block slot)`.
//! - **Type-2**: a merge of N Type-1 proofs over distinct messages — the single blob carried on
//!   `SignedBlock.proof`.
//!
//! On the wire, proofs are stored in *compact, no-pubkeys* form
//! (`compress_without_pubkeys`). The participant identities live separately in
//! the attestation `aggregation_bits`, and the verifier re-derives the pubkey
//! layout from the (already trusted) block body before decoding.

use anyhow::{Result, anyhow};
use lean_multisig_type2::{
    TypeOneMultiSignature, TypeTwoMultiSignature, XmssPublicKey, XmssSignature, aggregate_type_1,
    merge_many_type_1, setup_prover, split_type_2, verify_type_1, verify_type_2,
};

use crate::leansig::{public_key::PublicKey, signature::Signature};

/// Inverse rate exponent forwarded to the WHIR prover/verifier.
///
/// Mirrors `LOG_INV_RATE_PROD` in leanSpec (test mode uses `1`). Lower values
/// prove faster but yield larger proofs.
pub const LOG_INV_RATE: usize = 2;

/// Ensure the aggregation bytecode / prover twiddles are initialised.
///
/// Safe to call repeatedly; the underlying setup is idempotent (`OnceLock`).
pub fn type2_setup() {
    setup_prover();
}

/// Convert a ream public key into the multisig library's `XmssPublicKey`.
///
/// ream and `lean-multisig` are built against the same `leansig` crate and the
/// same `...Dim46Base8` instantiation, so `as_lean_sig()` already yields the
/// concrete type the library's aggregation API expects.
fn to_lib_pubkey(pk: &PublicKey) -> Result<XmssPublicKey> {
    pk.as_lean_sig()
}

/// Convert a ream signature into the multisig library's `XmssSignature`.
fn to_lib_signature(sig: &Signature) -> Result<XmssSignature> {
    sig.as_lean_sig()
}

/// Decode a ream Type-1 wire blob (`compress_without_pubkeys` bytes) back into a
/// library `TypeOneMultiSignature`, re-injecting the participants' public keys.
///
/// `public_keys` must be the keys of the participants this proof covers, in any
/// order (the library sorts/dedups internally).
pub fn type1_from_wire(wire: &[u8], public_keys: &[PublicKey]) -> Result<TypeOneMultiSignature> {
    let lib_pks = public_keys
        .iter()
        .map(to_lib_pubkey)
        .collect::<Result<Vec<_>>>()?;
    TypeOneMultiSignature::decompress_without_pubkeys(wire, lib_pks)
        .ok_or_else(|| anyhow!("Failed to decode Type-1 multi-signature from wire bytes"))
}

/// Serialise a library Type-1 proof into ream's compact wire form.
pub fn type1_to_wire(proof: &TypeOneMultiSignature) -> Vec<u8> {
    proof.compress_without_pubkeys()
}

/// Aggregate raw XMSS signatures and child Type-1 proofs into one Type-1 proof
/// over a single `(message, slot)`.
///
/// All `children` must already bind the same `message` and `slot`. Returns the
/// merged proof; serialise it with [`type1_to_wire`] for storage on the wire.
pub fn type1_aggregate(
    children: &[TypeOneMultiSignature],
    raw_xmss: &[(PublicKey, Signature)],
    message: &[u8; 32],
    slot: u32,
) -> Result<TypeOneMultiSignature> {
    type2_setup();

    let raw: Vec<_> = raw_xmss
        .iter()
        .map(|(pk, sig)| Ok((to_lib_pubkey(pk)?, to_lib_signature(sig)?)))
        .collect::<Result<Vec<_>>>()?;

    aggregate_type_1(children, raw, *message, slot, LOG_INV_RATE)
        .map_err(|err| anyhow!("Type-1 aggregation failed: {err:?}"))
}

/// Verify a standalone Type-1 proof.
///
/// Message/slot/pubkey bindings are embedded in the proof's `TypeOneInfo`, so
/// the caller is responsible for cross-checking those bindings against the
/// trusted block body where substitution attacks matter.
pub fn type1_verify(proof: &TypeOneMultiSignature) -> Result<()> {
    type2_setup();
    verify_type_1(proof)
        .map(|_| ())
        .map_err(|err| anyhow!("Type-1 verification failed: {err:?}"))
}

/// Merge several Type-1 proofs (each over a distinct message) into one Type-2
/// proof. Re-verifies every component internally; capped at `MAX_RECURSIONS`.
pub fn type2_merge(parts: Vec<TypeOneMultiSignature>) -> Result<TypeTwoMultiSignature> {
    type2_setup();
    merge_many_type_1(parts, LOG_INV_RATE).map_err(|err| anyhow!("Type-2 merge failed: {err:?}"))
}

/// Serialise a Type-2 proof into the compact, no-pubkeys wire form stored on
/// `SignedBlock.proof`.
pub fn type2_to_wire(proof: &TypeTwoMultiSignature) -> Vec<u8> {
    proof.compress_without_pubkeys()
}

/// Decode a `SignedBlock.proof` blob back into a library Type-2 proof.
///
/// `pubkeys_per_component` provides one pubkey set per merged component, in the
/// exact order they were merged: one entry per body attestation (its
/// participants) followed by a final single-key entry for the proposer.
pub fn type2_from_wire(
    wire: &[u8],
    pubkeys_per_component: &[Vec<PublicKey>],
) -> Result<TypeTwoMultiSignature> {
    let lib_pks = pubkeys_per_component
        .iter()
        .map(|pks| pks.iter().map(to_lib_pubkey).collect::<Result<Vec<_>>>())
        .collect::<Result<Vec<_>>>()?;
    TypeTwoMultiSignature::decompress_without_pubkeys(wire, lib_pks)
        .ok_or_else(|| anyhow!("Failed to decode Type-2 multi-signature from wire bytes"))
}

/// Verify a Type-2 proof.
///
/// All bindings are embedded; the caller must still cross-check each
/// component's `(message, slot)` against the trusted block body.
pub fn type2_verify(proof: &TypeTwoMultiSignature) -> Result<()> {
    type2_setup();
    verify_type_2(proof)
        .map(|_| ())
        .map_err(|err| anyhow!("Type-2 verification failed: {err:?}"))
}

/// Recover the Type-1 proof for the component at `index` from a Type-2 proof.
///
/// Used by the block-deconstruction path: `index` is the attestation's position
/// in the block body.
pub fn type2_split(proof: TypeTwoMultiSignature, index: usize) -> Result<TypeOneMultiSignature> {
    type2_setup();
    split_type_2(proof, index, LOG_INV_RATE).map_err(|err| anyhow!("Type-2 split failed: {err:?}"))
}

/// Decode, bind-check, and verify a block's merged Type-2 proof in one step.
///
/// - `wire` is the `SignedBlock.proof` blob.
/// - `pubkeys_per_component` is one pubkey set per merged component, in body order (one per
///   attestation) followed by a single-key proposer entry.
/// - `expected_bindings` is the parallel `(message, slot)` each component must bind:
///   `(attestation_data_root, attestation_slot)` per attestation, then `(block_root, block_slot)`
///   for the proposer.
///
/// The bindings cross-check defends against a proposer pairing honest
/// signatures with attacker-chosen data that hashes to the same pubkey layout —
/// `verify_type_2` alone trusts the embedded `TypeOneInfo`.
pub fn type2_verify_block(
    wire: &[u8],
    pubkeys_per_component: &[Vec<PublicKey>],
    expected_bindings: &[([u8; 32], u32)],
) -> Result<()> {
    type2_setup();

    let proof = type2_from_wire(wire, pubkeys_per_component)?;

    if proof.info.len() != expected_bindings.len() {
        return Err(anyhow!(
            "Block proof has {} components but {} bindings were expected",
            proof.info.len(),
            expected_bindings.len()
        ));
    }

    for (component, (message, slot)) in proof.info.iter().zip(expected_bindings.iter()) {
        if &component.without_pubkeys.message != message {
            return Err(anyhow!(
                "Block proof component message does not match block body"
            ));
        }
        if component.without_pubkeys.slot != *slot {
            return Err(anyhow!(
                "Block proof component slot does not match block body"
            ));
        }
    }

    verify_type_2(&proof)
        .map(|_| ())
        .map_err(|err| anyhow!("Type-2 verification failed: {err:?}"))
}
