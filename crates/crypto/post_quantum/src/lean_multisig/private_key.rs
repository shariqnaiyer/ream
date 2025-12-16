// TODO: This module needs to be updated for devnet2 branch which doesn't export individual XMSS
// types The devnet2 branch only exports aggregation functions
// This module is currently not used anywhere in the codebase

use crate::lean_multisig::{
    errors::LeanMultisigError, public_key::PublicKey, signature::Signature,
};

pub struct PrivateKey {
    // Placeholder - devnet2 doesn't export XmssSecretKey
    _placeholder: (),
}

impl PrivateKey {
    pub fn new(_inner: ()) -> Self {
        Self { _placeholder: () }
    }

    pub fn generate_key_pair<R: rand::Rng>(
        _rng: &mut R,
        _first_slot: u64,
        _log_lifetime: usize,
    ) -> Result<(PublicKey, Self), LeanMultisigError> {
        unimplemented!("XMSS key generation not available in devnet2 branch")
    }

    pub fn public_key(&self) -> Result<PublicKey, LeanMultisigError> {
        unimplemented!("XMSS public key not available in devnet2 branch")
    }

    pub fn sign<R: rand::Rng>(
        &self,
        _rng: &mut R,
        _message_hash: [u8; 32],
        _slot: u64,
    ) -> Result<Signature, LeanMultisigError> {
        unimplemented!("XMSS signing not available in devnet2 branch")
    }
}
