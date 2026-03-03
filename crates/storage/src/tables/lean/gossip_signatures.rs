use std::sync::Arc;

use ream_consensus_lean::attestation::SignatureKey;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};

use crate::{
    errors::StoreError,
    tables::{ssz_encoder::SSZEncoding, table::REDBTable},
};

// Type alias for signature storage - leansig Signature for devnet3, Vec<u8> for devnet4
#[cfg(feature = "devnet3")]
pub type GossipSignature = ream_post_quantum_crypto::leansig::signature::Signature;

#[cfg(feature = "devnet4")]
pub type GossipSignature = Vec<u8>;

// Fallback for when neither feature is enabled (shouldn't happen in practice)
#[cfg(not(any(feature = "devnet3", feature = "devnet4")))]
pub type GossipSignature = Vec<u8>;

/// Table for storing per-validator XMSS signatures learned from gossip.
/// Key: SignatureKey (validator_id, attestation_data_root)
/// Value: GossipSignature (leansig Signature for devnet3, Vec<u8> for devnet4)
pub struct GossipSignaturesTable {
    pub db: Arc<Database>,
}

impl REDBTable for GossipSignaturesTable {
    const TABLE_DEFINITION: TableDefinition<
        '_,
        SSZEncoding<SignatureKey>,
        SSZEncoding<GossipSignature>,
    > = TableDefinition::new("gossip_signatures");

    type Key = SignatureKey;
    type KeyTableDefinition = SSZEncoding<SignatureKey>;
    type Value = GossipSignature;
    type ValueTableDefinition = SSZEncoding<GossipSignature>;

    fn database(&self) -> Arc<Database> {
        self.db.clone()
    }
}

impl GossipSignaturesTable {
    pub fn get_keys(&self) -> Result<Vec<SignatureKey>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(Self::TABLE_DEFINITION)?;
        let mut keys = Vec::new();

        for item in table.iter()? {
            let (key, _) = item?;
            keys.push(key.value());
        }
        Ok(keys)
    }

    pub fn clear(&self) -> Result<(), StoreError> {
        let mut write_txn = self.db.begin_write()?;
        write_txn.set_durability(Durability::Immediate)?;
        let mut table = write_txn.open_table(Self::TABLE_DEFINITION)?;
        while table.pop_first()?.is_some() {}
        drop(table);
        write_txn.commit()?;
        Ok(())
    }

    pub fn retain<F>(&self, mut f: F) -> Result<(), StoreError>
    where
        F: FnMut(&SignatureKey) -> bool,
    {
        let mut write_txn = self.db.begin_write()?;
        write_txn.set_durability(Durability::Immediate)?;
        {
            let mut table = write_txn.open_table(Self::TABLE_DEFINITION)?;
            table.retain(|keys, _| f(&keys))?;
        }
        write_txn.commit()?;
        Ok(())
    }
}
