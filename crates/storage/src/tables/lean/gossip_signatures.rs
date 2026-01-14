use std::sync::Arc;

use ream_post_quantum_crypto::leansig::signature::Signature;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};

use super::aggregated_payloads::SignatureKey;
use crate::{errors::StoreError, tables::ssz_encoder::SSZEncoding};

pub struct GossipSignaturesTable {
    pub db: Arc<Database>,
}

const TABLE_DEF: TableDefinition<'_, SignatureKey, SSZEncoding<Signature>> =
    TableDefinition::new("gossip_signatures");

impl GossipSignaturesTable {
    pub fn get(&self, key: SignatureKey) -> Result<Option<Signature>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_DEF)?;
        Ok(table.get(key)?.map(|v| v.value()))
    }

    pub fn insert(&self, key: SignatureKey, value: Signature) -> Result<(), StoreError> {
        let mut write_txn = self.db.begin_write()?;
        write_txn.set_durability(Durability::Immediate)?;
        {
            let mut table = write_txn.open_table(TABLE_DEF)?;
            table.insert(key, value)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn remove(&self, key: SignatureKey) -> Result<(), StoreError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_DEF)?;
            table.remove(key)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get all entries in the table
    pub fn get_all(&self) -> Result<Vec<(SignatureKey, Signature)>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_DEF)?;
        table
            .iter()?
            .map(|entry| {
                let (k, v) = entry?;
                Ok((k.value(), v.value()))
            })
            .collect()
    }
}
