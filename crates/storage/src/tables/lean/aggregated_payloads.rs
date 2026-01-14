use std::sync::Arc;

use alloy_primitives::B256;
use ream_post_quantum_crypto::leansig::signature::Signature;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use ssz_types::{VariableList, typenum::U4096};

use crate::{errors::StoreError, tables::ssz_encoder::SSZEncoding};

/// Key for aggregated payloads: (validator_id, data_root)
/// Encoded as 40 bytes: 8 bytes for validator_id + 32 bytes for data_root
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureKey {
    pub validator_id: u64,
    pub data_root: B256,
}

impl SignatureKey {
    pub fn new(validator_id: u64, data_root: B256) -> Self {
        Self {
            validator_id,
            data_root,
        }
    }

    pub fn to_bytes(&self) -> [u8; 40] {
        let mut bytes = [0u8; 40];
        bytes[..8].copy_from_slice(&self.validator_id.to_le_bytes());
        bytes[8..].copy_from_slice(self.data_root.as_slice());
        bytes
    }

    pub fn from_bytes(bytes: &[u8; 40]) -> Self {
        let validator_id = u64::from_le_bytes(
            bytes[..8]
                .try_into()
                .expect("Failed to convert bytes to u64"),
        );
        let data_root = B256::from_slice(&bytes[8..]);
        Self {
            validator_id,
            data_root,
        }
    }
}

impl redb::Value for SignatureKey {
    type SelfType<'a> = SignatureKey;
    type AsBytes<'a> = [u8; 40];

    fn fixed_width() -> Option<usize> {
        Some(40)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        SignatureKey::from_bytes(
            data.try_into()
                .expect("Failed to convert bytes to [u8; 40]"),
        )
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        value.to_bytes()
    }

    fn type_name() -> redb::TypeName {
        redb::TypeName::new("SignatureKey")
    }
}

impl redb::Key for SignatureKey {
    fn compare(data1: &[u8], data2: &[u8]) -> std::cmp::Ordering {
        data1.cmp(data2)
    }
}

/// List of signature proofs for aggregation
pub type SignatureProofList = VariableList<Signature, U4096>;

pub struct AggregatedPayloadsTable {
    pub db: Arc<Database>,
}

const TABLE_DEF: TableDefinition<'_, SignatureKey, SSZEncoding<SignatureProofList>> =
    TableDefinition::new("aggregated_payloads");

impl AggregatedPayloadsTable {
    pub fn get(&self, key: SignatureKey) -> Result<Option<SignatureProofList>, StoreError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE_DEF)?;
        Ok(table.get(key)?.map(|v| v.value()))
    }

    pub fn insert(&self, key: SignatureKey, value: SignatureProofList) -> Result<(), StoreError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_DEF)?;
            table.insert(key, value)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Append a signature proof to the list for the given key
    pub fn append(&self, key: SignatureKey, proof: Signature) -> Result<(), StoreError> {
        let mut write_txn = self.db.begin_write()?;
        write_txn.set_durability(Durability::Immediate)?;
        {
            let mut table = write_txn.open_table(TABLE_DEF)?;

            let mut proofs = table
                .get(key)?
                .map(|v| v.value())
                .unwrap_or_else(VariableList::empty);

            proofs
                .push(proof)
                .map_err(|err| StoreError::DecodeError(format!("Too many proofs: {err}")))?;

            table.insert(key, proofs)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get all entries in the table
    pub fn get_all(&self) -> Result<Vec<(SignatureKey, SignatureProofList)>, StoreError> {
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
