use std::sync::atomic::{AtomicU64, Ordering};

static ATTESTATION_COMMITTEE_COUNT: AtomicU64 = AtomicU64::new(1);

pub fn attestation_committee_count() -> u64 {
    ATTESTATION_COMMITTEE_COUNT.load(Ordering::Relaxed)
}

/// Set the runtime attestation committee count. Returns the previous value so
/// callers can restore it (used in tests).
pub fn set_attestation_committee_count(value: u64) -> u64 {
    ATTESTATION_COMMITTEE_COUNT.swap(value, Ordering::Relaxed)
}

// NOTE: bumped 1 -> 64 to tolerate `current_time` (the store tick advanced by
// `on_tick`) lagging real time when the consensus task is blocked by zk proving
// on slower-than-M4 cores. With the default of 1 interval (~0.8s), a momentarily
// starved tick causes the aggregator to drop peers' attestations as
// "Attestation too far in future" (store.rs validate_attestation), which stalls
// justification on multi-node devnets off M4-class hardware. Proper fix: run
// proving off the consensus event loop.
pub const GOSSIP_DISPARITY_INTERVALS: u64 = 64;
pub const INTERVALS_PER_SLOT: u64 = 5;
pub const MAX_ATTESTATIONS_DATA: u64 = 16;
pub const MAX_HISTORICAL_BLOCK_HASHES: u64 = 262144;
pub const SLOT_DURATION: u64 = 4;
pub const VALIDATOR_REGISTRY_LIMIT: u64 = 4096;
