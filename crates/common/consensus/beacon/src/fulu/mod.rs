// Fulu only changes BeaconState (adds proposer_lookahead field)
// All other types are identical to Electra, so re-export them
pub use crate::electra::beacon_block;
pub use crate::electra::beacon_block_body;
pub use crate::electra::blinded_beacon_block;
pub use crate::electra::blinded_beacon_block_body;
pub use crate::electra::zkvm_types;

pub mod beacon_state;
