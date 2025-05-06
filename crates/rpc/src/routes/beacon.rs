use actix_web::web::ServiceConfig;

use crate::handlers::{
    block::{
        get_attestations_rewards_from_epoch, get_block_attestations, get_block_from_id,
        get_block_rewards, get_block_root, get_genesis,
    },
    header::get_headers,
    state::{
        get_pending_partial_withdrawals, get_state_finality_checkpoint, get_state_fork,
        get_state_randao, get_state_root,
    },
    validator::{
        get_validator_from_state, get_validators_from_state, post_validator_identities_from_state,
        post_validators_from_state,
    },
};

/// Creates and returns all `/beacon` routes.
pub fn register_beacon_routes(cfg: &mut ServiceConfig) {
    cfg.service(get_state_root)
        .service(get_state_fork)
        .service(get_state_finality_checkpoint)
        .service(get_state_randao)
        .service(get_validator_from_state)
        .service(get_validators_from_state)
        .service(post_validators_from_state)
        .service(post_validator_identities_from_state)
        .service(get_genesis)
        .service(get_headers)
        .service(get_block_root)
        .service(get_block_rewards)
        .service(get_pending_partial_withdrawals)
        .service(get_attestations_rewards_from_epoch);
}
pub fn register_beacon_routes_v2(cfg: &mut ServiceConfig) {
    cfg.service(get_block_attestations)
        .service(get_block_from_id);
}
