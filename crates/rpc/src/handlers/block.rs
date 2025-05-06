use std::collections::BTreeSet;

use actix_web::{
    HttpResponse, Responder, get, post,
    web::{Data, Json, Path},
};
use alloy_primitives::B256;
use ream_consensus::{
    attester_slashing::AttesterSlashing,
    constants::{
        EFFECTIVE_BALANCE_INCREMENT, INACTIVITY_PENALTY_QUOTIENT_BELLATRIX, INACTIVITY_SCORE_BIAS,
        MIN_ATTESTATION_INCLUSION_DELAY, PROPOSER_WEIGHT, SLOTS_PER_EPOCH, SYNC_COMMITTEE_SIZE,
        SYNC_REWARD_WEIGHT, TIMELY_HEAD_FLAG_INDEX, TIMELY_HEAD_WEIGHT, TIMELY_SOURCE_FLAG_INDEX,
        TIMELY_SOURCE_WEIGHT, TIMELY_TARGET_FLAG_INDEX, TIMELY_TARGET_WEIGHT, WEIGHT_DENOMINATOR,
        WHISTLEBLOWER_REWARD_QUOTIENT,
    },
    deneb::{beacon_block::SignedBeaconBlock, beacon_state::BeaconState},
    misc::compute_start_slot_at_epoch,
};
use ream_network_spec::networks::NetworkSpec;
use ream_storage::{
    db::ReamDB,
    tables::{Field, Table},
};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{
    handlers::state::get_state_from_id,
    types::{
        errors::ApiError,
        id::{ID, ValidatorID},
        response::{BeaconResponse, BeaconVersionedResponse, DataResponse, RootResponse},
    },
};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct BlockRewards {
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub total: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub attestations: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub sync_aggregate: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_slashings: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub attester_slashings: u64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct TotalReward {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub head: u64,
    #[serde(with = "serde_utils::quoted_i64")]
    pub target: i64,
    #[serde(with = "serde_utils::quoted_i64")]
    pub source: i64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub inclusion_delay: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub inactivity: u64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct IdealReward {
    #[serde(with = "serde_utils::quoted_u64")]
    pub effective_balance: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub head: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub target: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub source: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub inclusion_delay: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub inactivity: u64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AttestationRewards {
    pub ideal_rewards: Vec<IdealReward>,
    pub total_rewards: Vec<TotalReward>,
}

pub async fn get_block_root_from_id(block_id: ID, db: &ReamDB) -> Result<B256, ApiError> {
    let block_root = match block_id {
        ID::Finalized => {
            let finalized_checkpoint = db
                .finalized_checkpoint_provider()
                .get()
                .map_err(|err| {
                    error!("Failed to get block by block_root, error: {err:?}");
                    ApiError::InternalError
                })?
                .ok_or_else(|| ApiError::NotFound("Finalized checkpoint not found".to_string()))?;

            Ok(Some(finalized_checkpoint.root))
        }
        ID::Justified => {
            let justified_checkpoint = db
                .justified_checkpoint_provider()
                .get()
                .map_err(|err| {
                    error!("Failed to get block by block_root, error: {err:?}");
                    ApiError::InternalError
                })?
                .ok_or_else(|| ApiError::NotFound("Justified checkpoint not found".to_string()))?;

            Ok(Some(justified_checkpoint.root))
        }
        ID::Head | ID::Genesis => {
            return Err(ApiError::NotFound(format!(
                "This ID type is currently not supported: {block_id:?}"
            )));
        }
        ID::Slot(slot) => db.slot_index_provider().get(slot),
        ID::Root(root) => Ok(Some(root)),
    }
    .map_err(|err| {
        error!("Failed to get block by block_root, error: {err:?}");
        ApiError::InternalError
    })?
    .ok_or_else(|| ApiError::NotFound(format!("Failed to find `block_root` from {block_id:?}")))?;

    Ok(block_root)
}

async fn get_beacon_state(block_id: ID, db: &ReamDB) -> Result<BeaconState, ApiError> {
    let block_root = get_block_root_from_id(block_id, db).await?;

    db.beacon_state_provider()
        .get(block_root)
        .map_err(|_| ApiError::InternalError)?
        .ok_or(ApiError::NotFound(format!(
            "Failed to find `beacon_state` from {block_root:?}"
        )))
}

fn get_attestations_rewards(beacon_state: &BeaconState, beacon_block: &SignedBeaconBlock) -> u64 {
    let mut attester_reward = 0;
    let attestations = &beacon_block.message.body.attestations;
    for attestation in attestations {
        if let Ok(attesting_indices) = beacon_state.get_attesting_indices(attestation) {
            for index in attesting_indices {
                attester_reward += beacon_state.get_proposer_reward(index);
            }
        }
    }
    attester_reward
}

fn get_sync_committee_rewards(beacon_state: &BeaconState, beacon_block: &SignedBeaconBlock) -> u64 {
    let total_active_balance = beacon_state.get_total_active_balance();
    let total_active_increments = total_active_balance / EFFECTIVE_BALANCE_INCREMENT;
    let total_base_rewards = beacon_state.get_base_reward_per_increment() * total_active_increments;
    let max_participant_rewards =
        total_base_rewards * SYNC_REWARD_WEIGHT / WEIGHT_DENOMINATOR / SLOTS_PER_EPOCH;
    let participant_reward = max_participant_rewards / SYNC_COMMITTEE_SIZE;
    let proposer_reward =
        participant_reward * PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT);

    beacon_block
        .message
        .body
        .sync_aggregate
        .sync_committee_bits
        .num_set_bits() as u64
        * proposer_reward
}

fn get_slashable_attester_indices(
    beacon_state: &BeaconState,
    attester_shashing: &AttesterSlashing,
) -> Vec<u64> {
    let attestation_1 = &attester_shashing.attestation_1;
    let attestation_2 = &attester_shashing.attestation_2;

    let attestation_indices_1 = attestation_1
        .attesting_indices
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let attestation_indices_2 = attestation_2
        .attesting_indices
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut slashing_indices = vec![];

    for index in &attestation_indices_1 & &attestation_indices_2 {
        let validator = &beacon_state.validators[index as usize];
        let current_epoch = beacon_state.get_current_epoch();
        if validator.is_slashable_validator(current_epoch) {
            slashing_indices.push(index);
        }
    }

    slashing_indices
}

fn get_proposer_slashing_rewards(
    beacon_state: &BeaconState,
    beacon_block: &SignedBeaconBlock,
) -> u64 {
    let mut proposer_slashing_reward = 0;
    let proposer_slashings = &beacon_block.message.body.proposer_slashings;
    for proposer_slashing in proposer_slashings {
        let index = proposer_slashing.signed_header_1.message.proposer_index;
        let reward = beacon_state.validators[index as usize].effective_balance;
        proposer_slashing_reward += reward;
    }
    proposer_slashing_reward
}

fn get_attester_slashing_rewards(
    beacon_state: &BeaconState,
    beacon_block: &SignedBeaconBlock,
) -> u64 {
    let mut attester_slashing_reward = 0;
    let attester_shashings = &beacon_block.message.body.attester_slashings;
    for attester_shashing in attester_shashings {
        for index in get_slashable_attester_indices(beacon_state, attester_shashing) {
            let reward = beacon_state.validators[index as usize].effective_balance
                / WHISTLEBLOWER_REWARD_QUOTIENT;
            attester_slashing_reward += reward;
        }
    }

    attester_slashing_reward
}

pub async fn get_beacon_block_from_id(
    block_id: ID,
    db: &ReamDB,
) -> Result<SignedBeaconBlock, ApiError> {
    let block_root = get_block_root_from_id(block_id, db).await?;

    db.beacon_block_provider()
        .get(block_root)
        .map_err(|err| {
            error!("Failed to get block by block_root, error: {err:?}");
            ApiError::InternalError
        })?
        .ok_or_else(|| {
            ApiError::NotFound(format!("Failed to find `beacon block` from {block_root:?}"))
        })
}

/// Called by `/genesis` to get the Genesis Config of Beacon Chain.
#[get("/beacon/genesis")]
pub async fn get_genesis(network_spec: Data<NetworkSpec>) -> Result<impl Responder, ApiError> {
    Ok(HttpResponse::Ok().json(DataResponse::new(network_spec.genesis.clone())))
}

/// Called by `/eth/v2/beacon/blocks/{block_id}/attestations` to get block attestations
#[get("/beacon/blocks/{block_id}/attestations")]
pub async fn get_block_attestations(
    db: Data<ReamDB>,
    block_id: Path<ID>,
) -> Result<impl Responder, ApiError> {
    let beacon_block = get_beacon_block_from_id(block_id.into_inner(), &db).await?;

    Ok(HttpResponse::Ok().json(BeaconVersionedResponse::new(
        beacon_block.message.body.attestations,
    )))
}

/// Called by `/blocks/<block_id>/root` to get the Tree hash of the Block.
#[get("/beacon/blocks/{block_id}/root")]
pub async fn get_block_root(
    db: Data<ReamDB>,
    block_id: Path<ID>,
) -> Result<impl Responder, ApiError> {
    let block_root = get_block_root_from_id(block_id.into_inner(), &db).await?;

    Ok(HttpResponse::Ok().json(BeaconResponse::new(RootResponse::new(block_root))))
}

/// Called by `/beacon/blocks/{block_id}/rewards` to get the block rewards response
#[get("/beacon/blocks/{block_id}/rewards")]
pub async fn get_block_rewards(
    db: Data<ReamDB>,
    block_id: Path<ID>,
) -> Result<impl Responder, ApiError> {
    let block_id_value = block_id.into_inner();
    let beacon_block = get_beacon_block_from_id(block_id_value.clone(), &db).await?;
    let beacon_state = get_beacon_state(block_id_value.clone(), &db).await?;

    let attestation_reward = get_attestations_rewards(&beacon_state, &beacon_block);
    let attester_slashing_reward = get_attester_slashing_rewards(&beacon_state, &beacon_block);
    let proposer_slashing_reward = get_proposer_slashing_rewards(&beacon_state, &beacon_block);
    let sync_committee_reward = get_sync_committee_rewards(&beacon_state, &beacon_block);

    let total = attestation_reward
        + sync_committee_reward
        + proposer_slashing_reward
        + attester_slashing_reward;

    let response = BlockRewards {
        proposer_index: beacon_block.message.proposer_index,
        total,
        attestations: attestation_reward,
        sync_aggregate: sync_committee_reward,
        proposer_slashings: proposer_slashing_reward,
        attester_slashings: attester_slashing_reward,
    };

    Ok(HttpResponse::Ok().json(BeaconResponse::new(response)))
}

/// Called by `/blocks/<block_id>` to get the Beacon Block.
#[get("/beacon/blocks/{block_id}")]
pub async fn get_block_from_id(
    db: Data<ReamDB>,
    block_id: Path<ID>,
) -> Result<impl Responder, ApiError> {
    let beacon_block = get_beacon_block_from_id(block_id.into_inner(), &db).await?;

    Ok(HttpResponse::Ok().json(BeaconVersionedResponse::new(beacon_block)))
}

#[post("/beacon/rewards/attestations/{epoch}")]
pub async fn get_attestations_rewards_from_epoch(
    db: Data<ReamDB>,
    epoch: Path<u64>,
    validator_ids: Option<Json<Vec<ValidatorID>>>,
) -> Result<impl Responder, ApiError> {
    let epoch_value = epoch.into_inner();

    let state = get_state_from_id(ID::Slot(compute_start_slot_at_epoch(epoch_value)), &db).await?;

    let mut validator_indices_to_process = Vec::new();

    // Source: src/handlers/validator.rs
    if let Some(ids) = validator_ids {
        for validator_id in ids.iter() {
            let index = match validator_id {
                ValidatorID::Index(i) => {
                    if *i as usize >= state.validators.len() {
                        return Err(ApiError::NotFound(format!(
                            "Validator not found for index: {i}"
                        )));
                    }
                    *i as usize
                }
                ValidatorID::Address(pubkey) => {
                    match state
                        .validators
                        .iter()
                        .enumerate()
                        .find(|(_, v)| v.pubkey == *pubkey)
                    {
                        Some((i, _)) => i,
                        None => {
                            return Err(ApiError::NotFound(format!(
                                "Validator not found for pubkey: {pubkey:?}"
                            )));
                        }
                    }
                }
            };
            validator_indices_to_process.push(index);
        }
    } else {
        validator_indices_to_process = (0..state.validators.len()).collect();
    }

    let mut ideal_rewards = Vec::new();
    let mut total_rewards = Vec::new();

    for validator_index in validator_indices_to_process {
        let validator = &state.validators[validator_index as usize];
        let base_reward = state.get_base_reward(validator_index as u64);

        let source_reward = base_reward * TIMELY_SOURCE_WEIGHT / WEIGHT_DENOMINATOR;
        let target_reward = base_reward * TIMELY_TARGET_WEIGHT / WEIGHT_DENOMINATOR;
        let head_reward = base_reward * TIMELY_HEAD_WEIGHT / WEIGHT_DENOMINATOR;
        let inclusion_delay_reward = base_reward / MIN_ATTESTATION_INCLUSION_DELAY;

        let inactivity_penalty = if state.is_in_inactivity_leak() {
            let score = state.inactivity_scores[validator_index as usize];
            validator.effective_balance * score
                / (INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT_BELLATRIX)
        } else {
            0
        };

        ideal_rewards.push(IdealReward {
            effective_balance: validator.effective_balance,
            head: head_reward,
            target: target_reward,
            source: source_reward,
            inclusion_delay: inclusion_delay_reward,
            inactivity: inactivity_penalty,
        });

        let mut actual_head_reward = 0;
        let actual_target_reward;
        let actual_source_reward;
        let mut actual_inclusion_delay_reward = 0;
        let mut actual_inactivity_penalty = 0;

        let head_indices = state
            .get_unslashed_participating_indices(TIMELY_HEAD_FLAG_INDEX, epoch_value)
            .map_err(|_| ApiError::InternalError)?;

        let target_indices = state
            .get_unslashed_participating_indices(TIMELY_TARGET_FLAG_INDEX, epoch_value)
            .map_err(|_| ApiError::InternalError)?;

        let source_indices = state
            .get_unslashed_participating_indices(TIMELY_SOURCE_FLAG_INDEX, epoch_value)
            .map_err(|_| ApiError::InternalError)?;

        let base_reward = state.get_base_reward(validator_index as u64);

        if head_indices.contains(&(validator_index as u64)) {
            let head_reward = base_reward * TIMELY_HEAD_WEIGHT / WEIGHT_DENOMINATOR;
            actual_head_reward = head_reward;
        }

        if target_indices.contains(&(validator_index as u64)) {
            let target_reward = base_reward * TIMELY_TARGET_WEIGHT / WEIGHT_DENOMINATOR;
            actual_target_reward = target_reward as i64;
        } else {
            actual_target_reward =
                -((base_reward * TIMELY_TARGET_WEIGHT / WEIGHT_DENOMINATOR) as i64);
        }

        if source_indices.contains(&(validator_index as u64)) {
            let source_reward = base_reward * TIMELY_SOURCE_WEIGHT / WEIGHT_DENOMINATOR;
            actual_source_reward = source_reward as i64;
        } else {
            actual_source_reward =
                -((base_reward * TIMELY_SOURCE_WEIGHT / WEIGHT_DENOMINATOR) as i64);
        }

        if source_indices.contains(&(validator_index as u64)) {
            actual_inclusion_delay_reward = base_reward / MIN_ATTESTATION_INCLUSION_DELAY;
        }

        if state.is_in_inactivity_leak() {
            let score = state.inactivity_scores[validator_index as usize];
            let validator = &state.validators[validator_index as usize];
            actual_inactivity_penalty = validator.effective_balance * score
                / (INACTIVITY_SCORE_BIAS * INACTIVITY_PENALTY_QUOTIENT_BELLATRIX);
        }

        total_rewards.push(TotalReward {
            validator_index: validator_index as u64,
            head: actual_head_reward,
            target: actual_target_reward,
            source: actual_source_reward,
            inclusion_delay: actual_inclusion_delay_reward,
            inactivity: actual_inactivity_penalty,
        });
    }

    let response = AttestationRewards {
        ideal_rewards,
        total_rewards,
    };
    Ok(HttpResponse::Ok().json(BeaconResponse::new(response)))
}
