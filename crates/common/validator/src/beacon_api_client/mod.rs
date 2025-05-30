pub mod http_client;

use std::time::Duration;

use anyhow;
use http_client::{ClientWithBaseUrl, ContentType};
use ream_rpc::{handlers::duties::ProposerDuty, types::response::DutiesResponse};
use reqwest::{StatusCode, Url};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BeaconApiError {
    #[error("API request failed with status code: {status_code}")]
    RequestFailed { status_code: StatusCode },
    #[error("SSZ decode error: {0}")]
    SszDecode(String),
    #[error("JSON decode error: {0}")]
    JsonDecode(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub struct BeaconApiClient {
    pub http_client: ClientWithBaseUrl,
}

impl BeaconApiClient {
    pub fn new(beacon_api_endpoint: Url, request_timeout: Duration) -> anyhow::Result<Self> {
        Ok(Self {
            http_client: ClientWithBaseUrl::new(
                beacon_api_endpoint,
                request_timeout,
                ContentType::Ssz,
            )?,
        })
    }

    pub async fn get_proposer_duties(
        &self,
        epoch: u64,
    ) -> Result<DutiesResponse<ProposerDuty>, BeaconApiError> {
        let response = self.http_client.execute(self
            .http_client
            .get(format!("eth/v1/validator/duties/proposer/{epoch}"))?
            .build()?).await?;

        if !response.status().is_success() {
            return Err(BeaconApiError::RequestFailed {
                status_code: response.status(),
            });
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|content_type| content_type.to_str().ok());

        let proposer_duties: DutiesResponse<ProposerDuty> =
            if content_type.contains("application/octet-stream") {
                DutiesResponse::from_ssz_bytes(&response.bytes().await?)
                    .map_err(|err| BeaconApiError::SszDecode(err.to_string()))?
            } else {
                response.json().await
                    .map_err(|err| BeaconApiError::JsonDecode(err.to_string()))?
            };

        Ok(proposer_duties)
    }
}
