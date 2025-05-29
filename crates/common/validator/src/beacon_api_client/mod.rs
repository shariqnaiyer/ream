pub mod http_client;

use std::time::Duration;

use anyhow;
use http_client::{ClientWithBaseUrl, ContentType};
use ream_rpc::{handlers::duties::ProposerDuty, types::response::DutiesResponse};
use reqwest::Url;

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
    ) -> anyhow::Result<DutiesResponse<ProposerDuty>> {
        let request = self
            .http_client
            .get(format!("eth/v1/validator/duties/proposer/{epoch}"))?
            .build()?;
        let response = self.http_client.execute(request).await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "API request failed with status: {}",
                response.status()
            ));
        }

        let proposer_duties: DutiesResponse<ProposerDuty> = response.json().await?;
        Ok(proposer_duties)
    }
}
