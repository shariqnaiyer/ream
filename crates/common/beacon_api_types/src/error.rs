use reqwest::StatusCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BeaconApiClientError {
    #[error("Request failed with status code: {status_code}")]
    RequestFailed { status_code: StatusCode },

    #[error("Failed to decode SSZ response: {0}")]
    SszDecode(String),

    #[error("Failed to decode JSON response: {0}")]
    JsonDecode(String),

    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    #[error("URL parsing error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Invalid content type: expected application/octet-stream or application/json")]
    InvalidContentType,

    #[error("Network timeout")]
    Timeout,

    #[error("Invalid response format")]
    InvalidResponse,

    #[error("Anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
}
