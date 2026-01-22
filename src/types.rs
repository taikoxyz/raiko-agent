use alloy_primitives_v1p2p0::{hex, keccak256};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProverType {
    Boundless,
    Zisk,
    #[serde(alias = "brevis", alias = "pico")]
    BrevisPico,
}

impl ProverType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProverType::Boundless => "boundless",
            ProverType::Zisk => "zisk",
            ProverType::BrevisPico => "brevis_pico",
        }
    }
}

impl fmt::Display for ProverType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProverType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "boundless" => Ok(ProverType::Boundless),
            "zisk" => Ok(ProverType::Zisk),
            "brevis_pico" | "brevis" | "pico" => Ok(ProverType::BrevisPico),
            _ => Err(format!(
                "Invalid prover type: '{}'. Must be 'boundless', 'zisk', or 'brevis_pico'",
                s
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ToSchema)]
pub enum ElfType {
    Batch,
    Aggregation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, ToSchema)]
/// Type of proof to generate
pub enum ProofType {
    /// Generate a batch proof
    Batch,
    /// Aggregate multiple existing proofs
    Aggregate,
    /// Update ELF binary
    Update(ElfType),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofRequestStatus {
    Preparing,
    Submitted {
        provider_request_id: String,
        /// Unix timestamp (seconds) when the market request expires (if known)
        expires_at: Option<u64>,
    },
    Locked {
        provider_request_id: String,
        prover: Option<String>,
        /// Unix timestamp (seconds) when the market request expires (if known)
        expires_at: Option<u64>,
    },
    Fulfilled {
        provider_request_id: String,
        proof: Vec<u8>,
    },
    Failed {
        error: String,
    },
}

/// Async proof request tracking
#[derive(Debug, Clone, Serialize)]
pub struct AsyncProofRequest {
    pub request_id: String,
    pub prover_type: ProverType,
    pub provider_request_id: Option<String>,
    pub status: ProofRequestStatus,
    pub proof_type: ProofType,
    pub input: Vec<u8>,
    pub config: serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("Failed to build client: {0}")]
    ClientBuildError(String),
    #[error("Failed to encode guest environment: {0}")]
    GuestEnvEncodeError(String),
    #[error("Failed to upload input: {0}")]
    UploadError(String),
    #[error("Failed to upload program: {0}")]
    ProgramUploadError(String),
    #[error("Failed to build request: {0}")]
    RequestBuildError(String),
    #[error("Failed to submit request: {0}")]
    RequestSubmitError(String),
    #[error("Failed to wait for request fulfillment after {attempts} attempts: {error}")]
    RequestFulfillmentError { attempts: u32, error: String },
    #[error("Failed to encode response: {0}")]
    ResponseEncodeError(String),
    #[error("Failed to execute guest environment: {0}")]
    GuestExecutionError(String),
    #[error("Did not receive requested unaggregated receipt")]
    InvalidReceiptError,
    #[error("Missing journal in fulfillment data")]
    MissingJournalError,
    #[error("Failed to decode fulfillment data: {0}")]
    FulfillmentDecodeError(String),
    #[error("Storage provider is required")]
    StorageProviderRequired,
    #[error("Prover not configured: {0}")]
    ProverUnavailable(String),
    #[error("Prover not implemented: {0}")]
    NotImplemented(String),
}

pub type AgentResult<T> = Result<T, AgentError>;

/// Generate deterministic request ID from input, proof type, and prover type
pub fn generate_request_id(input: &[u8], proof_type: &ProofType, prover_type: &ProverType) -> String {
    let input_hash = keccak256(input);
    let proof_type_str = match proof_type {
        ProofType::Batch => "batch",
        ProofType::Aggregate => "aggregate",
        ProofType::Update(_) => "update",
    };
    format!("{}_{}_{}", hex::encode(input_hash), prover_type.as_str(), proof_type_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_prover_type_from_str_and_display() {
        assert_eq!(ProverType::from_str("boundless").unwrap(), ProverType::Boundless);
        assert_eq!(ProverType::from_str("zisk").unwrap(), ProverType::Zisk);
        assert_eq!(ProverType::from_str("brevis_pico").unwrap(), ProverType::BrevisPico);

        assert_eq!(ProverType::from_str("Brevis").unwrap(), ProverType::BrevisPico);
        assert_eq!(ProverType::from_str("PICO").unwrap(), ProverType::BrevisPico);

        assert_eq!(ProverType::Boundless.to_string(), "boundless");
        assert_eq!(ProverType::Zisk.to_string(), "zisk");
        assert_eq!(ProverType::BrevisPico.to_string(), "brevis_pico");

        let err = ProverType::from_str("nope").unwrap_err();
        assert!(err.contains("Invalid prover type"));
    }

    #[test]
    fn test_generate_request_id_is_stable_and_varies_by_inputs() {
        let input = b"hello";
        let prover = ProverType::Boundless;

        let batch = generate_request_id(input, &ProofType::Batch, &prover);
        let batch_again = generate_request_id(input, &ProofType::Batch, &prover);
        assert_eq!(batch, batch_again);

        let aggregate = generate_request_id(input, &ProofType::Aggregate, &prover);
        assert_ne!(batch, aggregate);

        let other_input = generate_request_id(b"world", &ProofType::Batch, &prover);
        assert_ne!(batch, other_input);

        let other_prover = generate_request_id(input, &ProofType::Batch, &ProverType::Zisk);
        assert_ne!(batch, other_prover);

        let update = generate_request_id(input, &ProofType::Update(ElfType::Batch), &prover);
        assert_ne!(batch, update);

        let parts: Vec<&str> = batch.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 64);
        assert_eq!(parts[1], "boundless");
        assert_eq!(parts[2], "batch");
    }
}
