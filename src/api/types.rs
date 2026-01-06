use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde_json::json;
use utoipa::ToSchema;

use crate::types::{ElfType, ProofType, ProverType};

#[derive(Debug, Deserialize, ToSchema)]
/// Request data for submitting an asynchronous proof request
pub struct AsyncProofRequestData {
    /// Prover backend type
    #[schema(example = json!("boundless"))]
    pub prover_type: ProverType,
    /// Binary input data as array of bytes
    #[schema(example = json!([1, 2, 3, 4, 5]))]
    pub input: Vec<u8>,
    /// Expected output bytes
    #[schema(example = json!([1, 2, 3, 4, 5]))]
    pub output: Vec<u8>,
    /// Type of proof to generate
    #[schema(example = json!("Batch"))]
    pub proof_type: ProofType,
    /// Optional ELF binary data for Update proof type
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = json!(null))]
    pub elf: Option<Vec<u8>>,
    /// Additional prover configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = json!({"max_cycles": 1000000}))]
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
/// Response for an asynchronous proof request submission
pub struct AsyncProofResponse {
    /// Unique identifier for tracking this request
    #[schema(example = "req_abc123def456")]
    pub request_id: String,
    /// Prover backend type
    #[schema(example = "boundless")]
    pub prover_type: ProverType,
    /// Provider-specific request identifier
    #[schema(example = json!("0x1234abcd"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_request_id: Option<String>,
    /// Current request status
    #[schema(example = "preparing")]
    pub status: String,
    /// Human-readable status description
    #[schema(example = "Proof request received and preparing for submission")]
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
/// Detailed status response for a proof request
pub struct DetailedStatusResponse {
    /// The original request identifier
    #[schema(example = "req_abc123def456")]
    pub request_id: String,
    /// Prover backend type
    #[schema(example = "boundless")]
    pub prover_type: ProverType,
    /// Provider-specific request identifier
    #[schema(example = json!("0x1234abcd"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_request_id: Option<String>,
    /// Current status
    #[schema(example = "in_progress")]
    pub status: String,
    /// Detailed human-readable status description
    #[schema(example = "A prover has accepted the request and is generating the proof")]
    pub status_message: String,
    /// Binary proof data when completed, null otherwise
    #[schema(example = json!(null))]
    pub proof_data: Option<Vec<u8>>,
    /// Error message if status is "failed"
    #[schema(example = json!(null))]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
/// Response containing a list of active requests
pub struct RequestListResponse {
    /// Number of active requests
    #[schema(example = 3)]
    pub active_requests: usize,
    /// List of detailed request statuses
    pub requests: Vec<DetailedStatusResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
/// Service health response
pub struct HealthResponse {
    /// Health status
    #[schema(example = "healthy")]
    pub status: String,
    /// Service name
    #[schema(example = "raiko-agent")]
    pub service: String,
}

#[derive(Debug, Serialize, ToSchema)]
/// Database statistics for monitoring
pub struct DatabaseStatsResponse {
    /// Database statistics
    pub database_stats: crate::DatabaseStats,
}

#[derive(Debug, Serialize, ToSchema)]
/// Response for delete all requests operation
pub struct DeleteAllResponse {
    /// Success message
    #[schema(example = "Successfully deleted 1247 requests")]
    pub message: String,
    /// Number of deleted requests
    #[schema(example = 1247)]
    pub deleted_count: usize,
}

#[derive(Debug, Serialize, ToSchema)]
/// Standard error response
pub struct ErrorResponse {
    /// Error type or code
    #[schema(example = "ValidationError")]
    pub error: String,
    /// Detailed error message
    #[schema(example = "Invalid request format")]
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
/// Response when uploading an ELF image
pub struct UploadImageResponse {
    /// Prover backend type
    #[schema(example = "boundless")]
    pub prover_type: ProverType,
    /// ELF type
    pub elf_type: ElfType,
    /// Image ID computed from the ELF (8 u32 values) if provided by the backend
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = json!([3537337764u32, 1055695413u32, 664197713u32, 1225410428u32, 3705161813u32, 2151977348u32, 4164639052u32, 2614443474u32]))]
    pub image_id: Option<Vec<u32>>,
    /// URL where the image is stored by the provider
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "https://storage.boundless.network/programs/abc123")]
    pub provider_url: Option<String>,
    /// Status of the upload
    #[schema(example = "uploaded")]
    pub status: String, // "uploaded" or "already_exists"
    /// Detailed message
    #[schema(example = "Image uploaded successfully")]
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
/// Information about an image's existence
pub struct ImageCheckResponse {
    /// Whether the image exists in the agent
    pub exists: bool,
    /// Image ID if it exists
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_id: Option<Vec<u32>>,
    /// Provider URL if it exists
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_url: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
/// Images available for a prover
pub struct ProverImages {
    pub prover_type: ProverType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch: Option<crate::image_manager::ImageDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregation: Option<crate::image_manager::ImageDetails>,
}

#[derive(Debug, Serialize, ToSchema)]
/// Response containing information about uploaded images
pub struct ImageInfoResponse {
    pub provers: Vec<ProverImages>,
}
