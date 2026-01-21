use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
};
use std::net::SocketAddr;
use std::str::FromStr;
use utoipa;

use super::types::{
    AsyncProofRequestData, AsyncProofResponse, DatabaseStatsResponse, DeleteAllResponse,
    DetailedStatusResponse, ErrorResponse, HealthResponse, ImageInfoResponse, ProverImages,
    RequestListResponse, UploadImageResponse,
};
use crate::{
    AppState,
    types::{
        AgentError, AsyncProofRequest, ElfType, ProofRequestStatus, ProofType, ProverType,
        generate_request_id,
    },
};

/// Convert internal ProofRequestStatus to user-friendly API response
fn map_status_to_api_response(request: &AsyncProofRequest) -> DetailedStatusResponse {
    let (status, status_message, proof_data, error) = match &request.status {
        ProofRequestStatus::Preparing => (
            "preparing".to_string(),
            "Request received. Executing guest program and preparing for submission..."
                .to_string(),
            None,
            None,
        ),
        ProofRequestStatus::Submitted { .. } => (
            "submitted".to_string(),
            "The proof request has been submitted and is waiting for an available prover to pick it up."
                .to_string(),
            None,
            None,
        ),
        ProofRequestStatus::Locked { .. } => (
            "in_progress".to_string(),
            "A prover has accepted the request and is generating the proof".to_string(),
            None,
            None,
        ),
        ProofRequestStatus::Fulfilled { proof, .. } => (
            "completed".to_string(),
            "The proof has been successfully generated and is ready for download.".to_string(),
            Some(proof.clone()),
            None,
        ),
        ProofRequestStatus::Failed { error } => (
            "failed".to_string(),
            format!("Proof generation failed: {}", error),
            None,
            Some(error.clone()),
        ),
    };

    let provider_request_id = match &request.status {
        ProofRequestStatus::Submitted { provider_request_id, .. }
        | ProofRequestStatus::Locked {
            provider_request_id, ..
        }
        | ProofRequestStatus::Fulfilled {
            provider_request_id, ..
        } => Some(provider_request_id.clone()),
        _ => request.provider_request_id.clone(),
    };

    DetailedStatusResponse {
        request_id: request.request_id.clone(),
        prover_type: request.prover_type.clone(),
        provider_request_id,
        status,
        status_message,
        proof_data,
        error,
    }
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse,
         example = json!({
             "status": "healthy",
             "service": "raiko-agent"
         }))
    )
)]
/// Health check endpoint
pub async fn health_check() -> (StatusCode, Json<HealthResponse>) {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "healthy".to_string(),
            service: "raiko-agent".to_string(),
        }),
    )
}

#[utoipa::path(
    post,
    path = "/proof",
    tag = "Proof",
    request_body = AsyncProofRequestData,
    responses(
        (status = 202, description = "Proof request accepted", body = AsyncProofResponse,
         example = json!({
             "request_id": "req_abc123def456",
             "prover_type": "boundless",
             "provider_request_id": null,
             "status": "preparing",
             "message": "Proof request received and preparing for submission"
         })),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
/// Submit an asynchronous proof generation request
pub async fn proof_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<AsyncProofRequestData>,
) -> Result<(StatusCode, Json<AsyncProofResponse>), (StatusCode, Json<ErrorResponse>)> {
    let AsyncProofRequestData {
        prover_type,
        input,
        output,
        proof_type,
        elf,
        config,
    } = request;

    if !state.rate_limiter.check(addr.ip()).await {
        tracing::warn!("Rate limit exceeded for IP: {}", addr.ip());
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "RateLimitExceeded".to_string(),
                message: "Too many requests. Please try again later.".to_string(),
            }),
        ));
    }

    if input.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "ValidationError".to_string(),
                message: "Input data cannot be empty".to_string(),
            }),
        ));
    }

    if let ProofType::Update(_) = &proof_type {
        match &elf {
            None => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "ValidationError".to_string(),
                        message: "ELF data is required for Update proof type".to_string(),
                    }),
                ));
            }
            Some(elf_data) if elf_data.is_empty() => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "ValidationError".to_string(),
                        message: "ELF data cannot be empty for Update proof type".to_string(),
                    }),
                ));
            }
            _ => {}
        }
    }

    let request_id = generate_request_id(&input, &proof_type, &prover_type);

    tracing::info!(
        "Received proof submission: {} (size: {} bytes, prover: {})",
        request_id,
        input.len(),
        prover_type
    );

    let config = config.unwrap_or_else(|| serde_json::Value::default());

    let result = state
        .registry
        .submit_proof(
            prover_type.clone(),
            request_id.clone(),
            proof_type,
            input,
            output,
            config,
            elf,
        )
        .await;

    match result {
        Ok(returned_request_id) => {
            tracing::info!(
                "Proof request received and preparing: {}",
                returned_request_id
            );
            Ok((
                StatusCode::ACCEPTED,
                Json(AsyncProofResponse {
                    request_id: returned_request_id,
                    prover_type,
                    provider_request_id: None,
                    status: "preparing".to_string(),
                    message: "Proof request received and preparing for submission".to_string(),
                }),
            ))
        }
        Err(e) => {
            let (status, error_code, message) = match e {
                AgentError::ProverUnavailable(_) => (
                    StatusCode::BAD_REQUEST,
                    "ProverUnavailable",
                    "Selected prover is not available".to_string(),
                ),
                AgentError::NotImplemented(_) => (
                    StatusCode::NOT_IMPLEMENTED,
                    "ProverNotImplemented",
                    "Selected prover is not implemented yet".to_string(),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ProofSubmissionError",
                    "Failed to submit proof request".to_string(),
                ),
            };

            tracing::error!("Failed to submit proof: {}", e);
            Err((
                status,
                Json(ErrorResponse {
                    error: error_code.to_string(),
                    message,
                }),
            ))
        }
    }
}

#[utoipa::path(
    get,
    path = "/status/{request_id}",
    tag = "Status",
    params(
        ("request_id" = String, Path, description = "Unique request identifier")
    ),
    responses(
        (status = 200, description = "Request status retrieved", body = DetailedStatusResponse,
         example = json!({
             "request_id": "req_abc123def456",
             "prover_type": "boundless",
             "provider_request_id": "0x1234abcd",
             "status": "in_progress",
             "status_message": "A prover has accepted the request and is generating the proof",
             "proof_data": null,
             "error": null
         })),
        (status = 404, description = "Request not found", body = ErrorResponse,
         example = json!({
             "error": "RequestNotFound",
             "message": "No proof request found with the specified request_id"
         })),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
/// Get the current status of a proof request
pub async fn get_async_proof_status(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(request_id): Path<String>,
) -> Result<Json<DetailedStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !state.rate_limiter.check(addr.ip()).await {
        tracing::warn!("Rate limit exceeded for IP: {} on status query", addr.ip());
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "RateLimitExceeded".to_string(),
                message: "Too many status queries. Please try again later.".to_string(),
            }),
        ));
    }

    match state.storage.get_request(&request_id).await {
        Ok(Some(request)) => {
            let detailed_response = map_status_to_api_response(&request);
            Ok(Json(detailed_response))
        }
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "RequestNotFound".to_string(),
                message: "No proof request found with the specified request_id".to_string(),
            }),
        )),
        Err(_e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "DatabaseError".to_string(),
                message: "Failed to retrieve request status".to_string(),
            }),
        )),
    }
}

#[utoipa::path(
    get,
    path = "/requests",
    tag = "Status",
    responses(
        (status = 200, description = "List of active requests", body = RequestListResponse,
         example = json!({
             "active_requests": 2,
             "requests": [
                 {
                     "request_id": "req_abc123def456",
                     "prover_type": "boundless",
                     "provider_request_id": "0x1234abcd",
                     "status": "in_progress",
                     "status_message": "A prover has accepted the request and is generating the proof",
                     "proof_data": null,
                     "error": null
                 }
             ]
         })),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
/// List all active proof requests
pub async fn list_async_requests(
    State(state): State<AppState>,
) -> Result<Json<RequestListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let requests = match state.storage.list_active_requests().await {
        Ok(requests) => requests,
        Err(_e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "DatabaseError".to_string(),
                    message: "Failed to list requests".to_string(),
                }),
            ));
        }
    };

    let detailed_requests: Vec<DetailedStatusResponse> = requests
        .iter()
        .map(|req| map_status_to_api_response(req))
        .collect();

    Ok(Json(RequestListResponse {
        active_requests: requests.len(),
        requests: detailed_requests,
    }))
}

#[utoipa::path(
    get,
    path = "/stats",
    tag = "Maintenance",
    responses(
        (status = 200, description = "Database statistics", body = DatabaseStatsResponse,
         example = json!({
             "database_stats": {
                 "total_requests": 1247,
                 "active_requests": 3,
                 "completed_requests": 1200,
                 "failed_requests": 44
             }
         })),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
/// Get database statistics for monitoring
pub async fn get_database_stats(
    State(state): State<AppState>,
) -> Result<Json<DatabaseStatsResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.storage.get_stats().await {
        Ok(stats) => Ok(Json(DatabaseStatsResponse {
            database_stats: stats,
        })),
        Err(_e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "DatabaseError".to_string(),
                message: "Failed to retrieve database statistics".to_string(),
            }),
        )),
    }
}

#[utoipa::path(
    delete,
    path = "/requests",
    tag = "Maintenance",
    responses(
        (status = 200, description = "All requests deleted", body = DeleteAllResponse,
         example = json!({
             "message": "Successfully deleted 1247 requests",
             "deleted_count": 1247
         })),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
/// Delete all requests from the database
pub async fn delete_all_requests(
    State(state): State<AppState>,
) -> Result<Json<DeleteAllResponse>, (StatusCode, Json<ErrorResponse>)> {
    let deleted_count = match state.storage.delete_all_requests().await {
        Ok(deleted_count) => deleted_count,
        Err(_e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "DatabaseError".to_string(),
                    message: "Failed to delete requests from database".to_string(),
                }),
            ));
        }
    };

    Ok(Json(DeleteAllResponse {
        message: format!("Successfully deleted {} requests", deleted_count),
        deleted_count,
    }))
}

#[utoipa::path(
    post,
    path = "/upload-image/{prover_type}/{image_type}",
    tag = "Image Management",
    params(
        ("prover_type" = String, Path, description = "Prover type: 'boundless', 'zisk', or 'brevis_pico'"),
        ("image_type" = String, Path, description = "Type of image: 'batch' or 'aggregation'")
    ),
    request_body(
        content = Vec<u8>,
        description = "Raw ELF binary data",
        content_type = "application/octet-stream"
    ),
    responses(
        (status = 200, description = "Image uploaded successfully", body = UploadImageResponse,
         example = json!({
             "prover_type": "boundless",
             "elf_type": "Batch",
             "image_id": [3537337764u32, 1055695413u32, 664197713u32, 1225410428u32, 3705161813u32, 2151977348u32, 4164639052u32, 2614443474u32],
             "provider_url": "https://storage.boundless.network/programs/abc123",
             "status": "uploaded",
             "message": "Image uploaded successfully"
         })),
        (status = 400, description = "Invalid image type or ELF data", body = ErrorResponse),
        (status = 429, description = "Rate limit exceeded", body = ErrorResponse),
        (status = 500, description = "Upload failed", body = ErrorResponse)
    )
)]
/// Upload an ELF image to the agent for use in proving
pub async fn upload_image_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path((prover_type, image_type)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Result<Json<UploadImageResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !state.rate_limiter.check(addr.ip()).await {
        tracing::warn!("Rate limit exceeded for IP: {} on image upload", addr.ip());
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "RateLimitExceeded".to_string(),
                message: "Too many image upload requests. Please try again later.".to_string(),
            }),
        ));
    }

    let prover_type = match ProverType::from_str(&prover_type) {
        Ok(prover_type) => prover_type,
        Err(message) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "InvalidProverType".to_string(),
                    message,
                }),
            ));
        }
    };

    let elf_type = match image_type.as_str() {
        "batch" => ElfType::Batch,
        "aggregation" => ElfType::Aggregation,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "InvalidImageType".to_string(),
                    message: format!(
                        "Invalid image type '{}'. Must be 'batch' or 'aggregation'",
                        image_type
                    ),
                }),
            ));
        }
    };

    let elf_bytes = body.to_vec();
    if elf_bytes.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "EmptyELF".to_string(),
                message: "ELF data cannot be empty".to_string(),
            }),
        ));
    }

    if elf_bytes.len() > 50 * 1024 * 1024 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "ELFTooLarge".to_string(),
                message: format!(
                    "ELF data too large: {:.2} MB. Maximum allowed: 50 MB",
                    elf_bytes.len() as f64 / 1_000_000.0
                ),
            }),
        ));
    }

    tracing::info!(
        "Received {} image upload for {} from {}: {:.2} MB",
        image_type,
        prover_type,
        addr.ip(),
        elf_bytes.len() as f64 / 1_000_000.0
    );

    let upload_result = match state
        .registry
        .upload_image(prover_type.clone(), elf_type.clone(), elf_bytes)
        .await
    {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("Failed to upload image: {:?}", e);
            let (status, error_code, message) = match e {
                AgentError::ProverUnavailable(_) => (
                    StatusCode::BAD_REQUEST,
                    "ProverUnavailable",
                    "Selected prover is not available".to_string(),
                ),
                AgentError::NotImplemented(_) => (
                    StatusCode::NOT_IMPLEMENTED,
                    "ProverNotImplemented",
                    "Selected prover is not implemented yet".to_string(),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ImageUploadError",
                    format!("Failed to upload image: {}", e),
                ),
            };
            return Err((
                status,
                Json(ErrorResponse {
                    error: error_code.to_string(),
                    message,
                }),
            ));
        }
    };

    let status = if upload_result.reused {
        "already_exists"
    } else {
        "uploaded"
    };

    Ok(Json(UploadImageResponse {
        prover_type,
        elf_type,
        image_id: upload_result
            .info
            .image_id
            .as_ref()
            .map(crate::image_manager::ImageManager::digest_to_vec),
        provider_url: upload_result
            .info
            .remote_url
            .as_ref()
            .map(|url| url.to_string()),
        status: status.to_string(),
        message: format!("{} image processed successfully", image_type),
    }))
}

#[utoipa::path(
    get,
    path = "/images",
    tag = "Image Management",
    responses(
        (status = 200, description = "Image information retrieved successfully", body = ImageInfoResponse,
         example = json!({
             "provers": [
                 {
                     "prover_type": "boundless",
                     "batch": {
                         "uploaded": true,
                         "image_id": [3537337764u32, 1055695413u32, 664197713u32, 1225410428u32, 3705161813u32, 2151977348u32, 4164639052u32, 2614443474u32],
                         "image_id_hex": "0xd2b5a444...",
                         "provider_url": "https://storage.boundless.network/programs/batch123",
                         "elf_size_bytes": 8700000
                     },
                     "aggregation": {
                         "uploaded": true,
                         "image_id": [2700732721u32, 2547473741u32, 423687947u32, 895656626u32, 623487531u32, 3508625552u32, 2848442538u32, 2984275190u32],
                         "image_id_hex": "0xa0f2b431...",
                         "provider_url": "https://storage.boundless.network/programs/agg456",
                         "elf_size_bytes": 2400000
                     }
                 }
             ]
         })),
        (status = 500, description = "Failed to retrieve image info", body = ErrorResponse)
    )
)]
/// Get information about uploaded batch and aggregation images
pub async fn image_info_handler(
    State(state): State<AppState>,
) -> Result<Json<ImageInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut provers = Vec::new();

    for prover_type in state.registry.supported_provers() {
        let batch = state
            .image_manager
            .get_image_details(prover_type.clone(), ElfType::Batch)
            .await;
        let aggregation = state
            .image_manager
            .get_image_details(prover_type.clone(), ElfType::Aggregation)
            .await;

        if batch.is_some() || aggregation.is_some() {
            provers.push(ProverImages {
                prover_type,
                batch,
                aggregation,
            });
        }
    }

    Ok(Json(ImageInfoResponse { provers }))
}
