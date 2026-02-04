use super::types::{
    AsyncProofRequestData, AsyncProofResponse, DatabaseStatsResponse, DeleteAllResponse,
    DetailedStatusResponse, ErrorResponse, HealthResponse, ImageInfoResponse, ProverImages,
    RequestListResponse, UploadImageResponse,
};
use crate::DatabaseStats;
use crate::api::handlers::{
    __path_delete_all_requests, __path_get_async_proof_status, __path_get_database_stats,
    __path_health_check, __path_image_info_handler, __path_list_async_requests,
    __path_proof_handler, __path_upload_image_handler,
};
use crate::image_manager::ImageDetails;
use crate::types::{ElfType, ProofType, ProverType};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Raiko Agent API",
        version = "1.0.0",
        description = r#"
REST API for Raiko Agent - Multi-prover proof generation service

Raiko Agent is a web service that acts as an intermediary between client applications and multiple prover backends. It provides a REST API for submitting proof requests, monitoring their progress, and retrieving completed proofs.

## Architecture
```
Client → Raiko Agent → Prover Backends
```

## Key Concepts
- **Asynchronous Processing**: All proof requests are processed asynchronously
- **Request Lifecycle**: Requests go through multiple states: preparing → submitting → submitted → in_progress → completed/failed
- **Proof Types**: Supports batch proofs, aggregation proofs, and ELF update proofs
- **Multi-Prover Routing**: Requests are dispatched to a selected prover backend
- **Prover Types**: `boundless` (implemented), `zisk` and `brevis_pico` (placeholders)
        "#,
        contact(
            name = "Raiko Agent Support",
            url = "https://github.com/taikoxyz/raiko-agent",
            email = ""
        ),
        license(
            name = "MIT",
            url = "https://github.com/taikoxyz/raiko-agent/blob/main/LICENSE"
        )
    ),
    servers(
        (url = "http://localhost:9999", description = "Local development server"),
        (url = "{protocol}://{host}:{port}", description = "Configurable server",
            variables(
                ("protocol" = (default = "http", enum_values("http", "https"))),
                ("host" = (default = "localhost")),
                ("port" = (default = "9999"))
            )
        )
    ),
    paths(
        health_check,
        proof_handler,
        get_async_proof_status,
        list_async_requests,
        get_database_stats,
        delete_all_requests,
        upload_image_handler,
        image_info_handler,
    ),
    components(schemas(
        AsyncProofRequestData,
        AsyncProofResponse,
        ProofType,
        ElfType,
        ProverType,
        DetailedStatusResponse,
        RequestListResponse,
        HealthResponse,
        DatabaseStatsResponse,
        DatabaseStats,
        DeleteAllResponse,
        ErrorResponse,
        UploadImageResponse,
        ImageInfoResponse,
        ProverImages,
        ImageDetails,
    )),
    tags(
        (name = "Health", description = "Service health and status endpoints"),
        (name = "Proof", description = "Proof generation and submission endpoints"),
        (name = "Status", description = "Request status monitoring and tracking endpoints"),
        (name = "Maintenance", description = "Database and system maintenance endpoints"),
        (name = "Image Management", description = "ELF image upload and management endpoints")
    ),
    external_docs(
        url = "https://github.com/taikoxyz/raiko-agent#readme",
        description = "Detailed API documentation and integration guide"
    )
)]
/// Raiko Agent OpenAPI Documentation
pub struct RaikoAgentApiDoc;

/// Generate OpenAPI specification
pub fn create_docs() -> utoipa::openapi::OpenApi {
    RaikoAgentApiDoc::openapi()
}
