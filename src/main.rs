pub mod api;
pub mod auth;
pub mod boundless;
pub mod image_manager;
pub mod rate_limit;
pub mod storage;

pub use boundless::{
    AgentError, AgentResult, AsyncProofRequest, BoundlessProver, DeploymentType, ElfType,
    ProofRequestStatus, ProofType as BoundlessProofType, ProverConfig, generate_request_id,
};
pub use image_manager::ImageManager;
pub use rate_limit::RateLimiter;
pub use storage::{BoundlessStorage, DatabaseStats};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, post},
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};
use utoipa_scalar::{Scalar, Servable};
use utoipa_swagger_ui::SwaggerUi;

use api::{
    create_docs,
    handlers::{
        delete_all_requests, get_async_proof_status, get_database_stats, health_check,
        image_info_handler, list_async_requests, proof_handler, upload_image_handler,
    },
};

#[derive(Debug, Clone)]
pub struct AppState {
    prover: Arc<Mutex<Option<BoundlessProver>>>,
    rate_limiter: RateLimiter,
    image_manager: ImageManager,
    api_key: Option<String>,
}

impl AppState {
    fn new(api_key: Option<String>) -> Self {
        Self {
            prover: Arc::new(Mutex::new(None)),
            rate_limiter: RateLimiter::from_env(),
            image_manager: ImageManager::new(),
            api_key,
        }
    }

    pub(crate) fn api_key(&self) -> Option<&str> {
        self.api_key.as_deref()
    }

    async fn init_prover(&self, config: ProverConfig) -> AgentResult<BoundlessProver> {
        let prover = BoundlessProver::new(config, self.image_manager.clone())
            .await
            .map_err(|e| {
                AgentError::ClientBuildError(format!("Failed to initialize prover: {}", e))
            })?;
        self.prover.lock().await.replace(prover.clone());
        Ok(prover)
    }

    /// Get the prover if initialized.
    async fn get_prover(&self) -> AgentResult<BoundlessProver> {
        let mut prover_guard = self.prover.lock().await;
        match prover_guard.as_ref() {
            Some(prover) => Ok(prover.clone()),
            None => Err(AgentError::ClientBuildError(
                "Prover not initialized".to_string(),
            )),
        }
    }
}

use clap::Parser;

/// Command line arguments for the RISC0 Boundless Agent
#[derive(Parser, Debug)]
#[command(name = "risc0-boundless-agent")]
#[command(about = "RISC0 Boundless Agent Web Service", long_about = None)]
struct CmdArgs {
    /// Address to bind the server to (e.g., 0.0.0.0)
    #[arg(long, default_value = "0.0.0.0")]
    address: String,

    /// Port to listen on
    #[arg(long, default_value_t = 9999)]
    port: u16,

    /// Enable offchain mode for the prover
    #[arg(long, default_value_t = false)]
    offchain: bool,

    /// RPC URL (can also be set via BOUNDLESS_RPC_URL env var)
    #[arg(
        long,
        env = "BOUNDLESS_RPC_URL",
        default_value = "https://base-rpc.publicnode.com"
    )]
    rpc_url: String,

    /// Pull interval
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(5..))]
    pull_interval: u64,

    /// URL TTL
    #[arg(long, default_value_t = 1800)]
    url_ttl: u64,

    /// singer key hex string
    #[arg(long)]
    signer_key: Option<String>,

    /// Path to boundless config file (JSON format)
    #[arg(long)]
    config_file: Option<String>,

    /// Optional API key required for all non-health requests
    #[arg(long, env = "BOUNDLESS_API_KEY")]
    api_key: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Write logs to stdout so Kubernetes/GCP doesn't treat them as errors
    env_logger::Builder::from_default_env()
        .target(env_logger::Target::Stdout)
        .init();
    tracing::info!("Starting RISC0 Boundless Agent Web Service...");

    let args = CmdArgs::parse();
    tracing::info!("Input config: {:?}", args);

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Create app state
    let state = AppState::new(args.api_key.clone());

    // Initialize the prover before starting the server
    tracing::info!("Initializing prover...");

    // Load boundless config from file if provided, otherwise use default
    let mut boundless_config = boundless::BoundlessConfig::default();
    if let Some(config_file) = &args.config_file {
        let config_content = std::fs::read_to_string(config_file)
            .map_err(|e| format!("Failed to read config file: {}", e))?;
        let file_config: boundless::BoundlessConfig = serde_json::from_str(&config_content)
            .map_err(|e| format!("Failed to parse config file: {}", e))?;
        boundless_config.merge(&file_config);
    }

    // Use rpc_url from config file if available, otherwise from args
    let rpc_url = boundless_config.rpc_url.clone().unwrap_or(args.rpc_url);

    let prover_config = ProverConfig {
        offchain: args.offchain,
        pull_interval: args.pull_interval,
        rpc_url,
        boundless_config,
        url_ttl: args.url_ttl,
    };
    tracing::info!("Start with prover config: {:?}", prover_config);

    match state.init_prover(prover_config).await {
        Ok(_) => {
            tracing::info!("Prover initialized successfully");
        }
        Err(e) => {
            tracing::error!("Failed to initialize prover: {:?}", e);
            return Err(format!("Failed to initialize prover: {:?}", e).into());
        }
    }

    // Start background task to clean up rate limiter state
    let limiter = state.rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // Cleanup every 5 minutes
        loop {
            interval.tick().await;
            limiter.cleanup().await;
        }
    });

    // Generate OpenAPI documentation
    let docs = create_docs();

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/proof", post(proof_handler))
        .route("/status/:request_id", get(get_async_proof_status))
        .route("/requests", get(list_async_requests))
        .route("/prune", delete(delete_all_requests))
        .route("/stats", get(get_database_stats))
        .route("/upload-image/:image_type", post(upload_image_handler))
        .route("/images", get(image_info_handler))
        // OpenAPI documentation endpoints
        .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", docs.clone()))
        .merge(Scalar::with_url("/scalar", docs.clone()))
        .route(
            "/openapi.json",
            get(move || async move { axum::Json(docs) }),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_api_key,
        ))
        .layer(DefaultBodyLimit::max(10000 * 1024 * 1024))
        .layer(cors)
        .with_state(state);

    let address = format!("{}:{}", args.address, args.port);
    // Start server
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!("Server listening on http://{}", &address);

    // Use into_make_service_with_connect_info to enable ConnectInfo extraction in handlers
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_deployment_type_parsing() {
        // Test valid deployment types
        assert_eq!(
            DeploymentType::from_str("sepolia").unwrap(),
            DeploymentType::Sepolia
        );

        assert_eq!(
            DeploymentType::from_str("base").unwrap(),
            DeploymentType::Base
        );

        // Test case insensitive
        assert_eq!(
            DeploymentType::from_str("SEPOLIA").unwrap(),
            DeploymentType::Sepolia
        );

        assert_eq!(
            DeploymentType::from_str("BASE").unwrap(),
            DeploymentType::Base
        );

        // Test invalid deployment type
        assert!(DeploymentType::from_str("invalid").is_err());
        assert!(DeploymentType::from_str("").is_err());
    }
}
