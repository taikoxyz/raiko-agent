pub mod api;
pub mod auth;
pub mod backends;
pub mod image_manager;
pub mod prover_registry;
pub mod rate_limit;
pub mod storage;
pub mod types;

pub use backends::boundless::{BoundlessConfig, BoundlessProver, DeploymentType, ProverConfig};
pub use image_manager::ImageManager;
pub use prover_registry::ProverRegistry;
pub use rate_limit::RateLimiter;
pub use storage::{DatabaseStats, RequestStorage};
pub use types::{
    AgentError, AgentResult, AsyncProofRequest, ElfType, ProofRequestStatus, ProofType, ProverType,
    generate_request_id,
};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, post},
};
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
use backends::{brevis::BrevisPicoProver, zisk::ZiskProver};

#[derive(Debug, Clone)]
pub struct AppState {
    pub(crate) registry: ProverRegistry,
    pub(crate) rate_limiter: RateLimiter,
    pub(crate) image_manager: ImageManager,
    pub(crate) storage: RequestStorage,
    pub(crate) api_key: Option<String>,
}

impl AppState {
    fn new(
        api_key: Option<String>,
        registry: ProverRegistry,
        storage: RequestStorage,
        image_manager: ImageManager,
    ) -> Self {
        Self {
            registry,
            rate_limiter: RateLimiter::from_env(),
            image_manager,
            storage,
            api_key,
        }
    }

    pub(crate) fn api_key(&self) -> Option<&str> {
        self.api_key.as_deref()
    }
}

use clap::Parser;

/// Command line arguments for the Raiko Agent
#[derive(Parser, Debug)]
#[command(name = "raiko-agent")]
#[command(about = "Raiko Agent Web Service", long_about = None)]
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
    env_logger::Builder::from_default_env()
        .target(env_logger::Target::Stdout)
        .init();
    tracing::info!("Starting Raiko Agent Web Service...");

    let args = CmdArgs::parse();
    tracing::info!("Input config: {:?}", args);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let image_manager = ImageManager::new();
    let db_path = std::env::var("SQLITE_DB_PATH")
        .unwrap_or_else(|_| "./proof_requests.db".to_string());
    let storage = RequestStorage::new(db_path);

    tracing::info!("Initializing provers...");

    let config_file = args
        .config_file
        .as_ref()
        .ok_or_else(|| "config-file is required".to_string())?;
    let config_content = std::fs::read_to_string(config_file)
        .map_err(|e| format!("Failed to read config file: {}", e))?;
    let boundless_config: BoundlessConfig = serde_json::from_str(&config_content)
        .map_err(|e| format!("Failed to parse config file: {}", e))?;

    let rpc_url = boundless_config.rpc_url.clone().unwrap_or(args.rpc_url);

    let prover_config = ProverConfig {
        offchain: args.offchain,
        pull_interval: args.pull_interval,
        rpc_url,
        boundless_config,
        url_ttl: args.url_ttl,
    };
    tracing::info!("Start with prover config: {:?}", prover_config);

    let boundless = BoundlessProver::new(prover_config, image_manager.clone(), storage.clone())
        .await
        .map_err(|e| {
            AgentError::ClientBuildError(format!("Failed to initialize boundless prover: {}", e))
        })?;

    let registry = ProverRegistry::new(
        Some(boundless),
        Some(ZiskProver::new(image_manager.clone(), storage.clone())),
        Some(BrevisPicoProver::new(image_manager.clone())),
    );

    let state = AppState::new(args.api_key.clone(), registry, storage, image_manager);

    let limiter = state.rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            limiter.cleanup().await;
        }
    });

    let docs = create_docs();

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/proof", post(proof_handler))
        .route("/status/:request_id", get(get_async_proof_status))
        .route("/requests", get(list_async_requests))
        .route("/requests", delete(delete_all_requests))
        .route("/stats", get(get_database_stats))
        .route("/upload-image/:prover_type/:image_type", post(upload_image_handler))
        .route("/images", get(image_info_handler))
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
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!("Server listening on http://{}", &address);

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
        assert_eq!(
            DeploymentType::from_str("sepolia").unwrap(),
            DeploymentType::Sepolia
        );

        assert_eq!(
            DeploymentType::from_str("base").unwrap(),
            DeploymentType::Base
        );

        assert_eq!(
            DeploymentType::from_str("SEPOLIA").unwrap(),
            DeploymentType::Sepolia
        );

        assert_eq!(
            DeploymentType::from_str("BASE").unwrap(),
            DeploymentType::Base
        );

        assert!(DeploymentType::from_str("invalid").is_err());
        assert!(DeploymentType::from_str("").is_err());
    }
}
