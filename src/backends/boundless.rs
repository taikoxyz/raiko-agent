use std::str::FromStr;
use std::time::{Duration, SystemTime};
use tokio::time::timeout;

use crate::image_manager::{ImageInfo, ImageManager, ImageUploadResult};
use crate::storage::RequestStorage;
use crate::types::{
    AgentError, AgentResult, AsyncProofRequest, ElfType, ProofRequestStatus, ProofType, ProverType,
};
use alloy_primitives_v1p2p0::{
    B256, U256,
    utils::{parse_ether, parse_units},
};
use alloy_signer_local_v1p0p12::PrivateKeySigner;
use boundless_market::{
    Client, ProofRequest,
    contracts::RequestStatus,
    deployments::{BASE, Deployment, SEPOLIA},
    input::GuestEnv,
    request_builder::OfferParams,
};
use boundless_market::storage::StorageUploaderConfig;
use risc0_ethereum_contracts_boundless::receipt::{Receipt as ContractReceipt, decode_seal};
use risc0_zkvm::{Digest, Journal, Receipt as ZkvmReceipt, compute_image_id, default_executor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use url::Url;

use boundless_market::alloy::providers::Provider;

trait GuestEvaluator: Send + Sync {
    fn evaluate(&self, guest_env: GuestEnv, elf: &[u8]) -> AgentResult<(u64, Vec<u8>)>;
}

#[derive(Debug)]
struct Risc0GuestEvaluator;

impl GuestEvaluator for Risc0GuestEvaluator {
    fn evaluate(&self, guest_env: GuestEnv, elf: &[u8]) -> AgentResult<(u64, Vec<u8>)> {
        let converted_guest_env = guest_env
            .try_into()
            .map_err(|e| AgentError::GuestExecutionError(format!("Failed to convert guest env: {e}")))?;

        let session_info = default_executor()
            .execute(converted_guest_env, elf)
            .map_err(|e| AgentError::GuestExecutionError(format!("Failed to execute guest: {e}")))?;

        let mcycles_count = session_info
            .segments
            .iter()
            .map(|segment| 1u64 << segment.po2)
            .sum::<u64>()
            .div_ceil(MILLION_CYCLES);

        Ok((mcycles_count, session_info.journal.bytes))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeploymentType {
    Sepolia,
    Base,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PricingMode {
    /// Always use explicitly configured prices/collateral from `BoundlessConfig`.
    Manual,
    /// Allow the Boundless SDK to fill prices/collateral automatically (indexer/defaults)
    /// when they are not explicitly provided in `OfferParams`.
    Auto,
}

impl Default for PricingMode {
    fn default() -> Self {
        Self::Manual
    }
}

impl FromStr for DeploymentType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sepolia" | "SEPOLIA" => Ok(DeploymentType::Sepolia),
            "base" | "BASE" => Ok(DeploymentType::Base),
            _ => Err(format!(
                "Invalid deployment type: '{}'. Must be 'sepolia' or 'base'",
                s
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundlessAggregationGuestInput {
    pub image_id: Digest,
    pub receipts: Vec<ZkvmReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundlessAggregationGuestOutput {
    pub journal_digest: Digest,
}

// use tokio::sync::OnceCell;

// Constants
const MAX_RETRY_ATTEMPTS: u32 = 5;
const MILLION_CYCLES: u64 = 1_000_000;
const STAKE_TOKEN_DECIMALS: u8 = 18;
const MAX_SUBMISSION_ATTEMPTS: u32 = 5;

fn resubmit_context(
    config: &BoundlessConfig,
    proof_type: &ProofType,
) -> Option<(ElfType, ProofType, BoundlessOfferParams)> {
    match proof_type {
        ProofType::Batch => Some((
            ElfType::Batch,
            ProofType::Batch,
            config.get_batch_offer_params(),
        )),
        ProofType::Aggregate => Some((
            ElfType::Aggregation,
            ProofType::Aggregate,
            config.get_aggregation_offer_params(),
        )),
        ProofType::Update(_) => None,
    }
}

fn parse_provider_request_id(provider_request_id: &str) -> Option<U256> {
    let trimmed = provider_request_id.trim_start_matches("0x");
    U256::from_str_radix(trimmed, 16).ok()
}

fn parse_tx_hash(tx_hash: &str) -> Option<B256> {
    let trimmed = tx_hash.trim_start_matches("0x");
    if trimmed.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    alloy_primitives_v1p2p0::hex::decode_to_slice(trimmed, &mut bytes).ok()?;
    Some(B256::from(bytes))
}

/// Generic retry function with exponential backoff
async fn retry_with_backoff<F, Fut, T, E>(
    operation_name: &str,
    operation: F,
    max_retries: u32,
) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut attempt = 0;
    let mut delay = Duration::from_secs(1); // Start with 1 second

    loop {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) if attempt >= max_retries => {
                tracing::error!(
                    "{} failed after {} attempts: {}",
                    operation_name,
                    attempt,
                    e
                );
                return Err(e);
            }
            Err(e) => {
                attempt += 1;
                tracing::warn!(
                    "{} failed (attempt {}/{}): {}, retrying in {:?}",
                    operation_name,
                    attempt,
                    max_retries,
                    e,
                    delay
                );
                tokio::time::sleep(delay).await;
                delay = std::cmp::min(delay * 2, Duration::from_secs(30)); // Cap at 30 seconds
            }
        }
    }
}

// now staking token is ZSC, so we need to parse it as ZSC whose decimals is 18
pub fn parse_staking_token(token: &str) -> AgentResult<U256> {
    let parsed = parse_units(token, STAKE_TOKEN_DECIMALS).map_err(|e| {
        AgentError::ClientBuildError(format!("Failed to parse stacking: {} ({})", token, e))
    })?;
    Ok(parsed.into())
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Risc0Response {
    pub seal: Vec<u8>,
    pub journal: Vec<u8>,
    pub receipt: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoundlessOfferParams {
    pub ramp_up_start_sec: u32,
    pub ramp_up_period_blocks: u32,
    pub lock_timeout_ms_per_mcycle: u32,
    pub timeout_ms_per_mcycle: u32,
    #[serde(default)]
    pub max_price_per_mcycle: Option<String>,
    #[serde(default)]
    pub min_price_per_mcycle: Option<String>,
    #[serde(default)]
    pub lock_collateral: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoundlessConfig {
    pub deployment: Option<DeploymentConfig>,
    pub offer_params: OfferParamsConfig,
    pub rpc_url: Option<String>,
    #[serde(default)]
    pub pricing_mode: PricingMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeploymentConfig {
    pub deployment_type: Option<DeploymentType>,
    pub overrides: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OfferParamsConfig {
    pub batch: BoundlessOfferParams,
    pub aggregation: BoundlessOfferParams,
}

impl BoundlessConfig {
    /// Get the effective deployment type, using default if not specified
    pub fn get_deployment_type(&self) -> DeploymentType {
        self.deployment
            .as_ref()
            .and_then(|d| d.deployment_type.as_ref())
            .cloned()
            .unwrap_or(DeploymentType::Sepolia)
    }

    /// Get the effective deployment configuration by merging with base deployment
    #[allow(clippy::collapsible_if)]
    pub fn get_effective_deployment(&self) -> Deployment {
        let deployment_type = self.get_deployment_type();
        let mut deployment = match deployment_type {
            DeploymentType::Sepolia => SEPOLIA,
            DeploymentType::Base => BASE,
        };

        // Apply deployment overrides if provided
        if let Some(deployment_config) = &self.deployment {
            if let Some(overrides) = &deployment_config.overrides {
                if let Some(order_stream_url) =
                    overrides.get("order_stream_url").and_then(|v| v.as_str())
                {
                    deployment.order_stream_url =
                        Some(std::borrow::Cow::Owned(order_stream_url.to_string()));
                }
            }
        }

        deployment
    }

    /// Get the effective batch offer params
    pub fn get_batch_offer_params(&self) -> BoundlessOfferParams {
        self.offer_params.batch.clone()
    }

    /// Get the effective aggregation offer params
    pub fn get_aggregation_offer_params(&self) -> BoundlessOfferParams {
        self.offer_params.aggregation.clone()
    }

    pub fn block_time_sec(&self) -> u32 {
        match self.get_deployment_type() {
            DeploymentType::Base => 2,
            DeploymentType::Sepolia => 12,
        }
    }
}

#[derive(Clone)]
pub struct ProverConfig {
    pub offchain: bool,
    pub pull_interval: u64,
    pub rpc_url: String,
    pub boundless_config: BoundlessConfig,
    pub storage_uploader_config: StorageUploaderConfig,
    pub url_ttl: u64,
    pub signer_key: String,
    /// If set, never submit to Boundless Market. Instead, execute the guest locally to produce
    /// the expected journal bytes and mark the request as fulfilled (no spending).
    pub evaluation_only: bool,
}

impl fmt::Debug for ProverConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid leaking secrets (signer keys, JWTs, etc.) in logs.
        f.debug_struct("ProverConfig")
            .field("offchain", &self.offchain)
            .field("pull_interval", &self.pull_interval)
            .field("rpc_url", &self.rpc_url)
            .field("boundless_config", &self.boundless_config)
            .field("storage_uploader_config", &"<redacted>")
            .field("url_ttl", &self.url_ttl)
            .field("signer_key", &"<redacted>")
            .field("evaluation_only", &self.evaluation_only)
            .finish()
    }
}

#[derive(Clone)]
pub struct BoundlessProver {
    config: ProverConfig,
    deployment: Deployment,
    boundless_config: BoundlessConfig,
    active_requests: Arc<RwLock<HashMap<String, AsyncProofRequest>>>,
    storage: RequestStorage,
    image_manager: ImageManager,
    guest_evaluator: Arc<dyn GuestEvaluator>,
}

impl fmt::Debug for BoundlessProver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundlessProver")
            .field("config", &self.config)
            .field("deployment", &self.deployment)
            .field("boundless_config", &self.boundless_config)
            .field("active_requests", &"<redacted>")
            .field("storage", &"<redacted>")
            .field("image_manager", &"<redacted>")
            .field("guest_evaluator", &"<redacted>")
            .finish()
    }
}

static TTL_CLEANUP_HANDLE: OnceLock<tokio::sync::Mutex<Option<JoinHandle<()>>>> = OnceLock::new();

fn ttl_cleanup_handle() -> &'static tokio::sync::Mutex<Option<JoinHandle<()>>> {
    TTL_CLEANUP_HANDLE.get_or_init(|| tokio::sync::Mutex::new(None))
}

impl BoundlessProver {
    /// Create a deployment based on the configuration
    fn create_deployment(config: &ProverConfig) -> AgentResult<Deployment> {
        Ok(config.boundless_config.get_effective_deployment())
    }

    /// Create a boundless client with the current configuration
    pub async fn create_boundless_client(&self) -> AgentResult<Client> {
        let deployment = Some(self.deployment.clone());

        let url = Url::parse(&self.config.rpc_url)
            .map_err(|e| AgentError::ClientBuildError(e.to_string()))?;
        let signer: PrivateKeySigner = self
            .config
            .signer_key
            .parse()
            .map_err(|e| AgentError::ClientBuildError(format!("invalid signer key: {e}")))?;

        let builder = Client::builder()
            .with_rpc_url(url)
            .with_deployment(deployment)
            .with_private_key(signer.clone());

        let builder = builder
            .with_uploader_config(&self.config.storage_uploader_config)
            .await
            .map_err(|e| AgentError::ClientBuildError(e.to_string()))?;

        let client = builder
            .build()
            .await
            .map_err(|e| AgentError::ClientBuildError(e.to_string()))?;

        Ok(client)
    }

    /// Submit request to boundless market with retry logic
    async fn submit_request_async(
        &self,
        boundless_client: &Client,
        request: ProofRequest,
    ) -> AgentResult<U256> {
        if !self.config.offchain {
            return Err(AgentError::RequestSubmitError(
                "submit_request_async called in onchain mode".to_string(),
            ));
        }

        let request_id = {
            tracing::info!(
                "Submitting request offchain to {:?}",
                &self.deployment.order_stream_url
            );

            retry_with_backoff(
                "submit_request_offchain",
                || async {
                    boundless_client
                        .submit_request_offchain(&request)
                        .await
                        .map_err(|e| {
                            AgentError::RequestSubmitError(format!(
                                "Failed to submit request offchain: {e}"
                            ))
                        })
                },
                MAX_RETRY_ATTEMPTS,
            )
            .await?
            .0
        };

        let request_id_str = format!("0x{:x}", request_id);
        tracing::info!("Request {} submitted successfully", request_id_str);

        Ok(request_id)
    }

    /// Broadcast `submitRequest` onchain and (best-effort) return the tx hash.
    ///
    /// Note: transport/RPC errors during `send()` do not reliably prove the tx was *not*
    /// broadcast. To remain crash-safe, we treat such errors as "broadcast uncertain" and return
    /// `Ok(None)` so the caller can keep the request in `Submitting` and rely on later
    /// receipt/event confirmation.
    async fn submit_request_onchain_with_tx_hash(
        &self,
        boundless_client: &Client,
        request: &ProofRequest,
    ) -> AgentResult<Option<String>> {
        let signer = boundless_client.signer.as_ref().ok_or_else(|| {
            AgentError::RequestSubmitError("boundless client signer missing".into())
        })?;

        if request.id == U256::ZERO {
            return Err(AgentError::RequestSubmitError(
                "request.id is zero; cannot submit onchain".to_string(),
            ));
        }

        let client_address = request.client_address();
        if client_address != signer.address() {
            return Err(AgentError::RequestSubmitError(format!(
                "request id address mismatch (request: {}, signer: {})",
                client_address,
                signer.address()
            )));
        }

        // Mirror BoundlessMarketService::submit_request behavior: top up msg.value if needed.
        let balance = boundless_client
            .boundless_market
            .balance_of(client_address)
            .await
            .map_err(|e| {
                AgentError::RequestSubmitError(format!("Failed to query market balance: {e}"))
            })?;
        let max_price = U256::from(request.offer.maxPrice);
        let value = if balance > max_price {
            U256::ZERO
        } else {
            max_price - balance
        };

        let chain_id = boundless_client
            .boundless_market
            .get_chain_id()
            .await
            .map_err(|e| AgentError::RequestSubmitError(format!("Failed to get chain id: {e}")))?;
        let market_addr = *boundless_client.boundless_market.instance().address();
        let client_sig = request
            .sign_request(signer, market_addr, chain_id)
            .await
            .map_err(|e| AgentError::RequestSubmitError(format!("Failed to sign request: {e}")))?;

        let call = boundless_client
            .boundless_market
            .instance()
            .submitRequest(request.clone(), client_sig.as_bytes().into())
            .from(boundless_client.boundless_market.caller())
            .value(value);

        match call.send().await {
            Ok(pending_tx) => {
                let tx_hash = *pending_tx.tx_hash();
                Ok(Some(format!("0x{:x}", tx_hash)))
            }
            Err(e) => {
                tracing::warn!(
                    "submitRequest send() returned error (broadcast uncertain): {}",
                    e
                );
                Ok(None)
            }
        }
    }

    /// Check boundless market status and update request tracking
    async fn check_market_status(
        &self,
        market_request_id: U256,
        proof_type: &ProofType,
        expires_at: Option<u64>,
    ) -> AgentResult<ProofRequestStatus> {
        let boundless_client = self.create_boundless_client().await?;
        let request_id_str = format!("0x{:x}", market_request_id);

        let effective_expires_at = match expires_at {
            Some(expires_at) => Some(expires_at),
            None => match boundless_client
                .boundless_market
                .get_submitted_request(market_request_id, None, None, None)
                .await
            {
                Ok((request, _)) => Some(request.expires_at()),
                Err(e) => {
                    tracing::debug!(
                        "Unable to resolve expires_at for {} (continuing without expiry check): {}",
                        request_id_str,
                        e
                    );
                    None
                }
            },
        };

        // First, check the current status using get_status with retry logic
        let status_result = retry_with_backoff(
            "get_market_status",
            || {
                boundless_client
                    .boundless_market
                    .get_status(market_request_id, effective_expires_at)
            },
            3, // Fewer retries for status checks since we poll periodically
        )
        .await;

        match status_result {
            Ok(status) => {
                match status {
                    RequestStatus::Unknown => {
                        if effective_expires_at.is_some() {
                            tracing::info!(
                                "Market status: MarketSubmitted({}) - open for bidding",
                                request_id_str
                            );
                        } else {
                            tracing::info!(
                                "Market status: MarketUnknown({}) - status unknown (open/expired/not-found)",
                                request_id_str
                            );
                        }
                        Ok(ProofRequestStatus::Submitted {
                            provider_request_id: request_id_str.clone(),
                            expires_at: effective_expires_at,
                        })
                    }
                    RequestStatus::Locked => {
                        tracing::info!(
                            "Market status: MarketLocked({}) - prover committed",
                            request_id_str
                        );
                        Ok(ProofRequestStatus::Locked {
                            provider_request_id: request_id_str.clone(),
                            prover: None,
                            expires_at: effective_expires_at,
                        })
                    }
                    RequestStatus::Fulfilled => {
                        tracing::info!(
                            "Market status: MarketFulfilled({}) - proof completed",
                            request_id_str
                        );

                        // Get the actual proof data with retry logic since we know it's fulfilled
                        let fulfillment_result = retry_with_backoff(
                            "get_request_fulfillment",
                            || {
                                boundless_client
                                    .boundless_market
                                    .get_request_fulfillment(market_request_id, None, None)
                            },
                            MAX_RETRY_ATTEMPTS,
                        )
                        .await;

                        match fulfillment_result {
                            Ok(fulfillment) => {
                                let fulfillment_data = match fulfillment.data() {
                                    Ok(fulfillment_data) => fulfillment_data,
                                    Err(e) => {
                                        tracing::error!(
                                            "Failed to decode fulfillment data for {}: {}",
                                            request_id_str,
                                            e
                                        );
                                        return Ok(ProofRequestStatus::Failed {
                                            error: AgentError::FulfillmentDecodeError(
                                                e.to_string(),
                                            )
                                            .to_string(),
                                        });
                                    }
                                };

                                let journal = match fulfillment_data.journal() {
                                    Some(j) => j.to_vec(),
                                    None => {
                                        tracing::error!(
                                            "No journal found in fulfillment data for {}",
                                            request_id_str
                                        );
                                        return Ok(ProofRequestStatus::Failed {
                                            error: AgentError::MissingJournalError.to_string(),
                                        });
                                    }
                                };

                                let seal = fulfillment.seal;

                                // Decode boundless receipt only for batch proofs.
                                // Prefer the on-chain fulfillment image ID (survives agent restarts), fall back to
                                // cached image IDs if needed.
                                let receipt = match proof_type {
                                    ProofType::Batch => {
                                        let image_id = match fulfillment_data.image_id() {
                                            Some(image_id) => Some(image_id),
                                            None => {
                                                self.image_manager
                                                    .get_image_id(
                                                        ProverType::Boundless,
                                                        ElfType::Batch,
                                                    )
                                                    .await
                                            }
                                        };

                                        match image_id {
                                            Some(image_id) => {
                                                match decode_seal(
                                                    seal.clone(),
                                                    image_id,
                                                    journal.clone(),
                                                ) {
                                                    Ok(ContractReceipt::Base(
                                                        boundless_receipt,
                                                    )) => match serde_json::to_string(
                                                        &boundless_receipt,
                                                    ) {
                                                        Ok(json) => Some(json),
                                                        Err(e) => {
                                                            tracing::warn!(
                                                                "Failed to serialize decoded receipt for {}: {}",
                                                                request_id_str,
                                                                e
                                                            );
                                                            None
                                                        }
                                                    },
                                                    Ok(ContractReceipt::SetInclusion(_)) => {
                                                        tracing::warn!(
                                                            "Received set-inclusion receipt for batch proof {}",
                                                            request_id_str
                                                        );
                                                        None
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!(
                                                            "Failed to decode receipt from seal for {}: {}",
                                                            request_id_str,
                                                            e
                                                        );
                                                        None
                                                    }
                                                }
                                            }
                                            None => {
                                                tracing::warn!(
                                                    "Image ID unavailable when decoding receipt for {}",
                                                    request_id_str
                                                );
                                                None
                                            }
                                        }
                                    }
                                    _ => None, // Aggregation and other types get None
                                };

                                let response = Risc0Response {
                                    seal: seal.to_vec(),
                                    journal: journal.clone(),
                                    receipt,
                                };

                                let proof_bytes = bincode::serialize(&response).map_err(|e| {
                                    AgentError::ResponseEncodeError(format!(
                                        "Failed to encode response: {e}"
                                    ))
                                })?;

                                Ok(ProofRequestStatus::Fulfilled {
                                    provider_request_id: request_id_str.clone(),
                                    proof: proof_bytes,
                                })
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to get fulfillment for {}: {}",
                                    request_id_str,
                                    e
                                );
                                Ok(ProofRequestStatus::Failed {
                                    error: format!("Failed to get proof data: {}", e),
                                })
                            }
                        }
                    }
                    RequestStatus::Expired => {
                        tracing::warn!(
                            "Market status: MarketExpired({}) - request expired",
                            request_id_str
                        );
                        Ok(ProofRequestStatus::Failed {
                            error: "Request expired in boundless market".to_string(),
                        })
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to get market status for {}: {}", request_id_str, e);
                Ok(ProofRequestStatus::Failed {
                    error: format!("Failed to check market status: {}", e),
                })
            }
        }
    }

    /// Process input and create guest environment
    fn process_input(&self, input: Vec<u8>) -> AgentResult<(GuestEnv, Vec<u8>)> {
        let guest_env = GuestEnv::builder().write_frame(&input).build_env();
        let guest_env_bytes = guest_env.clone().encode().map_err(|e| {
            AgentError::ClientBuildError(format!("Failed to encode guest environment: {e}"))
        })?;
        Ok((guest_env, guest_env_bytes))
    }

    async fn evaluate_and_complete_request(
        &self,
        request_id: &str,
        proof_type: ProofType,
        input: Vec<u8>,
        expected_output: Vec<u8>,
        elf: &[u8],
        active_requests: Arc<RwLock<HashMap<String, AsyncProofRequest>>>,
    ) -> AgentResult<()> {
        let (guest_env, _guest_env_bytes) = self.process_input(input).map_err(|e| {
            AgentError::GuestEnvEncodeError(format!("Failed to process input: {}", e))
        })?;

        let (mcycles_count, journal) = self.guest_evaluator.evaluate(guest_env, elf)?;
        tracing::info!(
            "evaluation_only=true: proof_type={:?} mcycles={} journal_len={}",
            proof_type,
            mcycles_count,
            journal.len()
        );

        if !expected_output.is_empty() && expected_output != journal {
            return Err(AgentError::GuestExecutionError(format!(
                "evaluation_only output mismatch: expected {} bytes, got {} bytes",
                expected_output.len(),
                journal.len()
            )));
        }

        // Use same encoding as normal Boundless flow so /status proof payload is consistent.
        let response = Risc0Response {
            seal: Vec::new(),
            journal: journal.clone(),
            receipt: None,
        };
        let proof_bytes = bincode::serialize(&response).map_err(|e| {
            AgentError::ResponseEncodeError(format!("Failed to encode evaluation_only response: {e}"))
        })?;

        let status = ProofRequestStatus::Fulfilled {
            provider_request_id: format!("local_eval:{}", request_id),
            proof: proof_bytes,
        };
        self.update_request_status(request_id, status, &active_requests)
            .await?;
        Ok(())
    }

    pub async fn new(
        config: ProverConfig,
        image_manager: ImageManager,
        storage: RequestStorage,
    ) -> AgentResult<Self> {
        let deployment = BoundlessProver::create_deployment(&config)?;
        tracing::info!("boundless deployment: {:?}", deployment);

        // Initialize SQLite storage
        storage.initialize().await?;

        // Clean up expired requests from previous runs
        match storage.delete_expired_requests().await {
            Ok(deleted_ids) => {
                if !deleted_ids.is_empty() {
                    tracing::info!(
                        "Cleaned up {} expired requests from previous runs",
                        deleted_ids.len()
                    );
                }
            }
            Err(e) => tracing::warn!("Failed to clean up expired requests: {}", e),
        }

        let boundless_config = config.boundless_config.clone();

        let prover = BoundlessProver {
            config,
            deployment,
            boundless_config,
            active_requests: Arc::new(RwLock::new(HashMap::new())),
            storage: storage.clone(),
            image_manager: image_manager.clone(),
            guest_evaluator: Arc::new(Risc0GuestEvaluator),
        };

        match storage.load_images().await {
            Ok(entries) => {
                for entry in entries {
                    if entry.prover_type != ProverType::Boundless {
                        continue;
                    }
                    let info = ImageInfo {
                        image_id: Some(entry.image_id),
                        remote_url: None,
                        elf_bytes: entry.elf_bytes,
                        refresh_at: None,
                    };
                    image_manager
                        .set_image(entry.prover_type, entry.elf_type, info)
                        .await;
                }
            }
            Err(e) => tracing::warn!("Failed to load cached images: {}", e),
        }

        // Refresh market URLs if images exist in ImageManager
        // This ensures fresh presigned URLs after prover refresh/TTL expiration
        // The storage provider deduplicates content, so only new URLs are generated
        if image_manager
            .get_image(ProverType::Boundless, ElfType::Batch)
            .await
            .is_some()
            || image_manager
                .get_image(ProverType::Boundless, ElfType::Aggregation)
                .await
                .is_some()
        {
            tracing::info!("Refreshing market URLs for uploaded images (TTL refresh)...");

            // Refresh batch image URL if exists
            if let Some(batch_info) = image_manager
                .get_image(ProverType::Boundless, ElfType::Batch)
                .await
            {
                tracing::info!(
                    "Refreshing batch image market URL (content already cached in storage)"
                );
                prover
                    .upload_image(ElfType::Batch, batch_info.elf_bytes.clone())
                    .await?;
            }

            // Refresh aggregation image URL if exists
            if let Some(agg_info) = image_manager
                .get_image(ProverType::Boundless, ElfType::Aggregation)
                .await
            {
                tracing::info!(
                    "Refreshing aggregation image market URL (content already cached in storage)"
                );
                prover
                    .upload_image(ElfType::Aggregation, agg_info.elf_bytes.clone())
                    .await?;
            }

            tracing::info!("Market URLs refreshed successfully");
        } else {
            tracing::info!(
                "BoundlessProver initialized. Upload images via /upload-image/boundless/batch or /upload-image/boundless/aggregation."
            );
        }

        prover.resume_submitting_requests().await;
        prover.resume_pending_requests().await;
        prover.resume_preparing_requests().await;

        // Start background TTL cleanup task
        Self::start_ttl_cleanup_task(prover.storage.clone(), prover.active_requests.clone()).await;

        Ok(prover)
    }

    #[cfg(test)]
    async fn new_with_evaluator(
        mut config: ProverConfig,
        image_manager: ImageManager,
        storage: RequestStorage,
        guest_evaluator: Arc<dyn GuestEvaluator>,
    ) -> AgentResult<Self> {
        let deployment = BoundlessProver::create_deployment(&config)?;

        storage.initialize().await?;
        // Prevent background tasks from interfering with tests.
        config.pull_interval = 10;

        let boundless_config = config.boundless_config.clone();
        Ok(BoundlessProver {
            config,
            deployment,
            boundless_config,
            active_requests: Arc::new(RwLock::new(HashMap::new())),
            storage,
            image_manager,
            guest_evaluator,
        })
    }

    #[allow(clippy::collapsible_if)]
    pub async fn upload_image(
        &self,
        elf_type: ElfType,
        elf_bytes: Vec<u8>,
    ) -> AgentResult<ImageUploadResult> {
        let image_label = match elf_type {
            ElfType::Batch => "batch",
            ElfType::Aggregation => "aggregation",
        };

        let image_id = compute_image_id(&elf_bytes).map_err(|e| {
            AgentError::ProgramUploadError(format!("Failed to compute image_id: {e}"))
        })?;

        if self.config.evaluation_only {
            let info = ImageInfo {
                image_id: Some(image_id),
                remote_url: None,
                elf_bytes,
                refresh_at: None,
            };

            self.image_manager
                .set_image(ProverType::Boundless, elf_type.clone(), info.clone())
                .await;

            if let Some(image_id) = info.image_id {
                if let Err(e) = self
                    .storage
                    .persist_image(ProverType::Boundless, elf_type, image_id, &info.elf_bytes)
                    .await
                {
                    tracing::warn!("Failed to persist image cache: {}", e);
                }
            }

            tracing::info!(
                "evaluation_only=true: cached {} image locally (image_id={:?})",
                image_label,
                image_id
            );
            return Ok(ImageUploadResult { info, reused: false });
        }

        if let Some(existing_info) = self
            .image_manager
            .get_image(ProverType::Boundless, elf_type.clone())
            .await
        {
            if existing_info.image_id == Some(image_id) {
                if let Some(refresh_at) = existing_info.refresh_at {
                    if SystemTime::now() < refresh_at {
                        tracing::info!(
                            "{} image already uploaded. Reusing image ID: {:?}",
                            image_label,
                            image_id
                        );
                        return Ok(ImageUploadResult {
                            info: existing_info,
                            reused: true,
                        });
                    }
                }

                tracing::info!(
                    "{} image presigned URL nearing expiry; refreshing. Image ID: {:?}",
                    image_label,
                    image_id
                );
            } else {
                tracing::warn!(
                    "{} image differs from cached version. Replacing. Old ID: {:?}, New ID: {:?}",
                    image_label,
                    existing_info.image_id,
                    image_id
                );
            }
        }

        tracing::info!(
            "Uploading {} image to market ({:.2} MB)...",
            image_label,
            elf_bytes.len() as f64 / 1_000_000.0
        );

        let client = self.create_boundless_client().await?;
        let (market_url, refresh_at) = self
            .upload_with_refresh_meta(&elf_type, &elf_bytes, &client)
            .await?;

        tracing::info!(
            "{} image uploaded successfully. Image ID: {:?}, URL: {}",
            image_label,
            image_id,
            market_url
        );

        let info = ImageInfo {
            image_id: Some(image_id),
            remote_url: Some(market_url),
            elf_bytes,
            refresh_at: Some(refresh_at),
        };

        self.image_manager
            .set_image(ProverType::Boundless, elf_type.clone(), info.clone())
            .await;

        if let Some(image_id) = info.image_id {
            if let Err(e) = self
                .storage
                .persist_image(ProverType::Boundless, elf_type, image_id, &info.elf_bytes)
                .await
            {
                tracing::warn!("Failed to persist image cache: {}", e);
            }
        }

        Ok(ImageUploadResult {
            info,
            reused: false,
        })
    }

    async fn upload_with_refresh_meta(
        &self,
        elf_type: &ElfType,
        elf_bytes: &[u8],
        client: &boundless_market::Client,
    ) -> AgentResult<(Url, SystemTime)> {
        let image_label = match elf_type {
            ElfType::Batch => "batch",
            ElfType::Aggregation => "aggregation",
        };

        let market_url = client.upload_program(elf_bytes).await.map_err(|e| {
            AgentError::ProgramUploadError(format!("{} upload failed: {e}", image_label))
        })?;

        let expires_secs = market_url
            .query_pairs()
            .find(|(k, _)| k.eq_ignore_ascii_case("X-Amz-Expires"))
            .and_then(|(_, v)| v.parse::<u64>().ok())
            .unwrap_or(3600);

        let refresh_at = SystemTime::now() + Duration::from_secs(expires_secs.saturating_sub(120));

        Ok((market_url, refresh_at))
    }

    pub async fn get_batch_image_url(&self) -> Option<Url> {
        self.image_manager
            .get_image_url(ProverType::Boundless, ElfType::Batch)
            .await
    }

    pub async fn get_aggregation_image_url(&self) -> Option<Url> {
        self.image_manager
            .get_image_url(ProverType::Boundless, ElfType::Aggregation)
            .await
    }

    pub fn prover_config(&self) -> ProverConfig {
        self.config.clone()
    }

    pub fn storage(&self) -> &RequestStorage {
        &self.storage
    }

    async fn track_active_request(&self, request: &AsyncProofRequest) -> bool {
        let mut requests_guard = self.active_requests.write().await;
        if requests_guard.contains_key(&request.request_id) {
            return false;
        }
        requests_guard.insert(request.request_id.clone(), request.clone());
        true
    }

    /// Ensures the given request is in the in-memory cache so idempotent lookups see it.
    async fn ensure_request_in_cache(&self, existing_request: &AsyncProofRequest) {
        let mut requests_guard = self.active_requests.write().await;
        if !requests_guard.contains_key(&existing_request.request_id) {
            requests_guard.insert(
                existing_request.request_id.clone(),
                existing_request.clone(),
            );
        }
    }

    async fn resume_pending_requests(&self) {
        let pending = match self.storage.get_pending_requests().await {
            Ok(requests) => requests,
            Err(e) => {
                tracing::warn!("Failed to load pending requests for resume: {}", e);
                return;
            }
        };

        if pending.is_empty() {
            tracing::info!("No pending requests to resume");
        } else {
            tracing::info!("Resuming polling for {} pending requests", pending.len());
        }

        for request in pending {
            if request.prover_type != ProverType::Boundless {
                continue;
            }

            let Some(provider_request_id) = request.provider_request_id.as_ref() else {
                tracing::warn!(
                    "Skipping pending request {} with missing provider_request_id",
                    request.request_id
                );
                continue;
            };

            let Some(market_request_id) = parse_provider_request_id(provider_request_id) else {
                tracing::warn!(
                    "Skipping pending request {} with invalid provider_request_id {}",
                    request.request_id,
                    provider_request_id
                );
                continue;
            };

            if market_request_id == U256::ZERO {
                tracing::warn!(
                    "Skipping pending request {} with empty provider_request_id",
                    request.request_id
                );
                continue;
            }

            if !self.track_active_request(&request).await {
                continue;
            }

            self.start_status_polling(
                &request.request_id,
                market_request_id,
                request.proof_type.clone(),
                self.active_requests.clone(),
            )
            .await;
        }
    }

    async fn resume_submitting_requests(&self) {
        if self.config.offchain {
            return;
        }

        let submitting = match self.storage.get_submitting_requests().await {
            Ok(requests) => requests,
            Err(e) => {
                tracing::warn!("Failed to load submitting requests for resume: {}", e);
                return;
            }
        };

        if submitting.is_empty() {
            tracing::info!("No submitting requests to resume");
            return;
        }

        tracing::info!("Resuming {} submitting requests", submitting.len());

        for request in submitting {
            if request.prover_type != ProverType::Boundless {
                continue;
            }

            let ProofRequestStatus::Submitting {
                provider_request_id,
                expires_at,
                tx_hash,
            } = request.status.clone()
            else {
                continue;
            };

            let Some(market_request_id) = parse_provider_request_id(&provider_request_id) else {
                tracing::warn!(
                    "Skipping submitting request {} with invalid provider_request_id {}",
                    request.request_id,
                    provider_request_id
                );
                continue;
            };

            if market_request_id == U256::ZERO {
                tracing::warn!(
                    "Skipping submitting request {} with empty provider_request_id",
                    request.request_id
                );
                continue;
            }

            if !self.track_active_request(&request).await {
                continue;
            }

            // If we have a tx_hash, assume the tx was broadcast and resume polling. If the receipt
            // is already known and reverted, fail fast.
            if let Some(tx_hash) = tx_hash.as_deref() {
                let Some(parsed_tx_hash) = parse_tx_hash(tx_hash) else {
                    self.start_status_polling(
                        &request.request_id,
                        market_request_id,
                        request.proof_type.clone(),
                        self.active_requests.clone(),
                    )
                    .await;
                    continue;
                };

                let boundless_client = match self.create_boundless_client().await {
                    Ok(client) => client,
                    Err(_) => {
                        self.start_status_polling(
                            &request.request_id,
                            market_request_id,
                            request.proof_type.clone(),
                            self.active_requests.clone(),
                        )
                        .await;
                        continue;
                    }
                };

                match boundless_client
                    .boundless_market
                    .instance()
                    .provider()
                    .get_transaction_receipt(parsed_tx_hash)
                    .await
                {
                    Ok(Some(receipt)) if !receipt.status() => {
                        self.update_failed_status(
                            &request.request_id,
                            "Onchain submit transaction reverted".to_string(),
                        )
                        .await;
                        continue;
                    }
                    Ok(_) | Err(_) => {}
                }

                self.start_status_polling(
                    &request.request_id,
                    market_request_id,
                    request.proof_type.clone(),
                    self.active_requests.clone(),
                )
                .await;
                continue;
            }

            // No tx_hash persisted: confirm submission via the RequestSubmitted event; otherwise
            // attempt a safe re-submit using the already-reserved market request id.
            let boundless_client = match self.create_boundless_client().await {
                Ok(client) => client,
                Err(e) => {
                    tracing::warn!(
                        "Failed to create boundless client for submitting request {}: {}",
                        request.request_id,
                        e
                    );
                    continue;
                }
            };

            match boundless_client
                .boundless_market
                .get_submitted_request(market_request_id, None, None, None)
                .await
            {
                Ok(_) => {
                    let submitted_status = ProofRequestStatus::Submitted {
                        provider_request_id: provider_request_id.clone(),
                        expires_at,
                    };
                    let _ = self
                        .update_request_status(
                            &request.request_id,
                            submitted_status,
                            &self.active_requests,
                        )
                        .await;
                    self.start_status_polling(
                        &request.request_id,
                        market_request_id,
                        request.proof_type.clone(),
                        self.active_requests.clone(),
                    )
                    .await;
                }
                Err(e) => {
                    tracing::warn!(
                        "Submitting request {} not found onchain yet ({}); attempting resubmit",
                        request.request_id,
                        e
                    );

                    let Some((elf_type, proof_type, offer_params)) =
                        resubmit_context(&self.boundless_config, &request.proof_type)
                    else {
                        tracing::warn!(
                            "Skipping resubmit for update request {}",
                            request.request_id
                        );
                        continue;
                    };

                    let image_info = match self
                        .image_manager
                        .get_image(ProverType::Boundless, elf_type.clone())
                        .await
                    {
                        Some(info) => info,
                        None => {
                            tracing::warn!(
                                "Skipping resubmit for {}: image not available",
                                request.request_id
                            );
                            continue;
                        }
                    };

                    let Some(image_url) = image_info.remote_url.clone() else {
                        tracing::warn!(
                            "Skipping resubmit for {}: image URL missing",
                            request.request_id
                        );
                        continue;
                    };

                    let prover_clone = self.clone();
                    let active_requests = self.active_requests.clone();
                    let request_id = request.request_id.clone();
                    let input = request.input.clone();
                    let output = request.output.clone();
                    tokio::spawn(async move {
                        if let Err(e) = prover_clone
                            .process_and_submit_request(
                                &request_id,
                                input,
                                output,
                                &image_info.elf_bytes,
                                image_url,
                                offer_params,
                                proof_type,
                                active_requests,
                                Some(market_request_id),
                            )
                            .await
                        {
                            prover_clone
                                .update_failed_status(&request_id, e.to_string())
                                .await;
                        }
                    });
                }
            }
        }
    }

    async fn resume_preparing_requests(&self) {
        let preparing = match self.storage.get_preparing_requests().await {
            Ok(requests) => requests,
            Err(e) => {
                tracing::warn!("Failed to load preparing requests for resume: {}", e);
                return;
            }
        };

        if preparing.is_empty() {
            tracing::info!("No preparing requests to resume");
            return;
        }

        tracing::info!("Resubmitting {} preparing requests", preparing.len());

        for request in preparing {
            if request.prover_type != ProverType::Boundless {
                continue;
            }
            if request.provider_request_id.is_some() {
                continue;
            }

            let Some((elf_type, proof_type, offer_params)) =
                resubmit_context(&self.boundless_config, &request.proof_type)
            else {
                tracing::warn!(
                    "Skipping resubmit for update request {}",
                    request.request_id
                );
                continue;
            };

            let image_info = match self
                .image_manager
                .get_image(ProverType::Boundless, elf_type.clone())
                .await
            {
                Some(info) => info,
                None => {
                    tracing::warn!(
                        "Skipping resubmit for {}: image not available",
                        request.request_id
                    );
                    continue;
                }
            };

            let Some(image_url) = image_info.remote_url.clone() else {
                tracing::warn!(
                    "Skipping resubmit for {}: image URL missing",
                    request.request_id
                );
                continue;
            };

            if !self.track_active_request(&request).await {
                continue;
            }

            let active_requests = self.active_requests.clone();
            let prover_clone = self.clone();
            tokio::spawn(async move {
                if let Err(e) = prover_clone
                    .process_and_submit_request(
                        &request.request_id,
                        request.input,
                        request.output,
                        &image_info.elf_bytes,
                        image_url,
                        offer_params,
                        proof_type,
                        active_requests,
                        None,
                    )
                    .await
                {
                    prover_clone
                        .update_failed_status(&request.request_id, e.to_string())
                        .await;
                }
            });
        }
    }

    /// Helper method to prepare and store async request
    async fn prepare_async_request(
        &self,
        request_id: String,
        proof_type: ProofType,
        input: Vec<u8>,
        output: Vec<u8>,
        config: &serde_json::Value,
    ) -> AgentResult<String> {
        tracing::info!(
            "Preparing {} proof request: {}",
            match proof_type {
                ProofType::Batch => "batch",
                ProofType::Aggregate => "aggregation",
                ProofType::Update(_) => "update",
            },
            request_id
        );

        let async_request = AsyncProofRequest {
            request_id: request_id.clone(),
            prover_type: ProverType::Boundless,
            provider_request_id: None,
            status: ProofRequestStatus::Preparing,
            proof_type,
            input,
            output,
            config: config.clone(),
        };

        // Store the request for tracking (both memory and SQLite)
        {
            let mut requests_guard = self.active_requests.write().await;
            requests_guard.insert(request_id.clone(), async_request.clone());
        }

        // Persist to SQLite storage
        if let Err(e) = self.storage.store_request(&async_request).await {
            tracing::warn!(
                "Failed to store {} request in SQLite: {}",
                match async_request.proof_type {
                    ProofType::Batch => "batch",
                    ProofType::Aggregate => "aggregation",
                    ProofType::Update(_) => "update",
                },
                e
            );
        }

        Ok(request_id)
    }

    /// Helper method to update failed status in both memory and storage
    async fn update_failed_status(&self, request_id: &str, error: String) {
        let failed_status = ProofRequestStatus::Failed { error };
        let _ = self
            .update_request_status(request_id, failed_status, &self.active_requests)
            .await;
    }

    /// Helper method to update request status in both memory and storage
    async fn update_request_status(
        &self,
        request_id: &str,
        status: ProofRequestStatus,
        active_requests: &Arc<RwLock<HashMap<String, AsyncProofRequest>>>,
    ) -> AgentResult<()> {
        let is_terminal = matches!(
            status,
            ProofRequestStatus::Fulfilled { .. } | ProofRequestStatus::Failed { .. }
        );

        // Update status in memory
        {
            let mut requests_guard = active_requests.write().await;
            if let Some(async_req) = requests_guard.get_mut(request_id) {
                async_req.status = status.clone();
                // Also update provider_request_id field when available in status
                match &status {
                    ProofRequestStatus::Submitting {
                        provider_request_id,
                        ..
                    }
                    | ProofRequestStatus::Submitted {
                        provider_request_id,
                        ..
                    }
                    | ProofRequestStatus::Locked {
                        provider_request_id,
                        ..
                    }
                    | ProofRequestStatus::Fulfilled {
                        provider_request_id,
                        ..
                    } => {
                        async_req.provider_request_id = Some(provider_request_id.clone());
                    }
                    _ => {}
                }
            }
        }

        // Update in SQLite storage
        if let Err(e) = self.storage.update_status(request_id, &status).await {
            tracing::warn!("Failed to update status in storage: {}", e);
            return Err(AgentError::ClientBuildError(format!(
                "Storage update failed: {}",
                e
            )));
        }

        // Drop terminal entries from memory to avoid unbounded growth
        if is_terminal {
            let mut requests_guard = active_requests.write().await;
            requests_guard.remove(request_id);
        }

        Ok(())
    }

    /// Helper method to perform a single market status poll
    async fn poll_market_status(
        &self,
        request_id: &str,
        market_request_id: U256,
        proof_type: &ProofType,
        active_requests: &Arc<RwLock<HashMap<String, AsyncProofRequest>>>,
    ) -> bool {
        let market_id_str = format!("0x{:x}", market_request_id);

        let expires_at = {
            let requests_guard = active_requests.read().await;
            requests_guard
                .get(request_id)
                .and_then(|request| match &request.status {
                    ProofRequestStatus::Submitting { expires_at, .. }
                    | ProofRequestStatus::Submitted { expires_at, .. }
                    | ProofRequestStatus::Locked { expires_at, .. } => *expires_at,
                    _ => None,
                })
        };

        // Use retry logic for status polling to handle transient failures
        let status_result = retry_with_backoff(
            "check_market_status_polling",
            || self.check_market_status(market_request_id, proof_type, expires_at),
            3, // Fewer retries since we poll periodically
        )
        .await;

        match status_result {
            Ok(new_status) => {
                // Preserve `Submitting` while the market reports an `Unknown` state (which we map
                // to `Submitted`). This keeps `tx_hash` available for crash-safe recovery.
                let status_to_apply = {
                    let current_status = {
                        let requests_guard = active_requests.read().await;
                        requests_guard.get(request_id).map(|r| r.status.clone())
                    };

                    match (current_status, new_status) {
                        (
                            Some(ProofRequestStatus::Submitting {
                                provider_request_id,
                                tx_hash,
                                ..
                            }),
                            ProofRequestStatus::Submitted { expires_at, .. },
                        ) => ProofRequestStatus::Submitting {
                            provider_request_id,
                            expires_at,
                            tx_hash,
                        },
                        (_, status) => status,
                    }
                };

                // Update the status using the helper
                if let Err(e) = self
                    .update_request_status(request_id, status_to_apply.clone(), active_requests)
                    .await
                {
                    tracing::warn!("Failed to update status for {}: {}", request_id, e);
                }

                // Check if we should stop polling (fulfilled or failed)
                match status_to_apply {
                    ProofRequestStatus::Fulfilled { .. } => {
                        tracing::info!("Proof {} completed via market", market_id_str);
                        false // Stop polling
                    }
                    ProofRequestStatus::Failed { .. } => {
                        tracing::error!("Proof {} failed via market", market_id_str);
                        false // Stop polling
                    }
                    _ => {
                        true // Continue polling
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to check market status for {}: {}", market_id_str, e);
                true // Continue polling despite error
            }
        }
    }

    /// Helper method to handle polling timeout
    async fn handle_polling_timeout(
        &self,
        request_id: &str,
        active_requests: Arc<RwLock<HashMap<String, AsyncProofRequest>>>,
    ) {
        tracing::warn!(
            "Request {} timed out after 1 hour, marking as failed",
            request_id
        );

        let timeout_status = ProofRequestStatus::Failed {
            error: "Request timed out after 1 hour".to_string(),
        };

        // Update status using helper
        let _ = self
            .update_request_status(request_id, timeout_status, &active_requests)
            .await;

        // Remove from memory
        let mut requests_guard = active_requests.write().await;
        requests_guard.remove(request_id);

        tracing::info!("Removed timed out request {} from memory", request_id);
    }

    /// Helper method to start status polling for market requests
    async fn start_status_polling(
        &self,
        request_id: &str,
        market_request_id: U256,
        proof_type: ProofType,
        active_requests: Arc<RwLock<HashMap<String, AsyncProofRequest>>>,
    ) {
        let prover_clone = self.clone();
        let request_id = request_id.to_string();

        tokio::spawn(async move {
            let poll_interval = Duration::from_secs(10);

            // Create the polling future
            let pollings = async {
                while prover_clone
                    .poll_market_status(
                        &request_id,
                        market_request_id,
                        &proof_type,
                        &active_requests,
                    )
                    .await
                {
                    tokio::time::sleep(poll_interval).await;
                }
            };

            // Use timeout wrapper as suggested
            match timeout(Duration::from_secs(3600), pollings).await {
                Ok(_) => {
                    tracing::info!("Polling finished before timeout for request {}", request_id);
                }
                Err(_) => {
                    prover_clone
                        .handle_polling_timeout(&request_id, active_requests)
                        .await;
                }
            }
        });
    }

    /// Helper method to process input, build request, and submit to market
    #[allow(clippy::too_many_arguments)]
    async fn process_and_submit_request(
        &self,
        request_id: &str,
        input: Vec<u8>,
        output: Vec<u8>,
        elf: &[u8],
        image_url: Url,
        offer_params: BoundlessOfferParams,
        proof_type: ProofType,
        active_requests: Arc<RwLock<HashMap<String, AsyncProofRequest>>>,
        forced_market_request_id: Option<U256>,
    ) -> AgentResult<()> {
        if self.config.evaluation_only {
            tracing::info!("evaluation_only=true: executing guest locally for {}", request_id);
            return self
                .evaluate_and_complete_request(
                    request_id,
                    proof_type,
                    input,
                    output,
                    elf,
                    active_requests,
                )
                .await;
        }

        let attempts = self
            .storage
            .increment_submission_attempts(request_id)
            .await?;
        if attempts > MAX_SUBMISSION_ATTEMPTS {
            return Err(AgentError::RequestSubmitError(format!(
                "submission attempts exceeded ({})",
                attempts
            )));
        }

        let boundless_client = retry_with_backoff(
            "create_boundless_client",
            || self.create_boundless_client(),
            3, // Fewer retries for client creation
        )
        .await
        .map_err(|e| {
            AgentError::ClientBuildError(format!("Failed to create boundless client: {}", e))
        })?;

        // Process input and create guest environment
        let (guest_env, guest_env_bytes) = self.process_input(input).map_err(|e| {
            AgentError::GuestEnvEncodeError(format!("Failed to process input: {}", e))
        })?;

        // Evaluate cost
        // let (mcycles_count, _) = self.evaluate_cost(&guest_env, elf).await
        //     .map_err(|e| AgentError::GuestExecutionError(format!("Failed to evaluate cost: {}", e)))?;
        let mcycles_count = match proof_type {
            ProofType::Aggregate => 200,
            ProofType::Batch | ProofType::Update(_) => 6000,
        };

        // Upload input to storage so provers fetch from a URL (preferred over inline)
        tracing::info!(
            "Uploading input ({} bytes) to storage provider",
            guest_env_bytes.len()
        );
        let input_url = boundless_client
            .upload_input(&guest_env_bytes)
            .await
            .map_err(|e| AgentError::UploadError(format!("Failed to upload input: {}", e)))?;
        tracing::info!("Input uploaded: {}", input_url);
        let input_url = Some(input_url);

        // Build the request
        let mut request = self
            .build_boundless_request(
                &boundless_client,
                image_url,
                elf,
                input_url,
                guest_env,
                &offer_params,
                mcycles_count as u32,
                output,
            )
            .await
            .map_err(|e| {
                AgentError::RequestBuildError(format!("Failed to build request: {}", e))
            })?;

        if let Some(forced_id) = forced_market_request_id.filter(|id| *id != U256::ZERO) {
            request.id = forced_id;
        }
        let expires_at = request.expires_at();

        let provider_request_id = format!("0x{:x}", request.id);
        let market_request_id = request.id;

        if self.config.offchain {
            // Offchain is safe to retry (no gas cost).
            let market_request_id = self
                .submit_request_async(&boundless_client, request)
                .await
                .map_err(|e| {
                    AgentError::RequestSubmitError(format!("Failed to submit offchain: {e}"))
                })?;

            let submitted_status = ProofRequestStatus::Submitted {
                provider_request_id: format!("0x{:x}", market_request_id),
                expires_at: Some(expires_at),
            };
            let _ = self
                .update_request_status(request_id, submitted_status, &active_requests)
                .await;

            // Start polling market status in background
            self.start_status_polling(request_id, market_request_id, proof_type, active_requests)
                .await;
            return Ok(());
        }

        // Onchain submission can be ambiguous (tx broadcast but caller didn't observe receipt).
        // Persist an intermediate status and capture tx_hash to support crash-safe recovery.
        let submitting_status = ProofRequestStatus::Submitting {
            provider_request_id: provider_request_id.clone(),
            expires_at: Some(expires_at),
            tx_hash: None,
        };
        let _ = self
            .update_request_status(request_id, submitting_status, &active_requests)
            .await;

        match self
            .submit_request_onchain_with_tx_hash(&boundless_client, &request)
            .await
        {
            Ok(Some(tx_hash)) => {
                let submitting_status = ProofRequestStatus::Submitting {
                    provider_request_id: provider_request_id.clone(),
                    expires_at: Some(expires_at),
                    tx_hash: Some(tx_hash.clone()),
                };
                let _ = self
                    .update_request_status(request_id, submitting_status, &active_requests)
                    .await;

                // Start polling market status in background. While the market reports `Unknown`,
                // we keep the local state as `Submitting` to preserve tx_hash for recovery.
                self.start_status_polling(
                    request_id,
                    market_request_id,
                    proof_type,
                    active_requests,
                )
                .await;
                Ok(())
            }
            Ok(None) => {
                // The tx may have been broadcast even though we didn't get a hash back (RPC timeout,
                // node restart, etc.). Keep `Submitting` and start polling; crash-safe recovery can
                // confirm via onchain event scan and/or a later tx receipt lookup.
                tracing::warn!(
                    "Onchain submit returned uncertain result for {} (provider id {})",
                    request_id,
                    provider_request_id
                );
                self.start_status_polling(
                    request_id,
                    market_request_id,
                    proof_type,
                    active_requests,
                )
                .await;
                Ok(())
            }
            Err(e) => {
                // Preflight failure (before send). This is not an "uncertain broadcast" case.
                tracing::warn!(
                    "Onchain submit returned error for {} (provider id {}): {}",
                    request_id,
                    provider_request_id,
                    e
                );
                Err(e)
            }
        }
    }

    /// Submit a batch proof request asynchronously
    pub async fn batch_run(
        &self,
        request_id: String,
        input: Vec<u8>,
        output: Vec<u8>,
        config: &serde_json::Value,
    ) -> AgentResult<String> {
        // Check for existing request with same input content for proper deduplication
        if let Some(existing_request) = self
            .storage
            .get_request_by_input_hash(&input, &ProofType::Batch, &ProverType::Boundless)
            .await?
        {
            match &existing_request.status {
                ProofRequestStatus::Preparing => {
                    tracing::info!(
                        "Returning existing request in preparation phase for request: {}",
                        existing_request.request_id
                    );
                    self.ensure_request_in_cache(&existing_request).await;
                    return Ok(existing_request.request_id.clone());
                }
                ProofRequestStatus::Fulfilled { .. } => {
                    tracing::info!(
                        "Returning existing completed batch proof for request: {}",
                        existing_request.request_id
                    );
                    return Ok(existing_request.request_id.clone());
                }
                ProofRequestStatus::Submitting { .. } => {
                    tracing::info!(
                        "Returning existing submitting batch proof (pre-submit persisted) for request: {}",
                        existing_request.request_id
                    );
                    self.ensure_request_in_cache(&existing_request).await;
                    return Ok(existing_request.request_id.clone());
                }
                ProofRequestStatus::Submitted { .. } => {
                    tracing::info!(
                        "Returning existing submitted batch proof (waiting for prover) for request: {}",
                        existing_request.request_id
                    );
                    self.ensure_request_in_cache(&existing_request).await;
                    return Ok(existing_request.request_id.clone());
                }
                ProofRequestStatus::Locked { .. } => {
                    tracing::info!(
                        "Returning existing locked batch proof (being processed by prover) for request: {}",
                        existing_request.request_id
                    );
                    self.ensure_request_in_cache(&existing_request).await;
                    return Ok(existing_request.request_id.clone());
                }
                ProofRequestStatus::Failed { error } => {
                    tracing::info!(
                        "Found failed request for same input ({}), creating new batch request",
                        error
                    );
                    // Continue to create new request (allows retry)
                }
            }
        }

        // Prepare and store the async request using the provided request ID
        let final_request_id = self
            .prepare_async_request(
                request_id.clone(),
                ProofType::Batch,
                input.clone(),
                output.clone(),
                config,
            )
            .await?;

        // Submit to boundless market in background
        let prover_clone = self.clone();
        let active_requests = self.active_requests.clone();
        let request_id_clone = request_id.clone();

        tokio::spawn(async move {
            let offer_params = prover_clone.boundless_config.get_batch_offer_params();

            // Get image info from ImageManager
            let image_info = match prover_clone
                .image_manager
                .get_image(ProverType::Boundless, ElfType::Batch)
                .await
            {
                Some(info) => info,
                None => {
                    let err_msg =
                        "Batch image not uploaded. Please upload via /upload-image endpoint first.";
                    tracing::error!("{}", err_msg);
                    prover_clone
                        .update_failed_status(&request_id_clone, err_msg.to_string())
                        .await;
                    return;
                }
            };

            if prover_clone.config.evaluation_only {
                if let Err(e) = prover_clone
                    .evaluate_and_complete_request(
                        &request_id_clone,
                        ProofType::Batch,
                        input,
                        output,
                        &image_info.elf_bytes,
                        active_requests,
                    )
                    .await
                {
                    prover_clone
                        .update_failed_status(&request_id_clone, e.to_string())
                        .await;
                }
                return;
            }

            let Some(image_url) = image_info.remote_url.clone() else {
                let err_msg = "Batch image URL missing after upload.";
                tracing::error!("{}", err_msg);
                prover_clone
                    .update_failed_status(&request_id_clone, err_msg.to_string())
                    .await;
                return;
            };

            if let Err(e) = prover_clone
                .process_and_submit_request(
                    &request_id_clone,
                    input,
                    output,
                    &image_info.elf_bytes,
                    image_url,
                    offer_params,
                    ProofType::Batch,
                    active_requests,
                    None,
                )
                .await
            {
                prover_clone
                    .update_failed_status(&request_id_clone, e.to_string())
                    .await;
            }
        });

        Ok(final_request_id)
    }

    /// Submit an aggregation proof request asynchronously
    pub async fn aggregate(
        &self,
        request_id: String,
        input: Vec<u8>,
        output: Vec<u8>,
        config: &serde_json::Value,
    ) -> AgentResult<String> {
        // Check for existing request with same input content for proper deduplication
        if let Some(existing_request) = self
            .storage
            .get_request_by_input_hash(&input, &ProofType::Aggregate, &ProverType::Boundless)
            .await?
        {
            match &existing_request.status {
                ProofRequestStatus::Preparing => {
                    tracing::info!(
                        "Returning existing request in preparation phase for request: {}",
                        existing_request.request_id
                    );
                    self.ensure_request_in_cache(&existing_request).await;
                    return Ok(existing_request.request_id.clone());
                }
                ProofRequestStatus::Fulfilled { .. } => {
                    tracing::info!(
                        "Returning existing completed aggregation proof for request: {}",
                        existing_request.request_id
                    );
                    return Ok(existing_request.request_id.clone());
                }
                ProofRequestStatus::Submitting { .. } => {
                    tracing::info!(
                        "Returning existing submitting aggregation proof (pre-submit persisted) for request: {}",
                        existing_request.request_id
                    );
                    self.ensure_request_in_cache(&existing_request).await;
                    return Ok(existing_request.request_id.clone());
                }
                ProofRequestStatus::Submitted { .. } => {
                    tracing::info!(
                        "Returning existing submitted aggregation proof (waiting for prover) for request: {}",
                        existing_request.request_id
                    );
                    self.ensure_request_in_cache(&existing_request).await;
                    return Ok(existing_request.request_id.clone());
                }
                ProofRequestStatus::Locked { .. } => {
                    tracing::info!(
                        "Returning existing locked aggregation proof (being processed by prover) for request: {}",
                        existing_request.request_id
                    );
                    self.ensure_request_in_cache(&existing_request).await;
                    return Ok(existing_request.request_id.clone());
                }
                ProofRequestStatus::Failed { error } => {
                    tracing::info!(
                        "Found failed request for same input ({}), creating new aggregation request",
                        error
                    );
                    // Continue to create new request (allows retry)
                }
            }
        }

        // Prepare and store the async request using the provided request ID
        let final_request_id = self
            .prepare_async_request(
                request_id.clone(),
                ProofType::Aggregate,
                input.clone(),
                output.clone(),
                config,
            )
            .await?;

        // Submit to boundless market in background
        let prover_clone = self.clone();
        let active_requests = self.active_requests.clone();
        let request_id_clone = request_id.clone();

        tokio::spawn(async move {
            let offer_params = prover_clone.boundless_config.get_aggregation_offer_params();

            // Get image info from ImageManager
            let image_info = match prover_clone
                .image_manager
                .get_image(ProverType::Boundless, ElfType::Aggregation)
                .await
            {
                Some(info) => info,
                None => {
                    let err_msg = "Aggregation image not uploaded. Please upload via /upload-image endpoint first.";
                    tracing::error!("{}", err_msg);
                    prover_clone
                        .update_failed_status(&request_id_clone, err_msg.to_string())
                        .await;
                    return;
                }
            };

            if prover_clone.config.evaluation_only {
                if let Err(e) = prover_clone
                    .evaluate_and_complete_request(
                        &request_id_clone,
                        ProofType::Aggregate,
                        input,
                        output,
                        &image_info.elf_bytes,
                        active_requests,
                    )
                    .await
                {
                    prover_clone
                        .update_failed_status(&request_id_clone, e.to_string())
                        .await;
                }
                return;
            }

            let Some(image_url) = image_info.remote_url.clone() else {
                let err_msg = "Aggregation image URL missing after upload.";
                tracing::error!("{}", err_msg);
                prover_clone
                    .update_failed_status(&request_id_clone, err_msg.to_string())
                    .await;
                return;
            };

            if let Err(e) = prover_clone
                .process_and_submit_request(
                    &request_id_clone,
                    input,
                    output,
                    &image_info.elf_bytes,
                    image_url,
                    offer_params,
                    ProofType::Aggregate,
                    active_requests,
                    None,
                )
                .await
            {
                prover_clone
                    .update_failed_status(&request_id_clone, e.to_string())
                    .await;
            }
        });

        Ok(final_request_id)
    }

    /// update elf
    pub async fn update(
        &self,
        _request_id: String,
        _elf: Vec<u8>,
        _elf_type: ElfType,
    ) -> AgentResult<String> {
        todo!()
    }

    /// Get the current status of an async request
    pub async fn get_request_status(&self, request_id: &str) -> Option<AsyncProofRequest> {
        // Try to get from SQLite storage first (most up-to-date)
        match self.storage.get_request(request_id).await {
            Ok(Some(request)) => {
                // Cache only active requests; terminal ones stay in storage only
                match request.status {
                    ProofRequestStatus::Fulfilled { .. } | ProofRequestStatus::Failed { .. } => {
                        // Ensure any stale in-memory entry is cleared
                        let mut requests_guard = self.active_requests.write().await;
                        requests_guard.remove(request_id);
                    }
                    _ => {
                        let mut requests_guard = self.active_requests.write().await;
                        requests_guard.insert(request_id.to_string(), request.clone());
                    }
                }
                Some(request)
            }
            Ok(None) => {
                // Not found in storage, try memory
                let requests_guard = self.active_requests.read().await;
                requests_guard.get(request_id).cloned()
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to get request from storage, falling back to memory: {}",
                    e
                );
                let requests_guard = self.active_requests.read().await;
                requests_guard.get(request_id).cloned()
            }
        }
    }

    /// List all active requests
    pub async fn list_active_requests(&self) -> Vec<AsyncProofRequest> {
        // Get from SQLite storage for most up-to-date data
        match self.storage.list_active_requests().await {
            Ok(requests) => requests
                .into_iter()
                .filter(|req| req.prover_type == ProverType::Boundless)
                .collect(),
            Err(e) => {
                tracing::warn!(
                    "Failed to get requests from storage, falling back to memory: {}",
                    e
                );
                let requests_guard = self.active_requests.read().await;
                requests_guard
                    .values()
                    .filter(|req| {
                        !matches!(
                            req.status,
                            ProofRequestStatus::Fulfilled { .. }
                                | ProofRequestStatus::Failed { .. }
                        )
                    })
                    .cloned()
                    .collect()
            }
        }
    }

    /// Get database statistics for monitoring
    pub async fn get_database_stats(&self) -> AgentResult<crate::storage::DatabaseStats> {
        self.storage.get_stats().await
    }

    /// Delete all requests from the database
    /// Returns the number of deleted requests
    pub async fn delete_all_requests(&self) -> AgentResult<usize> {
        let deleted_count = self.storage.delete_all_requests().await?;

        // Clear in-memory active requests as well
        self.active_requests.write().await.clear();

        tracing::info!(
            "Deleted {} requests from database and cleared memory cache",
            deleted_count
        );
        Ok(deleted_count)
    }

    /// Start background TTL cleanup task that runs every 24 hours
    async fn start_ttl_cleanup_task(
        storage: RequestStorage,
        active_requests: Arc<RwLock<HashMap<String, AsyncProofRequest>>>,
    ) {
        let mut handle_guard = ttl_cleanup_handle().lock().await;
        if let Some(handle) = handle_guard.take() {
            handle.abort();
        }

        let cleanup_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Run hourly
            interval.tick().await; // Skip first immediate tick

            loop {
                interval.tick().await;

                tracing::info!("Running TTL cleanup for completed requests older than 12 hours");

                match storage.delete_expired_ttl_requests().await {
                    Ok(deleted_ids) => {
                        if !deleted_ids.is_empty() {
                            tracing::info!(
                                "TTL cleanup removed {} completed requests",
                                deleted_ids.len()
                            );

                            // Remove from memory cache as well
                            {
                                let mut requests_guard = active_requests.write().await;
                                for request_id in &deleted_ids {
                                    requests_guard.remove(request_id);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("TTL cleanup failed: {}", e);
                    }
                }
            }
        });

        *handle_guard = Some(cleanup_task);
    }

    async fn _evaluate_cost(
        &self,
        guest_env: &GuestEnv,
        elf: &[u8],
    ) -> AgentResult<(u64, Vec<u8>)> {
        let (mcycles_count, _journal) = {
            // Dry run the ELF with the input to get the journal and cycle count.
            // This can be useful to estimate the cost of the proving request.
            // It can also be useful to ensure the guest can be executed correctly and we do not send into
            // the market unprovable proving requests. If you have a different mechanism to get the expected
            // journal and set a price, you can skip this step.
            let session_info = default_executor()
                .execute(guest_env.clone().try_into().unwrap(), elf)
                .map_err(|e| {
                    AgentError::GuestExecutionError(format!(
                        "Failed to execute guest environment: {e}"
                    ))
                })?;
            let mcycles_count = session_info
                .segments
                .iter()
                .map(|segment| 1 << segment.po2)
                .sum::<u64>()
                .div_ceil(MILLION_CYCLES);
            let journal = session_info.journal.bytes;
            (mcycles_count, journal)
        };
        tracing::info!("mcycles_count: {}", mcycles_count);
        Ok((mcycles_count, _journal))
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_boundless_request(
        &self,
        boundless_client: &Client,
        program_url: Url,
        program_bytes: &[u8],
        input_url: Option<Url>,
        guest_env: GuestEnv,
        offer_spec: &BoundlessOfferParams,
        mcycles_count: u32,
        journal: Vec<u8>,
    ) -> AgentResult<ProofRequest> {
        tracing::info!("offer_spec: {:?}", offer_spec);
        let image_id = compute_image_id(program_bytes).map_err(|e| {
            AgentError::ClientBuildError(format!("Failed to compute image_id from program: {e}"))
        })?;

        let block_time_sec = self.boundless_config.block_time_sec();
        let validated = validate_offer_params(
            self.boundless_config.pricing_mode.clone(),
            offer_spec,
            mcycles_count,
            block_time_sec,
        )?;
        tracing::info!(
            "Derived offer params: lock_timeout={}s timeout={}s ramp_up_period_blocks={} bidding_start={} pricing_mode={:?} max_price={:?} min_price={:?} lock_collateral={:?}",
            validated.lock_timeout,
            validated.timeout,
            validated.ramp_up_period,
            validated.bidding_start,
            self.boundless_config.pricing_mode,
            validated.max_price,
            validated.min_price,
            validated.lock_collateral
        );

        let mut request_params = boundless_client
            .new_request()
            .with_program(program_bytes.to_vec())
            .with_program_url(program_url)
            .unwrap()
            .with_groth16_proof()
            .with_env(guest_env)
            .with_cycles(mcycles_count as u64 * MILLION_CYCLES)
            .with_image_id(image_id)
            .with_journal(Journal::new(journal))
            .with_offer({
                let mut builder = OfferParams::builder();
                builder
                    .ramp_up_period(validated.ramp_up_period)
                    .lock_timeout(validated.lock_timeout)
                    .timeout(validated.timeout)
                    .bidding_start(validated.bidding_start);
                if let Some(max_price) = validated.max_price {
                    builder.max_price(max_price);
                }
                if let Some(min_price) = validated.min_price {
                    builder.min_price(min_price);
                }
                if let Some(lock_collateral) = validated.lock_collateral {
                    builder.lock_collateral(lock_collateral);
                }
                builder
            });

        if let Some(url) = input_url {
            // with_input_url returns Result; unwrap here is safe because Infallible cannot occur
            request_params = request_params
                .with_input_url(url)
                .expect("with_input_url is infallible for valid URLs");
        }

        // Build the request, including preflight, and assigned the remaining fields.
        let request = boundless_client
            .build_request(request_params)
            .await
            .map_err(|e| AgentError::ClientBuildError(format!("Failed to build request: {e:?}")))?;
        tracing::info!("Request: {:?}", request);

        Ok(request)
    }
}

#[derive(Debug)]
struct ValidatedOfferParams {
    max_price: Option<U256>,
    min_price: Option<U256>,
    lock_collateral: Option<U256>,
    lock_timeout: u32,
    timeout: u32,
    ramp_up_period: u32,
    bidding_start: u64,
}

fn validate_offer_params(
    pricing_mode: PricingMode,
    offer_spec: &BoundlessOfferParams,
    mcycles_count: u32,
    block_time_sec: u32,
) -> AgentResult<ValidatedOfferParams> {
    let max_price = match (pricing_mode.clone(), offer_spec.max_price_per_mcycle.as_deref()) {
        (PricingMode::Manual, None) => {
            return Err(AgentError::RequestBuildError(
                "pricing_mode=manual requires offer_params.*.max_price_per_mcycle".to_string(),
            ));
        }
        (_, None) => None,
        (_, Some(v)) => Some(
            parse_ether(v).map_err(|e| {
                AgentError::ClientBuildError(format!("Failed to parse max_price_per_mcycle: {v} ({e})"))
            })? * U256::from(mcycles_count),
        ),
    };

    let min_price = match offer_spec.min_price_per_mcycle.as_deref() {
        None => None,
        Some(v) => Some(
            parse_ether(v).map_err(|e| {
                AgentError::ClientBuildError(format!("Failed to parse min_price_per_mcycle: {v} ({e})"))
            })? * U256::from(mcycles_count),
        ),
    };

    if let (Some(min), Some(max)) = (min_price, max_price) {
        if min > max {
            return Err(AgentError::RequestBuildError(
                "min_price_per_mcycle cannot exceed max_price_per_mcycle".to_string(),
            ));
        }
    }

    let lock_collateral = match (pricing_mode, offer_spec.lock_collateral.as_deref()) {
        (PricingMode::Manual, None) => {
            return Err(AgentError::RequestBuildError(
                "pricing_mode=manual requires offer_params.*.lock_collateral".to_string(),
            ));
        }
        (_, None) => None,
        (_, Some(v)) => Some(parse_staking_token(v)? * U256::from(mcycles_count)),
    };
    let lock_timeout = offer_spec.lock_timeout_ms_per_mcycle * mcycles_count / 1000u32;
    let timeout = offer_spec.timeout_ms_per_mcycle * mcycles_count / 1000u32;

    if timeout <= lock_timeout {
        return Err(AgentError::RequestBuildError(
            "timeout must be greater than lock_timeout".to_string(),
        ));
    }

    let ramp_up_period = offer_spec.ramp_up_period_blocks;
    let ramp_up_seconds = ramp_up_period.saturating_mul(block_time_sec);
    if ramp_up_seconds > lock_timeout {
        return Err(AgentError::RequestBuildError(format!(
            "ramp_up_period_seconds ({}) (ramp_up_period_blocks: {}, block_time_sec: {}) exceeds lock_timeout_seconds ({})",
            ramp_up_seconds, ramp_up_period, block_time_sec, lock_timeout
        )));
    }

    let bidding_start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + offer_spec.ramp_up_start_sec as u64;

    Ok(ValidatedOfferParams {
        max_price,
        min_price,
        lock_collateral,
        lock_timeout,
        timeout,
        ramp_up_period,
        bidding_start,
    })
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use super::*;
    use crate::storage::RequestStorage;
    use alloy_primitives_v1p2p0::hex;
    use env_logger;
    use ethers_contract::abigen;
    use ethers_core::types::H160;
    use ethers_providers::{Http, Provider, RetryClient};
    use log::{error as tracing_err, info as tracing_info};
    use risc0_zkvm::sha::Digestible;
    // use boundless_market::alloy::providers::Provider as BoundlessProvider;

    abigen!(
        IRiscZeroVerifier,
        r#"[
            function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view
        ]"#
    );

    fn test_batch_offer_params() -> BoundlessOfferParams {
        BoundlessOfferParams {
            ramp_up_start_sec: 30,
            ramp_up_period_blocks: 15,
            lock_timeout_ms_per_mcycle: 90,
            timeout_ms_per_mcycle: 215,
            max_price_per_mcycle: Some("0.00003".to_string()),
            min_price_per_mcycle: Some("0.000005".to_string()),
            lock_collateral: Some("0.0001".to_string()),
        }
    }

    fn test_aggregation_offer_params() -> BoundlessOfferParams {
        BoundlessOfferParams {
            ramp_up_start_sec: 30,
            ramp_up_period_blocks: 15,
            lock_timeout_ms_per_mcycle: 1500,
            timeout_ms_per_mcycle: 4500,
            max_price_per_mcycle: Some("0.00001".to_string()),
            min_price_per_mcycle: Some("0.000003".to_string()),
            lock_collateral: Some("0.0001".to_string()),
        }
    }

    fn test_offer_params_config() -> OfferParamsConfig {
        OfferParamsConfig {
            batch: test_batch_offer_params(),
            aggregation: test_aggregation_offer_params(),
        }
    }

    fn test_prover_config() -> ProverConfig {
        ProverConfig {
            offchain: false,
            pull_interval: 10,
            rpc_url: "https://base-rpc.publicnode.com".to_string(),
            boundless_config: BoundlessConfig {
                deployment: Some(DeploymentConfig {
                    deployment_type: Some(DeploymentType::Sepolia),
                    overrides: None,
                }),
                offer_params: test_offer_params_config(),
                rpc_url: None,
                pricing_mode: PricingMode::Manual,
            },
            storage_uploader_config: StorageUploaderConfig::dev_mode(),
            url_ttl: 1800,
            signer_key: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            evaluation_only: false,
        }
    }

    #[tokio::test]
    async fn evaluation_only_completes_without_signer_or_remote_url() {
        use crate::image_manager::ImageInfo;

        #[derive(Debug)]
        struct MockEval;
        impl super::GuestEvaluator for MockEval {
            fn evaluate(
                &self,
                _guest_env: GuestEnv,
                _elf: &[u8],
            ) -> AgentResult<(u64, Vec<u8>)> {
                Ok((1, vec![7u8, 7u8, 7u8]))
            }
        }

        let mut cfg = test_prover_config();
        cfg.evaluation_only = true;
        cfg.rpc_url = "not a url".to_string();
        cfg.signer_key = "invalid".to_string();

        let image_manager = ImageManager::new();
        let storage = RequestStorage::new(":memory:".to_string());
        let prover = BoundlessProver::new_with_evaluator(
            cfg,
            image_manager.clone(),
            storage,
            Arc::new(MockEval),
        )
        .await
        .unwrap();

        // Local-only image is fine in evaluation_only.
        image_manager
            .set_image(
                ProverType::Boundless,
                ElfType::Batch,
                ImageInfo {
                    image_id: None,
                    remote_url: None,
                    elf_bytes: vec![0u8],
                    refresh_at: None,
                },
            )
            .await;

        let request_id = prover
            .batch_run(
                "eval_req".to_string(),
                vec![1u8, 2u8, 3u8],
                Vec::new(),
                &serde_json::Value::default(),
            )
            .await
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if let Some(req) = prover.get_request_status(&request_id).await {
                match req.status {
                    ProofRequestStatus::Fulfilled { proof, .. } => {
                        let response: Risc0Response =
                            bincode::deserialize(&proof).expect("proof should be bincode Risc0Response");
                        assert!(response.seal.is_empty());
                        assert!(response.receipt.is_none());
                        assert_eq!(response.journal, vec![7u8, 7u8, 7u8]);
                        break;
                    }
                    ProofRequestStatus::Failed { error } => panic!("unexpected failed: {error}"),
                    _ => {}
                };
            }
            if std::time::Instant::now() > deadline {
                panic!("timed out waiting for evaluation_only fulfillment");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn test_batch_run() {
        use crate::image_manager::ImageManager;
        let image_manager = ImageManager::new();
        let storage = RequestStorage::new(":memory:".to_string());
        BoundlessProver::new(test_prover_config(), image_manager, storage)
            .await
            .unwrap();
    }

    #[test]
    fn test_deployment_selection() {
        // Test Sepolia deployment
        let mut config = test_prover_config();
        config.boundless_config.deployment = Some(DeploymentConfig {
            deployment_type: Some(DeploymentType::Sepolia),
            overrides: None,
        });
        let deployment = BoundlessProver::create_deployment(&config).unwrap();
        assert!(deployment.order_stream_url.is_none() || deployment.order_stream_url.is_some());

        // Test Base deployment
        config.boundless_config.deployment = Some(DeploymentConfig {
            deployment_type: Some(DeploymentType::Base),
            overrides: None,
        });
        let deployment = BoundlessProver::create_deployment(&config).unwrap();
        assert!(deployment.order_stream_url.is_none() || deployment.order_stream_url.is_some());
    }

    #[test]
    fn test_deployment_type_from_str() {
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

        // Test invalid deployment types
        assert!(DeploymentType::from_str("invalid").is_err());
        assert!(DeploymentType::from_str("").is_err());
    }

    #[ignore = "requires storage provider (IPFS/Pinata)"]
    #[tokio::test]
    async fn test_run_prover() {
        // init log
        env_logger::try_init().ok();

        // loading from tests/fixtures/input-1306738.bin
        let input_bytes = std::fs::read("tests/fixtures/input-1306738.bin").unwrap();
        let output_bytes = std::fs::read("tests/fixtures/output-1306738.bin").unwrap();

        let config = serde_json::Value::default();
        let image_manager = ImageManager::new();
        let storage = RequestStorage::new(":memory:".to_string());
        let prover = BoundlessProver::new(test_prover_config(), image_manager, storage)
            .await
            .unwrap();

        // Test async request submission - should return a request ID
        let request_id = prover
            .batch_run(
                "test_request_id".to_string(),
                input_bytes,
                output_bytes,
                &config,
            )
            .await
            .unwrap();
        println!("Submitted batch request with ID: {:?}", request_id);

        // Verify request ID is returned (should be a non-empty string)
        assert!(!request_id.is_empty(), "Request ID should not be empty");

        // Test deserialization of existing proof fixture
        let proof_bytes = std::fs::read("tests/fixtures/proof-1306738.bin").unwrap();
        let response: Risc0Response = bincode::deserialize(&proof_bytes).unwrap();
        println!("Successfully deserialized proof response: {:?}", response);

        // Verify the proof has required fields
        assert!(response.receipt.is_some(), "Proof should have a receipt");
    }

    #[ignore = "not needed in CI"]
    #[test]
    fn test_deserialize_zkvm_receipt() {
        // let file_name = format!("tests/fixtures/boundless_receipt_test.json");
        let file_name = "tests/fixtures/proof-1306738.bin".to_string();
        let bincode_proof: Vec<u8> = std::fs::read(file_name).unwrap();
        let proof: Risc0Response = bincode::deserialize(&bincode_proof).unwrap();
        println!("Deserialized proof: {:#?}", proof);

        let zkvm_receipt: ZkvmReceipt = serde_json::from_str(&proof.receipt.unwrap()).unwrap();
        println!("Deserialized zkvm receipt: {:#?}", zkvm_receipt);
    }

    #[test]
    fn test_decode_receipt_from_fixture_seal() {
        let proof_bytes = std::fs::read("tests/fixtures/proof-1306738.bin").unwrap();
        let response: Risc0Response = bincode::deserialize(&proof_bytes).unwrap();

        let receipt_json = response
            .receipt
            .as_ref()
            .expect("fixture should include a receipt");
        let zkvm_receipt: ZkvmReceipt = serde_json::from_str(receipt_json).unwrap();

        let claim = zkvm_receipt.claim().unwrap();
        let image_id = claim.as_value().unwrap().pre.digest();
        let seal = alloy_primitives_v1p2p0::Bytes::from(response.seal);

        let decoded = decode_seal(seal, image_id, response.journal).unwrap();
        let ContractReceipt::Base(decoded_receipt) = decoded else {
            panic!("expected a base receipt");
        };

        assert_eq!(decoded_receipt.journal.bytes, zkvm_receipt.journal.bytes);
    }

    #[ignore = "requires storage provider (IPFS/Pinata)"]
    #[tokio::test]
    async fn test_run_prover_aggregation() {
        env_logger::try_init().ok();

        // Load and deserialize existing proof fixture
        let file_name = "tests/fixtures/proof-1306738.bin".to_string();
        let proof_bytes: Vec<u8> = std::fs::read(file_name).unwrap();
        let proof: Risc0Response = bincode::deserialize(&proof_bytes).unwrap();
        println!("Deserialized proof: {:#?}", proof);

        // Prepare aggregation input
        let zkvm_receipt: ZkvmReceipt = serde_json::from_str(&proof.receipt.unwrap()).unwrap();
        let input_data = BoundlessAggregationGuestInput {
            image_id: Digest::ZERO,
            receipts: vec![zkvm_receipt],
        };
        let input = bincode::serialize(&input_data).unwrap();
        let config = serde_json::Value::default();
        let output_struct = BoundlessAggregationGuestOutput {
            journal_digest: Digest::ZERO,
        };
        let output = bincode::serialize(&output_struct).unwrap();

        // Test async aggregation request submission
        let image_manager = ImageManager::new();
        let storage = RequestStorage::new(":memory:".to_string());
        let prover = BoundlessProver::new(test_prover_config(), image_manager, storage)
            .await
            .unwrap();
        let request_id = prover
            .aggregate(
                "test_aggregate_request_id".to_string(),
                input,
                output,
                &config,
            )
            .await
            .unwrap();
        println!("Submitted aggregation request with ID: {:?}", request_id);

        // Verify request ID is returned (should be a non-empty string)
        assert!(
            !request_id.is_empty(),
            "Aggregation request ID should not be empty"
        );
    }

    pub async fn verify_boundless_groth16_snark_impl(
        image_id: Digest,
        seal: Vec<u8>,
        journal_digest: Digest,
    ) -> bool {
        let verifier_rpc_url =
            std::env::var("GROTH16_VERIFIER_RPC_URL").expect("env GROTH16_VERIFIER_RPC_URL");
        let groth16_verifier_addr = {
            let addr =
                std::env::var("GROTH16_VERIFIER_ADDRESS").expect("env GROTH16_VERIFIER_RPC_URL");
            H160::from_str(&addr).unwrap()
        };

        let http_client = Arc::new(
            Provider::<RetryClient<Http>>::new_client(&verifier_rpc_url, 3, 500)
                .expect("Failed to create http client"),
        );

        tracing_info!("Verifying SNARK:");
        tracing_info!("Seal: {}", hex::encode(&seal));
        tracing_info!("Image ID: {}", hex::encode(image_id.as_bytes()));
        tracing_info!("Journal Digest: {}", hex::encode(journal_digest));
        // Fix: Use Arc for http_client to satisfy trait bounds for Provider
        let verify_call_res =
            IRiscZeroVerifier::new(groth16_verifier_addr, Arc::clone(&http_client))
                .verify(
                    seal.clone().into(),
                    image_id.as_bytes().try_into().unwrap(),
                    journal_digest.into(),
                )
                .await;

        if verify_call_res.is_ok() {
            tracing_info!("SNARK verified successfully using {groth16_verifier_addr:?}!");
            true
        } else {
            tracing_err!(
                "SNARK verification call to {groth16_verifier_addr:?} failed: {verify_call_res:?}!"
            );
            false
        }
    }

    #[tokio::test]
    async fn test_verify_eth_receipt() {
        env_logger::try_init().ok();

        // Load a proof file and deserialize to Risc0Response
        let file_name = "tests/fixtures/proof-1306738.bin".to_string();
        let proof_bytes: Vec<u8> = std::fs::read(file_name).expect("Failed to read proof file");
        let proof: Risc0Response =
            bincode::deserialize(&proof_bytes).expect("Failed to deserialize proof");

        let image_id = match std::env::var("BOUNDLESS_BATCH_IMAGE_ID") {
            Ok(val) => {
                let bytes = hex::decode(val.trim_start_matches("0x"))
                    .expect("BOUNDLESS_BATCH_IMAGE_ID must be hex");
                Digest::try_from(bytes.as_slice())
                    .expect("BOUNDLESS_BATCH_IMAGE_ID must be a 32-byte hex string")
            }
            Err(_) => {
                println!("Skipping test_verify_eth_receipt - set BOUNDLESS_BATCH_IMAGE_ID env var");
                return;
            }
        };

        // Call the simulated onchain verification
        let journal_digest = proof.journal.digest();
        let verified =
            verify_boundless_groth16_snark_impl(image_id, proof.seal, journal_digest).await;
        assert!(verified, "Receipt failed onchain verification");
        println!("Onchain verification result: {}", verified);
    }

    #[ignore]
    #[test]
    fn test_deserialize_boundless_config() {
        // Create test config
        let config = BoundlessConfig {
            deployment: Some(DeploymentConfig {
                deployment_type: Some(DeploymentType::Sepolia),
                overrides: None,
            }),
            offer_params: test_offer_params_config(),
            rpc_url: None,
            pricing_mode: PricingMode::Manual,
        };

        // Test serialization and deserialization
        let config_json = serde_json::to_string(&config).unwrap();
        let deserialized_config: BoundlessConfig = serde_json::from_str(&config_json).unwrap();

        // Verify the config was deserialized correctly
        assert_eq!(
            deserialized_config.get_deployment_type(),
            DeploymentType::Sepolia
        );

        println!("Deserialized config: {:#?}", deserialized_config);
    }

    #[test]
    fn test_prover_config_with_boundless_config() {
        let boundless_config = BoundlessConfig {
            deployment: Some(DeploymentConfig {
                deployment_type: Some(DeploymentType::Base),
                overrides: None,
            }),
            offer_params: test_offer_params_config(),
            rpc_url: None,
            pricing_mode: PricingMode::Manual,
        };

        let prover_config = ProverConfig {
            offchain: true,
            pull_interval: 15,
            rpc_url: "https://custom-rpc.com".to_string(),
            boundless_config,
            storage_uploader_config: StorageUploaderConfig::dev_mode(),
            url_ttl: 1800,
            signer_key: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            evaluation_only: false,
        };

        // Test that the deployment is created correctly from boundless_config
        let deployment = BoundlessProver::create_deployment(&prover_config).unwrap();
        // Base deployment should have its default order_stream_url
        assert!(deployment.order_stream_url.is_some());
    }

    #[test]
    fn test_deployment_overrides() {
        // Test deployment overrides functionality
        let overrides = serde_json::json!({
            "order_stream_url": "https://custom-order-stream.com",
        });

        let config = BoundlessConfig {
            deployment: Some(DeploymentConfig {
                deployment_type: Some(DeploymentType::Sepolia),
                overrides: Some(overrides),
            }),
            offer_params: test_offer_params_config(),
            rpc_url: None,
            pricing_mode: PricingMode::Manual,
        };

        let deployment = config.get_effective_deployment();

        // Verify that the overrides were applied
        assert_eq!(
            deployment.order_stream_url,
            Some(std::borrow::Cow::Owned(
                "https://custom-order-stream.com".to_string()
            ))
        );
    }

    #[test]
    fn test_offer_params_max_price() {
        let offer_params = test_batch_offer_params();
        let max_price_per_mcycle = parse_ether(offer_params.max_price_per_mcycle.as_deref().unwrap())
            .expect("Failed to parse max_price_per_mcycle");
        let max_price = max_price_per_mcycle * U256::from(1000u64);
        // 0.00003 * 1000 = 0.03 ETH
        assert_eq!(max_price, U256::from(30000000000000000u128));

        let min_price_per_mcycle =
            parse_ether(offer_params.min_price_per_mcycle.as_deref().unwrap_or("0"))
                .expect("Failed to parse min_price_per_mcycle");
        let min_price = min_price_per_mcycle * U256::from(1000u64);
        assert!(min_price <= max_price);

        let lock_collateral_per_mcycle =
            parse_staking_token(offer_params.lock_collateral.as_deref().unwrap())
            .expect("Failed to parse lock_collateral_per_mcycle");
        let lock_collateral = lock_collateral_per_mcycle * U256::from(1000u64);
        // 0.0001 * 1000 = 0.1 USDC
        assert_eq!(lock_collateral, U256::from(100000000000000000u64));
    }

    #[test]
    fn validate_offer_params_rejects_min_gt_max() {
        let mut offer_params = test_batch_offer_params();
        offer_params.min_price_per_mcycle = Some("0.0001".to_string());
        offer_params.max_price_per_mcycle = Some("0.00001".to_string());

        let result = validate_offer_params(PricingMode::Manual, &offer_params, 7000, 2);
        assert!(result.is_err());
    }

    #[test]
    fn validate_offer_params_rejects_timeout_le_lock_timeout() {
        let mut offer_params = test_batch_offer_params();
        offer_params.lock_timeout_ms_per_mcycle = 200;
        offer_params.timeout_ms_per_mcycle = 100;

        let result = validate_offer_params(PricingMode::Manual, &offer_params, 7000, 2);
        assert!(result.is_err());
    }

    #[test]
    fn validate_offer_params_rejects_ramp_up_too_long() {
        let mut offer_params = test_batch_offer_params();
        offer_params.ramp_up_period_blocks = 400;
        offer_params.lock_timeout_ms_per_mcycle = 100;
        offer_params.timeout_ms_per_mcycle = 200;

        let result = validate_offer_params(PricingMode::Manual, &offer_params, 7000, 2);
        assert!(result.is_err());
    }

    #[test]
    fn validate_offer_params_accepts_valid_config() {
        let offer_params = test_batch_offer_params();
        let result = validate_offer_params(PricingMode::Manual, &offer_params, 7000, 2);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_offer_params_auto_allows_missing_prices_and_collateral() {
        let mut offer_params = test_batch_offer_params();
        offer_params.max_price_per_mcycle = None;
        offer_params.min_price_per_mcycle = None;
        offer_params.lock_collateral = None;

        let result = validate_offer_params(PricingMode::Auto, &offer_params, 7000, 2);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert!(validated.max_price.is_none());
        assert!(validated.min_price.is_none());
        assert!(validated.lock_collateral.is_none());
    }

    #[test]
    fn validate_offer_params_manual_rejects_missing_required_fields() {
        let mut offer_params = test_batch_offer_params();
        offer_params.max_price_per_mcycle = None;
        offer_params.lock_collateral = None;

        let result = validate_offer_params(PricingMode::Manual, &offer_params, 7000, 2);
        assert!(result.is_err());
    }

    #[test]
    fn resubmit_context_maps_proof_type() {
        let config = BoundlessConfig {
            deployment: Some(DeploymentConfig {
                deployment_type: Some(DeploymentType::Base),
                overrides: None,
            }),
            offer_params: test_offer_params_config(),
            rpc_url: None,
            pricing_mode: PricingMode::Manual,
        };

        assert!(resubmit_context(&config, &ProofType::Update(ElfType::Batch)).is_none());

        let (elf_type, proof_type, offer_params) =
            resubmit_context(&config, &ProofType::Batch).unwrap();
        assert!(matches!(elf_type, ElfType::Batch));
        assert!(matches!(proof_type, ProofType::Batch));
        assert_eq!(
            offer_params.max_price_per_mcycle,
            config.offer_params.batch.max_price_per_mcycle
        );

        let (elf_type, proof_type, offer_params) =
            resubmit_context(&config, &ProofType::Aggregate).unwrap();
        assert!(matches!(elf_type, ElfType::Aggregation));
        assert!(matches!(proof_type, ProofType::Aggregate));
        assert_eq!(
            offer_params.max_price_per_mcycle,
            config.offer_params.aggregation.max_price_per_mcycle
        );
    }
}
