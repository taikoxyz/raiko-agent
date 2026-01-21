use crate::image_manager::{ImageInfo, ImageManager, ImageUploadResult};
use crate::storage::RequestStorage;
use crate::types::{
    AgentError, AgentResult, AsyncProofRequest, ElfType, ProofRequestStatus, ProofType, ProverType,
};
use alloy_primitives_v1p2p0::{Address, B256, hex, U256};
use anyhow::{anyhow, Result};
#[cfg(feature = "brevis")]
use pico_vm::{
    compiler::riscv::program::Program,
    configs::stark_config::KoalaBearPoseidon2,
    machine::keys::HashableKey,
    proverchain::{InitialProverSetup, MachineProver, RiscvProver},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use url::Url;

alloy::sol! {
    #[sol(rpc)]
    interface IERC20 {
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 value) external returns (bool);
    }
}

alloy::sol! {
    #[sol(rpc)]
    interface IBrevisMarket {
        enum ReqStatus {
            Pending,
            Fulfilled,
            Refunded,
            Slashed
        }

        struct FeeParams {
            uint96 maxFee;
            uint96 minStake;
            uint64 deadline;
        }

        struct ProofRequest {
            uint64 nonce;
            bytes32 vk;
            bytes32 publicValuesDigest;
            string imgURL;
            bytes inputData;
            string inputURL;
            uint32 version;
            FeeParams fee;
        }

        function requestProof(ProofRequest calldata req) external;

        function getRequest(bytes32 reqid)
            external
            view
            returns (
                ReqStatus status,
                uint64 timestamp,
                address sender,
                uint256 maxFee,
                uint256 minStake,
                uint64 deadline,
                bytes32 vk,
                bytes32 publicValuesDigest,
                uint32 version
            );

        function feeToken() external view returns (address);

        event NewRequest(bytes32 indexed reqid, ProofRequest req);
        event ProofSubmitted(bytes32 indexed reqid, address indexed prover, uint256[8] proof, uint256 actualFee);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BrevisProverNetFeePolicy {
    pub max_fee_wei: String,
    pub min_stake_wei: String,
    pub deadline_secs: u64,
}

fn default_input_inline_max_bytes() -> usize {
    4096
}

fn default_poll_interval_secs() -> u64 {
    10
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BrevisProverNetConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub brevis_market_address: String,
    #[serde(default)]
    pub market_viewer_address: Option<String>,
    pub signer_private_key: String,
    pub fee_policy: BrevisProverNetFeePolicy,
    pub artifact_base_url: String,
    #[serde(default = "default_input_inline_max_bytes")]
    pub input_inline_max_bytes: usize,
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,
}

impl BrevisProverNetConfig {
    pub fn from_json_str(raw: &str) -> anyhow::Result<Self> {
        let config: Self = serde_json::from_str(raw)
            .map_err(|e| anyhow::anyhow!("Invalid Brevis ProverNet config: {e}"))?;
        Ok(config)
    }

    pub fn from_file(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            anyhow::anyhow!(
                "Failed to read Brevis ProverNet config {:?}: {e}",
                path.as_ref()
            )
        })?;
        Self::from_json_str(&raw)
    }
}

fn join_base_url(base: &str, path: &str) -> anyhow::Result<String> {
    let mut base = base.to_string();
    if !base.ends_with('/') {
        base.push('/');
    }
    let base =
        Url::parse(&base).map_err(|e| anyhow::anyhow!("Invalid artifact_base_url '{}': {e}", base))?;
    Ok(base
        .join(path)
        .map_err(|e| anyhow::anyhow!("Failed to join URL path '{path}': {e}"))?
        .to_string())
}

fn build_img_url(base: &str, elf_type: ElfType) -> anyhow::Result<String> {
    let name = match elf_type {
        ElfType::Batch => "batch.elf",
        ElfType::Aggregation => "aggregation.elf",
    };
    join_base_url(base, &format!("artifacts/brevis/{name}"))
}

fn build_input_url(base: &str, request_id: &str) -> anyhow::Result<String> {
    join_base_url(base, &format!("inputs/{request_id}"))
}

fn compute_reqid(nonce: u64, vk: [u8; 32], public_values_digest: [u8; 32]) -> [u8; 32] {
    use alloy_primitives_v1p2p0::keccak256;

    let mut packed = [0u8; 8 + 32 + 32];
    packed[..8].copy_from_slice(&nonce.to_be_bytes());
    packed[8..40].copy_from_slice(&vk);
    packed[40..].copy_from_slice(&public_values_digest);
    keccak256(packed).into()
}

fn extract_proof_from_logs(
    expected_reqid: alloy_primitives_v1p2p0::B256,
    logs: Vec<alloy::rpc::types::Log>,
) -> anyhow::Result<Option<[alloy_primitives_v1p2p0::U256; 8]>> {
    for log in logs {
        let decoded = match log.log_decode::<IBrevisMarket::ProofSubmitted>() {
            Ok(decoded) => decoded,
            Err(_) => continue,
        };
        if decoded.inner.data.reqid == expected_reqid {
            return Ok(Some(decoded.inner.data.proof));
        }
    }
    Ok(None)
}

fn parse_u128(value: &str) -> anyhow::Result<u128> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u128::from_str_radix(hex, 16)
            .map_err(|e| anyhow::anyhow!("Invalid hex integer '{value}': {e}"));
    }
    trimmed
        .parse::<u128>()
        .map_err(|e| anyhow::anyhow!("Invalid integer '{value}': {e}"))
}

fn u128_to_u96(value: u128, field: &'static str) -> anyhow::Result<u128> {
    if value >= (1u128 << 96) {
        return Err(anyhow::anyhow!(
            "Value for {field} does not fit uint96: {value}"
        ));
    }
    Ok(value)
}

fn fee_params_from_config(
    cfg: &BrevisProverNetConfig,
    now_secs: u64,
) -> anyhow::Result<IBrevisMarket::FeeParams> {
    let max_fee = parse_u128(&cfg.fee_policy.max_fee_wei)?;
    let min_stake = parse_u128(&cfg.fee_policy.min_stake_wei)?;
    let deadline = now_secs
        .checked_add(cfg.fee_policy.deadline_secs)
        .ok_or_else(|| anyhow::anyhow!("deadline overflow"))?;

    Ok(IBrevisMarket::FeeParams {
        maxFee: u128_to_u96(max_fee, "max_fee_wei")?
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to convert max_fee_wei to uint96: {e}"))?,
        minStake: u128_to_u96(min_stake, "min_stake_wei")?
            .try_into()
            .map_err(|e| anyhow::anyhow!("Failed to convert min_stake_wei to uint96: {e}"))?,
        deadline,
    })
}

async fn submit_market_request(
    cfg: &BrevisProverNetConfig,
    request: IBrevisMarket::ProofRequest,
) -> anyhow::Result<alloy_primitives_v1p2p0::B256> {
    use alloy::network::EthereumWallet;
    use alloy::providers::{Provider, ProviderBuilder};
    use alloy::signers::local::PrivateKeySigner;
    use alloy_primitives_v1p2p0::{Address, U256};
    use std::str::FromStr;

    let signer: PrivateKeySigner = cfg
        .signer_private_key
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid signer_private_key: {e}"))?;
    let signer_addr = signer.address();
    let wallet = EthereumWallet::from(signer);

    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(&cfg.rpc_url)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect RPC provider: {e}"))?;

    let chain_id = provider
        .get_chain_id()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to query chain_id: {e}"))?;
    if chain_id != cfg.chain_id {
        return Err(anyhow::anyhow!(
            "RPC chain_id mismatch: expected {}, got {}",
            cfg.chain_id,
            chain_id
        ));
    }

    let market_addr = Address::from_str(&cfg.brevis_market_address)
        .map_err(|e| anyhow::anyhow!("Invalid brevis_market_address: {e}"))?;
    let market = IBrevisMarket::new(market_addr, provider.clone());

    let fee_token = market.feeToken().call().await?;
    let token = IERC20::new(fee_token, provider.clone());

    // Ensure allowance for maxFee (token uses uint256; request uses uint96).
    let max_fee: U256 = U256::from(request.fee.maxFee);
    if max_fee > U256::ZERO {
        let allowance = token.allowance(signer_addr, market_addr).call().await?;
        if allowance < max_fee {
            let pending = token.approve(market_addr, max_fee).send().await?;
            pending.watch().await?;
        }
    }

    let pending = market.requestProof(request).send().await?;
    let tx_hash = *pending.tx_hash();
    pending.watch().await?;

    Ok(tx_hash)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrevisProofBundle {
    pub riscv_vkey: [u8; 32],
    pub public_values: Vec<u8>,
    pub proof: [U256; 8],
    pub pico_proof: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct BrevisProver {
    image_manager: ImageManager,
    storage: RequestStorage,
    provernet_config: Option<BrevisProverNetConfig>,
    polling_requests: Arc<Mutex<HashSet<String>>>,
}

impl BrevisProver {
    pub fn new(
        image_manager: ImageManager,
        storage: RequestStorage,
        provernet_config: Option<BrevisProverNetConfig>,
    ) -> Self {
        let prover = Self {
            image_manager,
            storage,
            provernet_config,
            polling_requests: Arc::new(Mutex::new(HashSet::new())),
        };

        if prover.provernet_config.is_some() {
            let prover_clone = prover.clone();
            tokio::spawn(async move {
                prover_clone.resume_pending_provernet_requests().await;
            });
        }

        prover
    }

    pub async fn submit_proof(
        &self,
        request_id: String,
        proof_type: ProofType,
        input: Vec<u8>,
        output: Vec<u8>,
        config: serde_json::Value,
        _elf: Option<Vec<u8>>,
    ) -> AgentResult<String> {
        if self.provernet_config.is_none() {
            return Err(AgentError::ProverUnavailable(
                "Brevis ProverNet config not provided".to_string(),
            ));
        }

        match &proof_type {
            ProofType::Update(_) => {
                return Err(AgentError::NotImplemented(
                    "ProofType::Update is deprecated; use /upload-image/brevis/{batch|aggregation}"
                        .to_string(),
                ));
            }
            ProofType::Batch | ProofType::Aggregate => {}
        }

        if let Some(existing_request) = self
            .storage
            .get_request_by_input_hash(&input, &proof_type, &ProverType::Brevis)
            .await?
        {
            match &existing_request.status {
                ProofRequestStatus::Preparing
                | ProofRequestStatus::Submitted { .. }
                | ProofRequestStatus::Locked { .. }
                | ProofRequestStatus::Fulfilled { .. } => {
                    tracing::info!(
                        "Returning existing brevis request {} for identical input",
                        existing_request.request_id
                    );
                    return Ok(existing_request.request_id);
                }
                ProofRequestStatus::Failed { error } => {
                    tracing::info!(
                        "Found failed brevis request for same input ({}), creating new request",
                        error
                    );
                }
            }
        }

        let final_request_id = self
            .prepare_async_request(
                request_id.clone(),
                proof_type.clone(),
                input.clone(),
                &config,
            )
            .await?;

        let prover = self.clone();
        let request_id_clone = request_id.clone();
        let output_clone = output.clone();
        tokio::spawn(async move {
            let result = prover
                .submit_provernet_request(&request_id_clone, proof_type, input, output_clone)
                .await;

            match result {
                Ok((provider_request_id, tx_hash)) => {
                    tracing::info!(
                        "Brevis ProverNet request submitted (request_id={}, reqid={}, tx={})",
                        request_id_clone,
                        provider_request_id,
                        tx_hash
                    );
                    let submitted = ProofRequestStatus::Submitted { provider_request_id };
                    if let Err(e) = prover.storage.update_status(&request_id_clone, &submitted).await
                    {
                        tracing::warn!(
                            "Failed to update brevis provernet submitted status: {}",
                            e
                        );
                    }
                    prover.start_provernet_status_polling(request_id_clone.clone()).await;
                }
                Err(err) => {
                    prover
                        .update_failed_status(&request_id_clone, err.to_string())
                        .await;
                }
            }
        });

        Ok(final_request_id)
    }

    async fn start_provernet_status_polling(&self, request_id: String) {
        if self.provernet_config.is_none() {
            return;
        }

        {
            let mut guard = self.polling_requests.lock().await;
            if guard.contains(&request_id) {
                return;
            }
            guard.insert(request_id.clone());
        }

        let prover = self.clone();
        tokio::spawn(async move {
            let provider_request_id = match prover.storage.get_request(&request_id).await {
                Ok(Some(request)) => match &request.status {
                    ProofRequestStatus::Submitted { provider_request_id }
                    | ProofRequestStatus::Locked {
                        provider_request_id,
                        ..
                    }
                    | ProofRequestStatus::Fulfilled {
                        provider_request_id,
                        ..
                    } => Some(provider_request_id.clone()),
                    ProofRequestStatus::Preparing | ProofRequestStatus::Failed { .. } => None,
                },
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!(
                        "Failed to load brevis request {} for polling: {}",
                        request_id,
                        e
                    );
                    None
                }
            };

            let result = match provider_request_id.as_deref() {
                Some(reqid) => prover.poll_provernet_request(&request_id, reqid).await,
                None => Ok(()),
            };

            if let Err(err) = result {
                prover.update_failed_status(&request_id, err.to_string()).await;
            }

            let mut guard = prover.polling_requests.lock().await;
            guard.remove(&request_id);
        });
    }

    async fn poll_provernet_request(
        &self,
        request_id: &str,
        provider_request_id: &str,
    ) -> AgentResult<()> {
        use alloy::providers::{Provider, ProviderBuilder};
        use alloy::rpc::types::Filter;
        use alloy::sol_types::SolEvent;
        use std::str::FromStr;
        use std::time::Duration;

        let cfg = self.provernet_config.clone().ok_or_else(|| {
            AgentError::ProverUnavailable("Brevis ProverNet config not provided".to_string())
        })?;

        let reqid: B256 = provider_request_id.parse().map_err(|e| {
            AgentError::RequestBuildError(format!(
                "Invalid Brevis provider_request_id (expected 0x-prefixed bytes32): {e}"
            ))
        })?;

        let provider = ProviderBuilder::new()
            .connect(&cfg.rpc_url)
            .await
            .map_err(|e| {
                AgentError::ClientBuildError(format!("Failed to connect RPC provider: {e}"))
            })?;

        let chain_id = provider.get_chain_id().await.map_err(|e| {
            AgentError::ClientBuildError(format!("Failed to query chain_id: {e}"))
        })?;
        if chain_id != cfg.chain_id {
            return Err(AgentError::ClientBuildError(format!(
                "RPC chain_id mismatch: expected {}, got {}",
                cfg.chain_id, chain_id
            )));
        }

        let market_addr = Address::from_str(&cfg.brevis_market_address).map_err(|e| {
            AgentError::ClientBuildError(format!("Invalid brevis_market_address: {e}"))
        })?;
        let market = IBrevisMarket::new(market_addr, provider.clone());

        let poll_interval = Duration::from_secs(cfg.poll_interval_secs.max(1));
        let grace_secs = 600u64;
        let mut attempts: u32 = 0;

        loop {
            attempts = attempts.saturating_add(1);

            let response = market.getRequest(reqid).call().await.map_err(|e| {
                AgentError::RequestFulfillmentError {
                    attempts,
                    error: format!("BrevisMarket.getRequest failed: {e}"),
                }
            })?;

            let status = response.status;
            let deadline = response.deadline;
            let vk = response.vk;
            let public_values_digest = response.publicValuesDigest;

            match status {
                IBrevisMarket::ReqStatus::Pending => {}
                IBrevisMarket::ReqStatus::Fulfilled => {
                    let filter = Filter::new()
                        .address(market_addr)
                        .event_signature(IBrevisMarket::ProofSubmitted::SIGNATURE_HASH)
                        .topic1(reqid);

                    let logs = provider.get_logs(&filter).await.map_err(|e| {
                        AgentError::RequestFulfillmentError {
                            attempts,
                            error: format!("eth_getLogs failed: {e}"),
                        }
                    })?;

                    let Some(proof) = extract_proof_from_logs(reqid, logs)
                        .map_err(|e| AgentError::FulfillmentDecodeError(e.to_string()))?
                    else {
                        tokio::time::sleep(poll_interval).await;
                        continue;
                    };

                    let riscv_vkey: [u8; 32] = vk.into();
                    let public_values: [u8; 32] = public_values_digest.into();

                    let bundle = BrevisProofBundle {
                        riscv_vkey,
                        public_values: public_values.to_vec(),
                        proof,
                        pico_proof: Vec::new(),
                    };

                    let proof_bytes = bincode::serialize(&bundle).map_err(|e| {
                        AgentError::ResponseEncodeError(format!(
                            "Failed to serialize Brevis proof bundle: {e}"
                        ))
                    })?;

                    let fulfilled = ProofRequestStatus::Fulfilled {
                        provider_request_id: provider_request_id.to_string(),
                        proof: proof_bytes,
                    };

                    if let Err(e) = self.storage.update_status(request_id, &fulfilled).await {
                        tracing::warn!(
                            "Failed to update fulfilled brevis provernet status: {}",
                            e
                        );
                    }

                    return Ok(());
                }
                IBrevisMarket::ReqStatus::Refunded => {
                    return Err(AgentError::RequestFulfillmentError {
                        attempts,
                        error: "Brevis ProverNet request refunded".to_string(),
                    });
                }
                IBrevisMarket::ReqStatus::Slashed => {
                    return Err(AgentError::RequestFulfillmentError {
                        attempts,
                        error: "Brevis ProverNet request slashed".to_string(),
                    });
                }
                IBrevisMarket::ReqStatus::__Invalid => {
                    return Err(AgentError::RequestFulfillmentError {
                        attempts,
                        error: "Brevis ProverNet request returned invalid status".to_string(),
                    });
                }
            }

            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| AgentError::RequestBuildError(format!("System clock error: {e}")))?
                .as_secs();

            if now_secs > deadline.saturating_add(grace_secs) {
                return Err(AgentError::RequestFulfillmentError {
                    attempts,
                    error: format!(
                        "Brevis ProverNet request timed out (deadline={}, grace_secs={})",
                        deadline, grace_secs
                    ),
                });
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    async fn resume_pending_provernet_requests(&self) {
        let pending = match self.storage.get_pending_requests().await {
            Ok(requests) => requests,
            Err(e) => {
                tracing::warn!("Failed to load pending brevis requests for resume: {}", e);
                return;
            }
        };

        if pending.is_empty() {
            return;
        }

        for request in pending {
            if request.prover_type != ProverType::Brevis {
                continue;
            }

            let provider_request_id = match &request.status {
                ProofRequestStatus::Submitted { provider_request_id }
                | ProofRequestStatus::Locked {
                    provider_request_id,
                    ..
                }
                | ProofRequestStatus::Fulfilled {
                    provider_request_id,
                    ..
                } => Some(provider_request_id.clone()),
                ProofRequestStatus::Preparing | ProofRequestStatus::Failed { .. } => {
                    request.provider_request_id.clone()
                }
            };

            if provider_request_id.is_none() {
                continue;
            }

            self.start_provernet_status_polling(request.request_id).await;
        }
    }

    async fn submit_provernet_request(
        &self,
        request_id: &str,
        proof_type: ProofType,
        input: Vec<u8>,
        output: Vec<u8>,
    ) -> AgentResult<(String, String)> {
        let cfg = self.provernet_config.clone().ok_or_else(|| {
            AgentError::ProverUnavailable("Brevis ProverNet config not provided".to_string())
        })?;

        let elf_type = match proof_type {
            ProofType::Batch => ElfType::Batch,
            ProofType::Aggregate => ElfType::Aggregation,
            ProofType::Update(_) => {
                return Err(AgentError::NotImplemented(
                    "ProofType::Update is deprecated; use /upload-image/brevis/{batch|aggregation}"
                        .to_string(),
                ));
            }
        };

        let public_values_digest: [u8; 32] = output.as_slice().try_into().map_err(|_| {
            AgentError::RequestBuildError(format!(
                "For brevis provernet, /proof.output must be bytes32 (32 bytes); got {} bytes",
                output.len()
            ))
        })?;

        let image = self
            .image_manager
            .get_image(ProverType::Brevis, elf_type.clone())
            .await
            .ok_or_else(|| {
                let label = match elf_type {
                    ElfType::Batch => "batch",
                    ElfType::Aggregation => "aggregation",
                };
                AgentError::ProgramUploadError(format!(
                    "Brevis {} ELF not uploaded. Use /upload-image/brevis/{}",
                    label, label
                ))
            })?;

        let vk_digest = image
            .image_id
            .or_else(|| self.compute_riscv_vkey_digest(&image.elf_bytes))
            .ok_or_else(|| {
                AgentError::RequestBuildError(
                    "Brevis vk unavailable; build with `--features brevis` or provide vk out-of-band"
                        .to_string(),
                )
            })?;
        let mut vk = [0u8; 32];
        vk.copy_from_slice(vk_digest.as_bytes());

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AgentError::RequestBuildError(format!("System clock error: {e}")))?
            .as_secs();

        let fee = fee_params_from_config(&cfg, now_secs)
            .map_err(|e| AgentError::RequestBuildError(e.to_string()))?;

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AgentError::RequestBuildError(format!("System clock error: {e}")))?
            .as_nanos() as u64;

        let img_url = build_img_url(&cfg.artifact_base_url, elf_type.clone())
            .map_err(|e| AgentError::RequestBuildError(e.to_string()))?;

        let (input_data, input_url) = if input.len() <= cfg.input_inline_max_bytes {
            (alloy::primitives::Bytes::from(input), String::new())
        } else {
            (
                alloy::primitives::Bytes::new(),
                build_input_url(&cfg.artifact_base_url, request_id)
                    .map_err(|e| AgentError::RequestBuildError(e.to_string()))?,
            )
        };

        let request = IBrevisMarket::ProofRequest {
            nonce,
            vk: B256::from(vk),
            publicValuesDigest: B256::from(public_values_digest),
            imgURL: img_url,
            inputData: input_data,
            inputURL: input_url,
            version: 0,
            fee,
        };

        let reqid = compute_reqid(nonce, vk, public_values_digest);
        let provider_request_id = format!("0x{}", hex::encode(reqid));

        let tx_hash = submit_market_request(&cfg, request)
            .await
            .map_err(|e| AgentError::RequestSubmitError(e.to_string()))?;

        Ok((provider_request_id, format!("0x{}", hex::encode(tx_hash))))
    }

    pub async fn upload_image(
        &self,
        elf_type: ElfType,
        elf_bytes: Vec<u8>,
    ) -> AgentResult<ImageUploadResult> {
        let reused = self
            .image_manager
            .get_image(ProverType::Brevis, elf_type.clone())
            .await
            .map(|img| img.elf_bytes == elf_bytes)
            .unwrap_or(false);

        let info = ImageInfo {
            image_id: self.compute_riscv_vkey_digest(&elf_bytes),
            remote_url: None,
            elf_bytes,
            refresh_at: None,
        };

        self.image_manager
            .set_image(ProverType::Brevis, elf_type, info.clone())
            .await;

        Ok(ImageUploadResult { info, reused })
    }

    async fn prepare_async_request(
        &self,
        request_id: String,
        proof_type: ProofType,
        input: Vec<u8>,
        config: &serde_json::Value,
    ) -> AgentResult<String> {
        let async_request = AsyncProofRequest {
            request_id: request_id.clone(),
            prover_type: ProverType::Brevis,
            provider_request_id: None,
            status: ProofRequestStatus::Preparing,
            proof_type,
            input,
            config: config.clone(),
        };

        if let Err(e) = self.storage.store_request(&async_request).await {
            tracing::warn!("Failed to store brevis request in SQLite: {}", e);
        }

        Ok(request_id)
    }

    async fn update_failed_status(&self, request_id: &str, error: String) {
        let failed_status = ProofRequestStatus::Failed { error };
        if let Err(e) = self.storage.update_status(request_id, &failed_status).await {
            tracing::warn!("Failed to update brevis failed status: {}", e);
        }
    }

    fn compute_riscv_vkey_digest(&self, elf_bytes: &[u8]) -> Option<risc0_zkvm::sha::Digest> {
        #[cfg(not(feature = "brevis"))]
        {
            let _ = elf_bytes;
            None
        }

        #[cfg(feature = "brevis")]
        {
            let riscv: RiscvProver<KoalaBearPoseidon2, Program> =
                RiscvProver::new_initial_prover(
                    (KoalaBearPoseidon2::new(), elf_bytes),
                    Default::default(),
                    None,
                );
            let riscv_vkey_hex = riscv.vk().hash_str_via_bn254();
            let bytes = decode_bytes32(&riscv_vkey_hex).ok()?;
            risc0_zkvm::sha::Digest::try_from(bytes.as_slice()).ok()
        }
    }
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>> {
    let trimmed = value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .unwrap_or(value.trim());
    hex::decode(trimmed).map_err(|e| anyhow!("Invalid hex bytes '{}': {}", value, e))
}

fn decode_bytes32(value: &str) -> Result<[u8; 32]> {
    let bytes = decode_hex_bytes(value)?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "Invalid bytes32 length for '{}': expected 32 bytes, got {}",
            value,
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_bytes32_rejects_wrong_length() {
        assert!(decode_bytes32("0x11").is_err());
        assert!(decode_bytes32(&format!("0x{}", "11".repeat(31))).is_err());
        assert!(decode_bytes32(&format!("0x{}", "11".repeat(33))).is_err());
    }

    #[tokio::test]
    async fn submit_proof_requires_provernet_config() {
        let image_manager = ImageManager::new();
        let storage = RequestStorage::new(":memory:".to_string());
        storage.initialize().await.unwrap();

        let prover = BrevisProver::new(image_manager, storage, None);

        let result = prover
            .submit_proof(
                "req_1".to_string(),
                ProofType::Batch,
                vec![1, 2, 3],
                vec![0u8; 32],
                serde_json::Value::Null,
                None,
            )
            .await;

        assert!(matches!(result, Err(AgentError::ProverUnavailable(_))));
    }

    #[test]
    fn build_urls_from_base() {
        let base = "https://agent.example.com";
        assert_eq!(
            build_img_url(base, ElfType::Batch).unwrap(),
            "https://agent.example.com/artifacts/brevis/batch.elf"
        );
        assert_eq!(
            build_img_url(base, ElfType::Aggregation).unwrap(),
            "https://agent.example.com/artifacts/brevis/aggregation.elf"
        );
        assert_eq!(
            build_input_url(base, "req_123").unwrap(),
            "https://agent.example.com/inputs/req_123"
        );
    }

    #[test]
    fn compute_reqid_matches_ethers_encode_packed() {
        use alloy_primitives_v1p2p0::keccak256;
        use ethers_core::abi::encode_packed;
        use ethers_core::abi::Token;
        use ethers_core::types::H256;

        let nonce: u64 = 42;
        let vk = [0x11u8; 32];
        let public_values_digest = [0x22u8; 32];

        let ours = compute_reqid(nonce, vk, public_values_digest);

        let packed = encode_packed(&[
            // `abi.encodePacked(uint64)` is exactly 8 big-endian bytes.
            Token::FixedBytes(nonce.to_be_bytes().to_vec()),
            Token::FixedBytes(vk.to_vec()),
            Token::FixedBytes(public_values_digest.to_vec()),
        ])
        .expect("encode_packed");
        let expected: [u8; 32] = keccak256(&packed).into();
        assert_eq!(ours, expected);

        // sanity: must match H256 conversion too
        let h256 = H256::from(expected);
        assert_eq!(h256.as_bytes(), &ours);
    }

    #[test]
    fn extract_proof_from_logs_decodes_proof_submitted_event() {
        use alloy_primitives_v1p2p0::{Address, Log as PrimitiveLog, U256, B256};

        let market_addr = Address::repeat_byte(0x11);
        let reqid = B256::repeat_byte(0x22);
        let prover = Address::repeat_byte(0x33);
        let proof = [
            U256::from(1),
            U256::from(2),
            U256::from(3),
            U256::from(4),
            U256::from(5),
            U256::from(6),
            U256::from(7),
            U256::from(8),
        ];

        let event = IBrevisMarket::ProofSubmitted {
            reqid,
            prover,
            proof,
            actualFee: U256::from(123),
        };

        let typed = PrimitiveLog::new_from_event_unchecked(market_addr, event);
        let raw_inner = typed.reserialize();
        let raw = alloy::rpc::types::Log {
            inner: raw_inner,
            block_hash: None,
            block_number: None,
            block_timestamp: None,
            transaction_hash: None,
            transaction_index: None,
            log_index: None,
            removed: false,
        };

        let decoded = extract_proof_from_logs(reqid, vec![raw]).unwrap().unwrap();
        assert_eq!(decoded, proof);
    }
}
