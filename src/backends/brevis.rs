use crate::image_manager::{ImageInfo, ImageManager, ImageUploadResult};
use crate::storage::RequestStorage;
use crate::types::{
    AgentError, AgentResult, AsyncProofRequest, ElfType, ProofRequestStatus, ProofType, ProverType,
};
use alloy_primitives_v1p2p0::{hex, U256};
#[cfg(feature = "brevis")]
use alloy_primitives_v1p2p0::keccak256;
#[cfg(feature = "brevis")]
use pico_vm::{
    compiler::riscv::program::Program,
    configs::config::StarkGenericConfig,
    configs::stark_config::KoalaBearPoseidon2,
    emulator::stdin::EmulatorStdinBuilder,
    machine::proof::MetaProof,
    machine::keys::{BaseVerifyingKey, HashableKey},
    proverchain::{InitialProverSetup, MachineProver, RiscvProver},
};
#[cfg(feature = "brevis_evm")]
use pico_vm::configs::field_config::KoalaBearBn254;
#[cfg(feature = "brevis_evm")]
use pico_sdk::command::execute_command;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
#[cfg(feature = "brevis_evm")]
use std::process::Command;
#[cfg(feature = "brevis")]
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};

#[cfg(feature = "brevis")]
struct PicoRiscvClient {
    riscv: RiscvProver<KoalaBearPoseidon2, Program>,
}

#[cfg(feature = "brevis")]
impl PicoRiscvClient {
    fn new(elf: &[u8]) -> Self {
        let riscv = RiscvProver::new_initial_prover((KoalaBearPoseidon2::new(), elf), Default::default(), None);
        Self { riscv }
    }

    fn vk(&self) -> &BaseVerifyingKey<KoalaBearPoseidon2> {
        self.riscv.vk()
    }

    fn prove_riscv(
        &self,
        stdin: EmulatorStdinBuilder<Vec<u8>, KoalaBearPoseidon2>,
    ) -> Result<MetaProof<KoalaBearPoseidon2>> {
        let (stdin, _) = stdin.finalize();
        Ok(self.riscv.prove(stdin))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrevisProofBundle {
    pub riscv_vkey: [u8; 32],
    pub public_values: Vec<u8>,
    pub proof: [U256; 8],
    pub pico_proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrevisAggregationInput {
    guest_input: Vec<u8>,
    pico_proofs: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct BrevisProverConfig {
    pub max_concurrency: usize,
    pub max_proof_timeout_secs: u64,
}

impl Default for BrevisProverConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 1,
            max_proof_timeout_secs: 3600,
        }
    }
}

impl BrevisProverConfig {
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            max_concurrency: std::env::var("PICO_MAX_CONCURRENCY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.max_concurrency),
            max_proof_timeout_secs: std::env::var("PICO_MAX_PROOF_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.max_proof_timeout_secs),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BrevisProver {
    image_manager: ImageManager,
    storage: RequestStorage,
    config: BrevisProverConfig,
    concurrency: Arc<Semaphore>,
    program_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl BrevisProver {
    pub fn new(image_manager: ImageManager, storage: RequestStorage) -> Self {
        let config = BrevisProverConfig::from_env();
        let concurrency = Arc::new(Semaphore::new(config.max_concurrency));
        Self {
            image_manager,
            storage,
            config,
            concurrency,
            program_locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn submit_proof(
        &self,
        request_id: String,
        proof_type: ProofType,
        input: Vec<u8>,
        _output: Vec<u8>,
        config: serde_json::Value,
        _elf: Option<Vec<u8>>,
    ) -> AgentResult<String> {
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
        tokio::spawn(async move {
            let provider_request_id = request_id_clone.clone();
            let locked_status = ProofRequestStatus::Locked {
                provider_request_id: provider_request_id.clone(),
                prover: Some("brevis".to_string()),
            };
            if let Err(e) = prover
                .storage
                .update_status(&request_id_clone, &locked_status)
                .await
            {
                tracing::warn!("Failed to update brevis request status: {}", e);
            }

            let result = match proof_type {
                ProofType::Batch => prover
                    .run_pico_proof(&request_id_clone, ElfType::Batch, input)
                    .await
                    .map(|resp| (resp, "batch".to_string())),
                ProofType::Aggregate => prover
                    .run_pico_proof(&request_id_clone, ElfType::Aggregation, input)
                    .await
                    .map(|resp| (resp, "aggregation".to_string())),
                ProofType::Update(_) => unreachable!("handled above"),
            };

            match result {
                Ok((response, label)) => {
                    let proof_bytes = match bincode::serialize(&response) {
                        Ok(data) => data,
                        Err(e) => {
                            return prover
                                .update_failed_status(
                                    &request_id_clone,
                                    format!(
                                        "Failed to serialize brevis {} response: {}",
                                        label, e
                                    ),
                                )
                                .await;
                        }
                    };

                    let fulfilled = ProofRequestStatus::Fulfilled {
                        provider_request_id,
                        proof: proof_bytes,
                    };
                    if let Err(e) = prover.storage.update_status(&request_id_clone, &fulfilled).await
                    {
                        tracing::warn!("Failed to update fulfilled brevis status: {}", e);
                    }
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

    async fn program_mutex(&self, key: &str) -> Arc<Mutex<()>> {
        let mut locks = self.program_locks.lock().await;
        locks
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn run_pico_proof(
        &self,
        request_id: &str,
        elf_type: ElfType,
        input: Vec<u8>,
    ) -> AgentResult<BrevisProofBundle> {
        #[cfg(not(feature = "brevis"))]
        {
            let _ = (request_id, elf_type, input);
            return Err(AgentError::NotImplemented(
                "brevis support requires building with `--features brevis`".to_string(),
            ));
        }

        #[cfg(feature = "brevis")]
        {
            let image = self
                .image_manager
                .get_image(ProverType::Brevis, elf_type.clone())
                .await
                .ok_or_else(|| {
                    let label = elf_label(&elf_type);
                    AgentError::ProgramUploadError(format!(
                        "Brevis {} ELF not uploaded. Use /upload-image/brevis/{}",
                        label, label
                    ))
                })?;

            let is_aggregation = matches!(&elf_type, ElfType::Aggregation);
            let batch_elf_bytes = if is_aggregation {
                let batch_image = self
                    .image_manager
                    .get_image(ProverType::Brevis, ElfType::Batch)
                    .await
                    .ok_or_else(|| {
                        AgentError::ProgramUploadError(
                            "Brevis batch ELF not uploaded; upload /upload-image/brevis/batch"
                                .to_string(),
                        )
                    })?;
                Some(batch_image.elf_bytes.clone())
            } else {
                None
            };

            let elf_bytes = image.elf_bytes.clone();
            let request_id = request_id.to_string();
            let max_timeout = self.config.max_proof_timeout_secs;
            let semaphore = self.concurrency.clone();
            let program_hash = hex::encode(keccak256(&elf_bytes));
            let lock_key = format!("{}:0x{}", elf_label(&elf_type), program_hash);
            let program_lock = self.program_mutex(&lock_key).await;

            let bundle = tokio::time::timeout(
                Duration::from_secs(max_timeout),
                async move {
                    let _permit = semaphore.acquire().await.map_err(|_| {
                        anyhow!("Brevis prover concurrency limiter closed unexpectedly")
                    })?;
                    let _lock_guard = program_lock.lock().await;

                    tokio::task::spawn_blocking(move || {
                        let client = PicoRiscvClient::new(&elf_bytes);
                        let riscv_vkey_hex = client.vk().hash_str_via_bn254();

                        let (guest_input, pico_proofs) = if is_aggregation {
                            let wrapper: BrevisAggregationInput =
                                bincode::deserialize(&input).map_err(|e| {
                                    anyhow!("Failed to decode brevis aggregation input: {e}")
                                })?;
                            if wrapper.pico_proofs.is_empty() {
                                return Err(anyhow!("Brevis aggregation input missing pico proofs"));
                            }
                            (wrapper.guest_input, wrapper.pico_proofs)
                        } else {
                            (input, Vec::new())
                        };

                        let mut stdin_builder = EmulatorStdinBuilder::default();
                        stdin_builder.write_slice(&guest_input);

                        if let Some(batch_elf_bytes) = batch_elf_bytes {
                            let batch_client = PicoRiscvClient::new(&batch_elf_bytes);
                            let batch_vk = batch_client.vk().clone();
                            for proof_bytes in pico_proofs {
                                let proof: MetaProof<KoalaBearPoseidon2> =
                                    bincode::deserialize(&proof_bytes).map_err(|e| {
                                        anyhow!("Failed to decode pico proof: {e}")
                                    })?;
                                stdin_builder.write_pico_proof(proof, batch_vk.clone());
                            }
                        }

                        let bundle = {
                            #[cfg(feature = "brevis_evm")]
                            {
                                use pico_sdk::client::KoalaBearProverClient;

                                let evm_client = KoalaBearProverClient::new(&elf_bytes);
                                let program_dir = pico_cache_dir()
                                    .join("kb")
                                    .join("programs")
                                    .join(riscv_vkey_hex.trim_start_matches("0x"));

                                let bundle =
                                    prove_evm_and_parse(&evm_client, &program_dir, stdin_builder)?;

                                tracing::info!(
                                    "Brevis proof generated for request {} (program_dir={})",
                                    request_id,
                                    program_dir.display()
                                );

                                bundle
                            }

                            #[cfg(not(feature = "brevis_evm"))]
                            {
                                let riscv_proof = client.prove_riscv(stdin_builder)?;

                                let pico_proof = bincode::serialize(&riscv_proof).map_err(|e| {
                                    anyhow!("Failed to serialize pico proof: {e}")
                                })?;

                                tracing::info!(
                                    "Brevis proof generated for request {} (pico only; EVM artifacts disabled)",
                                    request_id
                                );

                                BrevisProofBundle {
                                    riscv_vkey: decode_bytes32(&riscv_vkey_hex)?,
                                    public_values: Vec::new(),
                                    proof: [U256::ZERO; 8],
                                    pico_proof,
                                }
                            }
                        };

                        Ok::<_, anyhow::Error>(bundle)
                    })
                    .await
                    .map_err(|e| anyhow!("Brevis prove task failed: {}", e))?
                },
            )
            .await
            .map_err(|_| {
                AgentError::GuestExecutionError(format!(
                    "Brevis proof timed out after {} seconds",
                    max_timeout
                ))
            })?
            .map_err(|e| AgentError::GuestExecutionError(e.to_string()))?;

            Ok(bundle)
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
            let client = PicoRiscvClient::new(elf_bytes);
            let riscv_vkey_hex = client.vk().hash_str_via_bn254();
            let bytes = decode_bytes32(&riscv_vkey_hex).ok()?;
            risc0_zkvm::sha::Digest::try_from(bytes.as_slice()).ok()
        }
    }
}

fn brevis_base_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PICO_BASE_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    std::env::temp_dir().join("raiko-agent").join("brevis")
}

fn pico_cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PICO_CACHE_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    brevis_base_dir().join("pico-cache")
}

fn elf_label(elf_type: &ElfType) -> &'static str {
    match elf_type {
        ElfType::Batch => "batch",
        ElfType::Aggregation => "aggregation",
    }
}

#[cfg(feature = "brevis_evm")]
fn prove_evm_and_parse(
    client: &pico_sdk::client::KoalaBearProverClient,
    program_dir: &Path,
    stdin_builder: EmulatorStdinBuilder<Vec<u8>, KoalaBearPoseidon2>,
) -> Result<BrevisProofBundle>
{
    std::fs::create_dir_all(program_dir)?;

    let inputs_path = program_dir.join("inputs.json");
    if inputs_path.exists() {
        let _ = std::fs::remove_file(&inputs_path);
    }

    let need_setup = !program_dir.join("Groth16Verifier.sol").exists();

    let mut riscv_proof: Option<MetaProof<KoalaBearPoseidon2>> = None;
    let run_prove = |setup: bool| -> Result<MetaProof<KoalaBearPoseidon2>> {
        let (riscv_proof, embed_proof) = client.prove(stdin_builder.clone())?;
        client.write_onchain_data(program_dir, &riscv_proof, &embed_proof)?;

        if setup {
            let mut setup_cmd = Command::new("sh");
            setup_cmd.arg("-c")
                .arg(format!("docker run --rm -v {}:/data brevishub/pico_gnark_cli:1.2 /pico_gnark_cli -field kb -cmd setup -sol ./data/Groth16Verifier.sol", program_dir.display()));
            execute_command(setup_cmd);
        }

        let mut prove_cmd = Command::new("sh");
        prove_cmd.arg("-c")
            .arg(format!("docker run --rm -v {}:/data brevishub/pico_gnark_cli:1.2 /pico_gnark_cli -field kb -cmd prove -sol ./data/Groth16Verifier.sol", program_dir.display()));
        execute_command(prove_cmd);

        pico_vm::instances::compiler::onchain_circuit::utils::generate_contract_inputs::<
            KoalaBearBn254,
        >(program_dir.to_path_buf())?;

        Ok(riscv_proof)
    };

    let call = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_prove(need_setup)));

    let mut last_err: Option<anyhow::Error> = None;
    match call {
        Ok(Ok(proof)) => riscv_proof = Some(proof),
        Ok(Err(e)) => last_err = Some(e),
        Err(_) => last_err = Some(anyhow!("Pico SDK panicked while running EVM proving")),
    }

    if !inputs_path.exists() {
        tracing::warn!(
            "Brevis inputs.json missing after prove (need_setup={}, retrying with setup)",
            need_setup
        );

        let retry = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_prove(true)));

        match retry {
            Ok(Ok(proof)) => riscv_proof = Some(proof),
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => last_err = Some(anyhow!("Pico SDK panicked while running EVM proving (retry)")),
        }
    }

    if !inputs_path.exists() {
        return Err(last_err.unwrap_or_else(|| anyhow!("EVM proving did not produce inputs.json")));
    }

    let mut bundle = parse_inputs_json(&inputs_path)?;
    let riscv_proof = riscv_proof.ok_or_else(|| anyhow!("Missing riscv proof output"))?;
    bundle.pico_proof = bincode::serialize(&riscv_proof)
        .map_err(|e| anyhow!("Failed to serialize pico proof: {e}"))?;

    use pico_sdk::HashableKey;
    let expected_vkey_hex = client.riscv_vk().hash_str_via_bn254();
    let expected_vkey = decode_bytes32(&expected_vkey_hex)?;
    if bundle.riscv_vkey != expected_vkey {
        return Err(anyhow!(
            "riscvVKey mismatch: inputs.json={}, expected={}",
            hex::encode(bundle.riscv_vkey),
            expected_vkey_hex
        ));
    }

    Ok(bundle)
}

fn parse_inputs_json(path: &Path) -> Result<BrevisProofBundle> {
    let contents =
        std::fs::read_to_string(path).map_err(|e| anyhow!("Failed to read {:?}: {}", path, e))?;
    let inputs: PicoInputsJson =
        serde_json::from_str(&contents).map_err(|e| anyhow!("Invalid inputs.json: {}", e))?;

    let riscv_vkey = decode_bytes32(&inputs.riscv_vkey)?;
    let public_values = decode_hex_bytes(&inputs.public_values)?;
    let proof = parse_u256_proof_array(&inputs.proof)?;

    Ok(BrevisProofBundle {
        riscv_vkey,
        public_values,
        proof,
        pico_proof: Vec::new(),
    })
}

#[derive(Debug, Deserialize)]
struct PicoInputsJson {
    #[serde(rename = "riscvVKey")]
    riscv_vkey: String,
    proof: Vec<String>,
    #[serde(rename = "publicValues")]
    public_values: String,
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

fn parse_u256_proof_array(values: &[String]) -> Result<[U256; 8]> {
    if values.len() < 8 {
        return Err(anyhow!(
            "Invalid proof length: expected at least 8 elements, got {}",
            values.len()
        ));
    }

    let parsed: Vec<U256> = values
        .iter()
        .take(8)
        .map(|value| {
            let trimmed = value
                .trim()
                .strip_prefix("0x")
                .or_else(|| value.trim().strip_prefix("0X"))
                .unwrap_or(value.trim());
            U256::from_str_radix(trimmed, 16)
                .map_err(|e| anyhow!("Invalid proof element '{}': {}", value, e))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok([
        parsed[0], parsed[1], parsed[2], parsed[3], parsed[4], parsed[5], parsed[6], parsed[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(label: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("raiko-agent-{}-{}", label, now))
    }

    #[test]
    fn test_parse_inputs_json_roundtrip() {
        let dir = unique_temp_dir("brevis-inputs");
        std::fs::create_dir_all(&dir).unwrap();

        let riscv_vkey = [0x11u8; 32];
        let riscv_vkey_hex = format!("0x{}", hex::encode(riscv_vkey));
        let public_values = vec![0xde, 0xad, 0xbe, 0xef];
        let public_values_hex = format!("0x{}", hex::encode(&public_values));
        let proof: Vec<String> = (1u64..=8).map(|i| format!("0x{i:x}")).collect();

        let json = serde_json::json!({
            "riscvVKey": riscv_vkey_hex,
            "proof": proof,
            "publicValues": public_values_hex,
        });

        let path = dir.join("inputs.json");
        std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

        let bundle = parse_inputs_json(&path).unwrap();
        assert_eq!(bundle.riscv_vkey, riscv_vkey);
        assert_eq!(bundle.public_values, public_values);
        assert_eq!(bundle.proof[0], U256::from(1u64));
        assert_eq!(bundle.proof[7], U256::from(8u64));
        assert!(bundle.pico_proof.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_decode_bytes32_rejects_wrong_length() {
        assert!(decode_bytes32("0x11").is_err());
        assert!(decode_bytes32(&format!("0x{}", "11".repeat(31))).is_err());
        assert!(decode_bytes32(&format!("0x{}", "11".repeat(33))).is_err());
    }
}
