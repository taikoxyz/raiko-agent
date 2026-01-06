use crate::image_manager::{ImageInfo, ImageManager, ImageUploadResult};
use crate::storage::RequestStorage;
use crate::types::{
    AgentError, AgentResult, AsyncProofRequest, ElfType, ProofRequestStatus, ProofType,
    ProverType,
};
use alloy_primitives_v1p2p0::{hex, keccak256};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::sync::{Mutex, Notify};

const PROOF_FILE_NAME: &str = "final_proof.bin";
const PUBLICS_FILE_NAME: &str = "publics.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZiskResponse {
    pub proof: Option<String>,
    pub receipt: Option<String>,
    pub input: Option<[u8; 32]>,
    pub uuid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ZiskProverConfig {
    pub verify: bool,
    pub concurrent_processes: Option<u32>,
    pub threads_per_process: Option<u32>,
    pub max_proof_timeout_secs: u64,
}

impl Default for ZiskProverConfig {
    fn default() -> Self {
        Self {
            verify: true,
            concurrent_processes: None,
            threads_per_process: None,
            max_proof_timeout_secs: 3600,
        }
    }
}

impl ZiskProverConfig {
    pub fn from_env() -> Self {
        let defaults = Self::default();

        Self {
            verify: std::env::var("ZISK_VERIFY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.verify),
            concurrent_processes: std::env::var("ZISK_CONCURRENT_PROCESSES")
                .ok()
                .and_then(|v| v.parse().ok())
                .or(defaults.concurrent_processes),
            threads_per_process: std::env::var("ZISK_THREADS_PER_PROCESS")
                .ok()
                .and_then(|v| v.parse().ok())
                .or(defaults.threads_per_process),
            max_proof_timeout_secs: std::env::var("ZISK_MAX_PROOF_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.max_proof_timeout_secs),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ZiskProver {
    image_manager: ImageManager,
    storage: RequestStorage,
    config: ZiskProverConfig,
}

impl ZiskProver {
    pub fn new(image_manager: ImageManager, storage: RequestStorage) -> Self {
        Self {
            image_manager,
            storage,
            config: ZiskProverConfig::from_env(),
        }
    }

    pub async fn submit_proof(
        &self,
        request_id: String,
        proof_type: ProofType,
        input: Vec<u8>,
        output: Vec<u8>,
        config: serde_json::Value,
        elf: Option<Vec<u8>>,
    ) -> AgentResult<String> {
        match proof_type {
            ProofType::Batch | ProofType::Aggregate => {
                if let Some(existing_request) = self
                    .storage
                    .get_request_by_input_hash(&input, &proof_type, &ProverType::Zisk)
                    .await?
                {
                    match &existing_request.status {
                        ProofRequestStatus::Preparing
                        | ProofRequestStatus::Submitted { .. }
                        | ProofRequestStatus::Locked { .. }
                        | ProofRequestStatus::Fulfilled { .. } => {
                            tracing::info!(
                                "Returning existing zisk request {} for identical input",
                                existing_request.request_id
                            );
                            return Ok(existing_request.request_id);
                        }
                        ProofRequestStatus::Failed { error } => {
                            tracing::info!(
                                "Found failed zisk request for same input ({}), creating new request",
                                error
                            );
                        }
                    }
                }
            }
            ProofType::Update(_) => {}
        }

        let final_request_id = self
            .prepare_async_request(request_id.clone(), proof_type.clone(), input.clone(), &config)
            .await?;

        let prover = self.clone();
        let request_id_clone = request_id.clone();
        tokio::spawn(async move {
            let provider_request_id = request_id_clone.clone();

            let locked_status = ProofRequestStatus::Locked {
                provider_request_id: provider_request_id.clone(),
                prover: Some("zisk".to_string()),
            };
            if let Err(e) = prover.storage.update_status(&request_id_clone, &locked_status).await {
                tracing::warn!("Failed to update zisk request status: {}", e);
            }

            let result = match proof_type {
                ProofType::Batch => {
                    prover
                        .run_batch_proof(&request_id_clone, input, output)
                        .await
                        .map(|resp| (resp, "batch".to_string()))
                }
                ProofType::Aggregate => {
                    prover
                        .run_aggregation_proof(&request_id_clone, input)
                        .await
                        .map(|resp| (resp, "aggregation".to_string()))
                }
                ProofType::Update(elf_type) => {
                    let elf = match elf {
                        Some(data) => data,
                        None => {
                            return prover
                                .update_failed_status(
                                    &request_id_clone,
                                    "ELF data is required for Update proof type".to_string(),
                                )
                                .await;
                        }
                    };
                    let upload_result = prover.upload_image(elf_type, elf).await;
                    match upload_result {
                        Ok(_result) => {
                            let response = ZiskResponse {
                                proof: None,
                                receipt: Some("zisk_update".to_string()),
                                input: None,
                                uuid: Some(request_id_clone.clone()),
                            };
                            Ok((response, "update".to_string()))
                        }
                        Err(err) => Err(err),
                    }
                }
            };

            match result {
                Ok((response, label)) => {
                    let proof_bytes = match bincode::serialize(&response) {
                        Ok(data) => data,
                        Err(e) => {
                            return prover
                                .update_failed_status(
                                    &request_id_clone,
                                    format!("Failed to serialize zisk {} response: {}", label, e),
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
                        tracing::warn!("Failed to update fulfilled zisk status: {}", e);
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
            .get_image(ProverType::Zisk, elf_type.clone())
            .await
            .map(|img| img.elf_bytes == elf_bytes)
            .unwrap_or(false);

        let info = ImageInfo {
            image_id: None,
            remote_url: None,
            elf_bytes,
            refresh_at: None,
        };

        self.image_manager
            .set_image(ProverType::Zisk, elf_type, info.clone())
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
            prover_type: ProverType::Zisk,
            provider_request_id: None,
            status: ProofRequestStatus::Preparing,
            proof_type,
            input,
            config: config.clone(),
        };

        if let Err(e) = self.storage.store_request(&async_request).await {
            tracing::warn!("Failed to store zisk request in SQLite: {}", e);
        }

        Ok(request_id)
    }

    async fn update_failed_status(&self, request_id: &str, error: String) {
        let failed_status = ProofRequestStatus::Failed { error };
        if let Err(e) = self.storage.update_status(request_id, &failed_status).await {
            tracing::warn!("Failed to update zisk failed status: {}", e);
        }
    }

    async fn run_batch_proof(
        &self,
        request_id: &str,
        input: Vec<u8>,
        output: Vec<u8>,
    ) -> AgentResult<ZiskResponse> {
        let batch_image = self
            .image_manager
            .get_image(ProverType::Zisk, ElfType::Batch)
            .await
            .ok_or_else(|| {
                AgentError::ProgramUploadError(
                    "Zisk batch ELF not uploaded. Use /upload-image/zisk/batch".to_string(),
                )
            })?;

        let expected_input = if output.is_empty() {
            None
        } else if output.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&output);
            Some(bytes)
        } else {
            return Err(AgentError::RequestBuildError(format!(
                "Invalid batch output length: expected 32 bytes, got {}",
                output.len()
            )));
        };

        let config = self.config.clone();
        let batch_elf_bytes = batch_image.elf_bytes.clone();
        let request_id = request_id.to_string();
        let input_copy = input.clone();
        let max_timeout = config.max_proof_timeout_secs;

        let response = tokio::time::timeout(
            Duration::from_secs(max_timeout),
            async move {
                execute_batch_proof(&request_id, &input_copy, expected_input, &batch_elf_bytes, &config).await
            },
        )
        .await
        .map_err(|_| {
            AgentError::GuestExecutionError(format!(
                "Zisk batch proof timed out after {} seconds",
                max_timeout
            ))
        })?
        .map_err(|e| AgentError::GuestExecutionError(e.to_string()))?;

        Ok(response)
    }

    async fn run_aggregation_proof(
        &self,
        request_id: &str,
        input: Vec<u8>,
    ) -> AgentResult<ZiskResponse> {
        let aggregation_image = self
            .image_manager
            .get_image(ProverType::Zisk, ElfType::Aggregation)
            .await
            .ok_or_else(|| {
                AgentError::ProgramUploadError(
                    "Zisk aggregation ELF not uploaded. Use /upload-image/zisk/aggregation"
                        .to_string(),
                )
            })?;

        let config = self.config.clone();
        let aggregation_elf_bytes = aggregation_image.elf_bytes.clone();
        let request_id = request_id.to_string();
        let max_timeout = config.max_proof_timeout_secs;

        let response = tokio::time::timeout(
            Duration::from_secs(max_timeout),
            async move {
                execute_aggregation_proof(
                    &request_id,
                    &input,
                    &aggregation_elf_bytes,
                    &config,
                )
                .await
            },
        )
        .await
        .map_err(|_| {
            AgentError::GuestExecutionError(format!(
                "Zisk aggregation proof timed out after {} seconds",
                max_timeout
            ))
        })?
        .map_err(|e| AgentError::GuestExecutionError(e.to_string()))?;

        Ok(response)
    }
}

fn build_base_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ZISK_BUILD_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }

    std::env::temp_dir().join("raiko-agent").join("zisk")
}

fn elf_cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ZISK_ELF_CACHE_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }

    build_base_dir().join("elf-cache")
}

fn cache_elf(elf_type: ElfType, elf_bytes: &[u8]) -> Result<PathBuf> {
    let hash = keccak256(elf_bytes);
    let hash_hex = hex::encode(hash);
    let label = match elf_type {
        ElfType::Batch => "batch",
        ElfType::Aggregation => "aggregation",
    };

    let dir = elf_cache_dir();
    std::fs::create_dir_all(&dir)?;

    let file_name = format!("zisk-{}-{}.elf", label, hash_hex);
    let path = dir.join(file_name);
    if !path.exists() {
        std::fs::write(&path, elf_bytes)?;
    }
    Ok(path)
}

fn run_command_streaming(mut command: Command, label: &str) -> Result<()> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|e| anyhow!("Failed to spawn {}: {}", label, e))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("Failed to capture {} stdout", label))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("Failed to capture {} stderr", label))?;

    let stdout_label = format!("{} stdout", label);
    let stderr_label = format!("{} stderr", label);

    let stdout_handle = std::thread::spawn(move || {
        let mut collected = String::new();
        let reader = BufReader::new(stdout);
        for line in reader.lines().flatten() {
            tracing::info!("[{}] {}", stdout_label, line);
            collected.push_str(&line);
            collected.push('\n');
        }
        collected
    });

    let stderr_handle = std::thread::spawn(move || {
        let mut collected = String::new();
        let reader = BufReader::new(stderr);
        for line in reader.lines().flatten() {
            tracing::error!("[{}] {}", stderr_label, line);
            collected.push_str(&line);
            collected.push('\n');
        }
        collected
    });

    let status = child
        .wait()
        .map_err(|e| anyhow!("Failed to wait for {}: {}", label, e))?;

    let stdout_collected = stdout_handle.join().unwrap_or_default();
    let stderr_collected = stderr_handle.join().unwrap_or_default();

    if !status.success() {
        let message = if stderr_collected.trim().is_empty() {
            stdout_collected
        } else {
            stderr_collected
        };
        return Err(anyhow!("{} failed: {}", label, message.trim_end()));
    }

    Ok(())
}

struct RomSetupCoordinator {
    completed: Mutex<HashSet<String>>,
    in_progress: Mutex<HashMap<String, Arc<Notify>>>,
}

impl RomSetupCoordinator {
    fn new() -> Self {
        Self {
            completed: Mutex::new(HashSet::new()),
            in_progress: Mutex::new(HashMap::new()),
        }
    }
}

static ROM_SETUP_STATE: LazyLock<RomSetupCoordinator> = LazyLock::new(RomSetupCoordinator::new);

async fn ensure_rom_setup(elf_path: &str) -> Result<()> {
    let coordinator = &*ROM_SETUP_STATE;

    {
        let completed = coordinator.completed.lock().await;
        if completed.contains(elf_path) {
            tracing::info!("ROM setup already completed for ELF: {}", elf_path);
            return Ok(());
        }
    }

    let notify_handle = {
        let mut in_progress = coordinator.in_progress.lock().await;

        {
            let completed = coordinator.completed.lock().await;
            if completed.contains(elf_path) {
                tracing::info!("ROM setup already completed for ELF: {}", elf_path);
                return Ok(());
            }
        }

        if let Some(existing_notify) = in_progress.get(elf_path) {
            tracing::info!("ROM setup in progress for ELF: {}, waiting...", elf_path);
            existing_notify.clone()
        } else {
            let notify = Arc::new(Notify::new());
            in_progress.insert(elf_path.to_string(), notify.clone());

            tracing::info!("Starting ROM setup for ELF: {} (first request)", elf_path);

            drop(in_progress);

            let rom_result = tokio::task::spawn_blocking({
                let elf_path = elf_path.to_string();
                move || {
                    let mut command = Command::new("cargo-zisk");
                    command.args(["rom-setup", "-e", &elf_path]);
                    run_command_streaming(command, "cargo-zisk rom-setup")
                }
            })
            .await;

            let rom_result = match rom_result {
                Ok(result) => result,
                Err(e) => return Err(anyhow!("ROM setup task failed: {}", e)),
            };

            if let Err(err) = rom_result {
                coordinator.in_progress.lock().await.remove(elf_path);
                notify.notify_waiters();
                return Err(err);
            }

            {
                let mut completed = coordinator.completed.lock().await;
                completed.insert(elf_path.to_string());
            }

            coordinator.in_progress.lock().await.remove(elf_path);
            notify.notify_waiters();

            tracing::info!("ROM setup completed successfully for {}", elf_path);
            return Ok(());
        }
    };

    notify_handle.notified().await;

    let completed = coordinator.completed.lock().await;
    if completed.contains(elf_path) {
        tracing::info!("ROM setup completed by another request for ELF: {}", elf_path);
        Ok(())
    } else {
        Err(anyhow!("ROM setup failed for ELF: {}", elf_path))
    }
}

fn prepare_output_dir(work_dir: &Path, label: &str) -> Result<PathBuf> {
    let output_dir = work_dir.join(format!("output-{}", label));
    std::fs::create_dir_all(&output_dir)?;
    std::fs::create_dir_all(output_dir.join("proofs"))?;

    let proof_file = output_dir.join(PROOF_FILE_NAME);
    let publics_file = output_dir.join(PUBLICS_FILE_NAME);
    if proof_file.exists() {
        std::fs::remove_file(&proof_file)?;
    }
    if publics_file.exists() {
        std::fs::remove_file(&publics_file)?;
    }
    if let Ok(entries) = std::fs::read_dir(&output_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "bin" {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }
    }

    Ok(output_dir)
}

fn locate_proof_file(output_dir: &Path) -> Result<PathBuf> {
    let default_path = output_dir.join(PROOF_FILE_NAME);
    if default_path.exists() {
        return Ok(default_path);
    }

    let mut best: Option<(PathBuf, u64)> = None;
    let candidate_dirs = [output_dir.to_path_buf(), output_dir.join("proofs")];

    for dir in candidate_dirs {
        if !dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "bin" {
                        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                        match &best {
                            Some((_, best_size)) if *best_size >= size => {}
                            _ => best = Some((path, size)),
                        }
                    }
                }
            }
        }
    }

    if let Some((path, _)) = best {
        tracing::info!("Using discovered proof file at {:?}", path);
        Ok(path)
    } else {
        Err(anyhow!(
            "Proof file not generated in output dir: {:?}",
            output_dir
        ))
    }
}

fn cleanup_intermediate_proofs(output_dir: &Path) {
    if std::env::var("ZISK_KEEP_PROOF_INTERMEDIATE").is_ok() {
        return;
    }

    let proofs_dir = output_dir.join("proofs");
    if proofs_dir.exists() {
        if let Err(err) = std::fs::remove_dir_all(&proofs_dir) {
            tracing::warn!(
                "Failed to remove intermediate proofs at {:?}: {}",
                proofs_dir,
                err
            );
        }
    }
}

fn read_public_input_from_output(output_dir: &Path) -> Result<[u8; 32]> {
    let publics_file = output_dir.join(PUBLICS_FILE_NAME);
    if !publics_file.exists() {
        return Err(anyhow!(
            "Public input file not found at: {:?}",
            publics_file
        ));
    }

    let contents = std::fs::read_to_string(&publics_file)
        .map_err(|e| anyhow!("Failed to read {:?}: {e}", publics_file))?;
    let values: Vec<serde_json::Value> =
        serde_json::from_str(&contents).map_err(|e| anyhow!("Invalid publics JSON: {e}"))?;

    if values.len() < 8 {
        return Err(anyhow!(
            "Publics file contains {} values, expected at least 8",
            values.len()
        ));
    }

    let parsed_values: Vec<u64> = values
        .iter()
        .enumerate()
        .map(|(i, value)| parse_public_value(value, i))
        .collect::<Result<Vec<_>>>()?;

    let mut start_idx = 0usize;
    if parsed_values.len() >= 5 {
        let header_has_large_values = parsed_values[..4]
            .iter()
            .any(|value| *value > u32::MAX as u64);
        let output_count = parsed_values[4] as usize;
        if header_has_large_values
            && output_count > 0
            && output_count <= 32
            && parsed_values.len() >= 5 + output_count
        {
            start_idx = 5;
        }
    }

    let output_values = &parsed_values[start_idx..];
    if output_values.len() < 8 {
        return Err(anyhow!(
            "Publics file contains {} output values, expected at least 8",
            output_values.len()
        ));
    }

    let mut bytes = [0u8; 32];
    for (i, word_u64) in output_values.iter().take(8).enumerate() {
        let value_index = start_idx + i;
        let word_u32 = u32::try_from(*word_u64).map_err(|_| {
            anyhow!(
                "Public value {} out of u32 range: {}",
                value_index,
                word_u64
            )
        })?;
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_u32.to_le_bytes());
    }

    Ok(bytes)
}

fn parse_public_value(value: &serde_json::Value, index: usize) -> Result<u64> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    if let Some(text) = value.as_str() {
        return text
            .parse::<u64>()
            .map_err(|e| anyhow!("Public value {} parse failed: {e}", index));
    }

    Err(anyhow!(
        "Public value {} has unexpected format: {}",
        index,
        value
    ))
}

async fn execute_batch_proof(
    request_id: &str,
    input_data: &[u8],
    expected_input: Option<[u8; 32]>,
    batch_elf_bytes: &[u8],
    config: &ZiskProverConfig,
) -> Result<ZiskResponse> {
    let work_dir = build_base_dir().join(request_id);
    std::fs::create_dir_all(&work_dir)?;

    let input_file = work_dir.join("input.bin");
    std::fs::write(&input_file, input_data)?;

    let batch_elf_path = cache_elf(ElfType::Batch, batch_elf_bytes)?;
    if !batch_elf_path.exists() {
        return Err(anyhow!(
            "Batch ELF file not found at: {}",
            batch_elf_path.display()
        ));
    }

    ensure_rom_setup(batch_elf_path.to_str().ok_or_else(|| {
        anyhow!("Batch ELF path contains invalid UTF-8: {:?}", batch_elf_path)
    })?)
    .await?;

    let output_dir = prepare_output_dir(&work_dir, "batch")?;

    tokio::task::spawn_blocking({
        let elf_path = batch_elf_path.clone();
        let input_path = input_file.clone();
        let output_dir = output_dir.clone();
        let config = config.clone();
        move || {
            generate_proof_with_mpi(
                elf_path.to_str().ok_or_else(|| {
                    anyhow!("Batch ELF path contains invalid UTF-8: {:?}", elf_path)
                })?,
                input_path.to_str().ok_or_else(|| {
                    anyhow!("Batch input path contains invalid UTF-8: {:?}", input_path)
                })?,
                output_dir.to_str().ok_or_else(|| {
                    anyhow!("Batch output path contains invalid UTF-8: {:?}", output_dir)
                })?,
                config.concurrent_processes,
                config.threads_per_process,
                true,
            )
        }
    })
    .await
    .map_err(|e| anyhow!("Batch proof task failed: {}", e))??;

    let proof_file = locate_proof_file(&output_dir)?;
    let proof_data = std::fs::read(&proof_file)?;
    let proof_hex = hex::encode(&proof_data);

    if config.verify {
        tokio::task::spawn_blocking(move || verify_proof(&proof_file))
            .await
            .map_err(|e| anyhow!("Proof verify task failed: {}", e))??;
    }

    let public_input = read_public_input_from_output(&output_dir)?;
    if let Some(expected) = expected_input {
        if public_input != expected {
            return Err(anyhow!(
                "Batch public input mismatch: guest={:?}, expected={:?}",
                public_input,
                expected
            ));
        }
    }

    cleanup_intermediate_proofs(&output_dir);

    let response = ZiskResponse {
        proof: Some(format!("0x{}", proof_hex)),
        receipt: Some("zisk_batch_receipt".to_string()),
        input: Some(public_input),
        uuid: Some(request_id.to_string()),
    };

    if let Err(e) = std::fs::remove_dir_all(&work_dir) {
        tracing::warn!("Failed to clean up build directory {}: {}", work_dir.display(), e);
    }

    Ok(response)
}

async fn execute_aggregation_proof(
    request_id: &str,
    input_data: &[u8],
    aggregation_elf_bytes: &[u8],
    config: &ZiskProverConfig,
) -> Result<ZiskResponse> {
    let work_dir = build_base_dir().join(request_id);
    std::fs::create_dir_all(&work_dir)?;

    let output_dir = prepare_output_dir(&work_dir, "aggregation")?;
    let aggregation_elf_path = cache_elf(ElfType::Aggregation, aggregation_elf_bytes)?;

    if !aggregation_elf_path.exists() {
        return Err(anyhow!(
            "Aggregation ELF file not found at: {}",
            aggregation_elf_path.display()
        ));
    }

    let input_file = work_dir.join("input.bin");
    std::fs::write(&input_file, input_data)?;

    ensure_rom_setup(aggregation_elf_path.to_str().ok_or_else(|| {
        anyhow!("Aggregation ELF path contains invalid UTF-8: {:?}", aggregation_elf_path)
    })?)
    .await?;

    tokio::task::spawn_blocking({
        let elf_path = aggregation_elf_path.clone();
        let input_path = input_file.clone();
        let output_dir = output_dir.clone();
        let config = config.clone();
        move || {
            generate_proof_with_mpi(
                elf_path.to_str().ok_or_else(|| {
                    anyhow!("Aggregation ELF path contains invalid UTF-8: {:?}", elf_path)
                })?,
                input_path.to_str().ok_or_else(|| {
                    anyhow!("Aggregation input path contains invalid UTF-8: {:?}", input_path)
                })?,
                output_dir.to_str().ok_or_else(|| {
                    anyhow!("Aggregation output path contains invalid UTF-8: {:?}", output_dir)
                })?,
                config.concurrent_processes,
                config.threads_per_process,
                true,
            )
        }
    })
    .await
    .map_err(|e| anyhow!("Aggregation proof task failed: {}", e))??;

    let proof_file = locate_proof_file(&output_dir)?;
    let proof_data = std::fs::read(&proof_file)?;
    let proof_hex = hex::encode(&proof_data);

    if config.verify {
        tokio::task::spawn_blocking(move || verify_proof(&proof_file))
            .await
            .map_err(|e| anyhow!("Proof verify task failed: {}", e))??;
    }

    let public_input = read_public_input_from_output(&output_dir)?;

    cleanup_intermediate_proofs(&output_dir);

    let response = ZiskResponse {
        proof: Some(format!("0x{}", proof_hex)),
        receipt: Some("zisk_aggregation_receipt".to_string()),
        input: Some(public_input),
        uuid: Some(request_id.to_string()),
    };

    if let Err(e) = std::fs::remove_dir_all(&work_dir) {
        tracing::warn!("Failed to clean up build directory {}: {}", work_dir.display(), e);
    }

    Ok(response)
}

fn generate_proof_with_mpi(
    elf_path: &str,
    input_path: &str,
    output_dir: &str,
    concurrent_processes: Option<u32>,
    threads_per_process: Option<u32>,
    aggregation: bool,
) -> Result<()> {
    if let (Some(processes), Some(threads)) = (concurrent_processes, threads_per_process) {
        tracing::info!(
            "Using MPI with {} processes, {} threads each",
            processes,
            threads
        );

        let mut command = Command::new("mpirun");
        command.args([
            "--bind-to",
            "none",
            "-np",
            &processes.to_string(),
            "-x",
            &format!("OMP_NUM_THREADS={}", threads),
            "-x",
            &format!("RAYON_NUM_THREADS={}", threads),
            "cargo-zisk",
            "prove",
            "-e",
            elf_path,
            "-i",
            input_path,
            "-o",
            output_dir,
            "-f",
            "-b",
        ]);
        if aggregation {
            command.arg("-a");
        }
        run_command_streaming(command, "cargo-zisk prove (mpirun)")?;
    } else {
        let mut command = Command::new("cargo-zisk");
        command.args([
            "prove", "-e", elf_path, "-i", input_path, "-o", output_dir, "-f", "-b",
        ]);
        if aggregation {
            command.arg("-a");
        }
        run_command_streaming(command, "cargo-zisk prove")?;
    }

    Ok(())
}

fn verify_proof(proof_file: &Path) -> Result<()> {
    let mut command = Command::new("cargo-zisk");
    command.args(["verify", "-p", proof_file.to_str().ok_or_else(|| {
        anyhow!("Proof file path contains invalid UTF-8: {:?}", proof_file)
    })?]);
    run_command_streaming(command, "cargo-zisk verify")
}
