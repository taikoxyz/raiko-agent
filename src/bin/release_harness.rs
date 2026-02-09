use clap::Parser;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Parser)]
#[command(name = "release-harness")]
struct Args {
    /// Path to the fixture manifest JSON.
    #[arg(long, default_value = "tests/fixtures/release_harness/fixture.json")]
    fixture: PathBuf,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    base_url: Option<String>,
    agent: Option<AgentCfg>,
    upload: UploadCfg,
    proof: ProofCfg,
    poll: PollCfg,
}

#[derive(Debug, Deserialize)]
struct AgentCfg {
    spawn: bool,
    binary_path: Option<String>,
    address: Option<String>,
    port: Option<u16>,
    config_file: Option<String>,
    offchain: Option<bool>,
    #[serde(default)]
    evaluation_only: Option<bool>,
    env: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct UploadCfg {
    prover_type: String,
    image_type: String, // "batch" | "aggregation"
    elf_path: Option<String>,
    docker_elf: Option<DockerElfCfg>,
}

#[derive(Debug, Deserialize)]
struct DockerElfCfg {
    image: String,
    internal_path: String,
}

#[derive(Debug, Clone)]
enum ElfSource {
    Path(String),
    Docker {
        image: String,
        internal_path: String,
    },
}

impl UploadCfg {
    fn elf_source(&self) -> Result<ElfSource, Box<dyn std::error::Error>> {
        if let Some(p) = self.elf_path.as_ref() {
            return Ok(ElfSource::Path(p.clone()));
        }
        if let Some(d) = self.docker_elf.as_ref() {
            return Ok(ElfSource::Docker {
                image: d.image.clone(),
                internal_path: d.internal_path.clone(),
            });
        }
        Err("upload config requires either upload.elf_path or upload.docker_elf".into())
    }
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum InputEncoding {
    /// Auto-detect: raw bytes for non-JSON; for JSON: if it's `[0..255]` use that as bytes,
    /// otherwise `bincode(serde_json::Value)`.
    Auto,
    /// Treat file bytes as-is.
    Raw,
    /// JSON must be an array of integers in `[0,255]`.
    JsonBytesArray,
    /// Parse JSON and bincode-encode the resulting `serde_json::Value`.
    BincodeJsonValue,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum OutputEncoding {
    /// Auto-detect:
    /// - if JSON object has a top-level "hash" hex string, encode as `len(u32 LE) + hash_bytes`
    /// - otherwise: JSON array -> bytes, else bincode(json value)
    Auto,
    /// Treat file bytes as-is.
    Raw,
    /// JSON must be an array of integers in `[0,255]`.
    JsonBytesArray,
    /// Parse JSON and bincode-encode the resulting `serde_json::Value`.
    BincodeJsonValue,
    /// JSON must contain a top-level `"hash": "0x..."` (or "...") hex string.
    LenPrefixedHash,
}

#[derive(Debug, Deserialize)]
struct ProofCfg {
    prover_type: String,
    proof_type: String, // "batch" | "aggregate" | {"update":"batch"} (we treat as string for now)
    input_path: String,
    #[serde(default)]
    input_encoding: Option<InputEncoding>,
    output_path: Option<String>,
    #[serde(default)]
    output_encoding: Option<OutputEncoding>,
    request_config_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PollCfg {
    interval_ms: u64,
    health_timeout_ms: u64,
    submit_timeout_ms: u64,
    require_fulfilled: bool,
    fulfill_timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
struct ProofSubmitResp {
    request_id: String,
    status: String,
    message: String,
    #[allow(dead_code)]
    prover_type: String,
    #[allow(dead_code)]
    provider_request_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StatusResp {
    #[allow(dead_code)]
    request_id: String,
    status: String,
    status_message: String,
    #[allow(dead_code)]
    prover_type: String,
    provider_request_id: Option<String>,
    error: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let fixture: Fixture = serde_json::from_slice(&tokio::fs::read(&args.fixture).await?)?;
    let fixture_dir = args
        .fixture
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let mut child: Option<Child> = None;

    let base_url = if let Some(url) = fixture.base_url.clone() {
        url
    } else {
        let agent = fixture
            .agent
            .as_ref()
            .ok_or("fixture.agent is required when base_url is null")?;
        if !agent.spawn {
            return Err("base_url is null but agent.spawn is false".into());
        }
        let (url, spawned) = spawn_agent(agent, &fixture_dir)?;
        child = Some(spawned);
        url
    };

    let http = reqwest::Client::new();

    // Wait for health.
    wait_for_health(
        &http,
        &base_url,
        Duration::from_millis(fixture.poll.health_timeout_ms),
    )
    .await?;

    // Upload ELF.
    let elf_bytes = resolve_elf_bytes(&fixture.upload)
        .await
        .map_err(|e| format!("failed to resolve ELF bytes: {e}"))?;
    upload_elf(&http, &base_url, &fixture.upload, elf_bytes).await?;

    // Submit proof.
    let input = read_input_bytes(
        Path::new(&fixture.proof.input_path),
        fixture.proof.input_encoding.unwrap_or(InputEncoding::Auto),
    )
    .map_err(|e| {
        format!(
            "failed to read/encode input_path {}: {}",
            fixture.proof.input_path, e
        )
    })?;
    let output = match fixture.proof.output_path.as_ref() {
        Some(p) => read_output_bytes(
            Path::new(p),
            fixture.proof.output_encoding.unwrap_or(OutputEncoding::Auto),
        )
        .map_err(|e| format!("failed to read/encode output_path {p}: {e}"))?,
        None => Vec::new(),
    };
    let req_config = match fixture.proof.request_config_path.as_ref() {
        Some(p) => {
            let bytes = tokio::fs::read(p)
                .await
                .map_err(|e| format!("failed to read request_config_path {p}: {e}"))?;
            Some(serde_json::from_slice::<serde_json::Value>(&bytes)?)
        }
        None => None,
    };

    let submit = submit_proof(&http, &base_url, &fixture.proof, input, output, req_config).await?;
    eprintln!(
        "submitted request_id={} status={} message={}",
        submit.request_id, submit.status, submit.message
    );

    // Poll status.
    let poll_interval = Duration::from_millis(fixture.poll.interval_ms);
    let fast_deadline = Duration::from_millis(fixture.poll.submit_timeout_ms);
    let slow_deadline = Duration::from_millis(fixture.poll.fulfill_timeout_ms);

    let (final_status, elapsed) = poll_until(
        &http,
        &base_url,
        &submit.request_id,
        poll_interval,
        if fixture.poll.require_fulfilled {
            slow_deadline
        } else {
            fast_deadline
        },
        fixture.poll.require_fulfilled,
    )
    .await?;

    eprintln!(
        "final status after {:?}: status={} provider_request_id={:?} message={}",
        elapsed, final_status.status, final_status.provider_request_id, final_status.status_message
    );
    if let Some(err) = final_status.error {
        eprintln!("error: {}", err);
    }

    // Best-effort cleanup.
    if let Some(mut c) = child {
        let _ = c.kill();
        let _ = c.wait();
    }

    if fixture.poll.require_fulfilled && final_status.status != "completed" {
        return Err(format!(
            "expected fulfilled (completed), got {}",
            final_status.status
        )
        .into());
    }

    Ok(())
}

fn read_input_bytes(
    path: &Path,
    encoding: InputEncoding,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;

    let ext_is_json = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    let encoding = match encoding {
        InputEncoding::Auto if ext_is_json => InputEncoding::Auto,
        InputEncoding::Auto => {
            if looks_like_json(&bytes) {
                InputEncoding::Auto
            } else {
                InputEncoding::Raw
            }
        }
        other => other,
    };

    match encoding {
        InputEncoding::Raw => Ok(bytes),
        InputEncoding::Auto => {
            let v: serde_json::Value = serde_json::from_slice(&bytes)?;
            if let Some(arr) = v.as_array() {
                json_array_to_bytes(arr)
            } else {
                Ok(bincode::serialize(&v)?)
            }
        }
        InputEncoding::JsonBytesArray => {
            let v: serde_json::Value = serde_json::from_slice(&bytes)?;
            let arr = v
                .as_array()
                .ok_or("json_bytes_array requires JSON array input")?;
            json_array_to_bytes(arr)
        }
        InputEncoding::BincodeJsonValue => {
            let v: serde_json::Value = serde_json::from_slice(&bytes)?;
            Ok(bincode::serialize(&v)?)
        }
    }
}

fn read_output_bytes(
    path: &Path,
    encoding: OutputEncoding,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;

    let encoding = match encoding {
        OutputEncoding::Auto => {
            if looks_like_json(&bytes) {
                OutputEncoding::Auto
            } else {
                OutputEncoding::Raw
            }
        }
        other => other,
    };

    match encoding {
        OutputEncoding::Raw => Ok(bytes),
        OutputEncoding::JsonBytesArray => {
            let v: serde_json::Value = serde_json::from_slice(&bytes)?;
            let arr = v
                .as_array()
                .ok_or("json_bytes_array requires JSON array output")?;
            json_array_to_bytes(arr)
        }
        OutputEncoding::BincodeJsonValue => {
            let v: serde_json::Value = serde_json::from_slice(&bytes)?;
            Ok(bincode::serialize(&v)?)
        }
        OutputEncoding::LenPrefixedHash => {
            let v: serde_json::Value = serde_json::from_slice(&bytes)?;
            json_hash_to_len_prefixed_bytes(&v)
        }
        OutputEncoding::Auto => {
            let v: serde_json::Value = serde_json::from_slice(&bytes)?;
            if v.is_object() && v.get("hash").is_some() {
                json_hash_to_len_prefixed_bytes(&v)
            } else if let Some(arr) = v.as_array() {
                json_array_to_bytes(arr)
            } else {
                Ok(bincode::serialize(&v)?)
            }
        }
    }
}

fn looks_like_json(bytes: &[u8]) -> bool {
    // Best-effort sniffing for fixtures: if it parses as JSON, treat it as JSON.
    // This avoids requiring `.json` extensions while still being robust for binary input.
    if bytes.is_empty() {
        return false;
    }
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let first = s.trim_start().as_bytes().first().copied();
    match first {
        Some(b'{') | Some(b'[') => serde_json::from_str::<serde_json::Value>(s).is_ok(),
        _ => false,
    }
}

fn json_hash_to_len_prefixed_bytes(
    v: &serde_json::Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let hash_str = v
        .get("hash")
        .and_then(|h| h.as_str())
        .ok_or("expected top-level \"hash\" string field")?;
    let hash_bytes = parse_hex_bytes(hash_str)?;
    let mut out = Vec::with_capacity(4 + hash_bytes.len());
    out.extend_from_slice(&(hash_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&hash_bytes);
    Ok(out)
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let trimmed = s.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex.len() % 2 != 0 {
        return Err(format!("hex string has odd length: {}", hex.len()).into());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| format!("invalid hex at {i}: {e}"))?;
        out.push(byte);
    }
    Ok(out)
}

fn json_array_to_bytes(arr: &[serde_json::Value]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        let n = v
            .as_u64()
            .ok_or_else(|| format!("input byte at index {i} is not an integer"))?;
        if n > 255 {
            return Err(format!("input byte at index {i} out of range: {n}").into());
        }
        out.push(n as u8);
    }
    Ok(out)
}

async fn resolve_elf_bytes(upload: &UploadCfg) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match upload.elf_source()? {
        ElfSource::Path(p) => Ok(tokio::fs::read(&p)
            .await
            .map_err(|e| format!("failed to read elf_path {p}: {e}"))?),
        ElfSource::Docker {
            image,
            internal_path,
        } => {
            let bytes = tokio::task::spawn_blocking(move || {
                extract_elf_from_docker(&image, &internal_path)
            })
            .await??;
            Ok(bytes)
        }
    }
}

fn extract_elf_from_docker(image: &str, internal_path: &str) -> Result<Vec<u8>, String> {
    // docker create <image>
    let output = Command::new("docker")
        .arg("create")
        .arg(image)
        .output()
        .map_err(|e| format!("failed to run docker create: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "docker create failed: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if container_id.is_empty() {
        return Err("docker create returned empty container id".to_string());
    }

    let tmp = std::env::temp_dir().join(format!(
        "raiko-agent-release-harness-elf-{}",
        std::process::id()
    ));

    // Ensure cleanup even if cp/read fails.
    let result = (|| {
        // docker cp <container>:<internal_path> <tmp>
        let cp = Command::new("docker")
            .arg("cp")
            .arg(format!("{container_id}:{internal_path}"))
            .arg(&tmp)
            .output()
            .map_err(|e| format!("failed to run docker cp: {e}"))?;
        if !cp.status.success() {
            return Err(format!(
                "docker cp failed: status={} stderr={}",
                cp.status,
                String::from_utf8_lossy(&cp.stderr)
            ));
        }

        let bytes = std::fs::read(&tmp)
            .map_err(|e| format!("failed to read extracted ELF temp file {:?}: {e}", tmp))?;
        Ok(bytes)
    })();

    let _ = Command::new("docker")
        .arg("rm")
        .arg("-f")
        .arg(&container_id)
        .output();
    let _ = std::fs::remove_file(&tmp);

    result
}

fn spawn_agent(
    cfg: &AgentCfg,
    fixture_dir: &Path,
) -> Result<(String, Child), Box<dyn std::error::Error>> {
    let address = cfg
        .address
        .clone()
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = cfg
        .port
        .unwrap_or_else(|| choose_free_port(&address).unwrap_or(9999));

    let binary_path = cfg
        .binary_path
        .clone()
        .unwrap_or_else(|| "target/release/raiko-agent".to_string());

    if !std::path::Path::new(&binary_path).exists() {
        return Err(format!(
            "agent binary not found at {} (build it with `cargo build --release`)",
            binary_path
        )
        .into());
    }

    let config_file = cfg
        .config_file
        .clone()
        .ok_or("agent.config_file is required when spawning")?;

    if let Some(env) = cfg.env.as_ref() {
        ensure_sqlite_parent_dir(env, fixture_dir)?;
    }

    let mut cmd = Command::new(&binary_path);
    apply_agent_args(&mut cmd, cfg, &address, port, &config_file, fixture_dir);

    cmd.stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let child = cmd.spawn().map_err(|e| {
        format!(
            "failed to spawn raiko-agent at {}: {} (did you run `cargo build --release`?)",
            binary_path, e
        )
    })?;

    Ok((format!("http://{}:{}", address, port), child))
}

fn ensure_sqlite_parent_dir(
    env: &BTreeMap<String, String>,
    fixture_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(db_path) = env.get("SQLITE_DB_PATH") else {
        return Ok(());
    };
    if db_path == ":memory:" {
        return Ok(());
    }

    let path = resolve_relative_path(fixture_dir, std::path::Path::new(db_path));
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "failed to create SQLITE_DB_PATH parent dir {:?}: {}",
                    parent, e
                )
            })?;
        }
    }
    Ok(())
}

fn apply_agent_args(
    cmd: &mut Command,
    cfg: &AgentCfg,
    address: &str,
    port: u16,
    config_file: &str,
    fixture_dir: &Path,
) {
    cmd.arg("--address")
        .arg(address)
        .arg("--port")
        .arg(port.to_string())
        .arg("--config-file")
        .arg(config_file);

    if cfg.offchain.unwrap_or(false) {
        cmd.arg("--offchain");
    }
    if cfg.evaluation_only.unwrap_or(false) {
        cmd.arg("--evaluation-only");
    }

    if let Some(env) = cfg.env.as_ref() {
        for (k, v) in env {
            if k == "//" {
                continue;
            }
            if k == "SQLITE_DB_PATH" && v != ":memory:" {
                let abs = resolve_relative_path(fixture_dir, std::path::Path::new(v));
                cmd.env(k, abs);
            } else {
                cmd.env(k, v);
            }
        }
    }
}

fn resolve_relative_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    base_dir.join(path)
}

fn choose_free_port(addr: &str) -> Option<u16> {
    let listener = std::net::TcpListener::bind((addr, 0)).ok()?;
    let port = listener.local_addr().ok()?.port();
    drop(listener);
    Some(port)
}

async fn wait_for_health(
    http: &reqwest::Client,
    base_url: &str,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let url = format!("{}/health", base_url.trim_end_matches('/'));
    loop {
        match http.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => {
                if start.elapsed() > timeout {
                    return Err(
                        format!("health check timed out after {:?} at {}", timeout, url).into(),
                    );
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }
}

async fn upload_elf(
    http: &reqwest::Client,
    base_url: &str,
    cfg: &UploadCfg,
    elf_bytes: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!(
        "{}/upload-image/{}/{}",
        base_url.trim_end_matches('/'),
        cfg.prover_type,
        cfg.image_type
    );

    let resp = http
        .post(&url)
        .header("content-type", "application/octet-stream")
        .body(elf_bytes)
        .send()
        .await?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("upload-image failed: status={} body={}", status, body).into());
    }

    eprintln!("upload-image ok: {}", body);
    Ok(())
}

async fn submit_proof(
    http: &reqwest::Client,
    base_url: &str,
    cfg: &ProofCfg,
    input: Vec<u8>,
    output: Vec<u8>,
    request_config: Option<serde_json::Value>,
) -> Result<ProofSubmitResp, Box<dyn std::error::Error>> {
    let url = format!("{}/proof", base_url.trim_end_matches('/'));

    let mut body = serde_json::json!({
        "prover_type": cfg.prover_type,
        "input": input,
        "proof_type": cfg.proof_type,
        "output": Vec::<u8>::new()
    });
    if let Some(v) = request_config {
        body["config"] = v;
    }

    let resp = http.post(&url).json(&body).send().await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() && status.as_u16() != 202 {
        return Err(format!("proof submit failed: status={} body={}", status, text).into());
    }

    let parsed: ProofSubmitResp = serde_json::from_str(&text)?;
    Ok(parsed)
}

async fn poll_until(
    http: &reqwest::Client,
    base_url: &str,
    request_id: &str,
    interval: Duration,
    timeout: Duration,
    require_fulfilled: bool,
) -> Result<(StatusResp, Duration), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let url = format!("{}/status/{}", base_url.trim_end_matches('/'), request_id);

    loop {
        let resp = http.get(&url).send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("status poll failed: status={} body={}", status, text).into());
        }
        let parsed: StatusResp = serde_json::from_str(&text)?;

        match parsed.status.as_str() {
            "failed" => return Ok((parsed, start.elapsed())),
            "completed" => return Ok((parsed, start.elapsed())),
            "submitted" | "in_progress" => {
                if !require_fulfilled {
                    return Ok((parsed, start.elapsed()));
                }
            }
            _ => {}
        }

        if start.elapsed() > timeout {
            return Ok((parsed, start.elapsed()));
        }

        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_tmp_path() -> std::path::PathBuf {
        static CTR: AtomicU64 = AtomicU64::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "raiko-agent-release-harness-input-{}-{}.json",
            std::process::id(),
            n
        ))
    }

    #[test]
    fn input_json_array_is_used_as_bytes() {
        let path = unique_tmp_path();
        std::fs::write(&path, "[1,2,255]").unwrap();

        let bytes = read_input_bytes(&path, InputEncoding::Auto).unwrap();
        assert_eq!(bytes, vec![1u8, 2u8, 255u8]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn input_json_object_defaults_to_bincode_of_json_value() {
        let path = unique_tmp_path();
        std::fs::write(&path, r#"{"chain":"hoodi","n":1}"#).unwrap();

        let bytes = read_input_bytes(&path, InputEncoding::Auto).unwrap();
        let v: serde_json::Value = serde_json::from_str(r#"{"chain":"hoodi","n":1}"#).unwrap();
        let expected = bincode::serialize(&v).unwrap();
        assert_eq!(bytes, expected);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn auto_encoding_sniffs_json_without_json_extension() {
        let path = std::env::temp_dir().join(format!(
            "raiko-agent-release-harness-input-{}-sniff.bin",
            std::process::id()
        ));
        std::fs::write(&path, "[1,2,3]").unwrap();
        let bytes = read_input_bytes(&path, InputEncoding::Auto).unwrap();
        assert_eq!(bytes, vec![1u8, 2u8, 3u8]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn output_len_prefixed_hash_from_json() {
        let path = std::env::temp_dir().join(format!(
            "raiko-agent-release-harness-output-{}-hash.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"hash":"0x0102ff"}"#).unwrap();
        let bytes = read_output_bytes(&path, OutputEncoding::Auto).unwrap();
        assert_eq!(bytes, vec![3u8, 0, 0, 0, 1, 2, 255]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn output_auto_falls_back_to_bincode_when_no_hash() {
        let path = std::env::temp_dir().join(format!(
            "raiko-agent-release-harness-output-{}-obj.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"a":1}"#).unwrap();
        let bytes = read_output_bytes(&path, OutputEncoding::Auto).unwrap();
        let v: serde_json::Value = serde_json::from_str(r#"{"a":1}"#).unwrap();
        assert_eq!(bytes, bincode::serialize(&v).unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upload_cfg_requires_some_elf_source() {
        let cfg = UploadCfg {
            prover_type: "boundless".to_string(),
            image_type: "batch".to_string(),
            elf_path: None,
            docker_elf: None,
        };
        assert!(cfg.elf_source().is_err());
    }

    #[test]
    fn upload_cfg_prefers_elf_path_over_docker() {
        let cfg = UploadCfg {
            prover_type: "boundless".to_string(),
            image_type: "batch".to_string(),
            elf_path: Some("local.elf".to_string()),
            docker_elf: Some(DockerElfCfg {
                image: "img:tag".to_string(),
                internal_path: "/path/in/image".to_string(),
            }),
        };
        match cfg.elf_source().unwrap() {
            ElfSource::Path(p) => assert_eq!(p, "local.elf"),
            _ => panic!("expected path source"),
        }
    }

    #[test]
    fn spawn_agent_applies_evaluation_only_flag() {
        let cfg = AgentCfg {
            spawn: true,
            binary_path: Some("raiko-agent".to_string()),
            address: Some("127.0.0.1".to_string()),
            port: Some(9999),
            config_file: Some("config.json".to_string()),
            offchain: Some(false),
            evaluation_only: Some(true),
            env: None,
        };

        let mut cmd = std::process::Command::new("raiko-agent");
        apply_agent_args(
            &mut cmd,
            &cfg,
            "127.0.0.1",
            9999,
            "config.json",
            std::path::Path::new("."),
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|s| s.to_string_lossy().to_string())
            .collect();

        assert!(args.contains(&"--evaluation-only".to_string()));
    }

    #[test]
    fn ensure_sqlite_parent_dir_creates_missing_directory() {
        use std::sync::atomic::{AtomicU64, Ordering};

        static CTR: AtomicU64 = AtomicU64::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);

        let base = std::env::temp_dir().join(format!(
            "raiko-agent-release-harness-sqlite-dir-{}-{}",
            std::process::id(),
            n
        ));
        let db_path = base.join("subdir").join("proof_requests.db");

        // Ensure clean start.
        let _ = std::fs::remove_dir_all(&base);

        let mut env = BTreeMap::new();
        env.insert(
            "SQLITE_DB_PATH".to_string(),
            db_path.to_string_lossy().to_string(),
        );

        ensure_sqlite_parent_dir(&env, std::path::Path::new(".")).unwrap();
        assert!(db_path.parent().unwrap().exists());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn sqlite_db_path_is_resolved_relative_to_fixture_dir() {
        let fixture_dir = std::env::temp_dir().join(format!(
            "raiko-agent-release-harness-fixture-dir-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&fixture_dir);

        let mut cfg = AgentCfg {
            spawn: true,
            binary_path: Some("raiko-agent".to_string()),
            address: Some("127.0.0.1".to_string()),
            port: Some(9999),
            config_file: Some("config.json".to_string()),
            offchain: Some(false),
            evaluation_only: Some(false),
            env: Some(BTreeMap::from([(
                "SQLITE_DB_PATH".to_string(),
                "relative/proof_requests.db".to_string(),
            )])),
        };

        let mut cmd = std::process::Command::new("raiko-agent");
        apply_agent_args(
            &mut cmd,
            &cfg,
            "127.0.0.1",
            9999,
            "config.json",
            &fixture_dir,
        );

        let envs: Vec<(String, String)> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                let k = k.to_string_lossy().to_string();
                let v = v?.to_string_lossy().to_string();
                Some((k, v))
            })
            .collect();

        let sqlite = envs
            .iter()
            .find(|(k, _)| k == "SQLITE_DB_PATH")
            .map(|(_, v)| v.clone())
            .expect("SQLITE_DB_PATH must be set");

        assert!(sqlite.starts_with(&*fixture_dir.to_string_lossy()));

        let _ = std::fs::remove_dir_all(&fixture_dir);
        // Keep cfg mutable to avoid clippy warnings in older toolchains.
        cfg.spawn = true;
    }
}
