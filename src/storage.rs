use crate::types::{
    AgentError, AgentResult, AsyncProofRequest, ProofRequestStatus, ProofType, ProverType,
};
use alloy_primitives_v1p2p0::keccak256;
use serde_json;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio_rusqlite::params;
use tracing;
use utoipa::ToSchema;

/// SQLite storage for persistent prover request tracking
#[derive(Debug, Clone)]
pub struct RequestStorage {
    db_path: String,
    pooled_conn: OnceCell<tokio_rusqlite::Connection>,
}

impl RequestStorage {
    pub fn new(db_path: String) -> Self {
        Self {
            db_path,
            pooled_conn: OnceCell::new(),
        }
    }

    fn apply_pragmas(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
        // WAL improves concurrent write behavior; busy_timeout lets readers wait briefly instead of erroring.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.busy_timeout(Duration::from_millis(5000))?;
        Ok(())
    }

    fn is_locked_error(err: &tokio_rusqlite::Error) -> bool {
        match err {
            tokio_rusqlite::Error::Rusqlite(rusqlite::Error::SqliteFailure(e, _)) => {
                matches!(
                    e.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                )
            }
            _ => false,
        }
    }

    async fn open_with_pragmas(&self) -> AgentResult<tokio_rusqlite::Connection> {
        // Use a single shared connection to reduce open/close overhead and lock churn.
        let conn = self
            .pooled_conn
            .get_or_try_init(|| async {
                let db_path = self.db_path.clone();
                let conn = tokio_rusqlite::Connection::open(db_path)
                    .await
                    .map_err(|e| {
                        AgentError::ClientBuildError(format!(
                            "Failed to open SQLite database: {}",
                            e
                        ))
                    })?;

                conn.call(|conn| {
                    Self::apply_pragmas(conn)?;
                    Ok(())
                })
                .await
                .map_err(|e| {
                    AgentError::ClientBuildError(format!(
                        "Failed to configure SQLite pragmas: {}",
                        e
                    ))
                })?;

                Ok(conn)
            })
            .await?;

        Ok(conn.clone())
    }

    /// Initialize the database and create tables if they don't exist
    pub async fn initialize(&self) -> AgentResult<()> {
        let conn = self.open_with_pragmas().await?;
        conn.call(move |conn| {
                Self::apply_pragmas(conn)?;
                conn.execute(
                    r#"
                    CREATE TABLE IF NOT EXISTS proof_requests (
                        request_id TEXT PRIMARY KEY,
                        prover_type TEXT NOT NULL,
                        provider_request_id TEXT,
                        status TEXT NOT NULL,
                        status_code TEXT,
                        proof_type TEXT NOT NULL,
                        input_data BLOB NOT NULL,
                        config_data TEXT NOT NULL,
                        updated_at INTEGER NOT NULL,
                        proof_data BLOB,
                        error_message TEXT,
                        input_hash TEXT,
                        proof_type_str TEXT,
                        ttl_expires_at INTEGER
                    )
                    "#,
                    [],
                )?;

                // Create index for faster status queries
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_status ON proof_requests(status)",
                    [],
                )?;

                // Migrate existing database by adding new columns if they don't exist
                let _ = conn.execute("ALTER TABLE proof_requests ADD COLUMN input_hash TEXT", []);
                let _ = conn.execute("ALTER TABLE proof_requests ADD COLUMN proof_type_str TEXT", []);
                let _ = conn.execute("ALTER TABLE proof_requests ADD COLUMN ttl_expires_at INTEGER", []);
                let _ = conn.execute("ALTER TABLE proof_requests ADD COLUMN status_code TEXT", []);

                // Create unique index for input deduplication
                conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_input_dedup ON proof_requests(input_hash, proof_type_str, prover_type) WHERE input_hash IS NOT NULL AND proof_type_str IS NOT NULL",
                    [],
                )?;

                // Index for status_code based filtering
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_status_code ON proof_requests(status_code)",
                    [],
                )?;

                // Create index for TTL-based cleanup
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_ttl_expires_at ON proof_requests(ttl_expires_at)",
                    [],
                )?;

                Ok(())
            })
            .await
            .map_err(|e| AgentError::ClientBuildError(format!("Database initialization failed: {}", e)))?;

        tracing::info!("SQLite database initialized at: {}", self.db_path);
        Ok(())
    }

    /// Compute Keccak256 hash of input data for deduplication
    fn compute_input_hash(input: &[u8]) -> String {
        format!("{:x}", keccak256(input))
    }

    /// Convert ProofType to string for database storage
    fn proof_type_to_string(proof_type: &ProofType) -> String {
        match proof_type {
            ProofType::Batch => "batch".to_string(),
            ProofType::Aggregate => "aggregate".to_string(),
            ProofType::Update(_) => "update".to_string(),
        }
    }

    /// Lightweight status code for indexed filters
    fn status_code(status: &ProofRequestStatus) -> &'static str {
        match status {
            ProofRequestStatus::Preparing => "preparing",
            ProofRequestStatus::Submitted { .. } => "submitted",
            ProofRequestStatus::Locked { .. } => "locked",
            ProofRequestStatus::Fulfilled { .. } => "fulfilled",
            ProofRequestStatus::Failed { .. } => "failed",
        }
    }

    /// Store a new async request
    pub async fn store_request(&self, request: &AsyncProofRequest) -> AgentResult<()> {
        let mut last_err: Option<tokio_rusqlite::Error> = None;
        for attempt in 0..3 {
            let req_clone = request.clone();
            let conn = self.open_with_pragmas().await?;
            let result = conn
                .call(move |conn| {
                    Self::apply_pragmas(conn)?;
                    let status_json = serde_json::to_string(&req_clone.status)
                        .map_err(|e| tokio_rusqlite::Error::Other(Box::new(e)))?;
                    let proof_type_json = serde_json::to_string(&req_clone.proof_type)
                        .map_err(|e| tokio_rusqlite::Error::Other(Box::new(e)))?;
                    let config_json = serde_json::to_string(&req_clone.config)
                        .map_err(|e| tokio_rusqlite::Error::Other(Box::new(e)))?;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;

                    // Compute input hash and proof type string for deduplication
                    let input_hash = Self::compute_input_hash(&req_clone.input);
                    let proof_type_str = Self::proof_type_to_string(&req_clone.proof_type);
                    let prover_type_str = req_clone.prover_type.as_str();
                    let status_code = Self::status_code(&req_clone.status);

                    // Set TTL to 12 hours from now (12 * 60 * 60 = 43200 seconds)
                    let ttl_expires_at = now + 43200;

                    conn.execute(
                        r#"
                        INSERT OR REPLACE INTO proof_requests
                        (request_id, prover_type, provider_request_id, status, status_code, proof_type, input_data, config_data,
                         updated_at, proof_data, error_message, input_hash, proof_type_str, ttl_expires_at)
                        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                        "#,
                        params![
                            req_clone.request_id,
                            prover_type_str,
                            req_clone.provider_request_id,
                            status_json,
                            status_code,
                            proof_type_json,
                            req_clone.input,
                            config_json,
                            now,
                            Option::<Vec<u8>>::None, // proof_data initially None
                            Option::<String>::None,   // error_message initially None
                            input_hash,
                            proof_type_str,
                            ttl_expires_at
                        ],
                    )?;

                    Ok(())
                })
                .await;

            match result {
                Ok(_) => return Ok(()),
                Err(e) if Self::is_locked_error(&e) && attempt < 2 => {
                    last_err = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(
                        200 * (attempt + 1) as u64,
                    ))
                    .await;
                    continue;
                }
                Err(e) => {
                    return Err(AgentError::ClientBuildError(format!(
                        "Failed to store request: {}",
                        e
                    )));
                }
            }
        }

        Err(AgentError::ClientBuildError(format!(
            "Failed to store request after retries: {:?}",
            last_err
        )))
    }

    /// Update request status
    pub async fn update_status(
        &self,
        request_id: &str,
        status: &ProofRequestStatus,
    ) -> AgentResult<()> {
        let mut last_err: Option<tokio_rusqlite::Error> = None;
        for attempt in 0..3 {
            let request_id = request_id.to_string();
            let status = status.clone();
            let conn = self.open_with_pragmas().await?;
            let result = conn
                .call(move |conn| {
                    Self::apply_pragmas(conn)?;
                    let status_json = serde_json::to_string(&status)
                        .map_err(|e| tokio_rusqlite::Error::Other(Box::new(e)))?;
                    let status_code = Self::status_code(&status);
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;

                    // Extract proof data, error message, and optional provider request ID
                    let (proof_data, error_message) = match &status {
                        ProofRequestStatus::Fulfilled { proof, .. } => (Some(proof.clone()), None),
                        ProofRequestStatus::Failed { error } => (None, Some(error.clone())),
                        _ => (None, None),
                    };

                    let provider_request_id = match &status {
                        ProofRequestStatus::Submitted { provider_request_id, .. }
                        | ProofRequestStatus::Locked {
                            provider_request_id,
                            ..
                        }
                        | ProofRequestStatus::Fulfilled {
                            provider_request_id,
                            ..
                        } => Some(provider_request_id.clone()),
                        _ => None,
                    };

                    if let Some(provider_request_id) = provider_request_id {
                        conn.execute(
                            r#"
                            UPDATE proof_requests 
                            SET status = ?1, status_code = ?2, updated_at = ?3, proof_data = ?4, error_message = ?5,
                                provider_request_id = ?6
                            WHERE request_id = ?7
                            "#,
                            params![
                                status_json,
                                status_code,
                                now,
                                proof_data,
                                error_message,
                                provider_request_id,
                                request_id
                            ],
                        )
                        ?;
                    } else {
                        conn.execute(
                            r#"
                            UPDATE proof_requests 
                            SET status = ?1, status_code = ?2, updated_at = ?3, proof_data = ?4, error_message = ?5
                            WHERE request_id = ?6
                            "#,
                            params![
                                status_json,
                                status_code,
                                now,
                                proof_data,
                                error_message,
                                request_id
                            ],
                        )
                        ?;
                    }

                    Ok(())
                })
                .await;

            match result {
                Ok(_) => return Ok(()),
                Err(e) if Self::is_locked_error(&e) && attempt < 2 => {
                    last_err = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(
                        200 * (attempt + 1) as u64,
                    ))
                    .await;
                    continue;
                }
                Err(e) => {
                    return Err(AgentError::ClientBuildError(format!(
                        "Failed to update status: {}",
                        e
                    )));
                }
            }
        }

        Err(AgentError::ClientBuildError(format!(
            "Failed to update status after retries: {:?}",
            last_err
        )))
    }

    /// Get a request by request ID
    pub async fn get_request(&self, request_id: &str) -> AgentResult<Option<AsyncProofRequest>> {
        let request_id = request_id.to_string();

        self.open_with_pragmas()
            .await?
            .call(move |conn| {
                Self::apply_pragmas(conn)?;
                let mut stmt = conn
                    .prepare(
                        r#"
                    SELECT request_id, prover_type, provider_request_id, status, proof_type, input_data, config_data
                    FROM proof_requests
                    WHERE request_id = ?1
                    "#,
                    )
                    ?;

                let mut rows = stmt.query_map([request_id], |row| {
                    Self::parse_request_row(row)
                })?;

                match rows.next() {
                    Some(Ok(request)) => Ok(Some(request)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| AgentError::ClientBuildError(format!("Failed to get request: {}", e)))
    }

    /// List all active (non-completed) requests (lightweight projection)
    pub async fn list_active_requests(&self) -> AgentResult<Vec<AsyncProofRequest>> {
        self.open_with_pragmas()
            .await?
            .call(move |conn| {
                Self::apply_pragmas(conn)?;
                let mut stmt = conn
                    .prepare(
                        r#"
                    SELECT request_id, prover_type, provider_request_id, status, proof_type, input_data, config_data
                    FROM proof_requests
                    WHERE (status_code IS NOT NULL AND status_code NOT IN ('fulfilled','failed'))
                       OR (status_code IS NULL AND status NOT LIKE '%Fulfilled%' AND status NOT LIKE '%Failed%')
                    ORDER BY updated_at DESC
                    "#,
                    )
                    ?;

                let rows = stmt.query_map([], |row| {
                    // Only parse minimal fields; leave input/config empty to avoid BLOB overhead.
                    let request_id: String = row.get(0)?;
                    let prover_type_str: String = row.get(1)?;
                    let provider_request_id: Option<String> = row.get(2)?;
                    let status_json: String = row.get(3)?;
                    let proof_type_json: String = row.get(4)?;

                    let prover_type = ProverType::from_str(&prover_type_str).map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            1,
                            "prover_type".to_string(),
                            rusqlite::types::Type::Text,
                        )
                    })?;

                    let status: ProofRequestStatus =
                        serde_json::from_str(&status_json).map_err(|_| {
                            rusqlite::Error::InvalidColumnType(
                                3,
                                "status".to_string(),
                                rusqlite::types::Type::Text,
                            )
                        })?;
                    let proof_type: ProofType =
                        serde_json::from_str(&proof_type_json).map_err(|_| {
                            rusqlite::Error::InvalidColumnType(
                                4,
                                "proof_type".to_string(),
                                rusqlite::types::Type::Text,
                            )
                        })?;

                    Ok(AsyncProofRequest {
                        request_id,
                        prover_type,
                        provider_request_id,
                        status,
                        proof_type,
                        input: Vec::new(), // omitted to reduce I/O
                        config: serde_json::Value::Null, // omitted
                    })
                })?;

                let mut requests = Vec::new();
                for row in rows {
                    match row {
                        Ok(request) => requests.push(request),
                        Err(e) => tracing::warn!("Failed to parse request from database: {}", e),
                    }
                }

                Ok(requests)
            })
            .await
            .map_err(|e| AgentError::ClientBuildError(format!("Failed to list requests: {}", e)))
    }

    /// Get all requests that need status polling (submitted or locked) - lightweight projection
    pub async fn get_pending_requests(&self) -> AgentResult<Vec<AsyncProofRequest>> {
        self.open_with_pragmas()
            .await?
            .call(move |conn| {
                Self::apply_pragmas(conn)?;

                let mut stmt = conn
                    .prepare(
                        r#"
                    SELECT request_id, prover_type, provider_request_id, status, proof_type, input_data, config_data
                    FROM proof_requests
                    WHERE (status_code IS NOT NULL AND status_code IN ('submitted','locked'))
                       OR (status_code IS NULL AND (status LIKE '%Submitted%' OR status LIKE '%Locked%'))
                    ORDER BY updated_at ASC
                    "#,
                    )
                    ?;

                let rows = stmt.query_map([], |row| {
                    let request_id: String = row.get(0)?;
                    let prover_type_str: String = row.get(1)?;
                    let provider_request_id: Option<String> = row.get(2)?;
                    let status_json: String = row.get(3)?;
                    let proof_type_json: String = row.get(4)?;

                    let prover_type = ProverType::from_str(&prover_type_str).map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            1,
                            "prover_type".to_string(),
                            rusqlite::types::Type::Text,
                        )
                    })?;

                    let status: ProofRequestStatus =
                        serde_json::from_str(&status_json).map_err(|_| {
                            rusqlite::Error::InvalidColumnType(
                                3,
                                "status".to_string(),
                                rusqlite::types::Type::Text,
                            )
                        })?;
                    let proof_type: ProofType =
                        serde_json::from_str(&proof_type_json).map_err(|_| {
                            rusqlite::Error::InvalidColumnType(
                                4,
                                "proof_type".to_string(),
                                rusqlite::types::Type::Text,
                            )
                        })?;

                    Ok(AsyncProofRequest {
                        request_id,
                        prover_type,
                        provider_request_id,
                        status,
                        proof_type,
                        input: Vec::new(),               // omitted
                        config: serde_json::Value::Null, // omitted
                    })
                })?;

                let mut requests = Vec::new();
                for row in rows {
                    match row {
                        Ok(request) => requests.push(request),
                        Err(e) => tracing::warn!("Failed to parse pending request: {}", e),
                    }
                }

                Ok(requests)
            })
            .await
            .map_err(|e| AgentError::ClientBuildError(format!("Failed to get pending requests: {}", e)))
    }

    /// Helper function to parse a database row into AsyncProofRequest
    fn parse_request_row(row: &rusqlite::Row) -> Result<AsyncProofRequest, rusqlite::Error> {
        let request_id: String = row.get(0)?;
        let prover_type_str: String = row.get(1)?;
        let provider_request_id: Option<String> = row.get(2)?;
        let status_json: String = row.get(3)?;
        let proof_type_json: String = row.get(4)?;
        let input_data: Vec<u8> = row.get(5)?;
        let config_json: String = row.get(6)?;

        let prover_type = ProverType::from_str(&prover_type_str).map_err(|_| {
            rusqlite::Error::InvalidColumnType(
                1,
                "prover_type".to_string(),
                rusqlite::types::Type::Text,
            )
        })?;

        // Deserialize JSON fields
        let status: ProofRequestStatus = serde_json::from_str(&status_json).map_err(|_| {
            rusqlite::Error::InvalidColumnType(3, "status".to_string(), rusqlite::types::Type::Text)
        })?;
        let proof_type: ProofType = serde_json::from_str(&proof_type_json).map_err(|_| {
            rusqlite::Error::InvalidColumnType(
                4,
                "proof_type".to_string(),
                rusqlite::types::Type::Text,
            )
        })?;
        let config: serde_json::Value = serde_json::from_str(&config_json).map_err(|_| {
            rusqlite::Error::InvalidColumnType(6, "config".to_string(), rusqlite::types::Type::Text)
        })?;

        Ok(AsyncProofRequest {
            request_id,
            prover_type,
            provider_request_id,
            status,
            proof_type,
            input: input_data,
            config,
        })
    }

    /// Get a request by input hash and proof type for deduplication
    pub async fn get_request_by_input_hash(
        &self,
        input: &[u8],
        proof_type: &ProofType,
        prover_type: &ProverType,
    ) -> AgentResult<Option<AsyncProofRequest>> {
        let input_hash = Self::compute_input_hash(input);
        let proof_type_str = Self::proof_type_to_string(proof_type);
        let prover_type_str = prover_type.as_str().to_string();

        self.open_with_pragmas()
            .await?
            .call(move |conn| {
                Self::apply_pragmas(conn)?;
                let mut stmt = conn.prepare(
                    r#"
                    SELECT request_id, prover_type, provider_request_id, status, proof_type, input_data, config_data
                    FROM proof_requests
                    WHERE input_hash = ?1 AND proof_type_str = ?2 AND prover_type = ?3
                    ORDER BY updated_at DESC
                    LIMIT 1
                    "#
                )?;

                let mut rows = stmt.query_map([input_hash, proof_type_str, prover_type_str], |row| {
                    Self::parse_request_row(row)
                })?;

                match rows.next() {
                    Some(Ok(request)) => Ok(Some(request)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| AgentError::ClientBuildError(format!("Failed to get request by input hash: {}", e)))
    }

    /// Delete expired non-successful requests (older than 2 hours)
    /// Returns list of deleted request IDs for memory cleanup
    pub async fn delete_expired_requests(&self) -> AgentResult<Vec<String>> {
        self.open_with_pragmas()
            .await?
            .call(move |conn| {
                Self::apply_pragmas(conn)?;
                // First, get the request IDs that will be deleted
                let mut stmt = conn.prepare(
                    r#"
                    SELECT request_id FROM proof_requests 
                    WHERE updated_at < (strftime('%s', 'now') - 7200)
                    AND ((status_code IS NOT NULL AND status_code NOT IN ('fulfilled','failed'))
                         OR (status_code IS NULL AND status NOT LIKE '%Fulfilled%'))
                    "#,
                )?;

                let rows = stmt.query_map([], |row| {
                    let request_id: String = row.get(0)?;
                    Ok(request_id)
                })?;

                let mut deleted_ids = Vec::new();
                for row in rows {
                    match row {
                        Ok(request_id) => deleted_ids.push(request_id),
                        Err(e) => {
                            tracing::warn!("Failed to parse request_id during cleanup: {}", e)
                        }
                    }
                }

                // Now delete the expired requests
                let deleted_count = conn.execute(
                    r#"
                    DELETE FROM proof_requests 
                    WHERE updated_at < (strftime('%s', 'now') - 7200)
                    AND ((status_code IS NOT NULL AND status_code NOT IN ('fulfilled','failed'))
                         OR (status_code IS NULL AND status NOT LIKE '%Fulfilled%'))
                    "#,
                    [],
                )?;

                if deleted_count > 0 {
                    tracing::info!(
                        "Deleted {} expired non-successful requests from database",
                        deleted_count
                    );
                }

                Ok(deleted_ids)
            })
            .await
            .map_err(|e| {
                AgentError::ClientBuildError(format!("Failed to delete expired requests: {}", e))
            })
    }

    /// Delete completed requests (fulfilled or failed) that have exceeded their TTL
    /// Returns list of deleted request IDs for memory cleanup
    pub async fn delete_expired_ttl_requests(&self) -> AgentResult<Vec<String>> {
        self.open_with_pragmas()
            .await?
            .call(move |conn| {
                Self::apply_pragmas(conn)?;
                // First, get the request IDs that will be deleted
                let mut stmt = conn
                    .prepare(
                        r#"
                    SELECT request_id FROM proof_requests
                    WHERE ttl_expires_at < strftime('%s', 'now')
                    AND (status LIKE '%Fulfilled%' OR status LIKE '%Failed%')
                    "#,
                    )
                    ?;

                let rows = stmt
                    .query_map([], |row| {
                        let request_id: String = row.get(0)?;
                        Ok(request_id)
                    })
                    ?;

                let mut deleted_ids = Vec::new();
                for row in rows {
                    match row {
                        Ok(request_id) => deleted_ids.push(request_id),
                        Err(e) => {
                            tracing::warn!("Failed to parse request_id during TTL cleanup: {}", e)
                        }
                    }
                }

                // Now delete the TTL-expired requests
                let deleted_count = conn
                    .execute(
                        r#"
                    DELETE FROM proof_requests
                    WHERE ttl_expires_at < strftime('%s', 'now')
                    AND ((status_code IS NOT NULL AND status_code IN ('fulfilled','failed'))
                         OR (status_code IS NULL AND (status LIKE '%Fulfilled%' OR status LIKE '%Failed%')))
                    "#,
                        [],
                    )
                    ?;

                if deleted_count > 0 {
                    tracing::info!(
                        "Deleted {} TTL-expired completed requests from database",
                        deleted_count
                    );
                }

                Ok(deleted_ids)
            })
            .await
            .map_err(|e| {
                AgentError::ClientBuildError(format!(
                    "Failed to delete TTL-expired requests: {}",
                    e
                ))
            })
    }

    /// Delete all requests from the database
    /// Returns the number of deleted requests
    pub async fn delete_all_requests(&self) -> AgentResult<usize> {
        self.open_with_pragmas()
            .await?
            .call(move |conn| {
                Self::apply_pragmas(conn)?;
                let deleted_count = conn.execute("DELETE FROM proof_requests", [])?;

                tracing::info!("Deleted {} requests from database", deleted_count);
                Ok(deleted_count)
            })
            .await
            .map_err(|e| {
                AgentError::ClientBuildError(format!("Failed to delete all requests: {}", e))
            })
    }

    /// Get database file path (useful for backups)
    pub fn db_path(&self) -> &str {
        &self.db_path
    }

    /// Get database stats
    pub async fn get_stats(&self) -> AgentResult<DatabaseStats> {
        self.open_with_pragmas()
            .await?
            .call(move |conn| {
                Self::apply_pragmas(conn)?;
                // Get total count
                let total: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM proof_requests",
                    [],
                    |row| row.get(0)
                )?;

                // Get active count
                let active: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM proof_requests WHERE (status_code IS NOT NULL AND status_code NOT IN ('fulfilled','failed')) OR (status_code IS NULL AND status NOT LIKE '%Fulfilled%' AND status NOT LIKE '%Failed%')",
                    [],
                    |row| row.get(0)
                )?;

                // Get completed count
                let completed: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM proof_requests WHERE (status_code IS NOT NULL AND status_code = 'fulfilled') OR (status_code IS NULL AND status LIKE '%Fulfilled%')",
                    [],
                    |row| row.get(0)
                )?;

                // Get failed count
                let failed: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM proof_requests WHERE (status_code IS NOT NULL AND status_code = 'failed') OR (status_code IS NULL AND status LIKE '%Failed%')",
                    [],
                    |row| row.get(0)
                )?;

                Ok(DatabaseStats {
                    total_requests: total as u64,
                    active_requests: active as u64,
                    completed_requests: completed as u64,
                    failed_requests: failed as u64,
                })
            })
            .await
            .map_err(|e| AgentError::ClientBuildError(format!("Failed to get database stats: {}", e)))
    }

    /// Store ELF URL for a given ELF type
    pub async fn store_elf_url(&self, _elf_type: &str, _url: &str) -> AgentResult<()> {
        todo!()
    }

    /// Retrieve ELF URL for a given ELF type
    pub async fn get_elf_url(&self, _elf_type: &str) -> AgentResult<Option<String>> {
        todo!()
    }

    /// Get all stored ELF URLs
    pub async fn get_all_elf_urls(&self) -> AgentResult<Vec<(String, String)>> {
        todo!()
    }
}

#[derive(Debug, Clone, serde::Serialize, ToSchema)]
pub struct DatabaseStats {
    pub total_requests: u64,
    pub active_requests: u64,
    pub completed_requests: u64,
    pub failed_requests: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_db_path() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("/tmp/raiko-agent-test-{}.db", nanos)
    }

    async fn insert_failed_request(
        conn: &tokio_rusqlite::Connection,
        request_id: String,
        updated_at: i64,
        ttl_expires_at: i64,
    ) {
        let status = ProofRequestStatus::Failed {
            error: "oops".to_string(),
        };
        let status_json = serde_json::to_string(&status).unwrap();
        let proof_type = ProofType::Batch;
        let proof_type_json = serde_json::to_string(&proof_type).unwrap();
        let config_json = serde_json::to_string(&serde_json::Value::Null).unwrap();

        conn.call(move |conn| {
            conn.execute(
                r#"
                INSERT INTO proof_requests
                (request_id, prover_type, provider_request_id, status, status_code, proof_type, input_data, config_data,
                 updated_at, proof_data, error_message, input_hash, proof_type_str, ttl_expires_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                "#,
                params![
                    request_id,
                    ProverType::Boundless.as_str(),
                    Option::<String>::None,
                    status_json,
                    "failed",
                    proof_type_json,
                    Vec::<u8>::new(),
                    config_json,
                    updated_at,
                    Option::<Vec<u8>>::None,
                    Option::<String>::None,
                    Option::<String>::None,
                    "batch",
                    ttl_expires_at
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    async fn count_request(conn: &tokio_rusqlite::Connection, request_id: String) -> i64 {
        conn.call(move |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM proof_requests WHERE request_id = ?1",
                [request_id],
                |row| row.get(0),
            )
            .map_err(tokio_rusqlite::Error::from)
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn failed_requests_cleanup_via_ttl_only() {
        let db_path = temp_db_path();
        let storage = RequestStorage::new(db_path.clone());
        storage.initialize().await.unwrap();

        let conn = tokio_rusqlite::Connection::open(db_path.clone())
            .await
            .unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let updated_at = now - 7201;
        let ttl_expires_at = now - 1;
        let request_id = "req_failed_old".to_string();

        insert_failed_request(&conn, request_id.clone(), updated_at, ttl_expires_at).await;

        let deleted = storage.delete_expired_requests().await.unwrap();
        assert!(
            !deleted.contains(&request_id),
            "Failed requests should not be deleted by non-terminal cleanup"
        );

        let remaining_after_nonterminal = count_request(&conn, request_id.clone()).await;
        assert_eq!(remaining_after_nonterminal, 1);

        let deleted_ttl = storage.delete_expired_ttl_requests().await.unwrap();
        assert!(
            deleted_ttl.contains(&request_id),
            "Failed requests should be deleted by TTL cleanup"
        );

        let remaining_after_ttl = count_request(&conn, request_id).await;
        assert_eq!(remaining_after_ttl, 0);
    }
}
