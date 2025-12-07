use crate::AgentError;
use alloy_primitives_v1p2p0::hex;
use risc0_zkvm::{compute_image_id, sha::Digest};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::RwLock;
use url::Url;

/// Information about an uploaded ELF image
#[derive(Debug, Clone)]
pub struct ImageInfo {
    /// RISC0 image ID computed from the ELF
    pub image_id: Digest,
    /// URL where the image is stored in Boundless Market
    pub market_url: Url,
    /// The original ELF bytes (cached for potential re-upload)
    pub elf_bytes: Vec<u8>,
    /// When to refresh the presigned URL before it expires
    pub refresh_at: SystemTime,
}

/// Manages ELF images for both batch and aggregation proving
#[derive(Debug, Clone)]
pub struct ImageManager {
    batch_image: Arc<RwLock<Option<ImageInfo>>>,
    aggregation_image: Arc<RwLock<Option<ImageInfo>>>,
}

impl ImageManager {
    /// Create a new empty image manager
    pub fn new() -> Self {
        Self {
            batch_image: Arc::new(RwLock::new(None)),
            aggregation_image: Arc::new(RwLock::new(None)),
        }
    }

    /// Store an image and upload it to Boundless Market
    pub async fn store_and_upload_image(
        &self,
        image_type: &str,
        elf_bytes: Vec<u8>,
        client: &boundless_market::Client,
    ) -> Result<ImageInfo, AgentError> {
        // Compute image_id from the ELF
        let image_id = compute_image_id(&elf_bytes).map_err(|e| {
            AgentError::ProgramUploadError(format!("Failed to compute image_id: {e}"))
        })?;

        // Validate image type early and load any existing cached entry
        let existing = match image_type {
            "batch" => self.batch_image.read().await.clone(),
            "aggregation" => self.aggregation_image.read().await.clone(),
            _ => {
                return Err(AgentError::RequestBuildError(format!(
                    "Invalid image type: {}. Must be 'batch' or 'aggregation'",
                    image_type
                )));
            }
        };

        // If the same image is already stored, reuse it and skip upload.
        if let Some(existing_info) = existing {
            if existing_info.image_id == image_id {
                // Refresh presigned URL if nearing or past expiry
                if SystemTime::now() < existing_info.refresh_at {
                    tracing::info!(
                        "{} image already uploaded. Reusing Image ID: {:?}",
                        image_type,
                        image_id
                    );
                    return Ok(existing_info);
                }
                tracing::info!(
                    "{} image presigned URL nearing expiry; refreshing. Image ID: {:?}",
                    image_type,
                    image_id
                );
            } else {
                tracing::warn!(
                    "{} image differs from cached version. Replacing. Old ID: {:?}, New ID: {:?}",
                    image_type,
                    existing_info.image_id,
                    image_id
                );
            }
        }

        // Upload to Boundless Market
        tracing::info!(
            "Uploading {} image to market ({:.2} MB)...",
            image_type,
            elf_bytes.len() as f64 / 1_000_000.0
        );

        let (market_url, refresh_at) = self
            .upload_with_refresh_meta(image_type, &elf_bytes, client)
            .await?;

        tracing::info!(
            "{} image uploaded successfully. Image ID: {:?}, URL: {}",
            image_type,
            image_id,
            market_url
        );

        // Create and store the image info
        let info = ImageInfo {
            image_id,
            market_url,
            elf_bytes,
            refresh_at,
        };

        // Store in the appropriate slot
        match image_type {
            "batch" => *self.batch_image.write().await = Some(info.clone()),
            "aggregation" => *self.aggregation_image.write().await = Some(info.clone()),
            _ => unreachable!(), // Already validated above
        }

        Ok(info)
    }

    /// Get the batch image info if available
    pub async fn get_batch_image(&self) -> Option<ImageInfo> {
        self.batch_image.read().await.clone()
    }

    /// Get the aggregation image info if available
    pub async fn get_aggregation_image(&self) -> Option<ImageInfo> {
        self.aggregation_image.read().await.clone()
    }

    /// Get the market URL for batch image if available
    pub async fn get_batch_image_url(&self) -> Option<Url> {
        self.batch_image
            .read()
            .await
            .as_ref()
            .map(|i| i.market_url.clone())
    }

    /// Get the market URL for aggregation image if available
    pub async fn get_aggregation_image_url(&self) -> Option<Url> {
        self.aggregation_image
            .read()
            .await
            .as_ref()
            .map(|i| i.market_url.clone())
    }

    /// Get comprehensive information about both uploaded images
    pub async fn get_batch_info(&self) -> Option<ImageDetails> {
        self.batch_image
            .read()
            .await
            .as_ref()
            .map(|img| ImageDetails {
                uploaded: true,
                image_id: Self::digest_to_vec(&img.image_id),
                image_id_hex: format!("0x{}", hex::encode(img.image_id.as_bytes())),
                market_url: img.market_url.to_string(),
                elf_size_bytes: img.elf_bytes.len(),
            })
    }

    /// Get aggregation image details
    pub async fn get_aggregation_info(&self) -> Option<ImageDetails> {
        self.aggregation_image
            .read()
            .await
            .as_ref()
            .map(|img| ImageDetails {
                uploaded: true,
                image_id: Self::digest_to_vec(&img.image_id),
                image_id_hex: format!("0x{}", hex::encode(img.image_id.as_bytes())),
                market_url: img.market_url.to_string(),
                elf_size_bytes: img.elf_bytes.len(),
            })
    }

    /// Get the stored batch image ID if available
    pub async fn get_batch_image_id(&self) -> Option<Digest> {
        self.batch_image
            .read()
            .await
            .as_ref()
            .map(|img| img.image_id)
    }

    /// Get the stored aggregation image ID if available
    pub async fn get_aggregation_image_id(&self) -> Option<Digest> {
        self.aggregation_image
            .read()
            .await
            .as_ref()
            .map(|img| img.image_id)
    }

    /// Convert Digest to Vec<u32> for JSON serialization
    pub fn digest_to_vec(digest: &Digest) -> Vec<u32> {
        digest
            .as_bytes()
            .chunks(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect()
    }

    /// Convert Digest to fixed array for decode/validation paths
    pub fn digest_to_array(digest: &Digest) -> [u32; 8] {
        let mut arr = [0u32; 8];
        for (i, chunk) in digest.as_bytes().chunks(4).enumerate() {
            arr[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        arr
    }

    /// Convert Vec<u32> back to Digest
    pub fn vec_to_digest(vec: &[u32]) -> Result<Digest, AgentError> {
        if vec.len() != 8 {
            return Err(AgentError::RequestBuildError(format!(
                "Invalid image_id length: expected 8 u32s, got {}",
                vec.len()
            )));
        }

        let bytes: Vec<u8> = vec.iter().flat_map(|&n| n.to_le_bytes()).collect();

        Digest::try_from(bytes.as_slice())
            .map_err(|e| AgentError::RequestBuildError(format!("Invalid image_id format: {e}")))
    }

    /// Upload the program and compute a refresh deadline based on the presigned URL expiry.
    async fn upload_with_refresh_meta(
        &self,
        image_type: &str,
        elf_bytes: &[u8],
        client: &boundless_market::Client,
    ) -> Result<(Url, SystemTime), AgentError> {
        let market_url = client.upload_program(elf_bytes).await.map_err(|e| {
            AgentError::ProgramUploadError(format!("{} upload failed: {e}", image_type))
        })?;

        // Try to derive expiry from the presigned URL; fallback to 1h.
        let expires_secs = market_url
            .query_pairs()
            .find(|(k, _)| k.eq_ignore_ascii_case("X-Amz-Expires"))
            .and_then(|(_, v)| v.parse::<u64>().ok())
            .unwrap_or(3600);

        // Refresh a bit before actual expiry to avoid 403; default buffer 120s.
        let refresh_at = SystemTime::now()
            + Duration::from_secs(expires_secs.saturating_sub(120));

        Ok((market_url, refresh_at))
    }
}

/// Details about an uploaded image for API responses
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ImageDetails {
    pub uploaded: bool,
    pub image_id: Vec<u32>,
    pub image_id_hex: String,
    pub market_url: String,
    pub elf_size_bytes: usize,
}

impl Default for ImageManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_conversion() {
        let original = vec![
            3537337764u32,
            1055695413,
            664197713,
            1225410428,
            3705161813,
            2151977348,
            4164639052,
            2614443474,
        ];

        let digest = ImageManager::vec_to_digest(&original).unwrap();
        let converted = ImageManager::digest_to_vec(&digest);

        assert_eq!(
            original, converted,
            "Digest conversion should be reversible"
        );
    }
}
