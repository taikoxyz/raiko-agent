use crate::types::{AgentError, ElfType, ProverType};
use alloy_primitives_v1p2p0::hex;
use risc0_zkvm::sha::Digest;
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::SystemTime,
};
use tokio::sync::RwLock;
use url::Url;
use utoipa::ToSchema;

/// Information about an uploaded ELF image
#[derive(Debug, Clone)]
pub struct ImageInfo {
    /// Optional image ID (provider-specific)
    pub image_id: Option<Digest>,
    /// Optional URL where the image is stored in the provider backend
    pub remote_url: Option<Url>,
    /// The original ELF bytes (cached for potential re-upload)
    pub elf_bytes: Vec<u8>,
    /// When to refresh the presigned URL before it expires
    pub refresh_at: Option<SystemTime>,
}

#[derive(Debug, Clone)]
pub struct ImageUploadResult {
    pub info: ImageInfo,
    pub reused: bool,
}

/// Manages ELF images for batch and aggregation proving per prover
#[derive(Debug, Clone)]
pub struct ImageManager {
    images: Arc<RwLock<HashMap<(ProverType, ElfType), ImageInfo>>>,
}

impl ImageManager {
    /// Create a new empty image manager
    pub fn new() -> Self {
        Self {
            images: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn key(prover_type: &ProverType, elf_type: &ElfType) -> (ProverType, ElfType) {
        (prover_type.clone(), elf_type.clone())
    }

    /// Store an image in the in-memory cache
    pub async fn set_image(&self, prover_type: ProverType, elf_type: ElfType, info: ImageInfo) {
        let mut images = self.images.write().await;
        images.insert(Self::key(&prover_type, &elf_type), info);
    }

    /// Get an image if available
    pub async fn get_image(&self, prover_type: ProverType, elf_type: ElfType) -> Option<ImageInfo> {
        self.images
            .read()
            .await
            .get(&Self::key(&prover_type, &elf_type))
            .cloned()
    }

    /// Get the stored image ID if available
    pub async fn get_image_id(&self, prover_type: ProverType, elf_type: ElfType) -> Option<Digest> {
        self.get_image(prover_type, elf_type)
            .await
            .and_then(|img| img.image_id)
    }

    /// Get the remote URL if available
    pub async fn get_image_url(&self, prover_type: ProverType, elf_type: ElfType) -> Option<Url> {
        self.get_image(prover_type, elf_type)
            .await
            .and_then(|img| img.remote_url)
    }

    /// Get image details for API responses
    pub async fn get_image_details(
        &self,
        prover_type: ProverType,
        elf_type: ElfType,
    ) -> Option<ImageDetails> {
        self.get_image(prover_type, elf_type).await.map(|img| {
            let (image_id, image_id_hex) = match &img.image_id {
                Some(id) => (
                    Some(Self::digest_to_vec(id)),
                    Some(format!("0x{}", hex::encode(id.as_bytes()))),
                ),
                None => (None, None),
            };

            ImageDetails {
                uploaded: true,
                image_id,
                image_id_hex,
                provider_url: img.remote_url.map(|url| url.to_string()),
                elf_size_bytes: img.elf_bytes.len(),
            }
        })
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
}

/// Details about an uploaded image for API responses
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ImageDetails {
    pub uploaded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_id: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_id_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_url: Option<String>,
    pub elf_size_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use risc0_zkvm::sha::Digest;

    #[test]
    fn test_digest_vec_roundtrip() {
        let bytes: Vec<u8> = (0u8..32u8).collect();
        let digest = Digest::try_from(bytes.as_slice()).unwrap();

        let vec = ImageManager::digest_to_vec(&digest);
        assert_eq!(vec.len(), 8);

        let rebuilt = ImageManager::vec_to_digest(&vec).unwrap();
        assert_eq!(rebuilt, digest);

        let arr = ImageManager::digest_to_array(&digest);
        assert_eq!(arr.as_slice(), vec.as_slice());
    }

    #[test]
    fn test_vec_to_digest_rejects_wrong_length() {
        let err = ImageManager::vec_to_digest(&[1u32, 2, 3]).unwrap_err();
        assert!(matches!(err, AgentError::RequestBuildError(_)));
    }

    #[tokio::test]
    async fn test_get_image_details_includes_hex_and_sizes() {
        let manager = ImageManager::new();

        let bytes: Vec<u8> = (0u8..32u8).collect();
        let digest = Digest::try_from(bytes.as_slice()).unwrap();
        let url = Url::parse("https://example.com/program").unwrap();

        manager
            .set_image(
                ProverType::Boundless,
                ElfType::Batch,
                ImageInfo {
                    image_id: Some(digest),
                    remote_url: Some(url.clone()),
                    elf_bytes: vec![1, 2, 3, 4, 5],
                    refresh_at: None,
                },
            )
            .await;

        let details = manager
            .get_image_details(ProverType::Boundless, ElfType::Batch)
            .await
            .unwrap();

        assert!(details.uploaded);
        assert_eq!(details.elf_size_bytes, 5);
        assert_eq!(details.provider_url.as_deref(), Some(url.as_str()));
        assert_eq!(details.image_id.as_ref().unwrap().len(), 8);
        assert!(details
            .image_id_hex
            .as_ref()
            .unwrap()
            .starts_with("0x"));
    }
}
