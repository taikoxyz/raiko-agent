use crate::image_manager::{ImageInfo, ImageManager, ImageUploadResult};
use crate::types::{AgentError, AgentResult, ElfType, ProofType, ProverType};

#[derive(Clone, Debug)]
pub struct ZiskProver {
    image_manager: ImageManager,
}

impl ZiskProver {
    pub fn new(image_manager: ImageManager) -> Self {
        Self { image_manager }
    }

    pub async fn submit_proof(
        &self,
        _request_id: String,
        _proof_type: ProofType,
        _input: Vec<u8>,
        _output: Vec<u8>,
        _config: serde_json::Value,
        _elf: Option<Vec<u8>>,
    ) -> AgentResult<String> {
        Err(AgentError::NotImplemented(
            "zisk prover is not implemented yet".to_string(),
        ))
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
}
