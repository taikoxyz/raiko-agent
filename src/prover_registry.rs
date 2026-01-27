use crate::backends::{boundless::BoundlessProver, brevis::BrevisPicoProver, zisk::ZiskProver};
use crate::image_manager::ImageUploadResult;
use crate::types::{AgentError, AgentResult, ElfType, ProofType, ProverType};

#[derive(Clone, Debug)]
pub struct ProverRegistry {
    boundless: Option<BoundlessProver>,
    zisk: Option<ZiskProver>,
    brevis_pico: Option<BrevisPicoProver>,
}

impl ProverRegistry {
    pub fn new(
        boundless: Option<BoundlessProver>,
        zisk: Option<ZiskProver>,
        brevis_pico: Option<BrevisPicoProver>,
    ) -> Self {
        Self {
            boundless,
            zisk,
            brevis_pico,
        }
    }

    pub fn supported_provers(&self) -> Vec<ProverType> {
        let mut provers = Vec::new();
        if self.boundless.is_some() {
            provers.push(ProverType::Boundless);
        }
        if self.zisk.is_some() {
            provers.push(ProverType::Zisk);
        }
        if self.brevis_pico.is_some() {
            provers.push(ProverType::BrevisPico);
        }
        provers
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn submit_proof(
        &self,
        prover_type: ProverType,
        request_id: String,
        proof_type: ProofType,
        input: Vec<u8>,
        output: Vec<u8>,
        config: serde_json::Value,
        elf: Option<Vec<u8>>,
    ) -> AgentResult<String> {
        match prover_type {
            ProverType::Boundless => match self.boundless.as_ref() {
                Some(prover) => match proof_type {
                    ProofType::Batch => prover.batch_run(request_id, input, output, &config).await,
                    ProofType::Aggregate => {
                        prover.aggregate(request_id, input, output, &config).await
                    }
                    ProofType::Update(elf_type) => {
                        let elf = elf.ok_or_else(|| {
                            AgentError::RequestBuildError(
                                "ELF data is required for Update proof type".to_string(),
                            )
                        })?;
                        prover.update(request_id, elf, elf_type).await
                    }
                },
                None => Err(AgentError::ProverUnavailable(prover_type.to_string())),
            },
            ProverType::Zisk => match self.zisk.as_ref() {
                Some(prover) => {
                    prover
                        .submit_proof(request_id, proof_type, input, output, config, elf)
                        .await
                }
                None => Err(AgentError::ProverUnavailable(prover_type.to_string())),
            },
            ProverType::BrevisPico => match self.brevis_pico.as_ref() {
                Some(prover) => {
                    prover
                        .submit_proof(request_id, proof_type, input, output, config, elf)
                        .await
                }
                None => Err(AgentError::ProverUnavailable(prover_type.to_string())),
            },
        }
    }

    pub async fn upload_image(
        &self,
        prover_type: ProverType,
        elf_type: ElfType,
        elf_bytes: Vec<u8>,
    ) -> AgentResult<ImageUploadResult> {
        match prover_type {
            ProverType::Boundless => match self.boundless.as_ref() {
                Some(prover) => prover.upload_image(elf_type, elf_bytes).await,
                None => Err(AgentError::ProverUnavailable(prover_type.to_string())),
            },
            ProverType::Zisk => match self.zisk.as_ref() {
                Some(prover) => prover.upload_image(elf_type, elf_bytes).await,
                None => Err(AgentError::ProverUnavailable(prover_type.to_string())),
            },
            ProverType::BrevisPico => match self.brevis_pico.as_ref() {
                Some(prover) => prover.upload_image(elf_type, elf_bytes).await,
                None => Err(AgentError::ProverUnavailable(prover_type.to_string())),
            },
        }
    }
}
