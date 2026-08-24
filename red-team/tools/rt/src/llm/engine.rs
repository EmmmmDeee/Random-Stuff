// ============================================================================
// ANALYSIS ENGINE (High-Level LLM API)
// ============================================================================

use super::error::{LLMError, LLMResult};
use super::config::LocalLLMConfig;
use super::client::OllamaClient;
use super::types::*;
use super::prompts::AnalysisPrompts;

pub struct AnalysisEngine {
    client: OllamaClient,
    config: LocalLLMConfig,
}

impl AnalysisEngine {
    pub fn new(client: OllamaClient, config: LocalLLMConfig) -> LLMResult<Self> {
        config.validate()?;
        Ok(AnalysisEngine { client, config })
    }

    pub fn from_config(config: &LocalLLMConfig) -> LLMResult<Self> {
        config.validate()?;
        let client = OllamaClient::from_config(config)?;
        Self::new(client, config.clone())
    }

    pub fn client(&self) -> &OllamaClient {
        &self.client
    }

    pub fn config(&self) -> &LocalLLMConfig {
        &self.config
    }

    /// Verify local LLM is available and responsive
    pub async fn health_check(&self) -> LLMResult<bool> {
        self.client.health_check().await
    }

    /// List models available in local Ollama
    pub async fn list_available_models(&self) -> LLMResult<Vec<String>> {
        self.client.list_models().await
    }

    /// Download model to local Ollama
    pub async fn ensure_model_available(&self) -> LLMResult<()> {
        if !self.health_check().await? {
            return Err(LLMError::ModelNotFound(
                format!("Ollama not running at {}", self.client.base_url()),
            ));
        }

        let available_models = self.list_available_models().await?;
        if !available_models.contains(&self.client.model().to_string()) {
            if self.config.auto_pull_model {
                self.client.pull_model(self.client.model()).await?;
            } else {
                return Err(LLMError::ModelNotFound(format!(
                    "Model '{}' not found locally. Use auto_pull_model=true or run: ollama pull {}",
                    self.client.model(),
                    self.client.model()
                )));
            }
        }
        Ok(())
    }

    /// Analyze OSINT entity
    pub async fn analyze_entity(&self, entity_data: &str) -> LLMResult<EntityAnalysis> {
        let prompt = format!(
            "{}\n\nEntity data: {}",
            AnalysisPrompts::entity_analysis(),
            entity_data
        );

        let request = LLMRequest::new(prompt)
            .with_system("You are an OSINT analyst.")
            .with_temperature(0.3)
            .with_max_tokens(1024);

        let response = self.client.generate(&request).await?;
        self.parse_json_response::<EntityAnalysis>(&response.content)
    }

    /// Correlate two OSINT entities
    pub async fn correlate_entities(
        &self,
        entity1_data: &str,
        entity2_data: &str,
    ) -> LLMResult<CorrelationAnalysis> {
        let prompt = format!(
            "{}\n\nEntity 1: {}\n\nEntity 2: {}",
            AnalysisPrompts::correlation_analysis(),
            entity1_data,
            entity2_data
        );

        let request = LLMRequest::new(prompt)
            .with_system("You are an entity correlation analyst.")
            .with_temperature(0.2)
            .with_max_tokens(1024);

        let response = self.client.generate(&request).await?;
        self.parse_json_response::<CorrelationAnalysis>(&response.content)
    }

    /// Assess threats from OSINT data
    pub async fn assess_threat(&self, entities_data: &str) -> LLMResult<ThreatAssessment> {
        let prompt = format!(
            "{}\n\nData: {}",
            AnalysisPrompts::threat_assessment(),
            entities_data
        );

        let request = LLMRequest::new(prompt)
            .with_system("You are a threat analyst.")
            .with_temperature(0.3)
            .with_max_tokens(1536);

        let response = self.client.generate(&request).await?;
        self.parse_json_response::<ThreatAssessment>(&response.content)
    }

    /// Recommend OSINT collection strategy
    pub async fn recommend_collection_strategy(
        &self,
        target_profile: &str,
    ) -> LLMResult<CollectionStrategy> {
        let prompt = format!(
            "{}\n\nTarget: {}",
            AnalysisPrompts::collection_strategy(),
            target_profile
        );

        let request = LLMRequest::new(prompt)
            .with_system("You are an OSINT collection planner.")
            .with_temperature(0.4)
            .with_max_tokens(1536);

        let response = self.client.generate(&request).await?;
        self.parse_json_response::<CollectionStrategy>(&response.content)
    }

    /// Validate OSINT data for accuracy
    pub async fn validate_data(&self, data: &str, data_type: &str) -> LLMResult<ValidationResult> {
        let prompt = format!(
            "{}\n\nType: {}\n\nData: {}",
            AnalysisPrompts::data_validation(),
            data_type,
            data
        );

        let request = LLMRequest::new(prompt)
            .with_system("You are a data validation expert.")
            .with_temperature(0.2)
            .with_max_tokens(1024);

        let response = self.client.generate(&request).await?;
        self.parse_json_response::<ValidationResult>(&response.content)
    }

    fn parse_json_response<T: serde::de::DeserializeOwned>(
        &self,
        content: &str,
    ) -> LLMResult<T> {
        serde_json::from_str(content).map_err(|e| {
            LLMError::ParseError(format!(
                "Failed to parse LLM response as JSON: {}. Response: {}",
                e, content
            ))
        })
    }
}
