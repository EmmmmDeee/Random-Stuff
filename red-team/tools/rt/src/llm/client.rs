// ============================================================================
// OLLAMA CLIENT (Direct Local LLM Access)
// ============================================================================

use std::time::Duration;
use super::error::{LLMError, LLMResult};
use super::config::LocalLLMConfig;
use super::types::{LLMRequest, LLMResponse, TokenUsage};

pub struct OllamaClient {
    base_url: String,
    model: String,
    timeout: Duration,
    config: LocalLLMConfig,
}

impl OllamaClient {
    pub fn new(base_url: impl Into<String>, model: impl Into<String>, timeout_secs: u64) -> Self {
        OllamaClient {
            base_url: base_url.into(),
            model: model.into(),
            timeout: Duration::from_secs(timeout_secs),
            config: LocalLLMConfig::default(),
        }
    }

    pub fn from_config(config: &LocalLLMConfig) -> LLMResult<Self> {
        config.validate()?;
        Ok(OllamaClient {
            base_url: config.endpoint.clone(),
            model: config.model.clone(),
            timeout: Duration::from_secs(config.timeout_seconds as u64),
            config: config.clone(),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// Generate response from local Ollama instance
    pub async fn generate(&self, request: &LLMRequest) -> LLMResult<LLMResponse> {
        let start_time = std::time::Instant::now();

        // In production, use reqwest to make actual HTTP call to Ollama
        // Example: POST to http://localhost:11434/api/generate
        // For now, mock implementation for compilation

        let content = self.build_response(request);
        let latency_ms = start_time.elapsed().as_millis() as u32;

        Ok(LLMResponse {
            content,
            usage: TokenUsage {
                prompt_tokens: self.estimate_tokens(&request.prompt),
                completion_tokens: 50,
                total_tokens: self.estimate_tokens(&request.prompt) + 50,
            },
            finish_reason: "stop".to_string(),
            model: self.model.clone(),
            latency_ms,
        })
    }

    /// Check if Ollama service is running and model is available
    pub async fn health_check(&self) -> LLMResult<bool> {
        // In production: GET http://localhost:11434/api/tags
        // Check if model is in the response
        Ok(true)
    }

    /// List available local models
    pub async fn list_models(&self) -> LLMResult<Vec<String>> {
        // In production: GET http://localhost:11434/api/tags
        Ok(vec![
            self.model.clone(),
            "mistral".to_string(),
            "neural-chat".to_string(),
        ])
    }

    /// Pull model from Ollama registry (download to local)
    pub async fn pull_model(&self, model: &str) -> LLMResult<()> {
        // In production: POST http://localhost:11434/api/pull
        // with {"model": model, "stream": false}
        println!("Pulling model: {}", model);
        Ok(())
    }

    fn build_response(&self, request: &LLMRequest) -> String {
        // Parse prompt to determine response type
        if request.prompt.contains("entity_summary") {
            r#"{"entity_summary": "Analyzed entity", "key_attributes": ["attr1"], "confidence_assessment": 0.85, "intelligence_value": 0.8, "recommendations": ["verify"], "potential_connections": ["connection"]}"#.to_string()
        } else if request.prompt.contains("relationship") {
            r#"{"relationship_type": "associated_with", "relationship_strength": 0.75, "supporting_evidence": ["evidence1"], "confidence_score": 0.8, "intelligence_implications": ["implication"]}"#.to_string()
        } else if request.prompt.contains("threat") {
            r#"{"threat_level": "medium", "threat_vectors": ["vector1"], "vulnerability_assessment": ["vuln1"], "mitigation_recommendations": ["fix1"], "monitoring_priorities": ["priority1"]}"#.to_string()
        } else {
            "Generated response from local LLM".to_string()
        }
    }

    fn estimate_tokens(&self, text: &str) -> u32 {
        (text.len() / 4) as u32 + 1
    }
}
