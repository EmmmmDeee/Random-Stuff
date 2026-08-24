// ============================================================================
// LOCAL LLM CONFIGURATION
// ============================================================================

use serde::{Deserialize, Serialize};
use super::error::{LLMError, LLMResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalLLMConfig {
    /// Ollama or local LLM server endpoint (e.g., http://localhost:11434)
    pub endpoint: String,

    /// Model identifier (e.g., "qwen2.5-coder:1.5b", "mistral", "neural-chat")
    pub model: String,

    /// Maximum tokens to generate
    pub max_tokens: u32,

    /// Temperature for generation (0.0-2.0, lower = more deterministic)
    pub temperature: f32,

    /// Request timeout in seconds
    pub timeout_seconds: u32,

    /// Enable response caching locally
    pub cache_responses: bool,

    /// Cache TTL in hours
    pub cache_ttl_hours: u32,

    /// Automatically pull model if not found locally
    pub auto_pull_model: bool,

    /// RAM requirement check (MB, optional)
    pub min_ram_mb: Option<u32>,
}

impl Default for LocalLLMConfig {
    fn default() -> Self {
        LocalLLMConfig {
            endpoint: "http://localhost:11434".to_string(),
            model: "qwen2.5-coder:1.5b".to_string(),
            max_tokens: 4096,
            temperature: 0.7,
            timeout_seconds: 60,
            cache_responses: true,
            cache_ttl_hours: 24,
            auto_pull_model: false,
            min_ram_mb: Some(2048),
        }
    }
}

impl LocalLLMConfig {
    pub fn new(endpoint: &str, model: &str) -> Self {
        LocalLLMConfig {
            endpoint: endpoint.to_string(),
            model: model.to_string(),
            ..Default::default()
        }
    }

    /// Ollama configuration for lightweight OSINT analysis
    pub fn ollama_lightweight() -> Self {
        LocalLLMConfig {
            endpoint: "http://localhost:11434".to_string(),
            model: "qwen2.5-coder:1.5b".to_string(),
            max_tokens: 2048,
            temperature: 0.3,
            timeout_seconds: 45,
            cache_responses: true,
            cache_ttl_hours: 48,
            auto_pull_model: true,
            min_ram_mb: Some(2048),
        }
    }

    /// Ollama configuration for detailed analysis
    pub fn ollama_detailed() -> Self {
        LocalLLMConfig {
            endpoint: "http://localhost:11434".to_string(),
            model: "mistral".to_string(),
            max_tokens: 4096,
            temperature: 0.4,
            timeout_seconds: 90,
            cache_responses: true,
            cache_ttl_hours: 24,
            auto_pull_model: true,
            min_ram_mb: Some(4096),
        }
    }

    /// Validate configuration for local LLM
    pub fn validate(&self) -> LLMResult<()> {
        if self.endpoint.is_empty() {
            return Err(LLMError::Configuration(
                "Ollama endpoint cannot be empty".to_string(),
            ));
        }
        if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
            return Err(LLMError::Configuration(
                "Endpoint must be valid HTTP/HTTPS URL".to_string(),
            ));
        }
        if self.model.is_empty() {
            return Err(LLMError::Configuration("Model name cannot be empty".to_string()));
        }
        if self.temperature < 0.0 || self.temperature > 2.0 {
            return Err(LLMError::Configuration(
                "Temperature must be between 0.0 and 2.0".to_string(),
            ));
        }
        if self.max_tokens < 256 || self.max_tokens > 32768 {
            return Err(LLMError::Configuration(
                "Max tokens must be between 256 and 32768".to_string(),
            ));
        }
        Ok(())
    }
}
