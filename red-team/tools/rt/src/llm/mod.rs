// ============================================================================
// HUNTSMAN OSINT ENGINE - LLM INTEGRATION MODULE
// ============================================================================
// Local-only LLM integration for OSINT analysis
// Focused on self-hosted, free, local LLM instances (Ollama, LLaMA, Mistral)
// ============================================================================

pub mod error;
pub mod config;
pub mod types;
pub mod prompts;
pub mod client;
pub mod cache;
pub mod engine;
pub mod integration;

// Re-export public API
pub use error::{LLMError, LLMResult};
pub use config::LocalLLMConfig;
pub use types::*;
pub use prompts::AnalysisPrompts;
pub use client::OllamaClient;
pub use cache::ResponseCache;
pub use engine::AnalysisEngine;
pub use integration::LLMIntegration;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LocalLLMConfig::default();
        assert_eq!(config.endpoint, "http://localhost:11434");
        assert_eq!(config.model, "qwen2.5-coder:1.5b");
        assert_eq!(config.max_tokens, 4096);
        assert_eq!(config.temperature, 0.7);
        assert!(config.cache_responses);
    }

    #[test]
    fn test_config_validation_success() {
        let config = LocalLLMConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_empty_endpoint() {
        let mut config = LocalLLMConfig::default();
        config.endpoint = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_invalid_url() {
        let mut config = LocalLLMConfig::default();
        config.endpoint = "not-a-url".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_empty_model() {
        let mut config = LocalLLMConfig::default();
        config.model = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_temperature_too_low() {
        let mut config = LocalLLMConfig::default();
        config.temperature = -0.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_temperature_too_high() {
        let mut config = LocalLLMConfig::default();
        config.temperature = 2.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_max_tokens_too_low() {
        let mut config = LocalLLMConfig::default();
        config.max_tokens = 100;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_max_tokens_too_high() {
        let mut config = LocalLLMConfig::default();
        config.max_tokens = 50000;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_lightweight_config() {
        let config = LocalLLMConfig::ollama_lightweight();
        assert_eq!(config.model, "qwen2.5-coder:1.5b");
        assert_eq!(config.max_tokens, 2048);
        assert_eq!(config.temperature, 0.3);
        assert!(config.auto_pull_model);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_detailed_config() {
        let config = LocalLLMConfig::ollama_detailed();
        assert_eq!(config.model, "mistral");
        assert_eq!(config.max_tokens, 4096);
        assert_eq!(config.temperature, 0.4);
        assert!(config.auto_pull_model);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_request_builder() {
        let req = types::LLMRequest::new("test")
            .with_system("system prompt")
            .with_temperature(0.5)
            .with_max_tokens(1024);

        assert_eq!(req.system_prompt, Some("system prompt".to_string()));
        assert_eq!(req.temperature, Some(0.5));
        assert_eq!(req.max_tokens, Some(1024));
    }

    #[test]
    fn test_entity_analysis_prompt() {
        let prompt = AnalysisPrompts::entity_analysis();
        assert!(prompt.contains("entity_summary"));
        assert!(prompt.contains("key_attributes"));
        assert!(prompt.contains("confidence_assessment"));
    }

    #[test]
    fn test_correlation_analysis_prompt() {
        let prompt = AnalysisPrompts::correlation_analysis();
        assert!(prompt.contains("relationship_type"));
        assert!(prompt.contains("relationship_strength"));
    }

    #[test]
    fn test_threat_assessment_prompt() {
        let prompt = AnalysisPrompts::threat_assessment();
        assert!(prompt.contains("threat_level"));
        assert!(prompt.contains("threat_vectors"));
    }

    #[test]
    fn test_collection_strategy_prompt() {
        let prompt = AnalysisPrompts::collection_strategy();
        assert!(prompt.contains("priority_sources"));
        assert!(prompt.contains("collection_methods"));
    }

    #[test]
    fn test_data_validation_prompt() {
        let prompt = AnalysisPrompts::data_validation();
        assert!(prompt.contains("accuracy_assessment"));
        assert!(prompt.contains("reliability_score"));
    }

    #[test]
    fn test_ollama_client_creation() {
        let client = OllamaClient::new("http://localhost:11434", "qwen2.5-coder:1.5b", 60);
        assert_eq!(client.base_url(), "http://localhost:11434");
        assert_eq!(client.model(), "qwen2.5-coder:1.5b");
    }

    #[test]
    fn test_analysis_engine_from_config() {
        let config = LocalLLMConfig::default();
        let engine = AnalysisEngine::from_config(&config);
        assert!(engine.is_ok());
    }
}
