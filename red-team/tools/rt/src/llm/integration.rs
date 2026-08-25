// ============================================================================
// LLM INTEGRATION (Startup & Lifecycle Management)
// ============================================================================

use super::error::{LLMError, LLMResult};
use super::config::LocalLLMConfig;
use super::engine::AnalysisEngine;

pub struct LLMIntegration {
    engine: AnalysisEngine,
    cache_enabled: bool,
}

impl LLMIntegration {
    /// Initialize LLM integration with local Ollama instance
    pub async fn initialize(config: &LocalLLMConfig) -> LLMResult<Self> {
        config.validate()?;

        let engine = AnalysisEngine::from_config(config)?;

        // Ensure model is available locally
        engine.ensure_model_available().await?;

        // Verify health
        if !engine.health_check().await? {
            return Err(LLMError::Configuration(
                format!(
                    "Cannot connect to local Ollama at {}. Is it running?",
                    config.endpoint
                )
            ));
        }

        println!(
            "✓ LLM Integration initialized: {} ({})",
            config.model, config.endpoint
        );

        Ok(LLMIntegration {
            engine,
            cache_enabled: config.cache_responses,
        })
    }

    pub fn engine(&self) -> &AnalysisEngine {
        &self.engine
    }

    pub fn is_cache_enabled(&self) -> bool {
        self.cache_enabled
    }

    pub fn model(&self) -> &str {
        self.engine.client().model()
    }

    pub fn endpoint(&self) -> &str {
        self.engine.client().base_url()
    }
}
