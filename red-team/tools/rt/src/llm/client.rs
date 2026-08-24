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

        let client = reqwest::Client::new();
        let url = format!("{}/api/generate", self.base_url);

        let temperature = request.temperature.unwrap_or(0.7);
        let max_tokens = request.max_tokens.unwrap_or(self.config.max_tokens);

        let mut prompt = request.prompt.clone();
        if let Some(system) = &request.system_prompt {
            prompt = format!("{}\n\n{}", system, prompt);
        }

        let body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "temperature": temperature,
            "num_predict": max_tokens,
            "stream": false,
        });

        let response = client
            .post(&url)
            .timeout(self.timeout)
            .json(&body)
            .send()
            .await
            .map_err(|e| LLMError::Network(format!("Failed to reach Ollama at {}: {}", url, e)))?;

        if !response.status().is_success() {
            return Err(LLMError::Network(format!(
                "Ollama returned status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            )));
        }

        let data: serde_json::Value = response
            .json()
            .await
            .map_err(|e| LLMError::InvalidResponse(format!("Failed to parse Ollama response: {}", e)))?;

        let content = data
            .get("response")
            .and_then(|v| v.as_str())
            .ok_or_else(|| LLMError::InvalidResponse("No response field in Ollama output".to_string()))?
            .to_string();

        let latency_ms = start_time.elapsed().as_millis() as u32;
        let prompt_tokens = self.estimate_tokens(&prompt);
        let completion_tokens = self.estimate_tokens(&content);

        Ok(LLMResponse {
            content,
            usage: TokenUsage {
                prompt_tokens,
                completion_tokens,
                total_tokens: prompt_tokens + completion_tokens,
            },
            finish_reason: "stop".to_string(),
            model: self.model.clone(),
            latency_ms,
        })
    }

    /// Check if Ollama service is running and model is available
    pub async fn health_check(&self) -> LLMResult<bool> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/tags", self.base_url);

        match client.get(&url).timeout(self.timeout).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(true)
                } else {
                    Err(LLMError::Network(format!(
                        "Ollama health check failed with status {}",
                        response.status()
                    )))
                }
            }
            Err(e) => Err(LLMError::Network(format!(
                "Cannot connect to Ollama at {}: {}",
                self.base_url, e
            ))),
        }
    }

    /// List available local models
    pub async fn list_models(&self) -> LLMResult<Vec<String>> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/tags", self.base_url);

        let response = client
            .get(&url)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| LLMError::Network(format!("Failed to fetch model list: {}", e)))?;

        let data: serde_json::Value = response
            .json()
            .await
            .map_err(|e| LLMError::InvalidResponse(format!("Failed to parse model list: {}", e)))?;

        let models: Vec<String> = data
            .get("models")
            .and_then(|v| v.as_array())
            .ok_or_else(|| LLMError::InvalidResponse("No models array in response".to_string()))?
            .iter()
            .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect();

        Ok(models)
    }

    /// Pull model from Ollama registry (download to local)
    pub async fn pull_model(&self, model: &str) -> LLMResult<()> {
        let client = reqwest::Client::new();
        let url = format!("{}/api/pull", self.base_url);

        let body = serde_json::json!({
            "model": model,
            "stream": false,
        });

        let response = client
            .post(&url)
            .timeout(self.timeout)
            .json(&body)
            .send()
            .await
            .map_err(|e| LLMError::ModelLoading(format!("Failed to pull model: {}", e)))?;

        if !response.status().is_success() {
            return Err(LLMError::ModelLoading(format!(
                "Failed to pull model {}: {}",
                model,
                response.text().await.unwrap_or_default()
            )));
        }

        println!("✓ Successfully pulled model: {}", model);
        Ok(())
    }

    fn estimate_tokens(&self, text: &str) -> u32 {
        (text.len() / 4) as u32 + 1
    }
}
