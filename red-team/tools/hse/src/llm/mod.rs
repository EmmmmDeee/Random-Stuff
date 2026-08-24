use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub mod ollama;
pub use ollama::OllamaClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMAnalysis {
    pub threat_type: String,
    pub confidence: f32,
    pub reasoning: String,
    pub recommended_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMDetectionResult {
    pub alert_type: String,
    pub confidence: f32,
    pub llm_reasoning: String,
    pub recommended_actions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OllamaRequest {
    pub model: String,
    pub prompt: String,
    pub stream: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OllamaResponse {
    pub response: String,
    pub model: String,
    pub done: bool,
}

/// Create a reusable HTTP client with timeout
pub fn create_http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| Client::new())
}
