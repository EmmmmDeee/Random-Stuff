use super::{create_http_client, LLMAnalysis};
use reqwest::Client;
use serde_json::{json, Value};

pub struct OllamaClient {
    pub model_name: String,
    pub endpoint: String,
    client: Client,
}

impl OllamaClient {
    pub fn new() -> Self {
        OllamaClient {
            model_name: "qwen2.5-coder:1.5b".to_string(),
            endpoint: "http://127.0.0.1:11434".to_string(),
            client: create_http_client(),
        }
    }

    pub fn with_endpoint(endpoint: String, model: String) -> Self {
        OllamaClient {
            model_name: model,
            endpoint,
            client: create_http_client(),
        }
    }

    /// Async analyze security event using Ollama
    pub async fn analyze_security_event(
        &self,
        event: &str,
        context: &str,
    ) -> Result<LLMAnalysis, String> {
        let prompt = format!(
            "Analyze this security event for threats. Return ONLY valid JSON with these fields: threat_type (string), confidence (0-1 float), reasoning (string), recommended_actions (string array).\n\nEvent: {}\nContext: {}\n\nReturn JSON:",
            event, context
        );

        let response = self
            .query_ollama(&prompt)
            .await
            .map_err(|e| format!("Ollama query failed: {}", e))?;

        self.parse_analysis_response(&response)
    }

    /// Async generate detection rule from threat pattern
    pub async fn generate_detection_rule(&self, threat_pattern: &str) -> Result<String, String> {
        let prompt = format!(
            "Generate a Rust detection function for this threat. Return ONLY the Rust code without markdown or explanation.\n\nThreat Pattern: {}",
            threat_pattern
        );

        self.query_ollama(&prompt)
            .await
            .map_err(|e| format!("Rule generation failed: {}", e))
    }

    /// Core Ollama API query (async)
    async fn query_ollama(&self, prompt: &str) -> Result<String, String> {
        let url = format!("{}/api/generate", self.endpoint);
        let request_body = json!({
            "model": self.model_name,
            "prompt": prompt,
            "stream": false
        });

        let response = self
            .client
            .post(&url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        let response_text = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        // Extract the "response" field from Ollama JSON
        if let Ok(json) = serde_json::from_str::<Value>(&response_text) {
            if let Some(response_field) = json.get("response") {
                return Ok(response_field.as_str().unwrap_or("").to_string());
            }
        }

        Err(format!("Invalid Ollama response format: {}", response_text))
    }

    /// Parse LLM analysis response JSON
    fn parse_analysis_response(&self, response: &str) -> Result<LLMAnalysis, String> {
        // Try to extract JSON from response (may contain extra text)
        let json_start = response.find('{').ok_or("No JSON found in response")?;
        let json_end = response.rfind('}').ok_or("No JSON found in response")?;
        let json_str = &response[json_start..=json_end];

        serde_json::from_str::<LLMAnalysis>(json_str)
            .map_err(|e| format!("JSON parse error: {}", e))
    }

    /// Health check - verify Ollama is reachable
    pub async fn health_check(&self) -> Result<bool, String> {
        let url = format!("{}/api/tags", self.endpoint);

        match self.client.get(&url).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(e) => Err(format!("Health check failed: {}", e)),
        }
    }
}

impl Default for OllamaClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ollama_client_creation() {
        let client = OllamaClient::new();
        assert_eq!(client.model_name, "qwen2.5-coder:1.5b");
        assert_eq!(client.endpoint, "http://127.0.0.1:11434");
    }

    #[test]
    fn test_custom_endpoint() {
        let client = OllamaClient::with_endpoint(
            "http://localhost:8000".to_string(),
            "custom-model".to_string(),
        );
        assert_eq!(client.endpoint, "http://localhost:8000");
        assert_eq!(client.model_name, "custom-model");
    }
}
