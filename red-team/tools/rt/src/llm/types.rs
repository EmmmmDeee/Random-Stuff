// ============================================================================
// DATA TYPES FOR LLM REQUESTS AND RESPONSES
// ============================================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- Request Types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMRequest {
    pub prompt: String,
    pub context: Option<String>,
    pub system_prompt: Option<String>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
}

impl LLMRequest {
    pub fn new(prompt: impl Into<String>) -> Self {
        LLMRequest {
            prompt: prompt.into(),
            context: None,
            system_prompt: None,
            temperature: None,
            max_tokens: None,
        }
    }

    pub fn with_system(mut self, system_prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(system_prompt.into());
        self
    }

    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    pub fn with_temperature(mut self, temp: f32) -> Self {
        self.temperature = Some(temp);
        self
    }

    pub fn with_max_tokens(mut self, tokens: u32) -> Self {
        self.max_tokens = Some(tokens);
        self
    }
}

// --- Response Types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMResponse {
    pub content: String,
    pub usage: TokenUsage,
    pub finish_reason: String,
    pub model: String,
    pub latency_ms: u32,
}

// --- Analysis Result Types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityAnalysis {
    pub entity_summary: String,
    pub key_attributes: Vec<String>,
    pub confidence_assessment: f32,
    pub intelligence_value: f32,
    pub recommendations: Vec<String>,
    pub potential_connections: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationAnalysis {
    pub relationship_type: String,
    pub relationship_strength: f32,
    pub supporting_evidence: Vec<String>,
    pub confidence_score: f32,
    pub intelligence_implications: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssessment {
    pub threat_level: String,
    pub threat_vectors: Vec<String>,
    pub vulnerability_assessment: Vec<String>,
    pub mitigation_recommendations: Vec<String>,
    pub monitoring_priorities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionStrategy {
    pub priority_sources: Vec<String>,
    pub collection_methods: HashMap<String, Vec<String>>,
    pub scheduling_recommendations: HashMap<String, String>,
    pub resource_requirements: Vec<String>,
    pub success_probability: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub accuracy_assessment: f32,
    pub reliability_score: f32,
    pub inconsistencies: Vec<String>,
    pub verification_recommendations: Vec<String>,
    pub confidence_level: f32,
}
