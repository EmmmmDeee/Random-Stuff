// ============================================================================
// BATCH PROCESSING FOR EFFICIENT OSINT ANALYSIS
// ============================================================================
// Handles multiple analysis requests concurrently with resource pooling
// ============================================================================

use std::sync::Arc;
use super::engine::AnalysisEngine;
use super::types::*;
use super::error::{LLMError, LLMResult};

pub struct BatchAnalyzer {
    engine: Arc<AnalysisEngine>,
    max_concurrent: usize,
}

impl BatchAnalyzer {
    pub fn new(engine: AnalysisEngine, max_concurrent: usize) -> Self {
        BatchAnalyzer {
            engine: Arc::new(engine),
            max_concurrent,
        }
    }

    /// Batch analyze multiple entities concurrently
    pub async fn analyze_entities_batch(
        &self,
        entities: Vec<String>,
    ) -> Vec<LLMResult<EntityAnalysis>> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_concurrent));
        let mut tasks = Vec::new();

        for entity in entities {
            let engine = Arc::clone(&self.engine);
            let sem = Arc::clone(&semaphore);

            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.ok();
                engine.analyze_entity(&entity).await
            });

            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(LLMError::Network(format!("Task error: {}", e)))),
            }
        }

        results
    }

    /// Batch correlate multiple entity pairs
    pub async fn correlate_entities_batch(
        &self,
        pairs: Vec<(String, String)>,
    ) -> Vec<LLMResult<CorrelationAnalysis>> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_concurrent));
        let mut tasks = Vec::new();

        for (entity1, entity2) in pairs {
            let engine = Arc::clone(&self.engine);
            let sem = Arc::clone(&semaphore);

            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.ok();
                engine.correlate_entities(&entity1, &entity2).await
            });

            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(LLMError::Network(format!("Task error: {}", e)))),
            }
        }

        results
    }

    /// Batch assess threats for multiple datasets
    pub async fn assess_threats_batch(
        &self,
        datasets: Vec<String>,
    ) -> Vec<LLMResult<ThreatAssessment>> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_concurrent));
        let mut tasks = Vec::new();

        for data in datasets {
            let engine = Arc::clone(&self.engine);
            let sem = Arc::clone(&semaphore);

            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.ok();
                engine.assess_threat(&data).await
            });

            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(LLMError::Network(format!("Task error: {}", e)))),
            }
        }

        results
    }

    /// Batch validate multiple data items
    pub async fn validate_data_batch(
        &self,
        items: Vec<(String, String)>,
    ) -> Vec<LLMResult<ValidationResult>> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_concurrent));
        let mut tasks = Vec::new();

        for (data, data_type) in items {
            let engine = Arc::clone(&self.engine);
            let sem = Arc::clone(&semaphore);

            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.ok();
                engine.validate_data(&data, &data_type).await
            });

            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(LLMError::Network(format!("Task error: {}", e)))),
            }
        }

        results
    }

    /// Get summary statistics for batch operation
    pub fn stats(&self) -> BatchStats {
        BatchStats {
            max_concurrent: self.max_concurrent,
        }
    }
}

#[derive(Debug)]
pub struct BatchStats {
    pub max_concurrent: usize,
}

pub struct BatchResult<T> {
    pub successful: Vec<T>,
    pub failed: Vec<(usize, LLMError)>,
}

impl<T> BatchResult<T> {
    pub fn new() -> Self {
        BatchResult {
            successful: Vec::new(),
            failed: Vec::new(),
        }
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.successful.len() + self.failed.len();
        if total == 0 {
            0.0
        } else {
            (self.successful.len() as f64 / total as f64) * 100.0
        }
    }

    pub fn print_summary(&self) {
        println!("\nBatch Processing Summary:");
        println!("  Successful: {}", self.successful.len());
        println!("  Failed: {}", self.failed.len());
        println!("  Success Rate: {:.2}%", self.success_rate());
        if !self.failed.is_empty() {
            println!("  Failures:");
            for (idx, err) in &self.failed {
                println!("    [{}]: {}", idx, err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::LocalLLMConfig;

    #[tokio::test]
    async fn test_batch_analyzer_creation() {
        let config = LocalLLMConfig::ollama_lightweight();
        let engine = AnalysisEngine::from_config(&config).expect("Failed to create engine");
        let analyzer = BatchAnalyzer::new(engine, 5);
        let stats = analyzer.stats();
        assert_eq!(stats.max_concurrent, 5);
    }
}
