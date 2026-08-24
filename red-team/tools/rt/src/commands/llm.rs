use crate::llm::*;
use anyhow::Result;

pub struct LLMCommand {
    config: LocalLLMConfig,
}

impl LLMCommand {
    pub fn new(config: LocalLLMConfig) -> Self {
        LLMCommand { config }
    }

    pub async fn health_check(&self) -> Result<()> {
        let engine = AnalysisEngine::from_config(&self.config)?;

        match engine.health_check().await {
            Ok(true) => {
                println!("✓ Ollama is running and responsive");
                println!("  Endpoint: {}", self.config.endpoint);
                println!("  Model: {}", self.config.model);

                match engine.list_available_models().await {
                    Ok(models) => {
                        println!("  Available models: {}", models.join(", "));
                    }
                    Err(e) => eprintln!("  Warning: Could not list models: {}", e),
                }
                Ok(())
            }
            Ok(false) => {
                Err(anyhow::anyhow!("Ollama is not responding. Is it running at {}?", self.config.endpoint))
            }
            Err(e) => Err(anyhow::anyhow!("Health check failed: {}", e)),
        }
    }

    pub async fn analyze_entity(&self, entity_json: &str) -> Result<()> {
        let engine = AnalysisEngine::from_config(&self.config)?;

        let analysis = engine.analyze_entity(entity_json).await?;
        println!("Entity Analysis Results:");
        println!("  Summary: {}", analysis.entity_summary);
        println!("  Confidence: {:.2}", analysis.confidence_assessment);
        println!("  Intelligence Value: {:.2}", analysis.intelligence_value);
        println!("  Attributes: {}", analysis.key_attributes.join(", "));
        println!("  Potential Connections: {}", analysis.potential_connections.join(", "));
        println!("  Recommendations:");
        for rec in analysis.recommendations {
            println!("    - {}", rec);
        }

        if self.config.cache_responses {
            if let Some(stats) = engine.cache_stats().await {
                println!("\n  Cache: {} total ({} valid, {} expired)",
                    stats.total, stats.valid, stats.expired);
            }
        }

        Ok(())
    }

    pub async fn correlate_entities(&self, entity1_json: &str, entity2_json: &str) -> Result<()> {
        let engine = AnalysisEngine::from_config(&self.config)?;

        let correlation = engine.correlate_entities(entity1_json, entity2_json).await?;
        println!("Correlation Analysis Results:");
        println!("  Relationship Type: {}", correlation.relationship_type);
        println!("  Strength: {:.2}", correlation.relationship_strength);
        println!("  Confidence: {:.2}", correlation.confidence_score);
        println!("  Evidence:");
        for evidence in correlation.supporting_evidence {
            println!("    - {}", evidence);
        }
        println!("  Intelligence Implications:");
        for impl_item in correlation.intelligence_implications {
            println!("    - {}", impl_item);
        }

        if self.config.cache_responses {
            if let Some(stats) = engine.cache_stats().await {
                println!("\n  Cache: {} total ({} valid, {} expired)",
                    stats.total, stats.valid, stats.expired);
            }
        }

        Ok(())
    }

    pub async fn assess_threat(&self, entities_json: &str) -> Result<()> {
        let engine = AnalysisEngine::from_config(&self.config)?;

        let assessment = engine.assess_threat(entities_json).await?;
        println!("Threat Assessment Results:");
        println!("  Threat Level: {} (critical)", assessment.threat_level);
        println!("  Threat Vectors:");
        for vector in assessment.threat_vectors {
            println!("    - {}", vector);
        }
        println!("  Vulnerabilities:");
        for vuln in assessment.vulnerability_assessment {
            println!("    - {}", vuln);
        }
        println!("  Mitigation Recommendations:");
        for mitigation in assessment.mitigation_recommendations {
            println!("    - {}", mitigation);
        }
        println!("  Monitoring Priorities:");
        for priority in assessment.monitoring_priorities {
            println!("    - {}", priority);
        }

        if self.config.cache_responses {
            if let Some(stats) = engine.cache_stats().await {
                println!("\n  Cache: {} total ({} valid, {} expired)",
                    stats.total, stats.valid, stats.expired);
            }
        }

        Ok(())
    }

    pub async fn collection_strategy(&self, target_profile_json: &str) -> Result<()> {
        let engine = AnalysisEngine::from_config(&self.config)?;

        let strategy = engine.recommend_collection_strategy(target_profile_json).await?;
        println!("Collection Strategy Recommendations:");
        println!("  Priority Sources:");
        for source in strategy.priority_sources {
            println!("    - {}", source);
        }
        println!("  Collection Methods:");
        for (source, methods) in strategy.collection_methods {
            println!("    {}: {}", source, methods.join(", "));
        }
        println!("  Scheduling:");
        for (source, schedule) in strategy.scheduling_recommendations {
            println!("    {}: {}", source, schedule);
        }
        println!("  Resource Requirements:");
        for req in strategy.resource_requirements {
            println!("    - {}", req);
        }
        println!("  Success Probability: {:.2}", strategy.success_probability);

        if self.config.cache_responses {
            if let Some(stats) = engine.cache_stats().await {
                println!("\n  Cache: {} total ({} valid, {} expired)",
                    stats.total, stats.valid, stats.expired);
            }
        }

        Ok(())
    }

    pub async fn validate_data(&self, data_json: &str, data_type: &str) -> Result<()> {
        let engine = AnalysisEngine::from_config(&self.config)?;

        let validation = engine.validate_data(data_json, data_type).await?;
        println!("Data Validation Results:");
        println!("  Accuracy Assessment: {:.2}", validation.accuracy_assessment);
        println!("  Reliability Score: {:.2}", validation.reliability_score);
        println!("  Confidence Level: {:.2}", validation.confidence_level);

        if !validation.inconsistencies.is_empty() {
            println!("  Inconsistencies Found:");
            for inconsistency in validation.inconsistencies {
                println!("    - {}", inconsistency);
            }
        } else {
            println!("  Inconsistencies: None");
        }

        println!("  Verification Recommendations:");
        for rec in validation.verification_recommendations {
            println!("    - {}", rec);
        }

        if self.config.cache_responses {
            if let Some(stats) = engine.cache_stats().await {
                println!("\n  Cache: {} total ({} valid, {} expired)",
                    stats.total, stats.valid, stats.expired);
            }
        }

        Ok(())
    }
}
