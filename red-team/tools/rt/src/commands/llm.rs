use crate::llm::*;
use crate::llm::batch::BatchResult;
use anyhow::Result;
use std::sync::Arc;

pub struct LLMCommand {
    config: LocalLLMConfig,
    pool: Option<Arc<ClientPool>>,
    metrics: Option<Arc<Metrics>>,
}

impl LLMCommand {
    pub fn new(config: LocalLLMConfig) -> Self {
        LLMCommand {
            config,
            pool: None,
            metrics: None,
        }
    }

    pub fn with_deployment_profile(profile_name: &str) -> Result<Self> {
        let _profile = DeploymentProfile::get_profile(profile_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown profile: {}", profile_name))?;

        let config = match profile_name.to_lowercase().as_str() {
            "edge" => ProductionConfig::edge(),
            "standard" => ProductionConfig::standard(),
            "enterprise" => ProductionConfig::enterprise(),
            "realtime" => ProductionConfig::realtime(),
            "batch" => ProductionConfig::batch(),
            _ => return Err(anyhow::anyhow!("Unknown profile: {}", profile_name)),
        };

        config.validate()?;
        Ok(LLMCommand {
            config,
            pool: None,
            metrics: None,
        })
    }

    pub fn init_pool(&mut self, pool_size: usize) -> Result<()> {
        let pool = ClientPool::new(self.config.clone(), pool_size)?;
        self.pool = Some(Arc::new(pool));
        Ok(())
    }

    pub fn init_metrics(&mut self) {
        self.metrics = Some(Arc::new(Metrics::new()));
    }

    pub fn show_deployment_profiles() {
        println!("\n=== Available Deployment Profiles ===\n");
        for profile_name in DeploymentProfile::all_profiles() {
            if let Some(profile) = DeploymentProfile::get_profile(profile_name) {
                profile.print_info();
            }
        }
    }

    pub fn show_metrics(&self) -> Result<()> {
        if let Some(metrics) = &self.metrics {
            let stats = metrics.get_stats();
            stats.print_summary();
            Ok(())
        } else {
            Err(anyhow::anyhow!("Metrics not initialized"))
        }
    }

    pub fn reset_metrics(&self) -> Result<()> {
        if let Some(metrics) = &self.metrics {
            metrics.reset();
            Ok(())
        } else {
            Err(anyhow::anyhow!("Metrics not initialized"))
        }
    }

    pub fn show_pool_stats(&self) -> Result<()> {
        if let Some(pool) = &self.pool {
            let stats = pool.stats();
            println!("\n=== Connection Pool Status ===");
            println!("Pool Size: {}", stats.pool_size);
            println!("Available Permits: {}", stats.available_permits);
            println!("Active Connections: {}", stats.pool_size - stats.available_permits);
            println!("==============================\n");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Connection pool not initialized"))
        }
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

    pub async fn batch_analyze_entities(&self, entities: Vec<String>, max_concurrent: usize) -> Result<()> {
        let engine = AnalysisEngine::from_config(&self.config)?;
        let analyzer = BatchAnalyzer::new(engine, max_concurrent);

        if let Some(metrics) = &self.metrics {
            let _timer = metrics.record_request_start();
        }

        let results = analyzer.analyze_entities_batch(entities).await;

        let mut batch_result = BatchResult::new();
        for (idx, result) in results.into_iter().enumerate() {
            match result {
                Ok(analysis) => batch_result.successful.push(analysis),
                Err(e) => batch_result.failed.push((idx, e)),
            }
        }

        batch_result.print_summary();
        Ok(())
    }

    pub async fn batch_correlate_entities(&self, pairs: Vec<(String, String)>, max_concurrent: usize) -> Result<()> {
        let engine = AnalysisEngine::from_config(&self.config)?;
        let analyzer = BatchAnalyzer::new(engine, max_concurrent);

        if let Some(metrics) = &self.metrics {
            let _timer = metrics.record_request_start();
        }

        let results = analyzer.correlate_entities_batch(pairs).await;

        let mut batch_result = BatchResult::new();
        for (idx, result) in results.into_iter().enumerate() {
            match result {
                Ok(correlation) => batch_result.successful.push(correlation),
                Err(e) => batch_result.failed.push((idx, e)),
            }
        }

        batch_result.print_summary();
        Ok(())
    }

    pub async fn batch_assess_threats(&self, datasets: Vec<String>, max_concurrent: usize) -> Result<()> {
        let engine = AnalysisEngine::from_config(&self.config)?;
        let analyzer = BatchAnalyzer::new(engine, max_concurrent);

        if let Some(metrics) = &self.metrics {
            let _timer = metrics.record_request_start();
        }

        let results = analyzer.assess_threats_batch(datasets).await;

        let mut batch_result = BatchResult::new();
        for (idx, result) in results.into_iter().enumerate() {
            match result {
                Ok(assessment) => batch_result.successful.push(assessment),
                Err(e) => batch_result.failed.push((idx, e)),
            }
        }

        batch_result.print_summary();
        Ok(())
    }

    pub async fn batch_validate_data(&self, items: Vec<(String, String)>, max_concurrent: usize) -> Result<()> {
        let engine = AnalysisEngine::from_config(&self.config)?;
        let analyzer = BatchAnalyzer::new(engine, max_concurrent);

        if let Some(metrics) = &self.metrics {
            let _timer = metrics.record_request_start();
        }

        let results = analyzer.validate_data_batch(items).await;

        let mut batch_result = BatchResult::new();
        for (idx, result) in results.into_iter().enumerate() {
            match result {
                Ok(validation) => batch_result.successful.push(validation),
                Err(e) => batch_result.failed.push((idx, e)),
            }
        }

        batch_result.print_summary();
        Ok(())
    }
}
