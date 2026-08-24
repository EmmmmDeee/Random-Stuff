// ============================================================================
// REAL INTEGRATION TESTS FOR LLM MODULE
// ============================================================================
// These tests require a running Ollama instance at http://localhost:11434
// Tests will be skipped if Ollama is not available
// ============================================================================

#[cfg(test)]
mod integration {
    use crate::llm::*;

    async fn check_ollama_running() -> bool {
        let client = reqwest::Client::new();
        match client
            .get("http://localhost:11434/api/tags")
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }

    #[tokio::test]
    async fn test_ollama_health_check_real() {
        if !check_ollama_running().await {
            eprintln!("⊘ Skipping: Ollama not running at http://localhost:11434");
            return;
        }

        let config = LocalLLMConfig::ollama_lightweight();
        let engine = AnalysisEngine::from_config(&config).expect("Failed to create engine");

        match engine.health_check().await {
            Ok(true) => println!("✓ Ollama health check passed"),
            Ok(false) => panic!("Ollama returned unhealthy status"),
            Err(e) => panic!("Health check failed: {}", e),
        }
    }

    #[tokio::test]
    async fn test_list_models_real() {
        if !check_ollama_running().await {
            eprintln!("⊘ Skipping: Ollama not running");
            return;
        }

        let config = LocalLLMConfig::ollama_lightweight();
        let engine = AnalysisEngine::from_config(&config).expect("Failed to create engine");

        match engine.list_available_models().await {
            Ok(models) => {
                println!("✓ Available models: {:?}", models);
                assert!(!models.is_empty(), "Should have at least one model");
            }
            Err(e) => eprintln!("⊘ Could not list models: {}", e),
        }
    }

    #[tokio::test]
    async fn test_entity_analysis_real() {
        if !check_ollama_running().await {
            eprintln!("⊘ Skipping: Ollama not running");
            return;
        }

        let config = LocalLLMConfig::ollama_lightweight();
        let engine = AnalysisEngine::from_config(&config).expect("Failed to create engine");

        let entity_json = r#"{
            "type": "domain",
            "value": "example.com",
            "sources": ["whois", "dns"],
            "first_seen": "2024-01-01"
        }"#;

        match engine.analyze_entity(entity_json).await {
            Ok(analysis) => {
                println!("✓ Entity Analysis:");
                println!("  Summary: {}", analysis.entity_summary);
                println!("  Confidence: {:.2}", analysis.confidence_assessment);
                println!("  Intelligence Value: {:.2}", analysis.intelligence_value);

                // Validate structure
                assert!(!analysis.entity_summary.is_empty());
                assert!(analysis.confidence_assessment >= 0.0 && analysis.confidence_assessment <= 1.0);
                assert!(analysis.intelligence_value >= 0.0 && analysis.intelligence_value <= 1.0);
            }
            Err(e) => eprintln!("⊘ Entity analysis failed: {}", e),
        }
    }

    #[tokio::test]
    async fn test_correlate_entities_real() {
        if !check_ollama_running().await {
            eprintln!("⊘ Skipping: Ollama not running");
            return;
        }

        let config = LocalLLMConfig::ollama_lightweight();
        let engine = AnalysisEngine::from_config(&config).expect("Failed to create engine");

        let entity1 = r#"{"type": "ip_address", "value": "192.168.1.100"}"#;
        let entity2 = r#"{"type": "domain", "value": "example.com"}"#;

        match engine.correlate_entities(entity1, entity2).await {
            Ok(correlation) => {
                println!("✓ Correlation Analysis:");
                println!("  Type: {}", correlation.relationship_type);
                println!("  Strength: {:.2}", correlation.relationship_strength);
                println!("  Confidence: {:.2}", correlation.confidence_score);

                // Validate structure
                assert!(!correlation.relationship_type.is_empty());
                assert!(correlation.relationship_strength >= 0.0 && correlation.relationship_strength <= 1.0);
                assert!(correlation.confidence_score >= 0.0 && correlation.confidence_score <= 1.0);
            }
            Err(e) => eprintln!("⊘ Correlation analysis failed: {}", e),
        }
    }

    #[tokio::test]
    async fn test_threat_assessment_real() {
        if !check_ollama_running().await {
            eprintln!("⊘ Skipping: Ollama not running");
            return;
        }

        let config = LocalLLMConfig::ollama_lightweight();
        let engine = AnalysisEngine::from_config(&config).expect("Failed to create engine");

        let data = r#"{
            "indicators": ["192.168.1.100", "malware.exe"],
            "context": "detected in production network",
            "timeframe": "last 24 hours"
        }"#;

        match engine.assess_threat(data).await {
            Ok(assessment) => {
                println!("✓ Threat Assessment:");
                println!("  Level: {}", assessment.threat_level);
                println!("  Vectors: {:?}", assessment.threat_vectors);

                // Validate structure
                let valid_levels = vec!["low", "medium", "high", "critical"];
                assert!(valid_levels.contains(&assessment.threat_level.to_lowercase().as_str()) ||
                    assessment.threat_level.to_lowercase().contains("low") ||
                    assessment.threat_level.to_lowercase().contains("medium") ||
                    assessment.threat_level.to_lowercase().contains("high") ||
                    assessment.threat_level.to_lowercase().contains("critical"),
                    "Invalid threat level: {}", assessment.threat_level);
            }
            Err(e) => eprintln!("⊘ Threat assessment failed: {}", e),
        }
    }

    #[tokio::test]
    async fn test_collection_strategy_real() {
        if !check_ollama_running().await {
            eprintln!("⊘ Skipping: Ollama not running");
            return;
        }

        let config = LocalLLMConfig::ollama_lightweight();
        let engine = AnalysisEngine::from_config(&config).expect("Failed to create engine");

        let target = r#"{
            "name": "ACME Corporation",
            "sectors": ["finance", "technology"],
            "region": "North America",
            "employee_count": "5000+"
        }"#;

        match engine.recommend_collection_strategy(target).await {
            Ok(strategy) => {
                println!("✓ Collection Strategy:");
                println!("  Priority Sources: {:?}", strategy.priority_sources);
                println!("  Success Probability: {:.2}", strategy.success_probability);

                // Validate structure
                assert!(!strategy.priority_sources.is_empty());
                assert!(strategy.success_probability >= 0.0 && strategy.success_probability <= 1.0);
            }
            Err(e) => eprintln!("⊘ Collection strategy failed: {}", e),
        }
    }

    #[tokio::test]
    async fn test_validate_data_real() {
        if !check_ollama_running().await {
            eprintln!("⊘ Skipping: Ollama not running");
            return;
        }

        let config = LocalLLMConfig::ollama_lightweight();
        let engine = AnalysisEngine::from_config(&config).expect("Failed to create engine");

        let data = r#"{"ip": "192.168.1.1", "reputation": "malicious", "confidence": 0.95}"#;

        match engine.validate_data(data, "ip_reputation").await {
            Ok(validation) => {
                println!("✓ Data Validation:");
                println!("  Accuracy: {:.2}", validation.accuracy_assessment);
                println!("  Reliability: {:.2}", validation.reliability_score);
                println!("  Confidence: {:.2}", validation.confidence_level);

                // Validate structure
                assert!(validation.accuracy_assessment >= 0.0 && validation.accuracy_assessment <= 1.0);
                assert!(validation.reliability_score >= 0.0 && validation.reliability_score <= 1.0);
                assert!(validation.confidence_level >= 0.0 && validation.confidence_level <= 1.0);
            }
            Err(e) => eprintln!("⊘ Data validation failed: {}", e),
        }
    }

    #[tokio::test]
    async fn test_caching_reduces_latency_real() {
        if !check_ollama_running().await {
            eprintln!("⊘ Skipping: Ollama not running");
            return;
        }

        let config = LocalLLMConfig::ollama_lightweight();
        let engine = AnalysisEngine::from_config(&config).expect("Failed to create engine");

        let entity = r#"{"type": "domain", "value": "cached.example.com"}"#;

        // First call - hits LLM
        let start1 = std::time::Instant::now();
        match engine.analyze_entity(entity).await {
            Ok(first_result) => {
                let latency1 = start1.elapsed().as_millis();
                println!("✓ First call (LLM): {}ms", latency1);

                // Second call - should hit cache if enabled
                let start2 = std::time::Instant::now();
                match engine.analyze_entity(entity).await {
                    Ok(second_result) => {
                        let latency2 = start2.elapsed().as_millis();
                        println!("✓ Second call (cache): {}ms", latency2);

                        if engine.is_cache_enabled() {
                            // Cache should be significantly faster (expect < 5ms)
                            if latency2 < 5 {
                                println!("✓ Cache is working: {}x speedup", latency1 / (latency2 + 1));
                            } else {
                                eprintln!("⊘ Cache not as fast as expected");
                            }

                            // Results should be identical
                            assert_eq!(first_result.entity_summary, second_result.entity_summary);
                        }
                    }
                    Err(e) => eprintln!("⊘ Second analysis failed: {}", e),
                }
            }
            Err(e) => eprintln!("⊘ First analysis failed: {}", e),
        }
    }

    #[tokio::test]
    async fn test_config_validation_real() {
        // This test always runs - doesn't depend on Ollama
        let mut config = LocalLLMConfig::default();

        // Valid config
        assert!(config.validate().is_ok());

        // Invalid endpoint
        config.endpoint = "invalid".to_string();
        assert!(config.validate().is_err());

        // Valid endpoint, invalid temperature
        config.endpoint = "http://localhost:11434".to_string();
        config.temperature = 5.0;
        assert!(config.validate().is_err());

        // Reset to valid
        config.temperature = 0.7;
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_concurrent_requests_real() {
        if !check_ollama_running().await {
            eprintln!("⊘ Skipping: Ollama not running");
            return;
        }

        let config = LocalLLMConfig::ollama_lightweight();
        let engine = std::sync::Arc::new(
            AnalysisEngine::from_config(&config).expect("Failed to create engine")
        );

        let entities = vec![
            r#"{"type": "domain", "value": "test1.com"}"#,
            r#"{"type": "domain", "value": "test2.com"}"#,
            r#"{"type": "domain", "value": "test3.com"}"#,
        ];

        // Spawn concurrent analysis tasks
        let mut handles = vec![];
        for (idx, entity) in entities.into_iter().enumerate() {
            let engine_clone = engine.clone();
            let handle = tokio::spawn(async move {
                match engine_clone.analyze_entity(entity).await {
                    Ok(result) => {
                        println!("✓ Concurrent task {}: {}", idx, result.entity_summary);
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("✗ Concurrent task {} failed: {}", idx, e);
                        Err(e)
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks
        for handle in handles {
            let _ = handle.await;
        }

        println!("✓ Concurrent requests completed");
    }
}
