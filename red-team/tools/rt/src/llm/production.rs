// ============================================================================
// PRODUCTION-OPTIMIZED CONFIGURATIONS
// ============================================================================
// Pre-tuned settings for different deployment scenarios and workloads
// ============================================================================

use super::config::LocalLLMConfig;

pub struct ProductionConfig;

impl ProductionConfig {
    /// Lightweight deployment: Single-machine, constrained resources
    /// - Minimal memory footprint
    /// - Fast response time priority
    /// - Good for edge deployments, laptops
    pub fn edge() -> LocalLLMConfig {
        LocalLLMConfig {
            endpoint: "http://localhost:11434".to_string(),
            model: "qwen2.5-coder:1.5b".to_string(),
            max_tokens: 1024,
            temperature: 0.3,
            timeout_seconds: 30,
            cache_responses: true,
            cache_ttl_hours: 48,
            auto_pull_model: true,
            min_ram_mb: Some(2048),
        }
    }

    /// Standard deployment: Small team, moderate resources
    /// - Balanced accuracy/speed
    /// - Reasonable cache size
    /// - Good for small organizations
    pub fn standard() -> LocalLLMConfig {
        LocalLLMConfig {
            endpoint: "http://localhost:11434".to_string(),
            model: "mistral".to_string(),
            max_tokens: 2048,
            temperature: 0.4,
            timeout_seconds: 60,
            cache_responses: true,
            cache_ttl_hours: 24,
            auto_pull_model: true,
            min_ram_mb: Some(4096),
        }
    }

    /// Enterprise deployment: High-volume analysis
    /// - Maximum accuracy
    /// - Aggressive caching
    /// - Connection pooling
    /// - For large teams and heavy workloads
    pub fn enterprise() -> LocalLLMConfig {
        LocalLLMConfig {
            endpoint: "http://localhost:11434".to_string(),
            model: "mistral".to_string(),
            max_tokens: 4096,
            temperature: 0.2,
            timeout_seconds: 120,
            cache_responses: true,
            cache_ttl_hours: 72,
            auto_pull_model: true,
            min_ram_mb: Some(8192),
        }
    }

    /// High-performance deployment: Real-time threat analysis
    /// - Speed optimized
    /// - Concurrent request handling
    /// - Minimal latency
    /// - For SOC/CSIRT operations
    pub fn realtime() -> LocalLLMConfig {
        LocalLLMConfig {
            endpoint: "http://localhost:11434".to_string(),
            model: "qwen2.5-coder:1.5b".to_string(),
            max_tokens: 512,
            temperature: 0.2,
            timeout_seconds: 15,
            cache_responses: true,
            cache_ttl_hours: 24,
            auto_pull_model: true,
            min_ram_mb: Some(2048),
        }
    }

    /// Batch processing deployment: Bulk OSINT analysis
    /// - Throughput optimized
    /// - Large token limits
    /// - Extended timeouts
    /// - For historical data analysis
    pub fn batch() -> LocalLLMConfig {
        LocalLLMConfig {
            endpoint: "http://localhost:11434".to_string(),
            model: "mistral".to_string(),
            max_tokens: 8192,
            temperature: 0.3,
            timeout_seconds: 300,
            cache_responses: true,
            cache_ttl_hours: 168,
            auto_pull_model: true,
            min_ram_mb: Some(16384),
        }
    }
}

pub struct DeploymentProfile {
    pub name: &'static str,
    pub description: &'static str,
    pub pool_size: usize,
    pub batch_size: usize,
    pub timeout_seconds: u32,
}

impl DeploymentProfile {
    pub fn get_profile(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "edge" => Some(DeploymentProfile {
                name: "edge",
                description: "Edge deployment - minimal resources",
                pool_size: 1,
                batch_size: 5,
                timeout_seconds: 30,
            }),
            "standard" => Some(DeploymentProfile {
                name: "standard",
                description: "Standard deployment - balanced performance",
                pool_size: 3,
                batch_size: 10,
                timeout_seconds: 60,
            }),
            "enterprise" => Some(DeploymentProfile {
                name: "enterprise",
                description: "Enterprise deployment - high throughput",
                pool_size: 5,
                batch_size: 20,
                timeout_seconds: 120,
            }),
            "realtime" => Some(DeploymentProfile {
                name: "realtime",
                description: "Real-time deployment - SOC/CSIRT operations",
                pool_size: 8,
                batch_size: 32,
                timeout_seconds: 15,
            }),
            "batch" => Some(DeploymentProfile {
                name: "batch",
                description: "Batch processing - historical analysis",
                pool_size: 2,
                batch_size: 100,
                timeout_seconds: 300,
            }),
            _ => None,
        }
    }

    pub fn print_info(&self) {
        println!("\n=== Deployment Profile: {} ===", self.name);
        println!("Description:  {}", self.description);
        println!("Pool Size:    {} concurrent clients", self.pool_size);
        println!("Batch Size:   {} items per batch", self.batch_size);
        println!("Timeout:      {} seconds", self.timeout_seconds);
        println!("=====================================\n");
    }

    pub fn all_profiles() -> Vec<&'static str> {
        vec!["edge", "standard", "enterprise", "realtime", "batch"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_config() {
        let config = ProductionConfig::edge();
        assert_eq!(config.model, "qwen2.5-coder:1.5b");
        assert_eq!(config.max_tokens, 1024);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_standard_config() {
        let config = ProductionConfig::standard();
        assert_eq!(config.model, "mistral");
        assert_eq!(config.max_tokens, 2048);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_enterprise_config() {
        let config = ProductionConfig::enterprise();
        assert_eq!(config.max_tokens, 4096);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_realtime_config() {
        let config = ProductionConfig::realtime();
        assert_eq!(config.timeout_seconds, 15);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_batch_config() {
        let config = ProductionConfig::batch();
        assert_eq!(config.max_tokens, 8192);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_deployment_profiles() {
        for profile_name in DeploymentProfile::all_profiles() {
            let profile = DeploymentProfile::get_profile(profile_name);
            assert!(profile.is_some());
        }
    }

    #[test]
    fn test_invalid_profile() {
        let profile = DeploymentProfile::get_profile("invalid");
        assert!(profile.is_none());
    }
}
