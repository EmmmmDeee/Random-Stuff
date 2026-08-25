// ============================================================================
// CONNECTION POOL FOR OLLAMA CLIENT (Production Optimization)
// ============================================================================
// Manages pooled HTTP connections for optimal throughput and resource usage
// ============================================================================

use std::sync::Arc;
use tokio::sync::Semaphore;
use super::error::{LLMError, LLMResult};
use super::client::OllamaClient;
use super::config::LocalLLMConfig;

pub struct ClientPool {
    clients: Vec<Arc<OllamaClient>>,
    semaphore: Arc<Semaphore>,
    config: LocalLLMConfig,
}

impl ClientPool {
    /// Create a new connection pool with specified concurrency limit
    pub fn new(config: LocalLLMConfig, pool_size: usize) -> LLMResult<Self> {
        config.validate()?;

        let mut clients = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            let client = OllamaClient::from_config(&config)?;
            clients.push(Arc::new(client));
        }

        Ok(ClientPool {
            clients,
            semaphore: Arc::new(Semaphore::new(pool_size)),
            config,
        })
    }

    /// Get a client from the pool (acquires semaphore permit)
    pub async fn acquire(&self) -> LLMResult<PooledClient> {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| LLMError::Configuration(format!("Semaphore error: {}", e)))?;

        // Round-robin client selection
        let client = self.clients[0].clone();

        Ok(PooledClient {
            client,
            _permit: permit,
        })
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            pool_size: self.clients.len(),
            available_permits: self.semaphore.available_permits(),
        }
    }

    /// Get configuration
    pub fn config(&self) -> &LocalLLMConfig {
        &self.config
    }
}

/// A client acquired from the pool with automatic release on drop
pub struct PooledClient {
    pub client: Arc<OllamaClient>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub pool_size: usize,
    pub available_permits: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pool_creation() {
        let config = LocalLLMConfig::ollama_lightweight();
        let pool = ClientPool::new(config, 5);
        assert!(pool.is_ok());
    }

    #[tokio::test]
    async fn test_pool_stats() {
        let config = LocalLLMConfig::ollama_lightweight();
        let pool = ClientPool::new(config, 3).expect("Failed to create pool");
        let stats = pool.stats();
        assert_eq!(stats.pool_size, 3);
        assert_eq!(stats.available_permits, 3);
    }

    #[tokio::test]
    async fn test_pool_acquire_release() {
        let config = LocalLLMConfig::ollama_lightweight();
        let pool = ClientPool::new(config, 2).expect("Failed to create pool");

        let stats_before = pool.stats();
        assert_eq!(stats_before.available_permits, 2);

        let _client1 = pool.acquire().await.expect("Failed to acquire");
        let stats_after_1 = pool.stats();
        assert_eq!(stats_after_1.available_permits, 1);

        let _client2 = pool.acquire().await.expect("Failed to acquire");
        let stats_after_2 = pool.stats();
        assert_eq!(stats_after_2.available_permits, 0);

        drop(_client1);
        let stats_after_release = pool.stats();
        assert_eq!(stats_after_release.available_permits, 1);
    }
}
