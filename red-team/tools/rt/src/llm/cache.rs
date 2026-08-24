// ============================================================================
// RESPONSE CACHING LAYER
// ============================================================================

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use super::types::LLMResponse;

#[derive(Clone, Debug)]
struct CachedEntry {
    response: LLMResponse,
    cached_at: SystemTime,
    ttl: Duration,
}

impl CachedEntry {
    fn is_expired(&self) -> bool {
        self.cached_at.elapsed().map_or(true, |age| age > self.ttl)
    }
}

pub struct ResponseCache {
    cache: Arc<Mutex<HashMap<String, CachedEntry>>>,
    ttl: Duration,
}

impl ResponseCache {
    pub fn new(ttl_hours: u32) -> Self {
        ResponseCache {
            cache: Arc::new(Mutex::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_hours as u64 * 3600),
        }
    }

    /// Generate cache key from request data
    fn generate_key(model: &str, prompt: &str, temperature: f32, max_tokens: u32) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        model.hash(&mut hasher);
        prompt.hash(&mut hasher);
        temperature.to_bits().hash(&mut hasher);
        max_tokens.hash(&mut hasher);

        format!("{:x}", hasher.finish())
    }

    /// Get cached response if available and not expired
    pub async fn get(
        &self,
        model: &str,
        prompt: &str,
        temperature: f32,
        max_tokens: u32,
    ) -> Option<LLMResponse> {
        let key = Self::generate_key(model, prompt, temperature, max_tokens);
        let cache = self.cache.lock().await;

        cache.get(&key).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.response.clone())
            }
        })
    }

    /// Store response in cache
    pub async fn put(
        &self,
        model: &str,
        prompt: &str,
        temperature: f32,
        max_tokens: u32,
        response: LLMResponse,
    ) {
        let key = Self::generate_key(model, prompt, temperature, max_tokens);
        let entry = CachedEntry {
            response,
            cached_at: SystemTime::now(),
            ttl: self.ttl,
        };

        let mut cache = self.cache.lock().await;
        cache.insert(key, entry);
    }

    /// Clear all expired entries
    pub async fn cleanup_expired(&self) {
        let mut cache = self.cache.lock().await;
        cache.retain(|_, entry| !entry.is_expired());
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let cache = self.cache.lock().await;
        let total = cache.len();
        let expired = cache.values().filter(|e| e.is_expired()).count();
        let valid = total - expired;

        CacheStats { total, valid, expired }
    }

    /// Clear entire cache
    pub async fn clear(&self) {
        self.cache.lock().await.clear();
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total: usize,
    pub valid: usize,
    pub expired: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_key_generation() {
        let key1 = ResponseCache::generate_key("model1", "prompt1", 0.7, 1024);
        let key2 = ResponseCache::generate_key("model1", "prompt1", 0.7, 1024);
        let key3 = ResponseCache::generate_key("model1", "prompt2", 0.7, 1024);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[tokio::test]
    async fn test_cache_storage_retrieval() {
        let cache = ResponseCache::new(1);
        let response = LLMResponse {
            content: "test".to_string(),
            usage: super::super::types::TokenUsage {
                prompt_tokens: 10,
                completion_tokens: 5,
                total_tokens: 15,
            },
            finish_reason: "stop".to_string(),
            model: "test-model".to_string(),
            latency_ms: 100,
        };

        cache.put("model", "prompt", 0.7, 1024, response.clone()).await;
        let retrieved = cache.get("model", "prompt", 0.7, 1024).await;

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().content, "test");
    }

    #[tokio::test]
    async fn test_cache_miss_different_params() {
        let cache = ResponseCache::new(1);
        let response = LLMResponse {
            content: "test".to_string(),
            usage: super::super::types::TokenUsage {
                prompt_tokens: 10,
                completion_tokens: 5,
                total_tokens: 15,
            },
            finish_reason: "stop".to_string(),
            model: "test-model".to_string(),
            latency_ms: 100,
        };

        cache.put("model", "prompt", 0.7, 1024, response).await;
        let retrieved = cache.get("model", "different_prompt", 0.7, 1024).await;

        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = ResponseCache::new(1);
        let response = LLMResponse {
            content: "test".to_string(),
            usage: super::super::types::TokenUsage {
                prompt_tokens: 10,
                completion_tokens: 5,
                total_tokens: 15,
            },
            finish_reason: "stop".to_string(),
            model: "test-model".to_string(),
            latency_ms: 100,
        };

        cache.put("model", "prompt1", 0.7, 1024, response.clone()).await;
        cache.put("model", "prompt2", 0.7, 1024, response).await;

        let stats = cache.stats().await;
        assert_eq!(stats.total, 2);
        assert_eq!(stats.valid, 2);
        assert_eq!(stats.expired, 0);
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let cache = ResponseCache::new(1);
        let response = LLMResponse {
            content: "test".to_string(),
            usage: super::super::types::TokenUsage {
                prompt_tokens: 10,
                completion_tokens: 5,
                total_tokens: 15,
            },
            finish_reason: "stop".to_string(),
            model: "test-model".to_string(),
            latency_ms: 100,
        };

        cache.put("model", "prompt", 0.7, 1024, response).await;
        cache.clear().await;

        let stats = cache.stats().await;
        assert_eq!(stats.total, 0);
    }
}
