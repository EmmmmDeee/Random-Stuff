use crate::osint::models::OsintResult;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct CacheEntry<T> {
    data: T,
    timestamp: u64,
    ttl_seconds: u64,
}

impl<T> CacheEntry<T> {
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now - self.timestamp > self.ttl_seconds
    }
}

pub struct OsintCache {
    email_cache: Arc<RwLock<HashMap<String, CacheEntry<OsintResult>>>>,
    domain_cache: Arc<RwLock<HashMap<String, CacheEntry<String>>>>,
    ttl_seconds: u64,
}

impl OsintCache {
    pub fn new(ttl_seconds: u64) -> Self {
        OsintCache {
            email_cache: Arc::new(RwLock::new(HashMap::new())),
            domain_cache: Arc::new(RwLock::new(HashMap::new())),
            ttl_seconds,
        }
    }

    pub async fn get_email(&self, email: &str) -> Option<OsintResult> {
        let cache = self.email_cache.read().await;
        if let Some(entry) = cache.get(email) {
            if !entry.is_expired() {
                return Some(entry.data.clone());
            }
        }
        None
    }

    pub async fn set_email(&self, email: String, result: OsintResult) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let entry = CacheEntry {
            data: result,
            timestamp: now,
            ttl_seconds: self.ttl_seconds,
        };

        let mut cache = self.email_cache.write().await;
        cache.insert(email, entry);
    }

    pub async fn clear_email_cache(&self) {
        let mut cache = self.email_cache.write().await;
        cache.clear();
    }

    pub async fn cache_size(&self) -> usize {
        let cache = self.email_cache.read().await;
        cache.len()
    }
}

impl Clone for OsintCache {
    fn clone(&self) -> Self {
        OsintCache {
            email_cache: self.email_cache.clone(),
            domain_cache: self.domain_cache.clone(),
            ttl_seconds: self.ttl_seconds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osint::models::EntityType;

    #[tokio::test]
    async fn test_cache_set_and_get() {
        let cache = OsintCache::new(3600);
        let entity = crate::osint::models::OsintEntity {
            entity: "test@example.com".to_string(),
            entity_type: EntityType::Email,
            timestamp: 0,
        };
        let result = OsintResult::new(entity);

        cache.set_email("test@example.com".to_string(), result).await;

        let cached = cache.get_email("test@example.com").await;
        assert!(cached.is_some());
    }

    #[tokio::test]
    async fn test_cache_size() {
        let cache = OsintCache::new(3600);
        let entity = crate::osint::models::OsintEntity {
            entity: "test@example.com".to_string(),
            entity_type: EntityType::Email,
            timestamp: 0,
        };
        let result = OsintResult::new(entity);

        cache.set_email("test@example.com".to_string(), result).await;
        assert_eq!(cache.cache_size().await, 1);
    }
}
