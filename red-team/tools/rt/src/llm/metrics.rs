// ============================================================================
// METRICS COLLECTION FOR PRODUCTION MONITORING
// ============================================================================
// Tracks latency, throughput, errors, cache performance for observability
// ============================================================================

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub struct Metrics {
    requests_total: Arc<AtomicU64>,
    requests_success: Arc<AtomicU64>,
    requests_error: Arc<AtomicU64>,
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    total_latency_ms: Arc<AtomicU64>,
    tokens_generated: Arc<AtomicU64>,
    errors_network: Arc<AtomicU64>,
    errors_parse: Arc<AtomicU64>,
    errors_timeout: Arc<AtomicU64>,
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            requests_total: Arc::new(AtomicU64::new(0)),
            requests_success: Arc::new(AtomicU64::new(0)),
            requests_error: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            total_latency_ms: Arc::new(AtomicU64::new(0)),
            tokens_generated: Arc::new(AtomicU64::new(0)),
            errors_network: Arc::new(AtomicU64::new(0)),
            errors_parse: Arc::new(AtomicU64::new(0)),
            errors_timeout: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_request_start(&self) -> RequestTimer {
        RequestTimer {
            start: Instant::now(),
            metrics: self.clone(),
        }
    }

    pub fn record_success(&self, latency_ms: u64, tokens: u32) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.requests_success.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);
        self.tokens_generated.fetch_add(tokens as u64, Ordering::Relaxed);
    }

    pub fn record_error(&self, error_type: &str) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.requests_error.fetch_add(1, Ordering::Relaxed);
        match error_type {
            "network" => self.errors_network.fetch_add(1, Ordering::Relaxed),
            "parse" => self.errors_parse.fetch_add(1, Ordering::Relaxed),
            "timeout" => self.errors_timeout.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> MetricsSnapshot {
        let total = self.requests_total.load(Ordering::Relaxed);
        let success = self.requests_success.load(Ordering::Relaxed);
        let errors = self.requests_error.load(Ordering::Relaxed);
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let latency = self.total_latency_ms.load(Ordering::Relaxed);
        let tokens = self.tokens_generated.load(Ordering::Relaxed);

        let success_rate = if total > 0 {
            (success as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        let avg_latency = if success > 0 {
            latency as f64 / success as f64
        } else {
            0.0
        };

        let cache_rate = if (hits + misses) > 0 {
            (hits as f64 / (hits + misses) as f64) * 100.0
        } else {
            0.0
        };

        MetricsSnapshot {
            requests_total: total,
            requests_success: success,
            requests_error: errors,
            success_rate,
            cache_hits: hits,
            cache_misses: misses,
            cache_hit_rate: cache_rate,
            average_latency_ms: avg_latency,
            total_tokens_generated: tokens,
            error_network: self.errors_network.load(Ordering::Relaxed),
            error_parse: self.errors_parse.load(Ordering::Relaxed),
            error_timeout: self.errors_timeout.load(Ordering::Relaxed),
        }
    }

    pub fn reset(&self) {
        self.requests_total.store(0, Ordering::Relaxed);
        self.requests_success.store(0, Ordering::Relaxed);
        self.requests_error.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.total_latency_ms.store(0, Ordering::Relaxed);
        self.tokens_generated.store(0, Ordering::Relaxed);
        self.errors_network.store(0, Ordering::Relaxed);
        self.errors_parse.store(0, Ordering::Relaxed);
        self.errors_timeout.store(0, Ordering::Relaxed);
    }
}

impl Clone for Metrics {
    fn clone(&self) -> Self {
        Metrics {
            requests_total: Arc::clone(&self.requests_total),
            requests_success: Arc::clone(&self.requests_success),
            requests_error: Arc::clone(&self.requests_error),
            cache_hits: Arc::clone(&self.cache_hits),
            cache_misses: Arc::clone(&self.cache_misses),
            total_latency_ms: Arc::clone(&self.total_latency_ms),
            tokens_generated: Arc::clone(&self.tokens_generated),
            errors_network: Arc::clone(&self.errors_network),
            errors_parse: Arc::clone(&self.errors_parse),
            errors_timeout: Arc::clone(&self.errors_timeout),
        }
    }
}

pub struct RequestTimer {
    start: Instant,
    metrics: Metrics,
}

impl RequestTimer {
    pub fn stop_success(self, tokens: u32) {
        let elapsed = self.start.elapsed().as_millis() as u64;
        self.metrics.record_success(elapsed, tokens);
    }

    pub fn stop_error(self, error_type: &str) {
        self.metrics.record_error(error_type);
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_success: u64,
    pub requests_error: u64,
    pub success_rate: f64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_rate: f64,
    pub average_latency_ms: f64,
    pub total_tokens_generated: u64,
    pub error_network: u64,
    pub error_parse: u64,
    pub error_timeout: u64,
}

impl MetricsSnapshot {
    pub fn print_summary(&self) {
        println!("\n=== LLM Metrics Summary ===");
        println!("Requests:        {} total ({} success, {} errors)",
            self.requests_total, self.requests_success, self.requests_error);
        println!("Success Rate:    {:.2}%", self.success_rate);
        println!("Cache:           {} hits, {} misses ({:.2}% hit rate)",
            self.cache_hits, self.cache_misses, self.cache_hit_rate);
        println!("Latency:         {:.2}ms average", self.average_latency_ms);
        println!("Tokens:          {} generated", self.total_tokens_generated);
        println!("Errors:          {} network, {} parse, {} timeout",
            self.error_network, self.error_parse, self.error_timeout);
        println!("=========================\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = Metrics::new();
        let stats = metrics.get_stats();
        assert_eq!(stats.requests_total, 0);
        assert_eq!(stats.success_rate, 0.0);
    }

    #[test]
    fn test_metrics_record_success() {
        let metrics = Metrics::new();
        metrics.record_success(100, 50);
        let stats = metrics.get_stats();
        assert_eq!(stats.requests_total, 1);
        assert_eq!(stats.requests_success, 1);
        assert_eq!(stats.total_tokens_generated, 50);
    }

    #[test]
    fn test_metrics_success_rate() {
        let metrics = Metrics::new();
        metrics.record_success(100, 50);
        metrics.record_success(120, 60);
        metrics.record_error("network");
        let stats = metrics.get_stats();
        assert_eq!(stats.requests_total, 3);
        assert_eq!(stats.requests_success, 2);
        assert!((stats.success_rate - 66.66).abs() < 1.0);
    }

    #[test]
    fn test_metrics_cache_rate() {
        let metrics = Metrics::new();
        metrics.record_cache_hit();
        metrics.record_cache_hit();
        metrics.record_cache_miss();
        let stats = metrics.get_stats();
        assert_eq!(stats.cache_hits, 2);
        assert_eq!(stats.cache_misses, 1);
        assert!((stats.cache_hit_rate - 66.66).abs() < 1.0);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = Metrics::new();
        metrics.record_success(100, 50);
        metrics.record_cache_hit();
        metrics.reset();
        let stats = metrics.get_stats();
        assert_eq!(stats.requests_total, 0);
        assert_eq!(stats.cache_hits, 0);
    }
}
