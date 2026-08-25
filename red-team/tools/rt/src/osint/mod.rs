pub mod models;
pub mod sources;
pub mod aggregator;
pub mod cache;
pub mod threat_feeds;
pub mod multi_source;
pub mod config;
pub mod correlation;

pub use models::{OsintEntity, EntityType, OsintResult, BreachData, ThreatIndicator};
pub use sources::{DataSource, DataSourceType, MockDataSource, HaveIBeenPwnedSource, VirusTotalSource, IPReputationSource};
pub use aggregator::OsintAggregator;
pub use cache::OsintCache;
pub use threat_feeds::{ThreatIntelligenceFeed, ThreatActor};
pub use multi_source::{MultiSourceAggregator, EntityEnrichment};
pub use config::OsintApiConfig;
pub use correlation::{CorrelationEngine, CorrelationLink, TTPPattern, ActorNetwork};
