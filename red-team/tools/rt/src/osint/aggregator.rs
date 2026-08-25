use crate::osint::models::*;
use crate::osint::sources::{DataSource, MockDataSource, HaveIBeenPwnedSource, VirusTotalSource, IPReputationSource};
use anyhow::Result;
use std::sync::Arc;

pub struct OsintAggregator {
    source: Arc<dyn DataSource>,
}

impl OsintAggregator {
    pub fn new(source: Arc<dyn DataSource>) -> Self {
        OsintAggregator { source }
    }

    pub fn with_mock() -> Self {
        OsintAggregator {
            source: Arc::new(MockDataSource),
        }
    }

    pub fn with_haveibeenpwned() -> Self {
        OsintAggregator {
            source: Arc::new(HaveIBeenPwnedSource::new()),
        }
    }

    pub fn with_virustotal(api_key: Option<String>) -> Self {
        OsintAggregator {
            source: Arc::new(VirusTotalSource::new(api_key)),
        }
    }

    pub fn with_ipreputat(abuseipdb_key: Option<String>) -> Self {
        OsintAggregator {
            source: Arc::new(IPReputationSource::new(abuseipdb_key)),
        }
    }

    pub fn with_hybrid(hibp_enabled: bool, virustotal_key: Option<String>) -> Self {
        if hibp_enabled {
            OsintAggregator {
                source: Arc::new(HaveIBeenPwnedSource::new()),
            }
        } else if virustotal_key.is_some() {
            OsintAggregator {
                source: Arc::new(VirusTotalSource::new(virustotal_key)),
            }
        } else {
            OsintAggregator {
                source: Arc::new(MockDataSource),
            }
        }
    }

    pub async fn analyze_email(&self, email: &str) -> Result<Option<OsintResult>> {
        let mut result = self.source.query_email(email).await?;

        if let Some(ref mut r) = result {
            self.enrich_result(r).await?;
        }

        Ok(result)
    }

    pub async fn analyze_domain(&self, domain: &str) -> Result<Option<DomainReputation>> {
        self.source.query_domain(domain).await
    }

    pub async fn analyze_ip(&self, ip: &str) -> Result<Option<IPIntelligence>> {
        self.source.query_ip(ip).await
    }

    pub async fn analyze_username(&self, username: &str) -> Result<Vec<CredentialData>> {
        self.source.query_username(username).await
    }

    async fn enrich_result(&self, result: &mut OsintResult) -> Result<()> {
        match &result.entity.entity_type {
            EntityType::Email => {
                if let Some(profile) = &result.email_profile {
                    if let Ok(Some(reputation)) = self.source.query_domain(&profile.domain).await {
                        result.domain_reputation = Some(reputation);
                    }
                }
            }
            EntityType::Domain => {
                if let Ok(Some(reputation)) = self.source.query_domain(&result.entity.entity).await {
                    result.domain_reputation = Some(reputation);
                }
            }
            EntityType::IPAddress => {
                if let Ok(Some(intel)) = self.source.query_ip(&result.entity.entity).await {
                    result.ip_intelligence = Some(intel);
                }
            }
            _ => {}
        }

        result.calculate_risk_level();
        result.add_recommendations();

        Ok(())
    }

    pub async fn batch_analyze(&self, entities: Vec<String>) -> Result<Vec<OsintResult>> {
        let mut results = Vec::new();

        for entity in entities {
            if let Ok(Some(result)) = self.analyze_email(&entity).await {
                results.push(result);
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_analyze_email() {
        let aggregator = OsintAggregator::with_mock();
        let result = aggregator
            .analyze_email("test@gmail.com")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(result.entity.entity_type, EntityType::Email);
        assert!(!result.breaches.is_empty());
        assert_eq!(result.risk_level, "low");
    }

    #[tokio::test]
    async fn test_batch_analyze() {
        let aggregator = OsintAggregator::with_mock();
        let entities = vec![
            "user1@gmail.com".to_string(),
            "user2@gmail.com".to_string(),
        ];

        let results = aggregator.batch_analyze(entities).await.unwrap();
        assert_eq!(results.len(), 2);
    }
}
