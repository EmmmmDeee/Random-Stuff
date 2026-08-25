use crate::osint::models::*;
use crate::osint::sources::{DataSource, HaveIBeenPwnedSource, VirusTotalSource, IPReputationSource};
use anyhow::Result;
use std::sync::Arc;
use tokio::task;

pub struct MultiSourceAggregator {
    hibp: Arc<HaveIBeenPwnedSource>,
    virustotal: Arc<VirusTotalSource>,
    ip_reputation: Arc<IPReputationSource>,
}

impl MultiSourceAggregator {
    pub fn new(vt_key: Option<String>, abuse_key: Option<String>) -> Self {
        MultiSourceAggregator {
            hibp: Arc::new(HaveIBeenPwnedSource::new()),
            virustotal: Arc::new(VirusTotalSource::new(vt_key)),
            ip_reputation: Arc::new(IPReputationSource::new(abuse_key)),
        }
    }

    pub async fn analyze_email_comprehensive(&self, email: &str) -> Result<Option<OsintResult>> {
        let email_clone = email.to_string();
        let hibp = self.hibp.clone();

        let task = task::spawn(async move {
            hibp.query_email(&email_clone).await
        });

        match task.await {
            Ok(Ok(Some(mut result))) => {
                result.calculate_risk_level();
                result.add_recommendations();
                Ok(Some(result))
            }
            _ => Ok(None),
        }
    }

    pub async fn analyze_domain_comprehensive(&self, domain: &str) -> Result<Option<DomainReputation>> {
        let domain_clone = domain.to_string();
        let virustotal = self.virustotal.clone();

        let task = task::spawn(async move {
            virustotal.query_domain(&domain_clone).await
        });

        match task.await {
            Ok(Ok(result)) => Ok(result),
            _ => Ok(None),
        }
    }

    pub async fn analyze_ip_comprehensive(&self, ip: &str) -> Result<Option<IPIntelligence>> {
        let ip_clone = ip.to_string();
        let ip_rep = self.ip_reputation.clone();

        let task = task::spawn(async move {
            ip_rep.query_ip(&ip_clone).await
        });

        match task.await {
            Ok(Ok(result)) => Ok(result),
            _ => Ok(None),
        }
    }

    pub async fn parallel_entity_analysis(
        &self,
        email: &str,
        domain: &str,
        ip: &str,
    ) -> Result<EntityEnrichment> {
        let email_task = {
            let email_clone = email.to_string();
            let hibp = self.hibp.clone();
            task::spawn(async move {
                hibp.query_email(&email_clone).await
            })
        };

        let domain_task = {
            let domain_clone = domain.to_string();
            let vt = self.virustotal.clone();
            task::spawn(async move {
                vt.query_domain(&domain_clone).await
            })
        };

        let ip_task = {
            let ip_clone = ip.to_string();
            let ip_rep = self.ip_reputation.clone();
            task::spawn(async move {
                ip_rep.query_ip(&ip_clone).await
            })
        };

        let email_result = match email_task.await {
            Ok(Ok(Some(result))) => Some(result),
            _ => None,
        };

        let domain_result = match domain_task.await {
            Ok(Ok(result)) => result,
            _ => None,
        };

        let ip_result = match ip_task.await {
            Ok(Ok(result)) => result,
            _ => None,
        };

        Ok(EntityEnrichment {
            email_result,
            domain_result,
            ip_result,
        })
    }
}

pub struct EntityEnrichment {
    pub email_result: Option<OsintResult>,
    pub domain_result: Option<DomainReputation>,
    pub ip_result: Option<IPIntelligence>,
}

impl EntityEnrichment {
    pub fn has_data(&self) -> bool {
        self.email_result.is_some() || self.domain_result.is_some() || self.ip_result.is_some()
    }

    pub fn combined_risk_level(&self) -> String {
        let mut max_risk: f64 = 0.0;

        if let Some(email) = &self.email_result {
            let risk_score = match email.risk_level.as_str() {
                "critical" => 4.0,
                "high" => 3.0,
                "medium" => 2.0,
                "low" => 1.0,
                _ => 0.0,
            };
            max_risk = max_risk.max(risk_score);
        }

        if let Some(domain) = &self.domain_result {
            let risk_score = if domain.is_malicious { 4.0 } else { 1.0 - domain.reputation_score };
            max_risk = max_risk.max(risk_score);
        }

        if let Some(ip) = &self.ip_result {
            let risk_score = match ip.threat_level.as_str() {
                "critical" => 4.0,
                "high" => 3.0,
                "medium" => 2.0,
                "low" => 1.0,
                _ => 0.0,
            };
            max_risk = max_risk.max(risk_score);
        }

        if max_risk > 3.5 {
            "critical".to_string()
        } else if max_risk > 2.5 {
            "high".to_string()
        } else if max_risk > 1.5 {
            "medium".to_string()
        } else {
            "low".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_multi_source_creation() {
        let agg = MultiSourceAggregator::new(None, None);
        let email_result = agg.analyze_email_comprehensive("test@gmail.com").await;
        assert!(email_result.is_ok());
    }

    #[tokio::test]
    async fn test_entity_enrichment_has_data() {
        let enrichment = EntityEnrichment {
            email_result: None,
            domain_result: None,
            ip_result: None,
        };
        assert!(!enrichment.has_data());
    }

    #[tokio::test]
    async fn test_combined_risk_level() {
        let enrichment = EntityEnrichment {
            email_result: None,
            domain_result: None,
            ip_result: None,
        };
        assert_eq!(enrichment.combined_risk_level(), "low");
    }
}
