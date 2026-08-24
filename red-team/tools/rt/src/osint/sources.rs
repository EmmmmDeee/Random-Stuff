use crate::osint::models::*;
use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSourceType {
    HaveIBeenPwned,
    VirusTotal,
    Hunter,
    Shodan,
    GreyNoise,
    AbuseIPDB,
    ThreatFeed,
    Whois,
}

#[async_trait]
pub trait DataSource: Send + Sync {
    async fn query_email(&self, email: &str) -> Result<Option<OsintResult>>;
    async fn query_domain(&self, domain: &str) -> Result<Option<DomainReputation>>;
    async fn query_ip(&self, ip: &str) -> Result<Option<IPIntelligence>>;
    async fn query_username(&self, username: &str) -> Result<Vec<CredentialData>>;
}

pub struct MockDataSource;

#[async_trait]
impl DataSource for MockDataSource {
    async fn query_email(&self, email: &str) -> Result<Option<OsintResult>> {
        let entity = OsintEntity {
            entity: email.to_string(),
            entity_type: EntityType::Email,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };

        let mut result = OsintResult::new(entity);

        if email.ends_with("@gmail.com") {
            result.breaches = vec![
                BreachData {
                    name: "LinkedIn".to_string(),
                    date: "2021-06-21".to_string(),
                    exposed_data: vec!["email".to_string(), "name".to_string()],
                    affected_count: Some(700_000_000),
                    source: "HaveIBeenPwned".to_string(),
                },
                BreachData {
                    name: "Twitter".to_string(),
                    date: "2021-06-01".to_string(),
                    exposed_data: vec!["email".to_string(), "username".to_string()],
                    affected_count: Some(5_400_000),
                    source: "HaveIBeenPwned".to_string(),
                },
            ];

            result.threats = vec![ThreatIndicator {
                indicator_type: "email_in_breach".to_string(),
                value: email.to_string(),
                threat_level: "medium".to_string(),
                source: "ThreatFeed".to_string(),
                last_seen: "2026-08-24".to_string(),
            }];

            result.email_profile = Some(EmailProfile {
                email: email.to_string(),
                domain: "gmail.com".to_string(),
                first_seen: Some("2015-01-01".to_string()),
                associated_names: vec!["Matthew Diegmann".to_string()],
                associated_companies: vec![],
                usage_context: "personal".to_string(),
            });

            result.domain_reputation = Some(DomainReputation {
                domain: "gmail.com".to_string(),
                reputation_score: 0.95,
                is_malicious: false,
                threat_votes: std::collections::HashMap::new(),
                last_update: "2026-08-24".to_string(),
            });
        }

        result.calculate_risk_level();
        result.add_recommendations();

        Ok(Some(result))
    }

    async fn query_domain(&self, domain: &str) -> Result<Option<DomainReputation>> {
        Ok(Some(DomainReputation {
            domain: domain.to_string(),
            reputation_score: 0.85,
            is_malicious: false,
            threat_votes: std::collections::HashMap::new(),
            last_update: "2026-08-24".to_string(),
        }))
    }

    async fn query_ip(&self, ip: &str) -> Result<Option<IPIntelligence>> {
        Ok(Some(IPIntelligence {
            ip_address: ip.to_string(),
            organization: "Unknown".to_string(),
            country: "Unknown".to_string(),
            is_vpn: false,
            is_proxy: false,
            is_datacenter: false,
            threat_level: "low".to_string(),
            abuse_reports: 0,
        }))
    }

    async fn query_username(&self, username: &str) -> Result<Vec<CredentialData>> {
        Ok(vec![CredentialData {
            username: username.to_string(),
            email: None,
            password_hash: None,
            breach_source: "LinkedIn".to_string(),
            date_exposed: "2021-06-21".to_string(),
        }])
    }
}

pub struct SourceConfig {
    pub sources_enabled: Vec<DataSourceType>,
    pub cache_ttl_seconds: u64,
    pub rate_limit_per_minute: u32,
}

impl Default for SourceConfig {
    fn default() -> Self {
        SourceConfig {
            sources_enabled: vec![
                DataSourceType::HaveIBeenPwned,
                DataSourceType::VirusTotal,
                DataSourceType::ThreatFeed,
            ],
            cache_ttl_seconds: 3600,
            rate_limit_per_minute: 60,
        }
    }
}
