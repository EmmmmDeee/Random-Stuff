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

pub struct HaveIBeenPwnedSource {
    client: reqwest::Client,
}

impl HaveIBeenPwnedSource {
    pub fn new() -> Self {
        HaveIBeenPwnedSource {
            client: reqwest::Client::new(),
        }
    }

    async fn fetch_breaches(&self, email: &str) -> Result<Vec<serde_json::Value>> {
        let url = format!(
            "https://haveibeenpwned.com/api/v3/breachedaccount/{}",
            urlencoding::encode(email)
        );

        match self
            .client
            .get(&url)
            .header("User-Agent", "rt-osint-framework/1.0")
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<Vec<serde_json::Value>>().await {
                        Ok(breaches) => Ok(breaches),
                        Err(_) => Ok(vec![]),
                    }
                } else if resp.status().as_u16() == 404 {
                    Ok(vec![])
                } else if resp.status().as_u16() == 429 {
                    anyhow::bail!("HaveIBeenPwned API rate limited (429)")
                } else {
                    Ok(vec![])
                }
            }
            Err(_) => Ok(vec![]),
        }
    }
}

#[async_trait]
impl DataSource for HaveIBeenPwnedSource {
    async fn query_email(&self, email: &str) -> Result<Option<OsintResult>> {
        let breaches_data = self.fetch_breaches(email).await.unwrap_or_default();

        if breaches_data.is_empty() {
            return Ok(None);
        }

        let entity = OsintEntity {
            entity: email.to_string(),
            entity_type: EntityType::Email,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };

        let mut result = OsintResult::new(entity);

        for breach_obj in breaches_data {
            if let (Some(name), Some(date)) = (
                breach_obj.get("Name").and_then(|v| v.as_str()),
                breach_obj.get("BreachDate").and_then(|v| v.as_str()),
            ) {
                let data_classes = breach_obj
                    .get("DataClasses")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                result.breaches.push(BreachData {
                    name: name.to_string(),
                    date: date.to_string(),
                    exposed_data: data_classes,
                    affected_count: breach_obj
                        .get("PwnCount")
                        .and_then(|v| v.as_i64())
                        .map(|n| n as u64),
                    source: "HaveIBeenPwned".to_string(),
                });
            }
        }

        if !result.breaches.is_empty() {
            result.threats.push(ThreatIndicator {
                indicator_type: "email_in_breach".to_string(),
                value: email.to_string(),
                threat_level: if result.breaches.len() > 5 {
                    "high".to_string()
                } else {
                    "medium".to_string()
                },
                source: "HaveIBeenPwned".to_string(),
                last_seen: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            });
        }

        result.calculate_risk_level();
        result.add_recommendations();

        Ok(Some(result))
    }

    async fn query_domain(&self, _domain: &str) -> Result<Option<DomainReputation>> {
        Ok(None)
    }

    async fn query_ip(&self, _ip: &str) -> Result<Option<IPIntelligence>> {
        Ok(None)
    }

    async fn query_username(&self, _username: &str) -> Result<Vec<CredentialData>> {
        Ok(vec![])
    }
}

pub struct VirusTotalSource {
    client: reqwest::Client,
    api_key: Option<String>,
}

impl VirusTotalSource {
    pub fn new(api_key: Option<String>) -> Self {
        VirusTotalSource {
            client: reqwest::Client::new(),
            api_key,
        }
    }

    async fn fetch_domain_report(&self, domain: &str) -> Result<serde_json::Value> {
        if self.api_key.is_none() {
            return Ok(serde_json::json!({}));
        }

        let api_key = self.api_key.as_ref().unwrap();
        let url = format!("https://www.virustotal.com/api/v3/domains/{}", domain);

        match self
            .client
            .get(&url)
            .header("x-apikey", api_key)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<serde_json::Value>().await {
                        Ok(data) => Ok(data),
                        Err(_) => Ok(serde_json::json!({})),
                    }
                } else if resp.status().as_u16() == 404 {
                    Ok(serde_json::json!({}))
                } else if resp.status().as_u16() == 429 {
                    anyhow::bail!("VirusTotal API rate limited (429)")
                } else {
                    Ok(serde_json::json!({}))
                }
            }
            Err(_) => Ok(serde_json::json!({})),
        }
    }
}

#[async_trait]
impl DataSource for VirusTotalSource {
    async fn query_email(&self, _email: &str) -> Result<Option<OsintResult>> {
        Ok(None)
    }

    async fn query_domain(&self, domain: &str) -> Result<Option<DomainReputation>> {
        let report = self.fetch_domain_report(domain).await?;

        if report.is_null() || report.get("data").is_none() {
            return Ok(None);
        }

        let data = &report["data"];
        let attributes = &data["attributes"];

        let last_analysis_stats = attributes
            .get("last_analysis_stats")
            .and_then(|v| v.as_object());

        let (malicious, suspicious) = if let Some(stats) = last_analysis_stats {
            (
                stats
                    .get("malicious")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0) as i32,
                stats
                    .get("suspicious")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0) as i32,
            )
        } else {
            (0, 0)
        };

        let reputation_score = if malicious > 0 {
            0.0
        } else if suspicious > 0 {
            0.3
        } else {
            0.9
        };

        let mut threat_votes = std::collections::HashMap::new();
        threat_votes.insert("malicious".to_string(), malicious);
        threat_votes.insert("suspicious".to_string(), suspicious);

        Ok(Some(DomainReputation {
            domain: domain.to_string(),
            reputation_score,
            is_malicious: malicious > 0,
            threat_votes,
            last_update: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        }))
    }

    async fn query_ip(&self, _ip: &str) -> Result<Option<IPIntelligence>> {
        Ok(None)
    }

    async fn query_username(&self, _username: &str) -> Result<Vec<CredentialData>> {
        Ok(vec![])
    }
}

pub struct IPReputationSource {
    client: reqwest::Client,
    abuseipdb_key: Option<String>,
}

impl IPReputationSource {
    pub fn new(abuseipdb_key: Option<String>) -> Self {
        IPReputationSource {
            client: reqwest::Client::new(),
            abuseipdb_key,
        }
    }

    async fn fetch_ip_reputation(&self, ip: &str) -> Result<serde_json::Value> {
        if self.abuseipdb_key.is_none() {
            return Ok(serde_json::json!({}));
        }

        let api_key = self.abuseipdb_key.as_ref().unwrap();
        let url = "https://api.abuseipdb.com/api/v2/check";

        match self
            .client
            .get(url)
            .header("Key", api_key)
            .header("Accept", "application/json")
            .query(&[("ipAddress", ip), ("maxAgeInDays", "90")])
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<serde_json::Value>().await {
                        Ok(data) => Ok(data),
                        Err(_) => Ok(serde_json::json!({})),
                    }
                } else if resp.status().as_u16() == 404 {
                    Ok(serde_json::json!({}))
                } else if resp.status().as_u16() == 429 {
                    anyhow::bail!("AbuseIPDB API rate limited (429)")
                } else {
                    Ok(serde_json::json!({}))
                }
            }
            Err(_) => Ok(serde_json::json!({})),
        }
    }
}

#[async_trait]
impl DataSource for IPReputationSource {
    async fn query_email(&self, _email: &str) -> Result<Option<OsintResult>> {
        Ok(None)
    }

    async fn query_domain(&self, _domain: &str) -> Result<Option<DomainReputation>> {
        Ok(None)
    }

    async fn query_ip(&self, ip: &str) -> Result<Option<IPIntelligence>> {
        let report = self.fetch_ip_reputation(ip).await?;

        if report.is_null() || report.get("data").is_none() {
            return Ok(None);
        }

        let data = &report["data"];

        let is_whitelisted = data
            .get("isWhitelisted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let abuse_confidence_score = data
            .get("abuseConfidenceScore")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;

        let threat_level = if abuse_confidence_score > 75 {
            "critical"
        } else if abuse_confidence_score > 50 {
            "high"
        } else if abuse_confidence_score > 25 {
            "medium"
        } else if is_whitelisted {
            "low"
        } else {
            "unknown"
        };

        Ok(Some(IPIntelligence {
            ip_address: ip.to_string(),
            organization: data
                .get("usageType")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Unknown".to_string()),
            country: data
                .get("countryCode")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Unknown".to_string()),
            is_vpn: false,
            is_proxy: false,
            is_datacenter: data
                .get("isDatacenter")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            threat_level: threat_level.to_string(),
            abuse_reports: data
                .get("totalReports")
                .and_then(|v| v.as_i64())
                .unwrap_or(0) as u32,
        }))
    }

    async fn query_username(&self, _username: &str) -> Result<Vec<CredentialData>> {
        Ok(vec![])
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_data_source_email() {
        let mock = MockDataSource;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            mock.query_email("test@gmail.com").await
        });

        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_mock_data_source_domain() {
        let mock = MockDataSource;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            mock.query_domain("example.com").await
        });

        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_haveibeenpwned_source_creation() {
        let source = HaveIBeenPwnedSource::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            source.query_email("nonexistent@example.com").await
        });

        assert!(result.is_ok());
    }

    #[test]
    fn test_source_config_default() {
        let config = SourceConfig::default();
        assert!(config.sources_enabled.contains(&DataSourceType::HaveIBeenPwned));
        assert_eq!(config.cache_ttl_seconds, 3600);
    }
}
