use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntityType {
    Email,
    Domain,
    IPAddress,
    PhoneNumber,
    Username,
    Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintEntity {
    pub entity: String,
    pub entity_type: EntityType,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachData {
    pub name: String,
    pub date: String,
    pub exposed_data: Vec<String>,
    pub affected_count: Option<u64>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: String,
    pub value: String,
    pub threat_level: String,
    pub source: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialData {
    pub username: String,
    pub email: Option<String>,
    pub password_hash: Option<String>,
    pub breach_source: String,
    pub date_exposed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReputation {
    pub domain: String,
    pub reputation_score: f64,
    pub is_malicious: bool,
    pub threat_votes: HashMap<String, i32>,
    pub last_update: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailProfile {
    pub email: String,
    pub domain: String,
    pub first_seen: Option<String>,
    pub associated_names: Vec<String>,
    pub associated_companies: Vec<String>,
    pub usage_context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPIntelligence {
    pub ip_address: String,
    pub organization: String,
    pub country: String,
    pub is_vpn: bool,
    pub is_proxy: bool,
    pub is_datacenter: bool,
    pub threat_level: String,
    pub abuse_reports: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintResult {
    pub entity: OsintEntity,
    pub breaches: Vec<BreachData>,
    pub threats: Vec<ThreatIndicator>,
    pub credentials: Vec<CredentialData>,
    pub domain_reputation: Option<DomainReputation>,
    pub email_profile: Option<EmailProfile>,
    pub ip_intelligence: Option<IPIntelligence>,
    pub risk_level: String,
    pub recommendations: Vec<String>,
}

impl OsintResult {
    pub fn new(entity: OsintEntity) -> Self {
        OsintResult {
            entity,
            breaches: Vec::new(),
            threats: Vec::new(),
            credentials: Vec::new(),
            domain_reputation: None,
            email_profile: None,
            ip_intelligence: None,
            risk_level: "unknown".to_string(),
            recommendations: Vec::new(),
        }
    }

    pub fn calculate_risk_level(&mut self) {
        let breach_score = (self.breaches.len() as f64) * 0.3;
        let threat_score = (self.threats.len() as f64) * 0.4;
        let credential_score = (self.credentials.len() as f64) * 0.3;

        let total = breach_score + threat_score + credential_score;

        self.risk_level = if total > 5.0 {
            "critical".to_string()
        } else if total > 3.0 {
            "high".to_string()
        } else if total > 1.0 {
            "medium".to_string()
        } else {
            "low".to_string()
        };
    }

    pub fn add_recommendations(&mut self) {
        self.recommendations.clear();

        match self.risk_level.as_str() {
            "critical" => {
                self.recommendations.push("Immediately change all account passwords".to_string());
                self.recommendations.push("Enable 2FA on all accounts".to_string());
                self.recommendations.push("Monitor for unauthorized account access".to_string());
                self.recommendations.push("Review recent account activity logs".to_string());
            }
            "high" => {
                self.recommendations.push("Change passwords for exposed accounts".to_string());
                self.recommendations.push("Enable 2FA where available".to_string());
                self.recommendations.push("Monitor breach notification sites".to_string());
            }
            "medium" => {
                self.recommendations.push("Review account security settings".to_string());
                self.recommendations.push("Consider enabling 2FA".to_string());
                self.recommendations.push("Update passwords on compromised services".to_string());
            }
            _ => {
                self.recommendations.push("Maintain regular security practices".to_string());
                self.recommendations.push("Monitor for future exposures".to_string());
            }
        }
    }
}
