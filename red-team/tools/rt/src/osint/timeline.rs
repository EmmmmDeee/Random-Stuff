use crate::osint::{BreachVictimData, ThreatIntelligenceFeed};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttackStage {
    Reconnaissance,
    Weaponization,
    Delivery,
    Exploitation,
    Installation,
    CommandControl,
    Actions,
    Breach,
    Unknown,
}

impl AttackStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttackStage::Reconnaissance => "Reconnaissance",
            AttackStage::Weaponization => "Weaponization",
            AttackStage::Delivery => "Delivery",
            AttackStage::Exploitation => "Exploitation",
            AttackStage::Installation => "Installation",
            AttackStage::CommandControl => "Command & Control",
            AttackStage::Actions => "Actions on Objectives",
            AttackStage::Breach => "Breach Detected",
            AttackStage::Unknown => "Unknown",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AttackStage::Reconnaissance => "Attacker gathers intelligence",
            AttackStage::Weaponization => "Attacker creates malware/payloads",
            AttackStage::Delivery => "Attacker delivers malware/payload",
            AttackStage::Exploitation => "Payload executes on target",
            AttackStage::Installation => "Attacker installs backdoors/persistence",
            AttackStage::CommandControl => "Attacker establishes command channel",
            AttackStage::Actions => "Attacker performs mission objectives",
            AttackStage::Breach => "Breach discovered by victim/analysts",
            AttackStage::Unknown => "Stage not determined",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub date: String,
    pub stage: AttackStage,
    pub event_type: String,
    pub description: String,
    pub indicators: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTimeline {
    pub email: String,
    pub total_events: usize,
    pub earliest_event: Option<String>,
    pub latest_event: Option<String>,
    pub attack_duration_days: usize,
    pub events: Vec<TimelineEvent>,
    pub stage_progression: Vec<AttackStage>,
    pub likely_attack_vector: String,
    pub estimated_attacker_country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignTimeline {
    pub campaign_name: String,
    pub actor_id: String,
    pub start_date: String,
    pub end_date: Option<String>,
    pub duration_days: usize,
    pub target_count: usize,
    pub affected_emails: Vec<String>,
    pub unique_stages: Vec<AttackStage>,
    pub progression_pattern: String,
    pub estimated_success_rate: f64,
}

pub struct TimelineAnalyzer {
    threat_feed: ThreatIntelligenceFeed,
}

impl TimelineAnalyzer {
    pub fn new(threat_feed: ThreatIntelligenceFeed) -> Self {
        TimelineAnalyzer { threat_feed }
    }

    pub fn analyze_attack_timeline(&self, email: &str, breaches: &[BreachVictimData]) -> AttackTimeline {
        if breaches.is_empty() {
            return AttackTimeline {
                email: email.to_string(),
                total_events: 0,
                earliest_event: None,
                latest_event: None,
                attack_duration_days: 0,
                events: vec![],
                stage_progression: vec![],
                likely_attack_vector: "Unknown".to_string(),
                estimated_attacker_country: None,
            };
        }

        let mut events = vec![];
        let mut stage_progression = vec![];

        // Sort breaches by date
        let mut sorted_breaches = breaches.to_vec();
        sorted_breaches.sort_by(|a, b| a.breach_date.cmp(&b.breach_date));

        // Map breaches to timeline events and attack stages
        for (i, breach) in sorted_breaches.iter().enumerate() {
            let stage = self.infer_attack_stage(breach);
            let indicators = self.extract_indicators(breach);

            events.push(TimelineEvent {
                date: breach.breach_date.clone(),
                stage: stage.clone(),
                event_type: breach.breach_name.clone(),
                description: format!("Breach: {} - Exposed fields: {}", breach.breach_name, breach.exposed_fields.join(", ")),
                indicators,
                confidence: if i == 0 { 0.6 } else { 0.8 },
            });

            if !stage_progression.contains(&stage) {
                stage_progression.push(stage);
            }
        }

        let earliest_event = sorted_breaches.first().map(|b| b.breach_date.clone());
        let latest_event = sorted_breaches.last().map(|b| b.breach_date.clone());

        let attack_duration_days = self.calculate_duration_days(
            earliest_event.as_deref(),
            latest_event.as_deref(),
        );

        let likely_attack_vector = self.determine_attack_vector(breaches);
        let estimated_attacker_country = self.infer_attacker_country(breaches);

        AttackTimeline {
            email: email.to_string(),
            total_events: events.len(),
            earliest_event,
            latest_event,
            attack_duration_days,
            events,
            stage_progression,
            likely_attack_vector,
            estimated_attacker_country,
        }
    }

    pub fn correlate_campaigns(&self, target_emails: &[&str]) -> Vec<CampaignTimeline> {
        let mut campaigns: HashMap<String, Vec<String>> = HashMap::new();

        for email in target_emails {
            let domain = email.split('@').nth(1).unwrap_or("unknown");
            campaigns.entry(domain.to_string()).or_insert_with(Vec::new).push(email.to_string());
        }

        campaigns
            .into_iter()
            .map(|(domain, emails)| {
                let start_date = "2024-01-01".to_string(); // Default, would come from actual data
                let end_date = Some("2024-12-31".to_string());
                let duration_days = 365;
                let target_count = emails.len();

                CampaignTimeline {
                    campaign_name: format!("Campaign-{}", domain),
                    actor_id: "Unknown".to_string(),
                    start_date,
                    end_date,
                    duration_days,
                    target_count,
                    affected_emails: emails,
                    unique_stages: vec![
                        AttackStage::Reconnaissance,
                        AttackStage::Delivery,
                        AttackStage::Exploitation,
                    ],
                    progression_pattern: "Standard Cyber Kill Chain".to_string(),
                    estimated_success_rate: 0.75,
                }
            })
            .collect()
    }

    fn infer_attack_stage(&self, breach: &BreachVictimData) -> AttackStage {
        if breach.exposed_fields.is_empty() {
            return AttackStage::Reconnaissance;
        }

        let has_credentials = breach.password_hash.is_some();
        let has_email = breach.exposed_fields.contains(&"email".to_string());
        let has_phone = breach.exposed_fields.contains(&"phone".to_string());
        let has_sensitive = breach
            .exposed_fields
            .iter()
            .any(|f| f.contains("ssn") || f.contains("credit") || f.contains("account"));

        if has_credentials && has_sensitive {
            AttackStage::Actions
        } else if has_credentials && has_phone {
            AttackStage::CommandControl
        } else if has_credentials {
            AttackStage::Installation
        } else if has_sensitive {
            AttackStage::Exploitation
        } else if has_email && has_phone {
            AttackStage::Delivery
        } else if has_email {
            AttackStage::Weaponization
        } else {
            AttackStage::Reconnaissance
        }
    }

    fn extract_indicators(&self, breach: &BreachVictimData) -> Vec<String> {
        let mut indicators = vec![];

        indicators.push(breach.breach_name.clone());
        if let Some(location) = &breach.victim_location {
            indicators.push(location.clone());
        }
        indicators.push(breach.stealer_forum.clone());

        indicators
    }

    fn determine_attack_vector(&self, breaches: &[BreachVictimData]) -> String {
        let breach_count = breaches.len();
        let has_phishing = breaches
            .iter()
            .any(|b| b.breach_name.to_lowercase().contains("phishing"));
        let has_credential_theft = breaches.iter().any(|b| b.password_hash.is_some());

        if has_phishing {
            "Phishing / Social Engineering".to_string()
        } else if has_credential_theft && breach_count > 1 {
            "Credential Compromise / Lateral Movement".to_string()
        } else if has_credential_theft {
            "Direct Credential Theft".to_string()
        } else if breach_count > 2 {
            "Multi-Vector Attack / Supply Chain".to_string()
        } else {
            "Data Exposure / Breach".to_string()
        }
    }

    fn infer_attacker_country(&self, breaches: &[BreachVictimData]) -> Option<String> {
        let forum_attribution: HashMap<&str, &str> = [
            ("BreachForums", "Russia"),
            ("XSS", "Russia"),
            ("Exploit", "Russia"),
            ("Underground", "China"),
            ("BlackMarket", "Unknown"),
        ]
        .iter()
        .copied()
        .collect();

        for breach in breaches {
            for (forum, country) in &forum_attribution {
                if breach.stealer_forum.contains(forum) {
                    return Some(country.to_string());
                }
            }
        }

        None
    }

    fn calculate_duration_days(&self, start: Option<&str>, end: Option<&str>) -> usize {
        match (start, end) {
            (Some(s), Some(e)) => {
                let start_parsed = s.replace("-", "").parse::<i32>().unwrap_or(0);
                let end_parsed = e.replace("-", "").parse::<i32>().unwrap_or(0);
                let diff = (end_parsed - start_parsed).abs() as usize;
                if diff > 10000 {
                    diff / 10000
                } else {
                    diff
                }
            }
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeline_analysis() {
        let feed = ThreatIntelligenceFeed::new();
        let analyzer = TimelineAnalyzer::new(feed);
        let breaches = vec![];
        let timeline = analyzer.analyze_attack_timeline("test@example.com", &breaches);
        assert_eq!(timeline.total_events, 0);
    }

    #[test]
    fn test_campaign_correlation() {
        let feed = ThreatIntelligenceFeed::new();
        let analyzer = TimelineAnalyzer::new(feed);
        let emails = vec!["user1@gmail.com", "user2@gmail.com"];
        let campaigns = analyzer.correlate_campaigns(&emails);
        assert!(!campaigns.is_empty());
    }

    #[test]
    fn test_attack_stage_inference() {
        let feed = ThreatIntelligenceFeed::new();
        let analyzer = TimelineAnalyzer::new(feed);
        let breach = BreachVictimData {
            breach_name: "Test".to_string(),
            breach_date: "2021-06-21".to_string(),
            victim_email: "test@example.com".to_string(),
            victim_location: None,
            username: None,
            password_hash: Some("hash".to_string()),
            exposed_fields: vec!["email".to_string()],
            stealer_forum: "Test".to_string(),
            recovery_possible: false,
        };
        let stage = analyzer.infer_attack_stage(&breach);
        assert_eq!(stage, AttackStage::Installation);
    }

    #[test]
    fn test_duration_calculation() {
        let feed = ThreatIntelligenceFeed::new();
        let analyzer = TimelineAnalyzer::new(feed);
        let duration = analyzer.calculate_duration_days(Some("2021-01-01"), Some("2021-12-31"));
        assert!(duration > 0);
    }

    #[test]
    fn test_attack_vector_determination() {
        let feed = ThreatIntelligenceFeed::new();
        let analyzer = TimelineAnalyzer::new(feed);
        let breaches = vec![];
        let vector = analyzer.determine_attack_vector(&breaches);
        assert!(!vector.is_empty());
    }
}
