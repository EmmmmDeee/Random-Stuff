use crate::osint::{GeolocationEngine, ThreatIntelligenceFeed, BreachVictimData, GeoLocation};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionIndicator {
    pub indicator_type: String, // technique, geography, target_sector, timeline
    pub value: String,
    pub confidence: f64, // 0.0 to 1.0
    pub matched_actors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignAttribution {
    pub victim_email: String,
    pub primary_attribution: Option<String>, // Most likely actor
    pub attribution_confidence: f64,
    pub secondary_attributions: Vec<(String, f64)>, // Other possible actors with scores
    pub indicators: Vec<AttributionIndicator>,
    pub geographic_fingerprint: String,
    pub timeline_stage: String, // reconnaissance, weaponization, delivery, etc.
    pub recommended_response: Vec<String>,
    pub detection_opportunities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentProfile {
    pub email: String,
    pub breach_count: usize,
    pub geographic_spread: usize,
    pub temporal_clustering: f64, // 0.0 to 1.0, how close breaches are in time
    pub highest_risk_breach: Option<String>,
    pub actor_profiles: Vec<String>,
    pub exposure_severity: String, // low, medium, high, critical
    pub recovery_difficulty: String,
}

pub struct AttributionEngine {
    geolocation_engine: GeolocationEngine,
    threat_feed: ThreatIntelligenceFeed,
}

impl AttributionEngine {
    pub fn new(threat_feed: ThreatIntelligenceFeed) -> Self {
        AttributionEngine {
            geolocation_engine: GeolocationEngine::new(),
            threat_feed,
        }
    }

    pub fn attribute_campaign(&self, email: &str) -> CampaignAttribution {
        let breach_data = self.geolocation_engine.get_breach_victim_data(email);
        let locations = self.geolocation_engine.resolve_domain_location(
            email.split('@').nth(1).unwrap_or("example.com"),
        );

        if breach_data.is_empty() {
            return CampaignAttribution {
                victim_email: email.to_string(),
                primary_attribution: None,
                attribution_confidence: 0.0,
                secondary_attributions: vec![],
                indicators: vec![],
                geographic_fingerprint: "unknown".to_string(),
                timeline_stage: "unknown".to_string(),
                recommended_response: vec![],
                detection_opportunities: vec![],
            };
        }

        let mut indicators = vec![];
        let mut actor_scores: HashMap<String, f64> = HashMap::new();

        // Analyze geographic indicators
        for location in &locations {
            indicators.push(AttributionIndicator {
                indicator_type: "geography".to_string(),
                value: format!("{} ({})", location.country, location.country_code),
                confidence: match location.threat_level.as_str() {
                    "critical" => 0.9,
                    "high" => 0.7,
                    "medium" => 0.5,
                    _ => 0.3,
                },
                matched_actors: self
                    .threat_feed
                    .find_actors_by_country(&location.country)
                    .iter()
                    .map(|a| a.actor_id.clone())
                    .collect(),
            });

            // Score actors by geography
            for actor in self
                .threat_feed
                .find_actors_by_country(&location.country)
            {
                let geo_confidence = match location.threat_level.as_str() {
                    "critical" => 0.85,
                    "high" => 0.65,
                    "medium" => 0.45,
                    _ => 0.25,
                };
                *actor_scores.entry(actor.actor_id.clone()).or_insert(0.0) +=
                    geo_confidence * 0.3;
            }
        }

        // Analyze target sector indicators
        for breach in &breach_data {
            let domain = email.split('@').nth(1).unwrap_or("");
            let is_corporate = !domain.ends_with(".com") || domain.contains("corp");

            if is_corporate {
                indicators.push(AttributionIndicator {
                    indicator_type: "target_sector".to_string(),
                    value: "Enterprise/Corporate".to_string(),
                    confidence: 0.6,
                    matched_actors: self
                        .threat_feed
                        .find_actors_targeting_sector("Enterprise")
                        .iter()
                        .map(|a| a.actor_id.clone())
                        .collect(),
                });

                // Score actors by target preference
                for actor in self
                    .threat_feed
                    .find_actors_targeting_sector("Enterprise")
                {
                    *actor_scores.entry(actor.actor_id.clone()).or_insert(0.0) +=
                        0.5 * 0.25;
                }
            }

            // Analyze breach characteristics
            let breach_year = breach
                .breach_date
                .split('-')
                .next()
                .and_then(|y| y.parse::<u32>().ok())
                .unwrap_or(0);
            let current_year = 2024u32;

            if current_year - breach_year <= 3 {
                indicators.push(AttributionIndicator {
                    indicator_type: "timeline".to_string(),
                    value: format!("{} (recent)", breach.breach_date),
                    confidence: 0.75,
                    matched_actors: self
                        .threat_feed
                        .list_actors()
                        .iter()
                        .map(|a| a.actor_id.clone())
                        .collect(),
                });

                // Recent breaches are more likely to be from active groups
                for actor in self.threat_feed.list_actors() {
                    *actor_scores.entry(actor.actor_id.clone()).or_insert(0.0) +=
                        0.4 * 0.2;
                }
            }
        }

        // Determine primary attribution
        let primary_attribution = actor_scores
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(actor, _)| actor.clone());

        let attribution_confidence = primary_attribution
            .as_ref()
            .and_then(|actor| actor_scores.get(actor))
            .copied()
            .unwrap_or(0.0)
            .min(1.0);

        // Build secondary attributions
        let mut secondary_attributions: Vec<_> = actor_scores
            .into_iter()
            .filter(|(actor, _)| Some(actor) != primary_attribution.as_ref())
            .collect();
        secondary_attributions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let secondary_attributions: Vec<_> = secondary_attributions
            .into_iter()
            .take(3)
            .collect();

        let geographic_fingerprint = self.build_geographic_fingerprint(&locations);
        let timeline_stage = self.determine_attack_stage(&breach_data);

        let recommended_response = self.generate_response_recommendations(
            primary_attribution.as_deref(),
            &breach_data,
        );

        let detection_opportunities = self.identify_detection_opportunities(
            primary_attribution.as_deref(),
            &geographic_fingerprint,
        );

        CampaignAttribution {
            victim_email: email.to_string(),
            primary_attribution,
            attribution_confidence,
            secondary_attributions,
            indicators,
            geographic_fingerprint,
            timeline_stage,
            recommended_response,
            detection_opportunities,
        }
    }

    pub fn profile_incident(&self, email: &str) -> IncidentProfile {
        let breach_data = self.geolocation_engine.get_breach_victim_data(email);
        let locations = self.geolocation_engine.resolve_domain_location(
            email.split('@').nth(1).unwrap_or("example.com"),
        );

        let geographic_spread = locations.len();

        let temporal_clustering = self.calculate_temporal_clustering(&breach_data);

        let highest_risk_breach = breach_data
            .iter()
            .max_by_key(|b| {
                (if b.recovery_possible { 1 } else { 2 })
                    + (if b.exposed_fields.contains(&"password_hash".to_string()) { 1 } else { 0 })
            })
            .map(|b| b.breach_name.clone());

        let actor_profiles = self
            .threat_feed
            .list_actors()
            .iter()
            .map(|a| a.actor_id.clone())
            .collect();

        let exposure_severity = match breach_data.len() {
            0 => "low".to_string(),
            1 => "medium".to_string(),
            2..=3 => "high".to_string(),
            _ => "critical".to_string(),
        };

        let recovery_difficulty = if breach_data
            .iter()
            .any(|b| !b.recovery_possible)
        {
            "difficult".to_string()
        } else if breach_data.iter().any(|b| b.password_hash.is_some()) {
            "moderate".to_string()
        } else {
            "easy".to_string()
        };

        IncidentProfile {
            email: email.to_string(),
            breach_count: breach_data.len(),
            geographic_spread,
            temporal_clustering,
            highest_risk_breach,
            actor_profiles,
            exposure_severity,
            recovery_difficulty,
        }
    }

    fn build_geographic_fingerprint(&self, locations: &[GeoLocation]) -> String {
        if locations.is_empty() {
            return "unknown".to_string();
        }

        let countries: Vec<&str> = locations
            .iter()
            .map(|l| l.country.as_str())
            .collect();

        if countries.iter().all(|c| *c == countries[0]) {
            format!("Single-country: {}", countries[0])
        } else {
            format!("Multi-country: {}", countries.join(", "))
        }
    }

    fn determine_attack_stage(&self, breaches: &[BreachVictimData]) -> String {
        if breaches.is_empty() {
            return "reconnaissance".to_string();
        }

        let has_credentials = breaches.iter().any(|b| b.password_hash.is_some());
        let has_email = breaches.iter().any(|b| b.exposed_fields.contains(&"email".to_string()));
        let has_phone = breaches.iter().any(|b| b.exposed_fields.contains(&"phone".to_string()));

        if has_credentials && has_phone {
            "exploitation".to_string()
        } else if has_credentials {
            "credential_theft".to_string()
        } else if has_email && has_phone {
            "post_compromise".to_string()
        } else {
            "weaponization".to_string()
        }
    }

    fn generate_response_recommendations(&self, actor: Option<&str>, breaches: &[BreachVictimData]) -> Vec<String> {
        let mut recommendations = vec![];

        if let Some(actor_id) = actor {
            if let Some(actor) = self.threat_feed.get_actor(actor_id) {
                recommendations.push(format!(
                    "Review {} techniques and TTPs for indicators of compromise",
                    actor_id
                ));
                if !actor.known_targets.is_empty() {
                    recommendations.push(format!(
                        "This actor targets: {}",
                        actor.known_targets.join(", ")
                    ));
                }
            }
        }

        if breaches.iter().any(|b| !b.recovery_possible) {
            recommendations.push(
                "Assume full account compromise - reset all credentials immediately".to_string(),
            );
        } else {
            recommendations.push(
                "Change passwords for all accounts, enable MFA where available".to_string(),
            );
        }

        if breaches.iter().any(|b| b.exposed_fields.contains(&"phone".to_string())) {
            recommendations.push("Monitor for SIM swap and account takeover attacks".to_string());
        }

        if breaches.len() > 2 {
            recommendations.push(
                "Multiple breach exposures detected - Consider changing email address".to_string(),
            );
        }

        recommendations.push("Set up breach monitoring alerts for this email".to_string());
        recommendations
    }

    fn identify_detection_opportunities(&self, actor: Option<&str>, _geographic: &str) -> Vec<String> {
        let mut opportunities = vec![];

        if let Some(actor_id) = actor {
            if let Some(actor) = self.threat_feed.get_actor(actor_id) {
                opportunities.push(format!("Monitor for {} infrastructure", actor_id));

                if !actor.infrastructure.c2_ips.is_empty() {
                    opportunities.push(format!(
                        "Alert on connections to known {} C2 IPs: {}",
                        actor_id,
                        actor.infrastructure.c2_ips.join(", ")
                    ));
                }

                if !actor.infrastructure.phishing_domains.is_empty() {
                    opportunities.push(format!(
                        "Block {} phishing domains at perimeter",
                        actor.infrastructure.phishing_domains.len()
                    ));
                }

                for technique in actor.techniques.iter().take(5) {
                    opportunities.push(format!("Implement detection for {} technique usage", technique));
                }
            }
        }

        opportunities.push("Enable logging on all compromised systems".to_string());
        opportunities.push("Review email forwarding rules and recovery options".to_string());

        opportunities.truncate(8);
        opportunities
    }

    fn calculate_temporal_clustering(&self, breaches: &[BreachVictimData]) -> f64 {
        if breaches.len() < 2 {
            return 0.0;
        }

        let dates: Vec<&str> = breaches.iter().map(|b| b.breach_date.as_str()).collect();
        let date_diffs: Vec<i32> = dates
            .windows(2)
            .map(|w| {
                let diff = (w[1]
                    .replace("-", "")
                    .parse::<i32>()
                    .unwrap_or(0)
                    - w[0]
                        .replace("-", "")
                        .parse::<i32>()
                        .unwrap_or(0)).abs();
                diff
            })
            .collect();

        if date_diffs.is_empty() {
            return 0.0;
        }

        let avg_diff = date_diffs.iter().sum::<i32>() / date_diffs.len() as i32;

        // Closer breaches = higher clustering score
        if avg_diff < 100 {
            0.9
        } else if avg_diff < 365 {
            0.6
        } else {
            0.2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_campaign_attribution() {
        let feed = ThreatIntelligenceFeed::new();
        let engine = AttributionEngine::new(feed);
        let attribution = engine.attribute_campaign("test@gmail.com");
        assert!(!attribution.indicators.is_empty());
    }

    #[test]
    fn test_incident_profile() {
        let feed = ThreatIntelligenceFeed::new();
        let engine = AttributionEngine::new(feed);
        let profile = engine.profile_incident("test@gmail.com");
        assert!(profile.breach_count >= 0);
    }

    #[test]
    fn test_geographic_fingerprint() {
        let feed = ThreatIntelligenceFeed::new();
        let engine = AttributionEngine::new(feed);
        let fingerprint = engine.build_geographic_fingerprint(&[]);
        assert_eq!(fingerprint, "unknown");
    }

    #[test]
    fn test_attack_stage_determination() {
        let feed = ThreatIntelligenceFeed::new();
        let engine = AttributionEngine::new(feed);
        let stage = engine.determine_attack_stage(&[]);
        assert_eq!(stage, "reconnaissance");
    }

    #[test]
    fn test_temporal_clustering() {
        let feed = ThreatIntelligenceFeed::new();
        let engine = AttributionEngine::new(feed);
        let clustering = engine.calculate_temporal_clustering(&[]);
        assert_eq!(clustering, 0.0);
    }
}
