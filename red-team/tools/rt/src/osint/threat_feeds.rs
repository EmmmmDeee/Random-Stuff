use crate::osint::models::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedData {
    pub c2_ips: Vec<String>,
    pub malware_hashes: Vec<String>,
    pub phishing_domains: Vec<String>,
    pub exploit_kits: Vec<String>,
    pub attributed_actors: Vec<String>,
    pub recent_campaigns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub actor_id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub country: String,
    pub motivation: String,
    pub techniques: Vec<String>,
    pub recent_activity: Vec<String>,
    pub known_targets: Vec<String>,
    pub infrastructure: ThreatFeedData,
}

#[derive(Debug, Clone)]
pub struct ThreatIntelligenceFeed {
    actors: HashMap<String, ThreatActor>,
    indicators: HashMap<String, ThreatIndicator>,
}

#[derive(Debug, Deserialize)]
struct FrameworkActor {
    id: String,
    aliases: Vec<String>,
    attributed_to: String,
    mitre_group_id: String,
    sophistication: String,
    primary_motivation: String,
    target_sectors: Vec<String>,
    notable_campaigns: Vec<String>,
    characteristic_ttps: Vec<TTP>,
    signature_behaviors: Vec<String>,
    emulation_difficulty: String,
    detection_priority_for_sectors: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TTP {
    tactic: String,
    technique: String,
    name: String,
    #[serde(default)]
    notes: String,
}

#[derive(Debug, Deserialize)]
struct FrameworkData {
    threat_actors: Vec<FrameworkActor>,
}

impl ThreatIntelligenceFeed {
    pub fn new() -> Self {
        match Self::load_from_framework() {
            Ok(feed) => feed,
            Err(e) => {
                eprintln!("Warning: Failed to load threat actors from framework: {}", e);
                Self::empty()
            }
        }
    }

    fn load_from_framework() -> Result<Self> {
        let framework_path = "../../intelligence-led/threat-actors.json";
        let json_content = fs::read_to_string(framework_path)?;
        let data: FrameworkData = serde_json::from_str(&json_content)?;

        let mut actors = HashMap::new();

        for fw_actor in data.threat_actors {
            let techniques: Vec<String> = fw_actor
                .characteristic_ttps
                .iter()
                .map(|ttp| ttp.technique.clone())
                .collect();

            let actor = ThreatActor {
                actor_id: fw_actor.id.clone(),
                name: fw_actor.id.clone(),
                aliases: fw_actor.aliases,
                country: fw_actor
                    .attributed_to
                    .split(" (")
                    .next()
                    .unwrap_or("Unknown")
                    .to_string(),
                motivation: fw_actor.primary_motivation,
                techniques,
                recent_activity: fw_actor.notable_campaigns,
                known_targets: fw_actor.target_sectors,
                infrastructure: ThreatFeedData {
                    c2_ips: vec![],
                    malware_hashes: vec![],
                    phishing_domains: vec![],
                    exploit_kits: vec![],
                    attributed_actors: vec![fw_actor.id.clone()],
                    recent_campaigns: fw_actor.signature_behaviors,
                },
            };

            actors.insert(fw_actor.id, actor);
        }

        Ok(ThreatIntelligenceFeed {
            actors,
            indicators: HashMap::new(),
        })
    }

    fn empty() -> Self {
        ThreatIntelligenceFeed {
            actors: HashMap::new(),
            indicators: HashMap::new(),
        }
    }

    pub fn get_actor(&self, actor_id: &str) -> Option<&ThreatActor> {
        self.actors.get(actor_id)
    }

    pub fn list_actors(&self) -> Vec<&ThreatActor> {
        self.actors.values().collect()
    }

    pub fn find_actors_by_country(&self, country: &str) -> Vec<&ThreatActor> {
        self.actors
            .values()
            .filter(|a| a.country == country)
            .collect()
    }

    pub fn find_actors_by_technique(&self, technique: &str) -> Vec<&ThreatActor> {
        self.actors
            .values()
            .filter(|a| a.techniques.contains(&technique.to_string()))
            .collect()
    }

    pub fn find_actors_targeting_sector(&self, sector: &str) -> Vec<&ThreatActor> {
        self.actors
            .values()
            .filter(|a| a.known_targets.iter().any(|t| t.contains(sector)))
            .collect()
    }

    pub fn check_indicator_presence(&self, indicator: &str) -> Vec<String> {
        let mut matches = Vec::new();

        for (actor_id, actor) in &self.actors {
            if actor.infrastructure.c2_ips.contains(&indicator.to_string()) {
                matches.push(format!("{} (C2 IP)", actor_id));
            }
            if actor.infrastructure.phishing_domains.contains(&indicator.to_string()) {
                matches.push(format!("{} (Phishing Domain)", actor_id));
            }
            if actor
                .infrastructure
                .malware_hashes
                .contains(&indicator.to_string())
            {
                matches.push(format!("{} (Malware Hash)", actor_id));
            }
        }

        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feed_creation() {
        let feed = ThreatIntelligenceFeed::new();
        assert!(!feed.list_actors().is_empty());
    }

    #[test]
    fn test_actors_loaded_from_framework() {
        let feed = ThreatIntelligenceFeed::new();
        let actors = feed.list_actors();
        assert!(actors.len() > 0);
        let actor_ids: Vec<_> = actors.iter().map(|a| a.actor_id.as_str()).collect();
        assert!(actor_ids.iter().any(|id| *id == "APT29" || *id == "FIN7" || *id == "LAZARUS" || *id == "APT41" || *id == "LOCKBIT" || *id == "SCATTERED_SPIDER"));
    }

    #[test]
    fn test_find_actors_by_technique() {
        let feed = ThreatIntelligenceFeed::new();
        let actors = feed.find_actors_by_technique("T1195.002");
        assert!(actors.len() >= 1);
    }

    #[test]
    fn test_actors_have_techniques() {
        let feed = ThreatIntelligenceFeed::new();
        for actor in feed.list_actors() {
            assert!(!actor.techniques.is_empty(), "Actor {} has no techniques", actor.actor_id);
        }
    }
}
