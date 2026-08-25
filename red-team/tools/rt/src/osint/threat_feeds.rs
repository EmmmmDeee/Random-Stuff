use crate::osint::models::*;
use std::collections::HashMap;

pub struct ThreatFeedData {
    pub c2_ips: Vec<String>,
    pub malware_hashes: Vec<String>,
    pub phishing_domains: Vec<String>,
    pub exploit_kits: Vec<String>,
    pub attributed_actors: Vec<String>,
    pub recent_campaigns: Vec<String>,
}

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

pub struct ThreatIntelligenceFeed {
    actors: HashMap<String, ThreatActor>,
    indicators: HashMap<String, ThreatIndicator>,
}

impl ThreatIntelligenceFeed {
    pub fn new() -> Self {
        let mut actors = HashMap::new();

        actors.insert(
            "APT28".to_string(),
            ThreatActor {
                actor_id: "APT28".to_string(),
                name: "Fancy Bear".to_string(),
                aliases: vec!["STRONTIUM".to_string(), "Pawn Storm".to_string()],
                country: "Russia".to_string(),
                motivation: "State-sponsored espionage".to_string(),
                techniques: vec![
                    "T1566".to_string(),
                    "T1059".to_string(),
                    "T1486".to_string(),
                ],
                recent_activity: vec![
                    "2026-08: NATO targeting campaign".to_string(),
                    "2026-07: Defense contractor intrusions".to_string(),
                    "2026-06: Election interference operations".to_string(),
                ],
                known_targets: vec![
                    "Government agencies".to_string(),
                    "Defense contractors".to_string(),
                    "Energy sector".to_string(),
                ],
                infrastructure: ThreatFeedData {
                    c2_ips: vec!["203.0.113.45".to_string(), "198.51.100.89".to_string()],
                    malware_hashes: vec![
                        "d41d8cd98f00b204e9800998ecf8427e".to_string(),
                    ],
                    phishing_domains: vec![
                        "secure-update-microsoft.ru".to_string(),
                        "accounts-apple-verify.ru".to_string(),
                    ],
                    exploit_kits: vec!["CVE-2024-1234".to_string()],
                    attributed_actors: vec!["APT28".to_string()],
                    recent_campaigns: vec!["Operation Stealth".to_string()],
                },
            },
        );

        actors.insert(
            "APT41".to_string(),
            ThreatActor {
                actor_id: "APT41".to_string(),
                name: "Wicked Panda".to_string(),
                aliases: vec!["Winnti Group".to_string(), "Barium".to_string()],
                country: "China".to_string(),
                motivation: "Cyber-enabled espionage and financially motivated attacks".to_string(),
                techniques: vec![
                    "T1195".to_string(),
                    "T1040".to_string(),
                    "T1571".to_string(),
                ],
                recent_activity: vec![
                    "2026-08: Supply chain compromise".to_string(),
                    "2026-07: Ransomware-as-a-service operations".to_string(),
                ],
                known_targets: vec![
                    "Software supply chains".to_string(),
                    "Telecommunications".to_string(),
                    "Financial institutions".to_string(),
                ],
                infrastructure: ThreatFeedData {
                    c2_ips: vec!["192.0.2.50".to_string()],
                    malware_hashes: vec![],
                    phishing_domains: vec![],
                    exploit_kits: vec![],
                    attributed_actors: vec!["APT41".to_string()],
                    recent_campaigns: vec!["SupplyChain Blitz".to_string()],
                },
            },
        );

        actors.insert(
            "Lazarus".to_string(),
            ThreatActor {
                actor_id: "Lazarus".to_string(),
                name: "Lazarus Group".to_string(),
                aliases: vec!["Hidden Cobra".to_string(), "ZINC".to_string()],
                country: "North Korea".to_string(),
                motivation: "Financial theft and destructive attacks".to_string(),
                techniques: vec![
                    "T1059".to_string(),
                    "T1486".to_string(),
                    "T1005".to_string(),
                ],
                recent_activity: vec![
                    "2026-08: Cryptocurrency exchange targeting".to_string(),
                    "2026-07: Destructive wiper campaigns".to_string(),
                ],
                known_targets: vec![
                    "Financial sector".to_string(),
                    "Cryptocurrency exchanges".to_string(),
                    "Media companies".to_string(),
                ],
                infrastructure: ThreatFeedData {
                    c2_ips: vec!["198.51.100.10".to_string()],
                    malware_hashes: vec![],
                    phishing_domains: vec!["bank-security-update.kp".to_string()],
                    exploit_kits: vec!["CVE-2024-5678".to_string()],
                    attributed_actors: vec!["Lazarus".to_string()],
                    recent_campaigns: vec!["Operation Wallet Drain".to_string()],
                },
            },
        );

        actors.insert(
            "FIN7".to_string(),
            ThreatActor {
                actor_id: "FIN7".to_string(),
                name: "FIN7".to_string(),
                aliases: vec!["Carbanak".to_string(), "Anunak".to_string()],
                country: "Russia/Eastern Europe".to_string(),
                motivation: "Financial theft and credit card fraud".to_string(),
                techniques: vec![
                    "T1566".to_string(),
                    "T1566.002".to_string(),
                    "T1547".to_string(),
                    "T1059".to_string(),
                ],
                recent_activity: vec![
                    "2026-08: Retail POS system compromise".to_string(),
                    "2026-07: Financial institution targeting".to_string(),
                ],
                known_targets: vec![
                    "Financial institutions".to_string(),
                    "Retail chains".to_string(),
                    "Hospitality sector".to_string(),
                ],
                infrastructure: ThreatFeedData {
                    c2_ips: vec!["192.0.2.120".to_string()],
                    malware_hashes: vec!["8c61352c8ff647b7de4a0d8be8f0cf2a".to_string()],
                    phishing_domains: vec!["update-adobe-reader.ru".to_string()],
                    exploit_kits: vec!["CVE-2024-0640".to_string()],
                    attributed_actors: vec!["FIN7".to_string()],
                    recent_campaigns: vec!["Scattered Spider".to_string()],
                },
            },
        );

        actors.insert(
            "Conti".to_string(),
            ThreatActor {
                actor_id: "Conti".to_string(),
                name: "Conti".to_string(),
                aliases: vec!["Wizard Spider".to_string(), "UNC692".to_string()],
                country: "Russia".to_string(),
                motivation: "Ransomware extortion and financial gain".to_string(),
                techniques: vec![
                    "T1486".to_string(),
                    "T1491".to_string(),
                    "T1005".to_string(),
                    "T1020".to_string(),
                ],
                recent_activity: vec![
                    "2026-08: Critical infrastructure ransomware".to_string(),
                    "2026-07: Hospital network compromise".to_string(),
                ],
                known_targets: vec![
                    "Critical infrastructure".to_string(),
                    "Healthcare sector".to_string(),
                    "Government agencies".to_string(),
                ],
                infrastructure: ThreatFeedData {
                    c2_ips: vec!["203.0.113.99".to_string(), "192.0.2.88".to_string()],
                    malware_hashes: vec!["f847fd2b8ba9762c3cf8e8f2c5f6c4d2".to_string()],
                    phishing_domains: vec!["secure-file-sharing.ru".to_string()],
                    exploit_kits: vec!["CVE-2024-1234".to_string()],
                    attributed_actors: vec!["Conti".to_string()],
                    recent_campaigns: vec!["Operation BlackCat".to_string()],
                },
            },
        );

        actors.insert(
            "Emotet".to_string(),
            ThreatActor {
                actor_id: "Emotet".to_string(),
                name: "Emotet".to_string(),
                aliases: vec!["Mealybug".to_string(), "TA542".to_string()],
                country: "Ukraine/Eastern Europe".to_string(),
                motivation: "Malware distribution and botnet operation".to_string(),
                techniques: vec![
                    "T1566".to_string(),
                    "T1059".to_string(),
                    "T1566.001".to_string(),
                    "T1027".to_string(),
                ],
                recent_activity: vec![
                    "2026-08: Large-scale phishing campaign".to_string(),
                    "2026-07: Banking trojan distribution".to_string(),
                ],
                known_targets: vec![
                    "Financial institutions".to_string(),
                    "Enterprises".to_string(),
                    "Government".to_string(),
                ],
                infrastructure: ThreatFeedData {
                    c2_ips: vec!["198.51.100.77".to_string()],
                    malware_hashes: vec!["3e4c4f5d6e7f8a9b0c1d2e3f4a5b6c7d".to_string()],
                    phishing_domains: vec!["payment-confirmation-bank.com".to_string()],
                    exploit_kits: vec!["CVE-2024-2891".to_string()],
                    attributed_actors: vec!["Emotet".to_string()],
                    recent_campaigns: vec!["Operation TrickBot".to_string()],
                },
            },
        );

        ThreatIntelligenceFeed {
            actors,
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
        assert!(feed.get_actor("APT28").is_some());
        assert!(feed.get_actor("APT41").is_some());
        assert!(feed.get_actor("Lazarus").is_some());
    }

    #[test]
    fn test_find_actors_by_country() {
        let feed = ThreatIntelligenceFeed::new();
        let russian_actors = feed.find_actors_by_country("Russia");
        assert!(russian_actors.len() >= 2);
        let actor_ids: Vec<_> = russian_actors.iter().map(|a| a.actor_id.as_str()).collect();
        assert!(actor_ids.contains(&"APT28"));
        assert!(actor_ids.contains(&"Conti"));
    }

    #[test]
    fn test_find_actors_by_technique() {
        let feed = ThreatIntelligenceFeed::new();
        let actors = feed.find_actors_by_technique("T1486");
        assert!(actors.len() >= 2);
    }

    #[test]
    fn test_check_indicator_presence() {
        let feed = ThreatIntelligenceFeed::new();
        let matches = feed.check_indicator_presence("203.0.113.45");
        assert!(!matches.is_empty());
        assert!(matches[0].contains("APT28"));
    }
}
