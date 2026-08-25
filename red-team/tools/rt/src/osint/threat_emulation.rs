use crate::osint::{ThreatIntelligenceFeed, ThreatActor};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackScenario {
    pub scenario_id: String,
    pub actor_id: String,
    pub actor_name: String,
    pub target_profile: String,
    pub attack_phases: Vec<AttackPhase>,
    pub estimated_duration_days: usize,
    pub success_probability: f64,
    pub required_capabilities: Vec<String>,
    pub recommended_infrastructure: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPhase {
    pub phase_number: usize,
    pub name: String,
    pub description: String,
    pub primary_techniques: Vec<String>,
    pub recommended_tools: Vec<String>,
    pub indicators_of_attack: Vec<String>,
    pub evasion_techniques: Vec<String>,
    pub duration_days: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetProfile {
    pub target_domain: String,
    pub estimated_size: String, // small, medium, large, enterprise
    pub industry: String,
    pub security_posture: String, // weak, moderate, strong
    pub attack_surface_score: f64,
    pub vulnerability_likelihood: f64,
    pub employee_count_estimate: usize,
    pub recommended_vectors: Vec<String>,
    pub likely_defenders: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconPlan {
    pub target_domain: String,
    pub actor_id: String,
    pub passive_recon_tasks: Vec<ReconTask>,
    pub active_recon_tasks: Vec<ReconTask>,
    pub social_engineering_targets: Vec<String>,
    pub infrastructure_needed: Vec<String>,
    pub opsec_requirements: Vec<String>,
    pub estimated_recon_duration_days: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconTask {
    pub task_id: String,
    pub description: String,
    pub technique_id: String,
    pub tools: Vec<String>,
    pub expected_output: String,
    pub risk_level: String,
    pub detection_likelihood: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryVector {
    pub vector_type: String, // phishing, supply_chain, watering_hole, c2
    pub technique_id: String,
    pub description: String,
    pub payload_type: String,
    pub success_rate: f64,
    pub detection_risk: f64,
    pub setup_complexity: String,
    pub required_infrastructure: Vec<String>,
}

pub struct ThreatEmulator {
    threat_feed: ThreatIntelligenceFeed,
}

impl ThreatEmulator {
    pub fn new(threat_feed: ThreatIntelligenceFeed) -> Self {
        ThreatEmulator { threat_feed }
    }

    pub fn emulate_actor_campaign(&self, actor_id: &str, target_domain: &str) -> Option<AttackScenario> {
        let actor = self.threat_feed.get_actor(actor_id)?;
        let target_profile = self.profile_target(target_domain, actor);

        let attack_phases = self.generate_attack_phases(actor, &target_profile);
        let required_capabilities = self.derive_required_capabilities(actor);
        let recommended_infrastructure = self.recommend_infrastructure(actor, target_domain);

        Some(AttackScenario {
            scenario_id: format!("EMUL-{}-{}", actor_id, chrono::Local::now().format("%Y%m%d%H%M%S")),
            actor_id: actor_id.to_string(),
            actor_name: actor.name.clone(),
            target_profile: target_domain.to_string(),
            attack_phases,
            estimated_duration_days: self.estimate_campaign_duration(actor),
            success_probability: self.estimate_success_probability(&target_profile, actor),
            required_capabilities,
            recommended_infrastructure,
        })
    }

    pub fn plan_reconnaissance(&self, actor_id: &str, target_domain: &str) -> Option<ReconPlan> {
        let actor = self.threat_feed.get_actor(actor_id)?;

        let passive_recon_tasks = vec![
            ReconTask {
                task_id: "RECON-001".to_string(),
                description: "OSINT via public records and databases".to_string(),
                technique_id: "T1589".to_string(),
                tools: vec!["SHODAN".to_string(), "LinkedIn".to_string(), "hunter.io".to_string()],
                expected_output: "Employee names, emails, departments".to_string(),
                risk_level: "low".to_string(),
                detection_likelihood: 0.05,
            },
            ReconTask {
                task_id: "RECON-002".to_string(),
                description: "DNS and domain enumeration".to_string(),
                technique_id: "T1589.002".to_string(),
                tools: vec!["dig".to_string(), "nslookup".to_string(), "subfinder".to_string()],
                expected_output: "Subdomains, DNS records, mail servers".to_string(),
                risk_level: "low".to_string(),
                detection_likelihood: 0.1,
            },
            ReconTask {
                task_id: "RECON-003".to_string(),
                description: "Breach database search".to_string(),
                technique_id: "T1592".to_string(),
                tools: vec!["HaveIBeenPwned".to_string(), "Breach compilations".to_string()],
                expected_output: "Exposed credentials, email lists, patterns".to_string(),
                risk_level: "low".to_string(),
                detection_likelihood: 0.0,
            },
        ];

        let active_recon_tasks = vec![
            ReconTask {
                task_id: "RECON-101".to_string(),
                description: "Port scanning and service enumeration".to_string(),
                technique_id: "T1046".to_string(),
                tools: vec!["nmap".to_string(), "masscan".to_string()],
                expected_output: "Open ports, running services, versions".to_string(),
                risk_level: "medium".to_string(),
                detection_likelihood: 0.6,
            },
            ReconTask {
                task_id: "RECON-102".to_string(),
                description: "Web application scanning".to_string(),
                technique_id: "T1592.004".to_string(),
                tools: vec!["Burp Suite".to_string(), "OWASP ZAP".to_string()],
                expected_output: "Vulnerabilities, authentication mechanisms, tech stack".to_string(),
                risk_level: "high".to_string(),
                detection_likelihood: 0.8,
            },
        ];

        let social_engineering_targets = self.identify_social_engineering_targets(actor, target_domain);
        let infrastructure_needed = self.recommend_recon_infrastructure(actor);
        let opsec_requirements = self.derive_opsec_requirements(actor);

        Some(ReconPlan {
            target_domain: target_domain.to_string(),
            actor_id: actor_id.to_string(),
            passive_recon_tasks,
            active_recon_tasks,
            social_engineering_targets,
            infrastructure_needed,
            opsec_requirements,
            estimated_recon_duration_days: 14,
        })
    }

    pub fn recommend_delivery_vectors(&self, actor_id: &str, target_profile: &TargetProfile) -> Vec<DeliveryVector> {
        let mut vectors = vec![];

        if target_profile.security_posture != "strong" {
            vectors.push(DeliveryVector {
                vector_type: "phishing".to_string(),
                technique_id: "T1566.002".to_string(),
                description: "Spear phishing with malicious attachments".to_string(),
                payload_type: "Office macro, executable, PDF exploit".to_string(),
                success_rate: 0.35,
                detection_risk: 0.4,
                setup_complexity: "low".to_string(),
                required_infrastructure: vec!["Email server".to_string(), "Hosting".to_string()],
            });
        }

        if target_profile.industry.to_lowercase().contains("tech") || target_profile.industry.to_lowercase().contains("finance") {
            vectors.push(DeliveryVector {
                vector_type: "supply_chain".to_string(),
                technique_id: "T1195.002".to_string(),
                description: "Software supply chain compromise".to_string(),
                payload_type: "Backdoored package, compromised dependency".to_string(),
                success_rate: 0.15,
                detection_risk: 0.2,
                setup_complexity: "high".to_string(),
                required_infrastructure: vec!["Package repository access".to_string(), "Build infrastructure".to_string()],
            });
        }

        if target_profile.employee_count_estimate > 500 {
            vectors.push(DeliveryVector {
                vector_type: "watering_hole".to_string(),
                technique_id: "T1583.001".to_string(),
                description: "Compromise websites frequented by target employees".to_string(),
                payload_type: "Browser exploit, drive-by download".to_string(),
                success_rate: 0.2,
                detection_risk: 0.35,
                setup_complexity: "medium".to_string(),
                required_infrastructure: vec!["Compromised website".to_string(), "Exploit kit".to_string()],
            });
        }

        vectors.push(DeliveryVector {
            vector_type: "c2".to_string(),
            technique_id: "T1071".to_string(),
            description: "Direct C2 channel establishment (for post-compromise)".to_string(),
            payload_type: "Reverse shell, implant, beacon".to_string(),
            success_rate: 0.8,
            detection_risk: 0.6,
            setup_complexity: "medium".to_string(),
            required_infrastructure: vec!["C2 infrastructure".to_string(), "Domain registration".to_string()],
        });

        vectors
    }

    fn profile_target(&self, domain: &str, actor: &ThreatActor) -> TargetProfile {
        let security_posture = if actor.known_targets.iter().any(|t| t.contains("Government")) {
            "strong".to_string()
        } else {
            "moderate".to_string()
        };

        let attack_surface_score = if domain.ends_with(".gov") || domain.ends_with(".mil") {
            0.3
        } else if domain.ends_with(".edu") {
            0.6
        } else {
            0.5
        };

        let estimated_size = match domain {
            d if d.contains("global") || d.len() < 10 => "large".to_string(),
            d if d.contains("corp") => "enterprise".to_string(),
            _ => "medium".to_string(),
        };

        TargetProfile {
            target_domain: domain.to_string(),
            estimated_size,
            industry: actor.known_targets.first().cloned().unwrap_or_else(|| "Unknown".to_string()),
            security_posture,
            attack_surface_score,
            vulnerability_likelihood: 1.0 - attack_surface_score,
            employee_count_estimate: 250,
            recommended_vectors: vec!["Phishing".to_string(), "Credential compromise".to_string()],
            likely_defenders: vec!["SOC".to_string(), "Incident Response".to_string()],
        }
    }

    fn generate_attack_phases(&self, actor: &ThreatActor, target: &TargetProfile) -> Vec<AttackPhase> {
        vec![
            AttackPhase {
                phase_number: 1,
                name: "Reconnaissance".to_string(),
                description: "Gather intelligence on target organization".to_string(),
                primary_techniques: vec!["T1589".to_string(), "T1590".to_string()],
                recommended_tools: vec!["OSINT tools".to_string(), "Shodan".to_string()],
                indicators_of_attack: vec!["Increased DNS queries".to_string(), "Port scans".to_string()],
                evasion_techniques: vec!["Distributed requests".to_string(), "Legitimate tools".to_string()],
                duration_days: 7,
            },
            AttackPhase {
                phase_number: 2,
                name: "Weaponization & Delivery".to_string(),
                description: "Create and deliver payload".to_string(),
                primary_techniques: actor.techniques.iter().take(3).cloned().collect(),
                recommended_tools: vec!["Custom payloads".to_string(), "Phishing framework".to_string()],
                indicators_of_attack: vec!["Malicious attachments".to_string(), "C2 callbacks".to_string()],
                evasion_techniques: vec!["Code obfuscation".to_string(), "Timing delays".to_string()],
                duration_days: 3,
            },
            AttackPhase {
                phase_number: 3,
                name: "Exploitation & Installation".to_string(),
                description: "Execute payload and establish persistence".to_string(),
                primary_techniques: vec!["T1087".to_string(), "T1098".to_string()],
                recommended_tools: vec!["Mimikatz".to_string(), "Persistence mechanisms".to_string()],
                indicators_of_attack: vec!["Registry modifications".to_string(), "New user accounts".to_string()],
                evasion_techniques: vec!["Living-off-the-land".to_string(), "Legitimate credentials".to_string()],
                duration_days: 2,
            },
            AttackPhase {
                phase_number: 4,
                name: "Command & Control".to_string(),
                description: "Establish command and control channel".to_string(),
                primary_techniques: vec!["T1071".to_string(), "T1008".to_string()],
                recommended_tools: vec!["C2 framework".to_string(), "Encrypted channels".to_string()],
                indicators_of_attack: vec!["Outbound C2 traffic".to_string(), "Unusual protocols".to_string()],
                evasion_techniques: vec!["Domain fronting".to_string(), "Traffic mimicry".to_string()],
                duration_days: 1,
            },
            AttackPhase {
                phase_number: 5,
                name: "Actions on Objectives".to_string(),
                description: "Achieve mission objectives".to_string(),
                primary_techniques: vec!["T1005".to_string(), "T1020".to_string()],
                recommended_tools: vec!["Data exfiltration tools".to_string(), "Lateral movement".to_string()],
                indicators_of_attack: vec!["Large data transfers".to_string(), "Privilege escalation".to_string()],
                evasion_techniques: vec!["Timing attacks".to_string(), "Data chunking".to_string()],
                duration_days: 30,
            },
        ]
    }

    fn estimate_campaign_duration(&self, _actor: &ThreatActor) -> usize {
        45
    }

    fn estimate_success_probability(&self, target: &TargetProfile, _actor: &ThreatActor) -> f64 {
        let base: f64 = 0.5;
        let adjustment: f64 = if target.security_posture == "strong" { 0.0 } else { 0.3 };
        (base + adjustment).min(0.95)
    }

    fn derive_required_capabilities(&self, actor: &ThreatActor) -> Vec<String> {
        vec![
            format!("OSINT capabilities for {} targets", actor.known_targets.first().unwrap_or(&"generic".to_string())),
            "Payload development (malware, exploits)".to_string(),
            "Social engineering skills".to_string(),
            "C2 infrastructure setup".to_string(),
            format!("Techniques: {}", actor.techniques.join(", ")),
        ]
    }

    fn recommend_infrastructure(&self, actor: &ThreatActor, target_domain: &str) -> Vec<String> {
        vec![
            format!("C2 domains masquerading as {} services", target_domain),
            "Bulletproof hosting (preferably in actor's country jurisdiction)".to_string(),
            "Compromised mail server for phishing".to_string(),
            "Proxy infrastructure for operational security".to_string(),
        ]
    }

    fn identify_social_engineering_targets(&self, _actor: &ThreatActor, target_domain: &str) -> Vec<String> {
        vec![
            format!("CEO/executives at {}", target_domain),
            format!("IT/Security team at {}", target_domain),
            format!("HR/Finance staff at {}", target_domain),
        ]
    }

    fn recommend_recon_infrastructure(&self, _actor: &ThreatActor) -> Vec<String> {
        vec![
            "Residential proxies".to_string(),
            "Distributed scanning infrastructure".to_string(),
            "Domain registration (lookalike)".to_string(),
            "Bulletproof hosting".to_string(),
        ]
    }

    fn derive_opsec_requirements(&self, _actor: &ThreatActor) -> Vec<String> {
        vec![
            "Use only approved communication channels".to_string(),
            "Avoid attribution patterns".to_string(),
            "Maintain operational security".to_string(),
            "Use exclusively infrastructure associated with actor".to_string(),
            "Avoid direct detection".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_emulation() {
        let feed = ThreatIntelligenceFeed::new();
        let emulator = ThreatEmulator::new(feed);
        let scenario = emulator.emulate_actor_campaign("APT29", "example.com");
        assert!(scenario.is_some());
    }

    #[test]
    fn test_reconnaissance_planning() {
        let feed = ThreatIntelligenceFeed::new();
        let emulator = ThreatEmulator::new(feed);
        let plan = emulator.plan_reconnaissance("APT29", "example.com");
        assert!(plan.is_some());
        let p = plan.unwrap();
        assert!(!p.passive_recon_tasks.is_empty());
    }

    #[test]
    fn test_delivery_vectors() {
        let feed = ThreatIntelligenceFeed::new();
        let emulator = ThreatEmulator::new(feed);
        let profile = TargetProfile {
            target_domain: "example.com".to_string(),
            estimated_size: "large".to_string(),
            industry: "Technology".to_string(),
            security_posture: "moderate".to_string(),
            attack_surface_score: 0.6,
            vulnerability_likelihood: 0.4,
            employee_count_estimate: 1000,
            recommended_vectors: vec![],
            likely_defenders: vec![],
        };
        let vectors = emulator.recommend_delivery_vectors("APT29", &profile);
        assert!(!vectors.is_empty());
    }

    #[test]
    fn test_target_profiling() {
        let feed = ThreatIntelligenceFeed::new();
        let emulator = ThreatEmulator::new(feed.clone());
        let actor = feed.get_actor("APT29").unwrap();
        let profile = emulator.profile_target("example.com", actor);
        assert!(!profile.target_domain.is_empty());
    }

    #[test]
    fn test_attack_phases() {
        let feed = ThreatIntelligenceFeed::new();
        let emulator = ThreatEmulator::new(feed.clone());
        let actor = feed.get_actor("APT29").unwrap();
        let target = TargetProfile {
            target_domain: "example.com".to_string(),
            estimated_size: "medium".to_string(),
            industry: "Finance".to_string(),
            security_posture: "strong".to_string(),
            attack_surface_score: 0.3,
            vulnerability_likelihood: 0.7,
            employee_count_estimate: 500,
            recommended_vectors: vec![],
            likely_defenders: vec![],
        };
        let phases = emulator.generate_attack_phases(actor, &target);
        assert_eq!(phases.len(), 5);
    }
}
