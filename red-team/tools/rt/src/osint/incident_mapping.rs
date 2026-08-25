use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioIncident {
    pub scenario_id: String,
    pub scenario_name: String,
    pub actor_id: String,
    pub actor_name: String,
    pub attack_confidence: f64,
    pub mapped_techniques: Vec<String>,
    pub execution_phase: String,
    pub infrastructure_indicators: Vec<String>,
    pub success_historical_rate: f64,
    pub detection_difficulty: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentChain {
    pub incident_id: String,
    pub actor_id: String,
    pub scenario_sequence: Vec<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub target_sector: String,
    pub total_targets: usize,
    pub attack_phases: Vec<(String, Vec<String>)>, // (phase, techniques)
    pub infrastructure_required: Vec<String>,
    pub evasion_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorScenarioMapping {
    pub actor_id: String,
    pub known_scenarios: Vec<ScenarioIncident>,
    pub preferred_techniques: Vec<String>,
    pub target_sectors: Vec<String>,
    pub infrastructure_patterns: HashMap<String, Vec<String>>,
    pub success_rate_average: f64,
    pub detection_evasion_score: f64,
}

pub struct IncidentMapper {
    actor_scenarios: HashMap<String, ActorScenarioMapping>,
}

impl IncidentMapper {
    pub fn new() -> Self {
        IncidentMapper {
            actor_scenarios: Self::build_mappings(),
        }
    }

    fn build_mappings() -> HashMap<String, ActorScenarioMapping> {
        let mut mappings = HashMap::new();

        // APT29 mappings
        mappings.insert(
            "APT29".to_string(),
            ActorScenarioMapping {
                actor_id: "APT29".to_string(),
                known_scenarios: vec![
                    ScenarioIncident {
                        scenario_id: "APT-029-001".to_string(),
                        scenario_name: "Cozy Bear Credential Theft Campaign".to_string(),
                        actor_id: "APT29".to_string(),
                        actor_name: "APT29 / Cozy Bear".to_string(),
                        attack_confidence: 0.95,
                        mapped_techniques: vec![
                            "T1589".to_string(),
                            "T1598.003".to_string(),
                            "T1566.002".to_string(),
                        ],
                        execution_phase: "Initial Access & Persistence".to_string(),
                        infrastructure_indicators: vec![
                            "Legitimate infrastructure hijacking".to_string(),
                            "Spear phishing email".to_string(),
                            "Office macro exploit".to_string(),
                        ],
                        success_historical_rate: 0.85,
                        detection_difficulty: "High".to_string(),
                    },
                    ScenarioIncident {
                        scenario_id: "APT-029-002".to_string(),
                        scenario_name: "SolarWinds Supply Chain Attack".to_string(),
                        actor_id: "APT29".to_string(),
                        actor_name: "APT29 / Cozy Bear".to_string(),
                        attack_confidence: 0.98,
                        mapped_techniques: vec![
                            "T1195.002".to_string(),
                            "T1195.003".to_string(),
                            "T1090".to_string(),
                        ],
                        execution_phase: "Supply Chain Compromise".to_string(),
                        infrastructure_indicators: vec![
                            "Compromised package repository".to_string(),
                            "Malicious update delivery".to_string(),
                            "Legitimate vendor infrastructure".to_string(),
                        ],
                        success_historical_rate: 0.92,
                        detection_difficulty: "Very High".to_string(),
                    },
                ],
                preferred_techniques: vec![
                    "T1566.002".to_string(),
                    "T1598".to_string(),
                    "T1589".to_string(),
                    "T1195".to_string(),
                    "T1199".to_string(),
                ],
                target_sectors: vec![
                    "Government".to_string(),
                    "Technology".to_string(),
                    "Utilities".to_string(),
                    "Defense Contractors".to_string(),
                ],
                infrastructure_patterns: {
                    let mut map = HashMap::new();
                    map.insert(
                        "C2".to_string(),
                        vec![
                            "SVR-hosted VPS".to_string(),
                            "Compromised infrastructure".to_string(),
                            "HTTPS on standard ports".to_string(),
                        ],
                    );
                    map.insert(
                        "Phishing".to_string(),
                        vec![
                            "Legitimate domain spoofing".to_string(),
                            "Email server compromise".to_string(),
                            "Office 365 federation abuse".to_string(),
                        ],
                    );
                    map
                },
                success_rate_average: 0.88,
                detection_evasion_score: 0.92,
            },
        );

        // APT28 mappings
        mappings.insert(
            "APT28".to_string(),
            ActorScenarioMapping {
                actor_id: "APT28".to_string(),
                known_scenarios: vec![
                    ScenarioIncident {
                        scenario_id: "APT-028-001".to_string(),
                        scenario_name: "Fancy Bear Credential Harvesting".to_string(),
                        actor_id: "APT28".to_string(),
                        actor_name: "APT28 / Fancy Bear".to_string(),
                        attack_confidence: 0.93,
                        mapped_techniques: vec![
                            "T1598.003".to_string(),
                            "T1589".to_string(),
                            "T1591".to_string(),
                        ],
                        execution_phase: "Reconnaissance & Social Engineering".to_string(),
                        infrastructure_indicators: vec![
                            "Lookalike phishing domains".to_string(),
                            "Gmail account takeovers".to_string(),
                            "Watering hole attacks".to_string(),
                        ],
                        success_historical_rate: 0.78,
                        detection_difficulty: "Medium".to_string(),
                    },
                ],
                preferred_techniques: vec![
                    "T1598.003".to_string(),
                    "T1583".to_string(),
                    "T1589".to_string(),
                    "T1566".to_string(),
                ],
                target_sectors: vec![
                    "Government".to_string(),
                    "Military".to_string(),
                    "Political Organizations".to_string(),
                ],
                infrastructure_patterns: {
                    let mut map = HashMap::new();
                    map.insert(
                        "Phishing".to_string(),
                        vec![
                            "Lookalike domains".to_string(),
                            "Typosquatting".to_string(),
                            "Homograph domains".to_string(),
                        ],
                    );
                    map
                },
                success_rate_average: 0.81,
                detection_evasion_score: 0.75,
            },
        );

        mappings
    }

    pub fn map_scenarios_to_actor(&self, actor_id: &str) -> Result<String, String> {
        if let Some(mapping) = self.actor_scenarios.get(actor_id) {
            let mut output = String::new();
            output.push_str(&format!("=== Scenario-to-Incident Mapping ===\n\n"));
            output.push_str(&format!("Actor: {} ({})\n", mapping.actor_id, mapping.actor_id));
            output.push_str(&format!(
                "Average Success Rate: {:.1}%\n",
                mapping.success_rate_average * 100.0
            ));
            output.push_str(&format!(
                "Evasion Capability Score: {:.1}%\n\n",
                mapping.detection_evasion_score * 100.0
            ));

            output.push_str("Known Attack Scenarios:\n");
            for (idx, scenario) in mapping.known_scenarios.iter().enumerate() {
                output.push_str(&format!("\n{}. {} (ID: {})\n", idx + 1, scenario.scenario_name, scenario.scenario_id));
                output.push_str(&format!(
                    "   Confidence: {:.0}% | Success Rate: {:.0}%\n",
                    scenario.attack_confidence * 100.0,
                    scenario.success_historical_rate * 100.0
                ));
                output.push_str(&format!("   Phase: {}\n", scenario.execution_phase));
                output.push_str("   Mapped Techniques:\n");
                for tech in &scenario.mapped_techniques {
                    output.push_str(&format!("     • {}\n", tech));
                }
                output.push_str("   Infrastructure Indicators:\n");
                for indicator in &scenario.infrastructure_indicators {
                    output.push_str(&format!("     • {}\n", indicator));
                }
            }

            output.push_str("\nTarget Sectors:\n");
            for sector in &mapping.target_sectors {
                output.push_str(&format!("  • {}\n", sector));
            }

            output.push_str("\nPreferred Techniques:\n");
            for tech in &mapping.preferred_techniques {
                output.push_str(&format!("  • {}\n", tech));
            }

            Ok(output)
        } else {
            Err(format!("No incident mappings found for actor: {}", actor_id))
        }
    }

    pub fn build_attack_chain(&self, actor_id: &str, target_sector: &str) -> Result<String, String> {
        if let Some(mapping) = self.actor_scenarios.get(actor_id) {
            let filtered_scenarios: Vec<_> = mapping
                .known_scenarios
                .iter()
                .filter(|s| s.attack_confidence > 0.7)
                .collect();

            if filtered_scenarios.is_empty() {
                return Err(format!(
                    "No high-confidence scenarios found for {} targeting {}",
                    actor_id, target_sector
                ));
            }

            let mut output = String::new();
            output.push_str(&format!("=== Attack Chain Analysis ===\n\n"));
            output.push_str(&format!("Actor: {}\n", actor_id));
            output.push_str(&format!("Target Sector: {}\n\n", target_sector));

            output.push_str("Probable Attack Sequence:\n");
            for (idx, scenario) in filtered_scenarios.iter().enumerate() {
                output.push_str(&format!(
                    "{}. {} (Confidence: {:.0}%)\n",
                    idx + 1,
                    scenario.scenario_name,
                    scenario.attack_confidence * 100.0
                ));
                output.push_str(&format!("   Techniques: {}\n", scenario.mapped_techniques.join(", ")));
                output.push_str("   Required Infrastructure:\n");
                for indicator in &scenario.infrastructure_indicators {
                    output.push_str(&format!("     • {}\n", indicator));
                }
            }

            output.push_str("\nOverall Attack Chain Characteristics:\n");
            output.push_str(&format!("  • Attack Complexity: High\n"));
            output.push_str(&format!(
                "  • Average Success Rate: {:.0}%\n",
                mapping.success_rate_average * 100.0
            ));
            output.push_str(&format!(
                "  • Detection Difficulty: {}+\n",
                if mapping.detection_evasion_score > 0.85 {
                    "Very High"
                } else {
                    "High"
                }
            ));

            Ok(output)
        } else {
            Err(format!("Actor not found: {}", actor_id))
        }
    }

    pub fn analyze_technique_usage(&self, actor_id: &str) -> Result<String, String> {
        if let Some(mapping) = self.actor_scenarios.get(actor_id) {
            let mut technique_map: HashMap<String, usize> = HashMap::new();

            for scenario in &mapping.known_scenarios {
                for technique in &scenario.mapped_techniques {
                    *technique_map.entry(technique.clone()).or_insert(0) += 1;
                }
            }

            let mut output = String::new();
            output.push_str(&format!("=== Technique Usage Analysis ===\n\n"));
            output.push_str(&format!("Actor: {}\n\n", actor_id));

            output.push_str("Technique Prevalence (across known scenarios):\n");
            let mut sorted: Vec<_> = technique_map.into_iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(&a.1));

            for (technique, count) in sorted {
                let percentage = (count as f64 / mapping.known_scenarios.len() as f64) * 100.0;
                output.push_str(&format!("  {} - {:.0}% (used in {} scenarios)\n", technique, percentage, count));
            }

            Ok(output)
        } else {
            Err(format!("Actor not found: {}", actor_id))
        }
    }

    pub fn get_infrastructure_patterns(&self, actor_id: &str) -> Result<String, String> {
        if let Some(mapping) = self.actor_scenarios.get(actor_id) {
            let mut output = String::new();
            output.push_str(&format!("=== Infrastructure Patterns ===\n\n"));
            output.push_str(&format!("Actor: {}\n\n", actor_id));

            for (pattern_type, patterns) in &mapping.infrastructure_patterns {
                output.push_str(&format!("{}:\n", pattern_type));
                for pattern in patterns {
                    output.push_str(&format!("  • {}\n", pattern));
                }
                output.push_str("\n");
            }

            Ok(output)
        } else {
            Err(format!("Actor not found: {}", actor_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scenario_mapping_creation() {
        let mapper = IncidentMapper::new();
        assert!(!mapper.actor_scenarios.is_empty());
    }

    #[test]
    fn test_map_scenarios_to_actor() {
        let mapper = IncidentMapper::new();
        let result = mapper.map_scenarios_to_actor("APT29");
        assert!(result.is_ok());
        assert!(result.unwrap().contains("APT29"));
    }

    #[test]
    fn test_build_attack_chain() {
        let mapper = IncidentMapper::new();
        let result = mapper.build_attack_chain("APT28", "Government");
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Attack Chain"));
    }

    #[test]
    fn test_analyze_technique_usage() {
        let mapper = IncidentMapper::new();
        let result = mapper.analyze_technique_usage("APT29");
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Technique Usage"));
    }

    #[test]
    fn test_infrastructure_patterns() {
        let mapper = IncidentMapper::new();
        let result = mapper.get_infrastructure_patterns("APT29");
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Infrastructure"));
    }
}
