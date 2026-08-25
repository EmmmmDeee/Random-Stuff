use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignPhase {
    pub phase_number: u32,
    pub phase_name: String,
    pub duration_days: u32,
    pub primary_actor: String,
    pub techniques: Vec<String>,
    pub objectives: Vec<String>,
    pub infrastructure_required: Vec<String>,
    pub detection_risk_score: f64,
    pub evasion_tactics: Vec<String>,
    pub success_probability: f64,
    pub resource_requirements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignStrategy {
    pub campaign_id: String,
    pub campaign_name: String,
    pub target_organization: String,
    pub target_sector: String,
    pub target_region: String,
    pub total_duration_days: u32,
    pub phases: Vec<CampaignPhase>,
    pub actors_involved: Vec<String>,
    pub estimated_success_rate: f64,
    pub detection_evasion_score: f64,
    pub total_infrastructure_required: Vec<String>,
    pub critical_success_factors: Vec<String>,
    pub risk_mitigation: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyWindow {
    pub window_type: String,
    pub description: String,
    pub timing: String,
    pub operational_guidance: String,
    pub risk_level: String,
}

pub struct CampaignPlanner;

impl CampaignPlanner {
    pub fn plan_multi_actor_campaign(
        &self,
        primary_actor: &str,
        target_org: &str,
        target_sector: &str,
    ) -> Result<CampaignStrategy> {
        let campaign_id = format!(
            "CAMP-{}-20260825120000",
            primary_actor,
        );

        // Build phase structure based on target characteristics
        let phases = self.build_campaign_phases(primary_actor, target_sector);
        let actors_involved = self.identify_supporting_actors(primary_actor);
        let total_duration = phases.iter().map(|p| p.duration_days).sum();
        let success_rate = self.calculate_campaign_success_rate(&phases);
        let evasion_score = self.calculate_evasion_score(&phases);

        let mut infrastructure = Vec::new();
        for phase in &phases {
            infrastructure.extend(phase.infrastructure_required.clone());
        }
        infrastructure.sort();
        infrastructure.dedup();

        Ok(CampaignStrategy {
            campaign_id,
            campaign_name: format!("{} Campaign Against {}", primary_actor, target_org),
            target_organization: target_org.to_string(),
            target_sector: target_sector.to_string(),
            target_region: "Global".to_string(),
            total_duration_days: total_duration,
            phases,
            actors_involved,
            estimated_success_rate: success_rate,
            detection_evasion_score: evasion_score,
            total_infrastructure_required: infrastructure,
            critical_success_factors: vec![
                "Early reconnaissance accuracy".to_string(),
                "Maintaining persistence through detection cycles".to_string(),
                "Coordinating multi-actor operations".to_string(),
                "Adapting to defensive responses".to_string(),
            ],
            risk_mitigation: Self::build_risk_mitigation(),
        })
    }

    fn build_campaign_phases(&self, actor: &str, sector: &str) -> Vec<CampaignPhase> {
        match actor {
            "APT29" => self.build_apt29_phases(sector),
            "APT28" => self.build_apt28_phases(sector),
            _ => self.build_generic_phases(sector),
        }
    }

    fn build_apt29_phases(&self, _sector: &str) -> Vec<CampaignPhase> {
        vec![
            CampaignPhase {
                phase_number: 1,
                phase_name: "Extended Reconnaissance".to_string(),
                duration_days: 30,
                primary_actor: "APT29".to_string(),
                techniques: vec![
                    "T1589".to_string(),
                    "T1590".to_string(),
                    "T1598".to_string(),
                ],
                objectives: vec![
                    "Map organizational structure".to_string(),
                    "Identify key personnel".to_string(),
                    "Document security tools".to_string(),
                    "Find third-party connections".to_string(),
                ],
                infrastructure_required: vec![
                    "Passive DNS monitoring".to_string(),
                    "WHOIS queries".to_string(),
                    "Breach database access".to_string(),
                ],
                detection_risk_score: 0.1,
                evasion_tactics: vec![
                    "Distributed queries over time".to_string(),
                    "Legitimate tool usage".to_string(),
                    "Third-party infrastructure".to_string(),
                ],
                success_probability: 0.95,
                resource_requirements: vec![
                    "Analyst time: 40 hours".to_string(),
                    "OSINT tools subscription".to_string(),
                ],
            },
            CampaignPhase {
                phase_number: 2,
                phase_name: "Initial Access via Supply Chain".to_string(),
                duration_days: 21,
                primary_actor: "APT29".to_string(),
                techniques: vec![
                    "T1195.002".to_string(),
                    "T1195.003".to_string(),
                    "T1566.002".to_string(),
                ],
                objectives: vec![
                    "Compromise third-party software".to_string(),
                    "Distribute trojanized update".to_string(),
                    "Establish initial foothold".to_string(),
                ],
                infrastructure_required: vec![
                    "Compromised software vendor account".to_string(),
                    "Code signing certificate (stolen/forged)".to_string(),
                    "Delivery infrastructure".to_string(),
                ],
                detection_risk_score: 0.25,
                evasion_tactics: vec![
                    "Legitimate vendor compromise".to_string(),
                    "Code obfuscation".to_string(),
                    "Signed executables".to_string(),
                    "Timing to match legitimate updates".to_string(),
                ],
                success_probability: 0.72,
                resource_requirements: vec![
                    "Access to vendor infrastructure".to_string(),
                    "Malware development".to_string(),
                    "Code signing capability".to_string(),
                ],
            },
            CampaignPhase {
                phase_number: 3,
                phase_name: "Persistence and Lateral Movement".to_string(),
                duration_days: 14,
                primary_actor: "APT29".to_string(),
                techniques: vec![
                    "T1098.001".to_string(),
                    "T1087".to_string(),
                    "T1570".to_string(),
                ],
                objectives: vec![
                    "Establish persistent backdoor".to_string(),
                    "Enumerate domain users".to_string(),
                    "Identify admin accounts".to_string(),
                    "Move to high-value systems".to_string(),
                ],
                infrastructure_required: vec![
                    "C2 infrastructure (HTTPS)".to_string(),
                    "Legitimate cloud services (O365, AWS)".to_string(),
                    "Proxy chains".to_string(),
                ],
                detection_risk_score: 0.35,
                evasion_tactics: vec![
                    "Living-off-the-land binaries".to_string(),
                    "Legitimate administrative tools".to_string(),
                    "Encrypted communications".to_string(),
                    "Timing attacks during business hours".to_string(),
                ],
                success_probability: 0.68,
                resource_requirements: vec![
                    "Malware development (beacons)".to_string(),
                    "C2 server management".to_string(),
                ],
            },
            CampaignPhase {
                phase_number: 4,
                phase_name: "Objective Achievement".to_string(),
                duration_days: 60,
                primary_actor: "APT29".to_string(),
                techniques: vec![
                    "T1005".to_string(),
                    "T1020".to_string(),
                    "T1041".to_string(),
                ],
                objectives: vec![
                    "Access sensitive data stores".to_string(),
                    "Exfiltrate target information".to_string(),
                    "Maintain access for future operations".to_string(),
                ],
                infrastructure_required: vec![
                    "Data staging servers".to_string(),
                    "Exfiltration infrastructure".to_string(),
                    "Long-term C2 servers".to_string(),
                ],
                detection_risk_score: 0.45,
                evasion_tactics: vec![
                    "Data chunking".to_string(),
                    "Scheduled transfers".to_string(),
                    "Steganography for sensitive data".to_string(),
                    "Encryption of all traffic".to_string(),
                ],
                success_probability: 0.85,
                resource_requirements: vec![
                    "Data exfiltration tools".to_string(),
                    "Long-term infrastructure".to_string(),
                ],
            },
        ]
    }

    fn build_apt28_phases(&self, _sector: &str) -> Vec<CampaignPhase> {
        vec![
            CampaignPhase {
                phase_number: 1,
                phase_name: "Intelligence Gathering".to_string(),
                duration_days: 14,
                primary_actor: "APT28".to_string(),
                techniques: vec![
                    "T1589".to_string(),
                    "T1591".to_string(),
                    "T1598.003".to_string(),
                ],
                objectives: vec![
                    "Identify high-value targets".to_string(),
                    "Build targeting lists".to_string(),
                    "Analyze email patterns".to_string(),
                ],
                infrastructure_required: vec![
                    "Credential database access".to_string(),
                    "Email enumeration tools".to_string(),
                ],
                detection_risk_score: 0.05,
                evasion_tactics: vec![
                    "Passive enumeration".to_string(),
                    "Third-party tool usage".to_string(),
                ],
                success_probability: 0.92,
                resource_requirements: vec![
                    "OSINT analysts".to_string(),
                    "Targeting infrastructure".to_string(),
                ],
            },
            CampaignPhase {
                phase_number: 2,
                phase_name: "Credential Harvesting".to_string(),
                duration_days: 21,
                primary_actor: "APT28".to_string(),
                techniques: vec![
                    "T1598.003".to_string(),
                    "T1566.002".to_string(),
                    "T1192".to_string(),
                ],
                objectives: vec![
                    "Send spear phishing emails".to_string(),
                    "Harvest valid credentials".to_string(),
                    "Setup fake credential pages".to_string(),
                ],
                infrastructure_required: vec![
                    "Lookalike domains".to_string(),
                    "Phishing infrastructure".to_string(),
                    "Credential harvesting pages".to_string(),
                ],
                detection_risk_score: 0.4,
                evasion_tactics: vec![
                    "Typosquatting domains".to_string(),
                    "Timing to evade detection".to_string(),
                    "Custom phishing templates".to_string(),
                ],
                success_probability: 0.65,
                resource_requirements: vec![
                    "Domain registration".to_string(),
                    "Phishing site development".to_string(),
                ],
            },
        ]
    }

    fn build_generic_phases(&self, _sector: &str) -> Vec<CampaignPhase> {
        vec![CampaignPhase {
            phase_number: 1,
            phase_name: "Initial Access".to_string(),
            duration_days: 30,
            primary_actor: "Unknown".to_string(),
            techniques: vec!["T1566.002".to_string(), "T1195".to_string()],
            objectives: vec!["Establish initial access".to_string()],
            infrastructure_required: vec!["Phishing infrastructure".to_string()],
            detection_risk_score: 0.3,
            evasion_tactics: vec!["Standard evasion".to_string()],
            success_probability: 0.7,
            resource_requirements: vec!["Standard tools".to_string()],
        }]
    }

    fn identify_supporting_actors(&self, primary: &str) -> Vec<String> {
        match primary {
            "APT29" => vec![
                primary.to_string(),
                "Affiliated groups".to_string(),
            ],
            "APT28" => vec![
                primary.to_string(),
                "Affiliated groups".to_string(),
            ],
            _ => vec![primary.to_string()],
        }
    }

    fn calculate_campaign_success_rate(&self, phases: &[CampaignPhase]) -> f64 {
        if phases.is_empty() {
            return 0.0;
        }
        let sum: f64 = phases.iter().map(|p| p.success_probability).sum();
        (sum / phases.len() as f64) * 0.9 // Slight degradation for multi-phase
    }

    fn calculate_evasion_score(&self, phases: &[CampaignPhase]) -> f64 {
        if phases.is_empty() {
            return 0.0;
        }
        let sum: f64 = phases
            .iter()
            .map(|p| 1.0 - p.detection_risk_score)
            .sum();
        sum / phases.len() as f64
    }

    fn build_risk_mitigation() -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert(
            "Detection during recon".to_string(),
            "Use distributed, long-term reconnaissance".to_string(),
        );
        map.insert(
            "Initial access failure".to_string(),
            "Prepare alternative attack vectors".to_string(),
        );
        map.insert(
            "Lateral movement blocked".to_string(),
            "Pre-position multiple footholds".to_string(),
        );
        map.insert(
            "IR team activated".to_string(),
            "Blend activity with legitimate traffic".to_string(),
        );
        map
    }

    pub fn identify_optimal_timing(&self) -> Result<Vec<AnomalyWindow>> {
        Ok(vec![
            AnomalyWindow {
                window_type: "Business Hours".to_string(),
                description: "Activity blends with legitimate business operations".to_string(),
                timing: "08:00-18:00 local time".to_string(),
                operational_guidance: "Leverage normal admin activity patterns".to_string(),
                risk_level: "Low".to_string(),
            },
            AnomalyWindow {
                window_type: "End of Month/Quarter".to_string(),
                description: "Financial system activity increases, hiding reconnaissance".to_string(),
                timing: "Last week of month/quarter".to_string(),
                operational_guidance: "Escalate access requests during legitimate cycle".to_string(),
                risk_level: "Low-Medium".to_string(),
            },
            AnomalyWindow {
                window_type: "Maintenance Windows".to_string(),
                description: "System changes blend with legitimate maintenance".to_string(),
                timing: "Post-patch Tuesday activity windows".to_string(),
                operational_guidance: "Exploit legitimate change windows".to_string(),
                risk_level: "Medium".to_string(),
            },
            AnomalyWindow {
                window_type: "Holiday Periods".to_string(),
                description: "Reduced security monitoring".to_string(),
                timing: "Weekends, nights, holidays".to_string(),
                operational_guidance: "Execute high-risk activities during low-detection periods".to_string(),
                risk_level: "High-Reward".to_string(),
            },
        ])
    }

    pub fn estimate_detection_timeline(&self, campaign: &CampaignStrategy) -> Result<String> {
        let mut output = String::new();
        output.push_str("=== Detection Timeline Estimates ===\n\n");

        let detection_probability = 1.0 - campaign.detection_evasion_score;
        let first_detection_days = (30.0 * detection_probability).max(5.0);

        output.push_str(&format!(
            "Estimated days until first detection: {:.0}\n",
            first_detection_days
        ));
        output.push_str(&format!(
            "Days until full campaign discovery: {:.0}\n",
            first_detection_days * 2.5
        ));
        output.push_str(&format!(
            "Overall evasion success rate: {:.0}%\n\n",
            campaign.detection_evasion_score * 100.0
        ));

        output.push_str("Detection Avoidance Recommendations:\n");
        output.push_str(&format!(
            "- Rotate infrastructure every {} days\n",
            (7.0 * detection_probability) as u32
        ));
        output.push_str(&format!(
            "- Vary timing patterns every {} days\n",
            (5.0 * detection_probability) as u32
        ));
        output.push_str(&format!(
            "- Change TTPs every {} days\n",
            (10.0 * detection_probability) as u32
        ));
        output.push_str("- Monitor security vendor capabilities\n");

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_actor_campaign_planning() {
        let planner = CampaignPlanner;
        let result = planner.plan_multi_actor_campaign("APT29", "Target Corp", "Government");
        assert!(result.is_ok());
        let campaign = result.unwrap();
        assert_eq!(campaign.actors_involved.len(), 2);
        assert!(campaign.total_duration_days > 0);
        assert!(campaign.phases.len() > 0);
    }

    #[test]
    fn test_apt29_campaign_phases() {
        let planner = CampaignPlanner;
        let phases = planner.build_apt29_phases("Government");
        assert_eq!(phases.len(), 4);
        assert_eq!(phases[0].phase_number, 1);
    }

    #[test]
    fn test_optimal_timing_windows() {
        let planner = CampaignPlanner;
        let windows = planner.identify_optimal_timing();
        assert!(windows.is_ok());
        assert!(windows.unwrap().len() > 0);
    }

    #[test]
    fn test_detection_timeline_estimation() {
        let planner = CampaignPlanner;
        let campaign = planner.plan_multi_actor_campaign("APT28", "Target", "Finance").unwrap();
        let timeline = planner.estimate_detection_timeline(&campaign);
        assert!(timeline.is_ok());
        let output = timeline.unwrap();
        assert!(output.contains("Detection Timeline"));
    }

    #[test]
    fn test_success_rate_calculation() {
        let planner = CampaignPlanner;
        let campaign = planner.plan_multi_actor_campaign("APT29", "Target", "Technology").unwrap();
        assert!(campaign.estimated_success_rate > 0.0 && campaign.estimated_success_rate <= 1.0);
    }
}
