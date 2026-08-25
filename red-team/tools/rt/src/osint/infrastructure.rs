use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Framework {
    pub name: String,
    pub description: String,
    pub command_protocol: String,
    pub stealth_capability: String,
    pub evasion_score: f64,
    pub operational_difficulty: String,
    pub persistence_options: Vec<String>,
    pub supported_payloads: Vec<String>,
    pub known_detections: Vec<String>,
    pub operator_skill_required: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VPSProvider {
    pub provider_name: String,
    pub geographic_locations: Vec<String>,
    pub ip_reputation: String,
    pub ddos_protection: bool,
    pub detection_risk: f64,
    pub cost_per_month: f64,
    pub payment_methods: Vec<String>,
    pub abuse_reporting_lag: String,
    pub law_enforcement_cooperation: String,
    pub provider_evasion_techniques: Vec<String>,
    pub previous_breach_history: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainStrategy {
    pub domain_name: String,
    pub registrar: String,
    pub whois_privacy: bool,
    pub privacy_provider: Option<String>,
    pub dns_provider: String,
    pub dns_records: Vec<String>,
    pub reputation_risk: f64,
    pub ssl_certificate_method: String,
    pub certificate_provider: String,
    pub domain_age_requirement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureDeployment {
    pub deployment_id: String,
    pub c2_framework: C2Framework,
    pub primary_vps: VPSProvider,
    pub backup_vps: Option<VPSProvider>,
    pub domain_strategy: DomainStrategy,
    pub redirector_count: usize,
    pub proxy_chain_depth: usize,
    pub dns_setup: Vec<String>,
    pub operational_cost_estimate: f64,
    pub detection_probability: f64,
    pub mean_time_to_detection: String,
    pub failover_procedures: Vec<String>,
    pub recovery_options: Vec<String>,
}

pub struct InfrastructureDeployer;

impl InfrastructureDeployer {
    pub fn recommend_c2_framework(&self, operation_type: &str) -> Result<Vec<C2Framework>> {
        let frameworks = vec![
            C2Framework {
                name: "Cobalt Strike".to_string(),
                description: "Commercial C2 platform with extensive obfuscation".to_string(),
                command_protocol: "HTTP/HTTPS + DNS + SMB".to_string(),
                stealth_capability: "Very High - Beacon obfuscation, HTTPS proxying".to_string(),
                evasion_score: 0.88,
                operational_difficulty: "Medium - Extensive features, complex tuning".to_string(),
                persistence_options: vec![
                    "Registry run keys".to_string(),
                    "Scheduled tasks".to_string(),
                    "WMI event subscriptions".to_string(),
                    "Services".to_string(),
                    "Startup folders".to_string(),
                ],
                supported_payloads: vec![
                    "Windows shellcode".to_string(),
                    "DLL injection".to_string(),
                    "Process hollowing".to_string(),
                    "Reflective DLL injection".to_string(),
                ],
                known_detections: vec![
                    "Beacon.exe pattern matching".to_string(),
                    "Beacon traffic signatures".to_string(),
                    "Malleable C2 profile defaults".to_string(),
                ],
                operator_skill_required: "Advanced - Custom C2 profiles, process injection".to_string(),
            },
            C2Framework {
                name: "Sliver".to_string(),
                description: "Open-source C2 inspired by Sliver's stealth design".to_string(),
                command_protocol: "gRPC + HTTP/HTTPS".to_string(),
                stealth_capability: "High - gRPC encrypted communication".to_string(),
                evasion_score: 0.82,
                operational_difficulty: "Medium - Simpler than Cobalt Strike".to_string(),
                persistence_options: vec![
                    "Registry modification".to_string(),
                    "Startup shortcuts".to_string(),
                    "Scheduled tasks".to_string(),
                ],
                supported_payloads: vec![
                    "Native Windows shellcode".to_string(),
                    "DLL loading".to_string(),
                    "Process injection".to_string(),
                ],
                known_detections: vec![
                    "gRPC pattern detection".to_string(),
                    "Process memory signatures".to_string(),
                ],
                operator_skill_required: "Intermediate - Configuration and payload generation".to_string(),
            },
            C2Framework {
                name: "Empire".to_string(),
                description: "PowerShell-based C2 framework for Windows environments".to_string(),
                command_protocol: "HTTP/HTTPS + DNS".to_string(),
                stealth_capability: "Medium - PowerShell-based, requires AMSI bypass".to_string(),
                evasion_score: 0.65,
                operational_difficulty: "Low - Script-based, easier for operators".to_string(),
                persistence_options: vec![
                    "PowerShell profiles".to_string(),
                    "WMI event subscriptions".to_string(),
                    "Scheduled tasks".to_string(),
                    "Registry run keys".to_string(),
                ],
                supported_payloads: vec![
                    "PowerShell agents".to_string(),
                    "Obfuscated scripts".to_string(),
                    "Staged payloads".to_string(),
                ],
                known_detections: vec![
                    "PowerShell command line logging".to_string(),
                    "Script block logging".to_string(),
                    "AMSI detection".to_string(),
                ],
                operator_skill_required: "Intermediate - PowerShell knowledge".to_string(),
            },
            C2Framework {
                name: "Metasploit".to_string(),
                description: "Open-source penetration testing framework with C2 capabilities".to_string(),
                command_protocol: "HTTP/HTTPS + DNS + raw TCP".to_string(),
                stealth_capability: "Low - Default signatures widely detected".to_string(),
                evasion_score: 0.42,
                operational_difficulty: "Low - Many defaults, detection-prone".to_string(),
                persistence_options: vec![
                    "Multiple persistence modules".to_string(),
                    "Registry modification".to_string(),
                    "Service installation".to_string(),
                ],
                supported_payloads: vec![
                    "Meterpreter".to_string(),
                    "Reverse shells".to_string(),
                    "Custom shellcode".to_string(),
                ],
                known_detections: vec![
                    "Meterpreter signature".to_string(),
                    "Metasploit user-agent strings".to_string(),
                    "Reverse shell patterns".to_string(),
                ],
                operator_skill_required: "Beginner to Intermediate - Wide documentation".to_string(),
            },
        ];

        let filtered: Vec<C2Framework> = match operation_type {
            "stealth" => frameworks
                .into_iter()
                .filter(|f| f.evasion_score > 0.75)
                .collect(),
            "fast" => frameworks
                .into_iter()
                .filter(|f| f.operational_difficulty != "Advanced - Custom C2 profiles, process injection")
                .collect(),
            "advanced" => frameworks,
            _ => frameworks,
        };

        Ok(filtered)
    }

    pub fn recommend_vps_provider(&self, region: &str, risk_tolerance: &str) -> Result<Vec<VPSProvider>> {
        let providers = vec![
            VPSProvider {
                provider_name: "Digital Ocean".to_string(),
                geographic_locations: vec![
                    "US".to_string(),
                    "UK".to_string(),
                    "Germany".to_string(),
                    "Singapore".to_string(),
                ],
                ip_reputation: "Medium - Some datacenter IPs detected in threat lists".to_string(),
                ddos_protection: true,
                detection_risk: 0.65,
                cost_per_month: 5.0,
                payment_methods: vec!["Credit Card".to_string(), "PayPal".to_string()],
                abuse_reporting_lag: "4-6 hours (responsive to reports)".to_string(),
                law_enforcement_cooperation: "High - US-based, quick compliance".to_string(),
                provider_evasion_techniques: vec![
                    "Use older datacenter IP blocks (less monitored)".to_string(),
                    "Rotate IPs frequently".to_string(),
                    "Use load balancer for traffic distribution".to_string(),
                ],
                previous_breach_history: vec!["2019: SSH key exposure (limited)".to_string()],
            },
            VPSProvider {
                provider_name: "Vultr".to_string(),
                geographic_locations: vec![
                    "US".to_string(),
                    "Netherlands".to_string(),
                    "Japan".to_string(),
                    "Australia".to_string(),
                ],
                ip_reputation: "Low - Less common in threat intelligence feeds".to_string(),
                ddos_protection: true,
                detection_risk: 0.48,
                cost_per_month: 6.0,
                payment_methods: vec!["Credit Card".to_string(), "Bitcoin".to_string()],
                abuse_reporting_lag: "2-3 hours (very responsive)".to_string(),
                law_enforcement_cooperation: "Medium-High - US-based".to_string(),
                provider_evasion_techniques: vec![
                    "Use Netherlands or Japan nodes (less common for C2)".to_string(),
                    "Implement traffic rate limiting".to_string(),
                    "Use multiple small instances vs single large".to_string(),
                ],
                previous_breach_history: vec!["No major breaches reported".to_string()],
            },
            VPSProvider {
                provider_name: "OVH".to_string(),
                geographic_locations: vec![
                    "France".to_string(),
                    "Canada".to_string(),
                    "Singapore".to_string(),
                    "Poland".to_string(),
                ],
                ip_reputation: "Low - Less monitoring from US-centric vendors".to_string(),
                ddos_protection: true,
                detection_risk: 0.42,
                cost_per_month: 4.0,
                payment_methods: vec!["Credit Card".to_string(), "Cryptocurrency".to_string()],
                abuse_reporting_lag: "12-24 hours (slower response)".to_string(),
                law_enforcement_cooperation: "Medium - EU-based, GDPR considerations".to_string(),
                provider_evasion_techniques: vec![
                    "Use France or Poland nodes".to_string(),
                    "GDPR-based privacy claims".to_string(),
                    "European customers may face less monitoring".to_string(),
                ],
                previous_breach_history: vec!["2013: Customer data exposure (resolved)".to_string()],
            },
            VPSProvider {
                provider_name: "AWS EC2".to_string(),
                geographic_locations: vec![
                    "Global (25+ regions)".to_string(),
                    "US".to_string(),
                    "EU".to_string(),
                    "Asia-Pacific".to_string(),
                ],
                ip_reputation: "High-Varied - AWS IPs heavily monitored, but massive scale".to_string(),
                ddos_protection: true,
                detection_risk: 0.72,
                cost_per_month: 10.0,
                payment_methods: vec!["Credit Card".to_string(), "Bank Account".to_string()],
                abuse_reporting_lag: "1-2 hours (extremely responsive)".to_string(),
                law_enforcement_cooperation: "Very High - Rapid compliance with US warrants".to_string(),
                provider_evasion_techniques: vec![
                    "Use dormant AWS IPs (non-standard ports)".to_string(),
                    "Use CloudFront distribution for traffic masking".to_string(),
                    "Implement within security groups for traffic filtering".to_string(),
                ],
                previous_breach_history: vec![
                    "2019: Elasticsearch exposure (customer misconfiguration)".to_string(),
                ],
            },
        ];

        let filtered: Vec<VPSProvider> = match risk_tolerance {
            "low" => providers
                .into_iter()
                .filter(|p| p.detection_risk < 0.5)
                .collect(),
            "medium" => providers
                .into_iter()
                .filter(|p| p.detection_risk < 0.65)
                .collect(),
            "high" => providers,
            _ => providers,
        };

        Ok(filtered)
    }

    pub fn plan_domain_strategy(&self, strategy_type: &str) -> Result<DomainStrategy> {
        match strategy_type {
            "legitimate_looking" => Ok(DomainStrategy {
                domain_name: "Example domain similar to target organization".to_string(),
                registrar: "Namecheap or GoDaddy (legitimate, bulk registrations common)".to_string(),
                whois_privacy: true,
                privacy_provider: Some("Domain.com Privacy Services".to_string()),
                dns_provider: "CloudFlare (free DNS, abuse-resistant)".to_string(),
                dns_records: vec![
                    "A record pointing to redirector".to_string(),
                    "MX records for mail spoofing".to_string(),
                    "TXT records for phishing credibility".to_string(),
                    "CNAME for CDN masking".to_string(),
                ],
                reputation_risk: 0.35,
                ssl_certificate_method: "Let's Encrypt (free, automated)".to_string(),
                certificate_provider: "Let's Encrypt via ACME".to_string(),
                domain_age_requirement: "Ideally 3-6 months old for credibility".to_string(),
            }),
            "disposable" => Ok(DomainStrategy {
                domain_name: "Random domain registered for short-term use".to_string(),
                registrar: "Cheap registrar (1&1, Bluehost for bulk purchases)".to_string(),
                whois_privacy: true,
                privacy_provider: Some("Basic privacy service".to_string()),
                dns_provider: "AWS Route53 or Azure DNS".to_string(),
                dns_records: vec![
                    "Minimal DNS records".to_string(),
                    "Direct A record to C2".to_string(),
                    "Fast TTL for quick pivots".to_string(),
                ],
                reputation_risk: 0.65,
                ssl_certificate_method: "Self-signed or free Let's Encrypt".to_string(),
                certificate_provider: "Self-hosted or Let's Encrypt".to_string(),
                domain_age_requirement: "None - disposable by design".to_string(),
            }),
            "compromised_registrar" => Ok(DomainStrategy {
                domain_name: "Use compromised registrar account for domain hijacking".to_string(),
                registrar: "Compromised high-value registrar account".to_string(),
                whois_privacy: true,
                privacy_provider: Some("Use registrar's privacy if available".to_string()),
                dns_provider: "Registrar's DNS (minimal changes)".to_string(),
                dns_records: vec![
                    "Modify existing legitimate records".to_string(),
                    "Redirect to attacker infrastructure".to_string(),
                    "Maintain some legitimate traffic".to_string(),
                ],
                reputation_risk: 0.25,
                ssl_certificate_method: "Use existing SSL cert or issue from Let's Encrypt".to_string(),
                certificate_provider: "Registrar or Let's Encrypt".to_string(),
                domain_age_requirement: "Existing domain (no age suspicion)".to_string(),
            }),
            _ => Ok(DomainStrategy {
                domain_name: "Generic domain".to_string(),
                registrar: "Generic registrar".to_string(),
                whois_privacy: true,
                privacy_provider: None,
                dns_provider: "Generic DNS provider".to_string(),
                dns_records: vec!["A record".to_string()],
                reputation_risk: 0.50,
                ssl_certificate_method: "Let's Encrypt".to_string(),
                certificate_provider: "Let's Encrypt".to_string(),
                domain_age_requirement: "Variable".to_string(),
            }),
        }
    }

    pub fn plan_infrastructure_deployment(&self, operation_type: &str) -> Result<InfrastructureDeployment> {
        let c2_options = self.recommend_c2_framework("stealth")?;
        let c2 = c2_options.first().cloned().unwrap_or_else(|| C2Framework {
            name: "Default".to_string(),
            description: "Default C2".to_string(),
            command_protocol: "HTTP".to_string(),
            stealth_capability: "Medium".to_string(),
            evasion_score: 0.50,
            operational_difficulty: "Medium".to_string(),
            persistence_options: vec![],
            supported_payloads: vec![],
            known_detections: vec![],
            operator_skill_required: "Intermediate".to_string(),
        });

        let vps_options = self.recommend_vps_provider("US", "low")?;
        let primary_vps = vps_options.first().cloned().unwrap_or_else(|| VPSProvider {
            provider_name: "Default".to_string(),
            geographic_locations: vec![],
            ip_reputation: "Unknown".to_string(),
            ddos_protection: false,
            detection_risk: 0.50,
            cost_per_month: 0.0,
            payment_methods: vec![],
            abuse_reporting_lag: "Unknown".to_string(),
            law_enforcement_cooperation: "Unknown".to_string(),
            provider_evasion_techniques: vec![],
            previous_breach_history: vec![],
        });

        let backup_vps = vps_options.get(1).cloned();

        let domain_strategy = self.plan_domain_strategy("legitimate_looking")?;

        Ok(InfrastructureDeployment {
            deployment_id: format!("INFRA-{}-20260825", operation_type),
            c2_framework: c2,
            primary_vps,
            backup_vps,
            domain_strategy,
            redirector_count: 2,
            proxy_chain_depth: 3,
            dns_setup: vec![
                "Primary DNS via CloudFlare".to_string(),
                "Secondary DNS via AWS Route53".to_string(),
                "Fast TTL (300s) for quick pivots".to_string(),
            ],
            operational_cost_estimate: 50.0,
            detection_probability: 0.35,
            mean_time_to_detection: "21-45 days (enterprise environment)".to_string(),
            failover_procedures: vec![
                "Activate backup VPS within 5 minutes of detection".to_string(),
                "Change DNS records to redirect traffic".to_string(),
                "Implement traffic obfuscation on backup".to_string(),
            ],
            recovery_options: vec![
                "Establish new infrastructure via different providers".to_string(),
                "Use compromised infrastructure if available".to_string(),
                "Pivot through legitimate cloud services (S3, Dropbox, etc.)".to_string(),
            ],
        })
    }

    pub fn generate_infrastructure_report(&self, operation_type: &str) -> Result<String> {
        let deployment = self.plan_infrastructure_deployment(operation_type)?;
        let mut output = String::new();

        output.push_str("\n=== Infrastructure Deployment Plan ===\n\n");
        output.push_str(&format!("Deployment ID: {}\n", deployment.deployment_id));
        output.push_str(&format!("Operation Type: {}\n\n", operation_type));

        output.push_str(&format!("C2 Framework: {}\n", deployment.c2_framework.name));
        output.push_str(&format!("  Description: {}\n", deployment.c2_framework.description));
        output.push_str(&format!("  Protocol: {}\n", deployment.c2_framework.command_protocol));
        output.push_str(&format!("  Stealth: {}\n", deployment.c2_framework.stealth_capability));
        output.push_str(&format!("  Evasion Score: {:.0}%\n", deployment.c2_framework.evasion_score * 100.0));
        output.push_str(&format!("  Difficulty: {}\n\n", deployment.c2_framework.operational_difficulty));

        output.push_str("Persistence Options:\n");
        for option in &deployment.c2_framework.persistence_options {
            output.push_str(&format!("  • {}\n", option));
        }

        output.push_str(&format!("\nPrimary VPS Provider: {}\n", deployment.primary_vps.provider_name));
        output.push_str(&format!("  Locations: {}\n", deployment.primary_vps.geographic_locations.join(", ")));
        output.push_str(&format!("  IP Reputation: {}\n", deployment.primary_vps.ip_reputation));
        output.push_str(&format!("  Detection Risk: {:.0}%\n", deployment.primary_vps.detection_risk * 100.0));
        output.push_str(&format!("  Cost: ${}/month\n", deployment.primary_vps.cost_per_month));
        output.push_str(&format!("  Abuse Response: {}\n", deployment.primary_vps.abuse_reporting_lag));
        output.push_str(&format!("  LE Cooperation: {}\n\n", deployment.primary_vps.law_enforcement_cooperation));

        if let Some(backup) = &deployment.backup_vps {
            output.push_str(&format!("Backup VPS Provider: {}\n", backup.provider_name));
            output.push_str(&format!("  Detection Risk: {:.0}%\n\n", backup.detection_risk * 100.0));
        }

        output.push_str(&format!("Domain Strategy: {}\n", deployment.domain_strategy.domain_name));
        output.push_str(&format!("  Registrar: {}\n", deployment.domain_strategy.registrar));
        output.push_str(&format!("  WHOIS Privacy: {}\n", deployment.domain_strategy.whois_privacy));
        output.push_str(&format!("  DNS Provider: {}\n", deployment.domain_strategy.dns_provider));
        output.push_str(&format!("  Reputation Risk: {:.0}%\n\n", deployment.domain_strategy.reputation_risk * 100.0));

        output.push_str(&format!("Infrastructure Summary:\n"));
        output.push_str(&format!("  Redirectors: {}\n", deployment.redirector_count));
        output.push_str(&format!("  Proxy Chain Depth: {}\n", deployment.proxy_chain_depth));
        output.push_str(&format!("  Monthly Cost: ${:.2}\n", deployment.operational_cost_estimate));
        output.push_str(&format!("  Detection Probability: {:.0}%\n", deployment.detection_probability * 100.0));
        output.push_str(&format!("  Mean Time to Detection: {}\n\n", deployment.mean_time_to_detection));

        output.push_str("Failover Procedures:\n");
        for (i, proc) in deployment.failover_procedures.iter().enumerate() {
            output.push_str(&format!("  {}. {}\n", i + 1, proc));
        }

        output.push_str("\nRecovery Options:\n");
        for (i, option) in deployment.recovery_options.iter().enumerate() {
            output.push_str(&format!("  {}. {}\n", i + 1, option));
        }

        output.push_str("\n========================================\n");
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recommend_c2_frameworks() {
        let deployer = InfrastructureDeployer;
        let frameworks = deployer.recommend_c2_framework("stealth").unwrap();
        assert!(!frameworks.is_empty());
        assert!(frameworks[0].evasion_score > 0.75);
    }

    #[test]
    fn test_recommend_vps_providers() {
        let deployer = InfrastructureDeployer;
        let providers = deployer.recommend_vps_provider("US", "low").unwrap();
        assert!(!providers.is_empty());
        assert!(providers[0].detection_risk < 0.5);
    }

    #[test]
    fn test_plan_legitimate_domain() {
        let deployer = InfrastructureDeployer;
        let domain = deployer.plan_domain_strategy("legitimate_looking").unwrap();
        assert!(domain.whois_privacy);
        assert!(domain.reputation_risk < 0.5);
    }

    #[test]
    fn test_plan_disposable_domain() {
        let deployer = InfrastructureDeployer;
        let domain = deployer.plan_domain_strategy("disposable").unwrap();
        assert!(domain.whois_privacy);
        assert!(domain.reputation_risk > 0.6);
    }

    #[test]
    fn test_infrastructure_deployment() {
        let deployer = InfrastructureDeployer;
        let deployment = deployer.plan_infrastructure_deployment("stealth").unwrap();
        assert!(!deployment.c2_framework.name.is_empty());
        assert!(!deployment.primary_vps.provider_name.is_empty());
        assert!(!deployment.failover_procedures.is_empty());
    }
}
