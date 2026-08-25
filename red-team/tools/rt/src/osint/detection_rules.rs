use crate::osint::ThreatIntelligenceFeed;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleFormat {
    Sigma,
    Yara,
    SiemQuery,
    Snort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub format: RuleFormat,
    pub content: String,
    pub severity: String, // low, medium, high, critical
    pub confidence: f64,
    pub false_positive_risk: String,
    pub actor_id: String,
    pub techniques: Vec<String>,
    pub coverage: f64, // percentage of technique coverage
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRuleset {
    pub actor_id: String,
    pub actor_name: String,
    pub rules: Vec<DetectionRule>,
    pub total_techniques: usize,
    pub covered_techniques: usize,
    pub overall_coverage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuningGuidance {
    pub rule_id: String,
    pub false_positive_causes: Vec<String>,
    pub tuning_recommendations: Vec<String>,
    pub baseline_period_days: usize,
    pub alert_threshold: String,
}

pub struct DetectionRuleGenerator {
    threat_feed: ThreatIntelligenceFeed,
}

impl DetectionRuleGenerator {
    pub fn new(threat_feed: ThreatIntelligenceFeed) -> Self {
        DetectionRuleGenerator { threat_feed }
    }

    pub fn generate_rules_for_actor(
        &self,
        actor_id: &str,
        format: RuleFormat,
    ) -> Option<DetectionRuleset> {
        let actor = self.threat_feed.get_actor(actor_id)?;
        let mut rules = Vec::new();

        for (i, technique) in actor.techniques.iter().enumerate() {
            let rule_id = format!("DET-{}-{:03}", actor_id, i + 1);
            let rule = self.generate_rule_for_technique(
                &rule_id,
                technique,
                actor_id,
                &format,
            );
            rules.push(rule);
        }

        let total_techniques = actor.techniques.len();
        let covered_techniques = rules.len();
        let overall_coverage = (covered_techniques as f64 / total_techniques as f64).min(1.0);

        Some(DetectionRuleset {
            actor_id: actor_id.to_string(),
            actor_name: actor.name.clone(),
            rules,
            total_techniques,
            covered_techniques,
            overall_coverage,
        })
    }

    pub fn generate_rule_for_technique(
        &self,
        rule_id: &str,
        technique: &str,
        actor_id: &str,
        format: &RuleFormat,
    ) -> DetectionRule {
        let (title, description, content, severity) = match technique {
            t if t.contains("T1566") => (
                "Phishing - Email Attachment".to_string(),
                "Detects suspicious email attachments commonly used in phishing campaigns".to_string(),
                self.generate_phishing_rule(format),
                "high".to_string(),
            ),
            t if t.contains("T1195") => (
                "Supply Chain Compromise".to_string(),
                "Detects indicators of supply chain compromise and software tampering".to_string(),
                self.generate_supply_chain_rule(format),
                "critical".to_string(),
            ),
            t if t.contains("T1078") => (
                "Valid Accounts Abuse".to_string(),
                "Detects unauthorized use of valid user credentials".to_string(),
                self.generate_valid_accounts_rule(format),
                "high".to_string(),
            ),
            t if t.contains("T1087") => (
                "Account Discovery".to_string(),
                "Detects enumeration of user accounts and credentials".to_string(),
                self.generate_discovery_rule(format),
                "medium".to_string(),
            ),
            t if t.contains("T1110") => (
                "Brute Force Attack".to_string(),
                "Detects brute force and credential stuffing attempts".to_string(),
                self.generate_bruteforce_rule(format),
                "high".to_string(),
            ),
            t if t.contains("T1586") => (
                "Credential Phishing".to_string(),
                "Detects credential harvesting and phishing attempts".to_string(),
                self.generate_credential_phishing_rule(format),
                "high".to_string(),
            ),
            t if t.contains("T1098") => (
                "Account Manipulation".to_string(),
                "Detects unauthorized account modifications and takeovers".to_string(),
                self.generate_account_manipulation_rule(format),
                "high".to_string(),
            ),
            t if t.contains("T1021") => (
                "Remote Service Exploitation".to_string(),
                "Detects exploitation of remote services and lateral movement".to_string(),
                self.generate_remote_service_rule(format),
                "critical".to_string(),
            ),
            _ => (
                format!("Technique {} Detection", technique),
                format!("Generic detection for MITRE technique {}", technique),
                self.generate_generic_rule(format),
                "medium".to_string(),
            ),
        };

        let confidence = match severity.as_str() {
            "critical" => 0.95,
            "high" => 0.85,
            "medium" => 0.7,
            _ => 0.6,
        };

        let false_positive_risk = match severity.as_str() {
            "critical" => "low".to_string(),
            "high" => "low".to_string(),
            "medium" => "medium".to_string(),
            _ => "high".to_string(),
        };

        DetectionRule {
            rule_id: rule_id.to_string(),
            title,
            description,
            format: format.clone(),
            content,
            severity,
            confidence,
            false_positive_risk,
            actor_id: actor_id.to_string(),
            techniques: vec![technique.to_string()],
            coverage: 1.0,
        }
    }

    pub fn get_tuning_guidance(&self, rule_id: &str) -> TuningGuidance {
        let technique_part = rule_id.split('-').nth(1).unwrap_or("");

        let (false_positives, recommendations) = match technique_part {
            t if t.contains("566") => (
                vec![
                    "Legitimate attachment delivery".to_string(),
                    "Mass email marketing".to_string(),
                    "Document sharing services".to_string(),
                ],
                vec![
                    "Whitelist known document sources".to_string(),
                    "Baseline external email volume".to_string(),
                    "Monitor file type patterns".to_string(),
                    "Correlate with user role and department".to_string(),
                ],
            ),
            t if t.contains("078") => (
                vec![
                    "Legitimate remote access".to_string(),
                    "Shared accounts".to_string(),
                    "Service accounts accessing resources".to_string(),
                ],
                vec![
                    "Establish baseline login patterns per account".to_string(),
                    "Monitor after-hours access for sensitive accounts".to_string(),
                    "Alert on geographic anomalies".to_string(),
                    "Correlate with failed login attempts".to_string(),
                ],
            ),
            _ => (
                vec!["Monitor initial baseline period".to_string()],
                vec!["Adjust thresholds based on environment".to_string()],
            ),
        };

        TuningGuidance {
            rule_id: rule_id.to_string(),
            false_positive_causes: false_positives,
            tuning_recommendations: recommendations,
            baseline_period_days: 14,
            alert_threshold: "Match any indicator".to_string(),
        }
    }

    fn generate_phishing_rule(&self, format: &RuleFormat) -> String {
        match format {
            RuleFormat::Sigma => "title: Phishing - Email Attachment\nlogsource:\n  product: exchange\n  service: audit\ndetection:\n  selection:\n    EventID: 2063\n    AttachmentFileName|endswith: '.exe'\n  condition: selection".to_string(),
            RuleFormat::Yara => "rule phishing_email_attachment {\n  strings:\n    $attach = /\\.exe$/ nocase\n  condition:\n    $attach\n}".to_string(),
            RuleFormat::SiemQuery => "source=email attachment_name=*.exe | stats count by sender, recipient".to_string(),
            RuleFormat::Snort => "alert smtp $EXTERNAL_NET any -> $HOME_NET 25 (msg:\"Phishing Email with Executable\"; flow:to_server,established; content:\"Content-Disposition\"; content:\".exe\"; sid:1000001;)".to_string(),
        }
    }

    fn generate_supply_chain_rule(&self, format: &RuleFormat) -> String {
        match format {
            RuleFormat::Sigma => "title: Supply Chain Compromise\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 1\n    Image|endswith: 'sccm.exe'\n  condition: selection".to_string(),
            RuleFormat::Yara => "rule supply_chain_malware {\n  strings:\n    $unsigned = \"unsigned\"\n  condition:\n    $unsigned\n}".to_string(),
            RuleFormat::SiemQuery => "source=endpoint process_name=sccm.exe parent_process!=ccm.exe | stats count".to_string(),
            RuleFormat::Snort => "alert tcp any any -> any any (msg:\"Suspected Supply Chain Compromise\"; content:\"sccm\"; sid:1000002;)".to_string(),
        }
    }

    fn generate_valid_accounts_rule(&self, format: &RuleFormat) -> String {
        match format {
            RuleFormat::Sigma => "title: Valid Accounts Abuse\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4625\n    FailureCount: '>5'\n  condition: selection".to_string(),
            RuleFormat::Yara => "rule valid_account_abuse {\n  strings:\n    $attempt = /failed.*logon/ nocase\n  condition:\n    $attempt\n}".to_string(),
            RuleFormat::SiemQuery => "source=windows_security EventID=4625 | stats count by user_name | where count > 5".to_string(),
            RuleFormat::Snort => "alert tcp any any -> any 445 (msg:\"Multiple Failed Login Attempts\"; flow:established; threshold: type both, track by_src, count 5; sid:1000003;)".to_string(),
        }
    }

    fn generate_discovery_rule(&self, format: &RuleFormat) -> String {
        match format {
            RuleFormat::Sigma => "title: Account Discovery\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: 'net user'\n  condition: selection".to_string(),
            RuleFormat::Yara => "rule account_discovery {\n  strings:\n    $cmd = /net user/ nocase\n  condition:\n    $cmd\n}".to_string(),
            RuleFormat::SiemQuery => "source=process CommandLine=\"net user\" | stats count by user".to_string(),
            RuleFormat::Snort => "alert tcp any any -> any 445 (msg:\"Account Enumeration Detected\"; content:\"net user\"; sid:1000004;)".to_string(),
        }
    }

    fn generate_bruteforce_rule(&self, format: &RuleFormat) -> String {
        match format {
            RuleFormat::Sigma => "title: Brute Force Attack\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4625\n  timeframe: 5m\n  condition: selection | count > 10".to_string(),
            RuleFormat::Yara => "rule brute_force_attack {\n  strings:\n    $fail = /authentication failed/i\n  condition:\n    #fail > 10\n}".to_string(),
            RuleFormat::SiemQuery => "source=auth failed_logins=* | stats count by src_ip | where count > 10".to_string(),
            RuleFormat::Snort => "alert tcp any any -> any any (msg:\"Brute Force Attempt Detected\"; flow:established; threshold: type both, track by_src, count 10, seconds 300; sid:1000005;)".to_string(),
        }
    }

    fn generate_credential_phishing_rule(&self, format: &RuleFormat) -> String {
        match format {
            RuleFormat::Sigma => "title: Credential Phishing\nlogsource:\n  product: proxy\ndetection:\n  selection:\n    url|contains: 'login'\n    domain|contains: 'phishing'\n  condition: selection".to_string(),
            RuleFormat::Yara => "rule credential_phishing {\n  strings:\n    $phish = /login.*phishing/ nocase\n  condition:\n    $phish\n}".to_string(),
            RuleFormat::SiemQuery => "source=proxy url=*login* domain=*phishing* | stats count by user".to_string(),
            RuleFormat::Snort => "alert http any any -> any any (msg:\"Credential Phishing Detection\"; content:\"login\"; content:\"phishing\"; sid:1000006;)".to_string(),
        }
    }

    fn generate_account_manipulation_rule(&self, format: &RuleFormat) -> String {
        match format {
            RuleFormat::Sigma => "title: Account Manipulation\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4720\n  condition: selection".to_string(),
            RuleFormat::Yara => "rule account_manipulation {\n  strings:\n    $create = /account created/ nocase\n  condition:\n    $create\n}".to_string(),
            RuleFormat::SiemQuery => "source=windows EventID=4720 | stats count by creator".to_string(),
            RuleFormat::Snort => "alert tcp any any -> any 445 (msg:\"Suspicious Account Created\"; sid:1000007;)".to_string(),
        }
    }

    fn generate_remote_service_rule(&self, format: &RuleFormat) -> String {
        match format {
            RuleFormat::Sigma => "title: Remote Service Exploitation\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4688\n    CommandLine|contains: 'psexec'\n  condition: selection".to_string(),
            RuleFormat::Yara => "rule remote_exploitation {\n  strings:\n    $psexec = /psexec/ nocase\n  condition:\n    $psexec\n}".to_string(),
            RuleFormat::SiemQuery => "source=process CommandLine=*psexec* | stats count".to_string(),
            RuleFormat::Snort => "alert tcp any any -> any 445 (msg:\"PsExec Lateral Movement Detected\"; content:\"psexec\"; sid:1000008;)".to_string(),
        }
    }

    fn generate_generic_rule(&self, format: &RuleFormat) -> String {
        match format {
            RuleFormat::Sigma => "title: Generic Threat Detection\nlogsource:\n  product: generic\ndetection:\n  selection:\n    indicator: present\n  condition: selection".to_string(),
            RuleFormat::Yara => "rule generic_threat {\n  strings:\n    $indicator = \"threat\"\n  condition:\n    $indicator\n}".to_string(),
            RuleFormat::SiemQuery => "source=* | stats count".to_string(),
            RuleFormat::Snort => "alert tcp any any -> any any (msg:\"Generic Threat Detected\"; sid:9000001;)".to_string(),
        }
    }

    pub fn export_ruleset_as_text(&self, ruleset: &DetectionRuleset) -> String {
        let mut output = String::new();
        output.push_str(&format!(
            "=== Detection Rules for {} ===\n\n",
            ruleset.actor_name
        ));
        output.push_str(&format!(
            "Coverage: {}/{} techniques ({:.1}%)\n\n",
            ruleset.covered_techniques, ruleset.total_techniques, ruleset.overall_coverage * 100.0
        ));

        for rule in &ruleset.rules {
            output.push_str(&format!("Rule ID: {}\n", rule.rule_id));
            output.push_str(&format!("Title: {}\n", rule.title));
            output.push_str(&format!("Description: {}\n", rule.description));
            output.push_str(&format!("Severity: {}\n", rule.severity));
            output.push_str(&format!("Confidence: {:.0}%\n", rule.confidence * 100.0));
            output.push_str(&format!(
                "False Positive Risk: {}\n",
                rule.false_positive_risk
            ));
            output.push_str(&format!("Format: {:?}\n", rule.format));
            output.push_str("\n");
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_generation() {
        let feed = ThreatIntelligenceFeed::new();
        let generator = DetectionRuleGenerator::new(feed);
        let ruleset = generator.generate_rules_for_actor("APT29", RuleFormat::Sigma);
        assert!(ruleset.is_some());
        let rs = ruleset.unwrap();
        assert!(!rs.rules.is_empty());
    }

    #[test]
    fn test_rule_formats() {
        let feed = ThreatIntelligenceFeed::new();
        let generator = DetectionRuleGenerator::new(feed);

        for format in &[RuleFormat::Sigma, RuleFormat::Yara, RuleFormat::SiemQuery, RuleFormat::Snort] {
            let ruleset = generator.generate_rules_for_actor("APT29", format.clone());
            assert!(ruleset.is_some());
        }
    }

    #[test]
    fn test_tuning_guidance() {
        let feed = ThreatIntelligenceFeed::new();
        let generator = DetectionRuleGenerator::new(feed);
        let guidance = generator.get_tuning_guidance("DET-APT29-001");
        assert!(!guidance.false_positive_causes.is_empty());
        assert!(!guidance.tuning_recommendations.is_empty());
    }

    #[test]
    fn test_ruleset_export() {
        let feed = ThreatIntelligenceFeed::new();
        let generator = DetectionRuleGenerator::new(feed);
        let ruleset = generator.generate_rules_for_actor("APT29", RuleFormat::Sigma);
        if let Some(rs) = ruleset {
            let exported = generator.export_ruleset_as_text(&rs);
            assert!(exported.contains("APT29"));
            assert!(exported.contains("Coverage"));
        }
    }
}
