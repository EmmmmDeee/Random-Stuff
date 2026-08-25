use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonnelProfile {
    pub job_title: String,
    pub department: String,
    pub responsibility_level: String,
    pub likely_access: Vec<String>,
    pub vulnerability_factors: Vec<String>,
    pub social_network_presence: Vec<String>,
    pub motivation_levers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingTemplate {
    pub template_id: String,
    pub pretense_scenario: String,
    pub sender_identity: String,
    pub subject_line: String,
    pub body_outline: String,
    pub call_to_action: String,
    pub urgency_level: String,
    pub authenticity_indicators: Vec<String>,
    pub payload_mechanism: String,
    pub success_probability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialEngineeringCampaign {
    pub campaign_id: String,
    pub target_organization: String,
    pub target_department: String,
    pub phishing_template: String,
    pub target_profiles: Vec<PersonnelProfile>,
    pub estimated_success_rate: f64,
    pub number_of_phases: u32,
    pub total_targets: usize,
    pub expected_credential_harvest: usize,
    pub alternative_exploits: Vec<String>,
}

pub struct SocialEngineer;

impl SocialEngineer {
    pub fn analyze_target_personnel(&self, department: &str, role: &str) -> Result<PersonnelProfile> {
        match (department, role) {
            ("IT", "Administrator") => Ok(PersonnelProfile {
                job_title: "System Administrator".to_string(),
                department: "IT".to_string(),
                responsibility_level: "High".to_string(),
                likely_access: vec![
                    "Domain admin credentials".to_string(),
                    "Email systems".to_string(),
                    "File servers".to_string(),
                    "VPN access".to_string(),
                    "Backup systems".to_string(),
                ],
                vulnerability_factors: vec![
                    "Credential reuse".to_string(),
                    "Password managers".to_string(),
                    "Sticky notes".to_string(),
                    "Shared credentials".to_string(),
                    "Emergency access procedures".to_string(),
                ],
                social_network_presence: vec![
                    "LinkedIn (technical details)".to_string(),
                    "GitHub (code/repos)".to_string(),
                    "Technical blogs".to_string(),
                ],
                motivation_levers: vec![
                    "System outages".to_string(),
                    "Security alerts".to_string(),
                    "Employee onboarding".to_string(),
                    "Compliance issues".to_string(),
                ],
            }),
            ("Finance", "Accountant") => Ok(PersonnelProfile {
                job_title: "Accountant".to_string(),
                department: "Finance".to_string(),
                responsibility_level: "Medium".to_string(),
                likely_access: vec![
                    "Financial systems".to_string(),
                    "Banking portals".to_string(),
                    "Wire transfer authority".to_string(),
                    "Vendor databases".to_string(),
                ],
                vulnerability_factors: vec![
                    "Process-driven (predictable)".to_string(),
                    "High email volume".to_string(),
                    "Time pressure (month-end)".to_string(),
                    "Legitimate money movement".to_string(),
                ],
                social_network_presence: vec![
                    "LinkedIn".to_string(),
                    "Professional networks".to_string(),
                ],
                motivation_levers: vec![
                    "Urgent vendor payment".to_string(),
                    "Compliance deadline".to_string(),
                    "Executive request".to_string(),
                    "Banking authority issues".to_string(),
                ],
            }),
            ("HR", "Manager") => Ok(PersonnelProfile {
                job_title: "HR Manager".to_string(),
                department: "HR".to_string(),
                responsibility_level: "Medium-High".to_string(),
                likely_access: vec![
                    "Employee database".to_string(),
                    "Salary information".to_string(),
                    "Personal details (SSN, etc)".to_string(),
                    "Executive contacts".to_string(),
                ],
                vulnerability_factors: vec![
                    "Empathy/concern for employees".to_string(),
                    "Assistance mindset".to_string(),
                    "Legitimate employee requests".to_string(),
                ],
                social_network_presence: vec![
                    "LinkedIn".to_string(),
                    "Facebook (personal)".to_string(),
                ],
                motivation_levers: vec![
                    "Employee emergency".to_string(),
                    "Compliance/legal issue".to_string(),
                    "Executive request".to_string(),
                ],
            }),
            ("Executive", "C-Level") => Ok(PersonnelProfile {
                job_title: "Executive".to_string(),
                department: "Executive".to_string(),
                responsibility_level: "Very High".to_string(),
                likely_access: vec![
                    "Strategic plans".to_string(),
                    "M&A information".to_string(),
                    "Board communications".to_string(),
                    "Financial data".to_string(),
                    "Legal agreements".to_string(),
                ],
                vulnerability_factors: vec![
                    "Trusted relationships".to_string(),
                    "Delegation authority".to_string(),
                    "Limited technical knowledge".to_string(),
                    "Time constraints".to_string(),
                ],
                social_network_presence: vec![
                    "LinkedIn (public profile)".to_string(),
                    "News articles".to_string(),
                    "Company announcements".to_string(),
                ],
                motivation_levers: vec![
                    "Board/investor communications".to_string(),
                    "Urgent business matter".to_string(),
                    "Legal/regulatory issue".to_string(),
                    "Trusted advisor request".to_string(),
                ],
            }),
            _ => Ok(PersonnelProfile {
                job_title: "Generic Role".to_string(),
                department: department.to_string(),
                responsibility_level: "Medium".to_string(),
                likely_access: vec!["General system access".to_string()],
                vulnerability_factors: vec!["Generic vulnerabilities".to_string()],
                social_network_presence: vec!["Social networks".to_string()],
                motivation_levers: vec!["Legitimate requests".to_string()],
            }),
        }
    }

    pub fn create_phishing_template(&self, pretext: &str) -> Result<PhishingTemplate> {
        match pretext {
            "executive_directive" => Ok(PhishingTemplate {
                template_id: "PHISH-001-EXEC".to_string(),
                pretense_scenario: "Executive request for urgent action".to_string(),
                sender_identity: "Spoofed executive email or compromised account".to_string(),
                subject_line: "URGENT: Immediate action required - [specific request]".to_string(),
                body_outline: "Executive/Board request requiring immediate attention, confidentiality emphasized, urgency stressed".to_string(),
                call_to_action: "Click link to verify/confirm/access or reply with credentials".to_string(),
                urgency_level: "Very High - Time-sensitive".to_string(),
                authenticity_indicators: vec![
                    "Domain spoofing or near-miss (@companyxxx.com vs @company.com)".to_string(),
                    "Executive letterhead spoofed".to_string(),
                    "Legitimate formatting".to_string(),
                    "Specific details about company/projects".to_string(),
                ],
                payload_mechanism: "Credential harvesting page or malicious attachment".to_string(),
                success_probability: 0.72,
            }),
            "security_alert" => Ok(PhishingTemplate {
                template_id: "PHISH-002-SEC".to_string(),
                pretense_scenario: "Security/compliance alert".to_string(),
                sender_identity: "Spoofed IT security or external compliance firm".to_string(),
                subject_line: "SECURITY ALERT: Unusual activity detected - verification required".to_string(),
                body_outline: "Security incident notification, account verification needed, urgent compliance requirement".to_string(),
                call_to_action: "Click to verify identity or re-enter credentials".to_string(),
                urgency_level: "High - Account at risk".to_string(),
                authenticity_indicators: vec![
                    "IT security branding".to_string(),
                    "Legitimate security language".to_string(),
                    "Technical details".to_string(),
                    "Official-looking buttons/links".to_string(),
                ],
                payload_mechanism: "Phishing page disguised as security portal".to_string(),
                success_probability: 0.65,
            }),
            "vendor_communication" => Ok(PhishingTemplate {
                template_id: "PHISH-003-VEND".to_string(),
                pretense_scenario: "Important vendor communication".to_string(),
                sender_identity: "Trusted vendor or spoofed vendor email".to_string(),
                subject_line: "Action Required: Payment/Invoice Update/System Change".to_string(),
                body_outline: "Routine vendor communication, updated payment info, system access changes, contract updates".to_string(),
                call_to_action: "Update information, verify payment, or grant access".to_string(),
                urgency_level: "Medium-High - Business continuity".to_string(),
                authenticity_indicators: vec![
                    "Vendor branding and logos".to_string(),
                    "Legitimate banking/system details".to_string(),
                    "Professional formatting".to_string(),
                    "Reference to existing contracts".to_string(),
                ],
                payload_mechanism: "Banking credential capture or malware".to_string(),
                success_probability: 0.60,
            }),
            "personal_pretext" => Ok(PhishingTemplate {
                template_id: "PHISH-004-PERS".to_string(),
                pretense_scenario: "Personal/emergency scenario".to_string(),
                sender_identity: "Spoofed colleague, family, or support service".to_string(),
                subject_line: "Help needed - [personal emergency or request]".to_string(),
                body_outline: "Personal emergency, unusual request, help needed urgently".to_string(),
                call_to_action: "Respond with assistance, click to help, or provide information".to_string(),
                urgency_level: "High - Emotional appeal".to_string(),
                authenticity_indicators: vec![
                    "Personalized details".to_string(),
                    "Emotional language".to_string(),
                    "Requests matching person's typical interactions".to_string(),
                    "Reasonable scenario".to_string(),
                ],
                payload_mechanism: "Information gathering or malware link".to_string(),
                success_probability: 0.55,
            }),
            _ => Ok(PhishingTemplate {
                template_id: "PHISH-000-GEN".to_string(),
                pretense_scenario: "Generic phishing".to_string(),
                sender_identity: "Spoofed generic entity".to_string(),
                subject_line: "Action Required: Please Review".to_string(),
                body_outline: "Generic request for action".to_string(),
                call_to_action: "Click or respond".to_string(),
                urgency_level: "Medium".to_string(),
                authenticity_indicators: vec!["Generic indicators".to_string()],
                payload_mechanism: "Generic payload".to_string(),
                success_probability: 0.40,
            }),
        }
    }

    pub fn build_campaign(&self, org: &str, department: &str, pretext: &str) -> Result<SocialEngineeringCampaign> {
        let template = self.create_phishing_template(pretext)?;
        let target_prof = self.analyze_target_personnel(department, "Manager")?;

        let campaign_id = format!("SENG-{}-20260825", org);

        Ok(SocialEngineeringCampaign {
            campaign_id,
            target_organization: org.to_string(),
            target_department: department.to_string(),
            phishing_template: template.template_id.clone(),
            target_profiles: vec![target_prof],
            estimated_success_rate: template.success_probability * 0.8,
            number_of_phases: 3,
            total_targets: 50,
            expected_credential_harvest: (50.0 * template.success_probability * 0.8) as usize,
            alternative_exploits: vec![
                "USB drop attack".to_string(),
                "Malicious QR code".to_string(),
                "Physical pretext".to_string(),
                "Voice social engineering".to_string(),
            ],
        })
    }

    pub fn identify_high_value_targets(&self, org: &str) -> Result<Vec<String>> {
        Ok(vec![
            format!("CEO/President of {} - highest access", org),
            format!("CTO/IT Director - system access"),
            format!("CFO - financial systems"),
            format!("Security Officer - security knowledge"),
            format!("System Administrators - domain control"),
            format!("Finance Team - wire transfer capability"),
            format!("HR Director - personnel data"),
            format!("Legal Counsel - sensitive documents"),
        ])
    }

    pub fn calculate_roi(&self, estimated_harvest: usize) -> Result<String> {
        let mut output = String::new();
        output.push_str("=== Social Engineering Campaign ROI ===\n\n");

        let initial_investment = 500; // Estimated hours
        let credentials_per_successful = 2;
        let total_credentials = estimated_harvest * credentials_per_successful;

        output.push_str(&format!("Estimated credential harvest: {}\n", total_credentials));
        output.push_str(&format!("Time investment: ~{} hours\n", initial_investment));
        output.push_str(&format!("Cost per credential: ${:.2}\n\n", (initial_investment as f64 * 50.0) / total_credentials as f64));

        output.push_str("Derived capabilities:\n");
        output.push_str(&format!("  • Valid credentials: {}\n", total_credentials));
        output.push_str(&format!("  • Compromised accounts: {}\n", estimated_harvest));
        output.push_str(&format!("  • Network access points: {}\n", estimated_harvest / 5));
        output.push_str(&format!("  • Lateral movement paths: {}\n", estimated_harvest / 3));

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_analysis() {
        let engineer = SocialEngineer;
        let profile = engineer.analyze_target_personnel("IT", "Administrator").unwrap();
        assert!(!profile.likely_access.is_empty());
    }

    #[test]
    fn test_phishing_template_creation() {
        let engineer = SocialEngineer;
        let template = engineer.create_phishing_template("executive_directive").unwrap();
        assert_eq!(template.template_id, "PHISH-001-EXEC");
    }

    #[test]
    fn test_campaign_building() {
        let engineer = SocialEngineer;
        let campaign = engineer.build_campaign("Target Corp", "IT", "executive_directive").unwrap();
        assert!(!campaign.campaign_id.is_empty());
        assert!(campaign.expected_credential_harvest > 0);
    }

    #[test]
    fn test_high_value_targeting() {
        let engineer = SocialEngineer;
        let targets = engineer.identify_high_value_targets("Corp").unwrap();
        assert!(targets.len() > 0);
    }

    #[test]
    fn test_roi_calculation() {
        let engineer = SocialEngineer;
        let roi = engineer.calculate_roi(50).unwrap();
        assert!(roi.contains("ROI"));
    }
}
