use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceMechanism {
    pub mechanism_id: String,
    pub name: String,
    pub technique_id: String,
    pub description: String,
    pub windows_version: String,
    pub detection_difficulty: String,
    pub implementation_steps: Vec<String>,
    pub detection_risks: Vec<String>,
    pub behavioral_indicators: Vec<String>,
    pub recovery_options: Vec<String>,
    pub reliability_score: f64,
    pub privilege_level_required: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackdoorChain {
    pub chain_id: String,
    pub primary_backdoor: String,
    pub secondary_backdoors: Vec<String>,
    pub privilege_escalation_path: String,
    pub detection_evasion_score: f64,
    pub recovery_resilience: f64,
    pub estimated_persistence_days: u32,
    pub failover_mechanisms: Vec<String>,
    pub evidence_cleanup_procedures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeEscalation {
    pub escalation_id: String,
    pub vulnerability: String,
    pub affected_versions: Vec<String>,
    pub exploitation_difficulty: String,
    pub success_probability: f64,
    pub detection_risk: f64,
    pub steps: Vec<String>,
    pub defender_mitigations: Vec<String>,
    pub alternative_methods: Vec<String>,
    pub post_exploitation_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceStrategy {
    pub strategy_id: String,
    pub target_environment: String,
    pub primary_mechanism: PersistenceMechanism,
    pub fallback_mechanisms: Vec<PersistenceMechanism>,
    pub backdoor_chain: BackdoorChain,
    pub privilege_escalation: Option<PrivilegeEscalation>,
    pub evidence_cleanup: Vec<String>,
    pub monitoring_evasion: Vec<String>,
    pub success_probability: f64,
    pub estimated_detection_timeline: String,
}

pub struct PersistenceStrategist;

impl PersistenceStrategist {
    pub fn plan_persistence_mechanism(&self, mechanism_type: &str) -> Result<PersistenceMechanism> {
        match mechanism_type {
            "registry_run" => Ok(PersistenceMechanism {
                mechanism_id: "PERSIST-REG-RUN".to_string(),
                name: "Registry Run Keys".to_string(),
                technique_id: "T1547.001".to_string(),
                description: "Add malware to Windows Registry Run key for automatic execution at startup".to_string(),
                windows_version: "All versions".to_string(),
                detection_difficulty: "Low - Easy to detect via registry monitoring".to_string(),
                implementation_steps: vec![
                    "Step 1: Create payload in temp directory with legitimate name".to_string(),
                    "Step 2: Add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run entry".to_string(),
                    "Step 3: Point to payload with obfuscated command line".to_string(),
                    "Step 4: Optionally disable UAC prompts via registry".to_string(),
                ],
                detection_risks: vec![
                    "Registry auditing (enabled by default in enterprise)".to_string(),
                    "EDR registry monitoring".to_string(),
                    "Sysmon registry event logging".to_string(),
                ],
                behavioral_indicators: vec![
                    "New registry Run key creation".to_string(),
                    "Suspicious command line in registry value".to_string(),
                    "Process execution from temp directory at startup".to_string(),
                ],
                recovery_options: vec![
                    "Manual registry deletion".to_string(),
                    "Registry restore from backup".to_string(),
                    "Safe Mode boot to remove entry".to_string(),
                ],
                reliability_score: 0.65,
                privilege_level_required: "User (HKCU) or Administrator (HKLM)".to_string(),
            }),
            "scheduled_task" => Ok(PersistenceMechanism {
                mechanism_id: "PERSIST-SCHED-TASK".to_string(),
                name: "Scheduled Tasks".to_string(),
                technique_id: "T1053.005".to_string(),
                description: "Create scheduled task to execute malware at specified intervals".to_string(),
                windows_version: "All versions".to_string(),
                detection_difficulty: "Medium - Requires task scheduler auditing".to_string(),
                implementation_steps: vec![
                    "Step 1: Create task with legitimate name (e.g., 'Windows Update Check')".to_string(),
                    "Step 2: Set execution to SYSTEM account via RPC".to_string(),
                    "Step 3: Point to malware payload or command".to_string(),
                    "Step 4: Set trigger to boot, logon, or time-based interval".to_string(),
                    "Step 5: Hide task from standard display".to_string(),
                ],
                detection_risks: vec![
                    "Task Scheduler event logs (1698, 1699, 1702)".to_string(),
                    "Registry key modifications for hidden tasks".to_string(),
                    "EDR task creation monitoring".to_string(),
                    "Process execution from unexpected directories".to_string(),
                ],
                behavioral_indicators: vec![
                    "New scheduled task creation (especially SYSTEM account)".to_string(),
                    "Task pointing to suspicious binary".to_string(),
                    "Boot-time or logon-time task execution".to_string(),
                    "Hidden task registry entries".to_string(),
                ],
                recovery_options: vec![
                    "Delete task via Task Scheduler".to_string(),
                    "Remove task via registry".to_string(),
                    "Disable task scheduler service temporarily".to_string(),
                ],
                reliability_score: 0.85,
                privilege_level_required: "Administrator (for SYSTEM account tasks)".to_string(),
            }),
            "wmi_event" => Ok(PersistenceMechanism {
                mechanism_id: "PERSIST-WMI-EVENT".to_string(),
                name: "WMI Event Subscriptions".to_string(),
                technique_id: "T1547.013".to_string(),
                description: "Create WMI event consumer for persistence with process monitoring".to_string(),
                windows_version: "Windows XP and later".to_string(),
                detection_difficulty: "High - Requires WMI monitoring".to_string(),
                implementation_steps: vec![
                    "Step 1: Create event filter watching for trigger (e.g., process creation)".to_string(),
                    "Step 2: Create event consumer (command to execute)".to_string(),
                    "Step 3: Bind filter and consumer together".to_string(),
                    "Step 4: Trigger event executes malware (fileless execution possible)".to_string(),
                ],
                detection_risks: vec![
                    "WMI audit logging (not enabled by default)".to_string(),
                    "Sysmon WMI event monitoring (not default)".to_string(),
                    "WMI repository queries by security tools".to_string(),
                    "Process execution from WMI command line".to_string(),
                ],
                behavioral_indicators: vec![
                    "WMI event filter creation".to_string(),
                    "WMI event consumer binding".to_string(),
                    "PowerShell WMI commands in logs".to_string(),
                    "Process creation from WMI service".to_string(),
                ],
                recovery_options: vec![
                    "Remove WMI class instances via WMI tools".to_string(),
                    "Rebuild WMI repository".to_string(),
                    "Disable WMI service".to_string(),
                ],
                reliability_score: 0.88,
                privilege_level_required: "Administrator".to_string(),
            }),
            "dll_hijack" => Ok(PersistenceMechanism {
                mechanism_id: "PERSIST-DLL-HIJACK".to_string(),
                name: "DLL Search Order Hijacking".to_string(),
                technique_id: "T1574.001".to_string(),
                description: "Place malicious DLL in directory with higher precedence in search order".to_string(),
                windows_version: "All versions".to_string(),
                detection_difficulty: "Low - Pattern detection challenging".to_string(),
                implementation_steps: vec![
                    "Step 1: Identify legitimate application with missing DLL import".to_string(),
                    "Step 2: Create malicious DLL with same name".to_string(),
                    "Step 3: Place DLL in directory searched before legitimate library".to_string(),
                    "Step 4: Application loads hijacked DLL on next execution".to_string(),
                ],
                detection_risks: vec![
                    "File integrity monitoring (FIM) on system directories".to_string(),
                    "DLL signing validation".to_string(),
                    "Application whitelisting (if implemented)".to_string(),
                ],
                behavioral_indicators: vec![
                    "DLL in unusual directory with legitimate application name".to_string(),
                    "DLL execution from non-standard paths".to_string(),
                    "Mismatch between expected and actual DLL".to_string(),
                ],
                recovery_options: vec![
                    "Delete malicious DLL".to_string(),
                    "Restore original DLL from backup".to_string(),
                    "Modify application search path".to_string(),
                ],
                reliability_score: 0.92,
                privilege_level_required: "User or Administrator (depends on directory)".to_string(),
            }),
            "netsh_helper" => Ok(PersistenceMechanism {
                mechanism_id: "PERSIST-NETSH".to_string(),
                name: "Netsh Helper DLL".to_string(),
                technique_id: "T1547.007".to_string(),
                description: "Register DLL as netsh helper to execute arbitrary code".to_string(),
                windows_version: "Windows Vista and later".to_string(),
                detection_difficulty: "Very High - Unusual execution path".to_string(),
                implementation_steps: vec![
                    "Step 1: Create DLL with DllMain function".to_string(),
                    "Step 2: Register DLL path in registry: HKLM\\Software\\Microsoft\\Netsh".to_string(),
                    "Step 3: Code executes when netsh.exe loads helper".to_string(),
                    "Step 4: Netsh.exe typically runs with NT AUTHORITY\\SYSTEM".to_string(),
                ],
                detection_risks: vec![
                    "Registry audit for netsh entries".to_string(),
                    "DLL signing verification".to_string(),
                    "Unusual DLL loading in netsh process (EDR)".to_string(),
                ],
                behavioral_indicators: vec![
                    "Netsh helper DLL registry entry".to_string(),
                    "DLL execution from unusual path via netsh".to_string(),
                    "Suspicious code in netsh.exe process memory".to_string(),
                ],
                recovery_options: vec![
                    "Remove registry entry for helper DLL".to_string(),
                    "Delete malicious DLL file".to_string(),
                ],
                reliability_score: 0.95,
                privilege_level_required: "Administrator (for registry write)".to_string(),
            }),
            _ => Ok(PersistenceMechanism {
                mechanism_id: "PERSIST-GENERIC".to_string(),
                name: "Generic Persistence".to_string(),
                technique_id: "T1547".to_string(),
                description: "Generic persistence mechanism".to_string(),
                windows_version: "All".to_string(),
                detection_difficulty: "Unknown".to_string(),
                implementation_steps: vec!["Generic steps".to_string()],
                detection_risks: vec!["Generic risks".to_string()],
                behavioral_indicators: vec!["Generic indicators".to_string()],
                recovery_options: vec!["Generic recovery".to_string()],
                reliability_score: 0.50,
                privilege_level_required: "Variable".to_string(),
            }),
        }
    }

    pub fn plan_backdoor_chain(&self, environment: &str) -> Result<BackdoorChain> {
        let (primary, secondaries) = match environment {
            "enterprise" => (
                "Cobalt Strike Beacon via scheduled task".to_string(),
                vec![
                    "Empire PowerShell agent via WMI event subscription".to_string(),
                    "Custom C++ implant via DLL hijacking".to_string(),
                    "Metasploit Meterpreter via Registry Run key".to_string(),
                ],
            ),
            "mid_market" => (
                "Sliver C2 via scheduled task".to_string(),
                vec![
                    "PowerShell reverse shell via Registry Run".to_string(),
                    "Custom bash/Python script via cron".to_string(),
                ],
            ),
            _ => (
                "Generic backdoor via scheduled task".to_string(),
                vec!["Secondary backdoor".to_string()],
            ),
        };

        Ok(BackdoorChain {
            chain_id: format!("CHAIN-{}-20260825", environment),
            primary_backdoor: primary,
            secondary_backdoors: secondaries,
            privilege_escalation_path: "From user → SYSTEM via scheduled task or WMI".to_string(),
            detection_evasion_score: 0.72,
            recovery_resilience: 0.88,
            estimated_persistence_days: match environment {
                "enterprise" => 60,
                "mid_market" => 90,
                _ => 30,
            },
            failover_mechanisms: vec![
                "Fallback to secondary backdoor if primary blocked".to_string(),
                "Automatic C2 infrastructure failover".to_string(),
                "Domain-flux C2 channels".to_string(),
                "DNS-based C2 tunnel as last resort".to_string(),
            ],
            evidence_cleanup_procedures: vec![
                "Remove scheduled task entries from Task Scheduler".to_string(),
                "Clear WMI repository events".to_string(),
                "Remove registry persistence keys".to_string(),
                "Delete artifacts from temp directories".to_string(),
                "Clear event logs (Security, System, Application)".to_string(),
            ],
        })
    }

    pub fn plan_privilege_escalation(&self, escalation_method: &str) -> Result<PrivilegeEscalation> {
        match escalation_method {
            "uac_bypass" => Ok(PrivilegeEscalation {
                escalation_id: "PRIVESC-UAC-001".to_string(),
                vulnerability: "User Account Control (UAC) bypass via token impersonation".to_string(),
                affected_versions: vec![
                    "Windows 7 and later".to_string(),
                ],
                exploitation_difficulty: "Low".to_string(),
                success_probability: 0.80,
                detection_risk: 0.45,
                steps: vec![
                    "Step 1: Identify UAC bypass vector (CMSTPLUA.EXE, eventvwr, fodhelper, etc.)".to_string(),
                    "Step 2: Create registry key for administrator process".to_string(),
                    "Step 3: Execute bypass binary to elevate privilege".to_string(),
                    "Step 4: Verify SYSTEM or Administrator token".to_string(),
                ],
                defender_mitigations: vec![
                    "UAC elevation prompts (can be clicked through)".to_string(),
                    "Code Integrity Guard (CIG)".to_string(),
                    "AppLocker rules".to_string(),
                ],
                alternative_methods: vec![
                    "Token impersonation via named pipes".to_string(),
                    "COM elevation moniker abuse".to_string(),
                    "DLL hijacking of privileged process".to_string(),
                ],
                post_exploitation_actions: vec![
                    "Install persistence mechanism as SYSTEM".to_string(),
                    "Dump LSASS for credential harvesting".to_string(),
                    "Disable Windows Defender as SYSTEM".to_string(),
                    "Create administrative backdoor account".to_string(),
                ],
            }),
            "kernel_exploit" => Ok(PrivilegeEscalation {
                escalation_id: "PRIVESC-KERNEL-001".to_string(),
                vulnerability: "Windows Kernel vulnerability (e.g., CVE-2021-1732, CVE-2020-1054)".to_string(),
                affected_versions: vec![
                    "Windows 7 SP1".to_string(),
                    "Windows 8.1".to_string(),
                    "Windows 10 (various builds)".to_string(),
                ],
                exploitation_difficulty: "High".to_string(),
                success_probability: 0.65,
                detection_risk: 0.60,
                steps: vec![
                    "Step 1: Identify applicable kernel vulnerability on target".to_string(),
                    "Step 2: Compile exploit for specific Windows version".to_string(),
                    "Step 3: Execute exploit to trigger kernel bug".to_string(),
                    "Step 4: Obtain SYSTEM token from kernel".to_string(),
                ],
                defender_mitigations: vec![
                    "Windows Update patches".to_string(),
                    "Driver signature enforcement".to_string(),
                    "Kernel patch guard".to_string(),
                    "Control Flow Guard (CFG)".to_string(),
                ],
                alternative_methods: vec![
                    "LTSC (Long-Term Servicing Channel) exploitation".to_string(),
                    "Unpatched system targeting".to_string(),
                    "Virtual machine escape (if applicable)".to_string(),
                ],
                post_exploitation_actions: vec![
                    "Load malicious kernel driver".to_string(),
                    "Patch kernel structures".to_string(),
                    "Install low-level rootkit".to_string(),
                    "Disable security features at kernel level".to_string(),
                ],
            }),
            _ => Ok(PrivilegeEscalation {
                escalation_id: "PRIVESC-GENERIC".to_string(),
                vulnerability: "Generic privilege escalation".to_string(),
                affected_versions: vec!["All".to_string()],
                exploitation_difficulty: "Unknown".to_string(),
                success_probability: 0.50,
                detection_risk: 0.50,
                steps: vec!["Generic steps".to_string()],
                defender_mitigations: vec!["Generic mitigations".to_string()],
                alternative_methods: vec!["Generic alternatives".to_string()],
                post_exploitation_actions: vec!["Generic actions".to_string()],
            }),
        }
    }

    pub fn generate_persistence_strategy(&self, environment: &str) -> Result<String> {
        let primary_mech = self.plan_persistence_mechanism("scheduled_task")?;
        let backdoor_chain = self.plan_backdoor_chain(environment)?;
        let privilege_esc = self.plan_privilege_escalation("uac_bypass")?;

        let mut output = String::new();
        output.push_str("\n=== Post-Compromise Persistence Strategy ===\n\n");
        output.push_str(&format!("Target Environment: {}\n", environment));
        output.push_str(&format!("Strategy ID: {}\n\n", backdoor_chain.chain_id));

        output.push_str("Phase 1: Initial Persistence (Scheduled Task)\n");
        output.push_str(&format!("  Mechanism: {}\n", primary_mech.name));
        output.push_str(&format!("  Technique: {}\n", primary_mech.technique_id));
        output.push_str("  Steps:\n");
        for step in &primary_mech.implementation_steps {
            output.push_str(&format!("    • {}\n", step));
        }
        output.push_str(&format!("  Reliability: {:.0}%\n", primary_mech.reliability_score * 100.0));
        output.push_str(&format!("  Privilege Required: {}\n\n", primary_mech.privilege_level_required));

        output.push_str("Phase 2: Privilege Escalation (UAC Bypass)\n");
        output.push_str(&format!("  Vulnerability: {}\n", privilege_esc.vulnerability));
        output.push_str(&format!("  Affected Versions: {}\n", privilege_esc.affected_versions.join(", ")));
        output.push_str(&format!("  Success Rate: {:.0}%\n", privilege_esc.success_probability * 100.0));
        output.push_str(&format!("  Detection Risk: {:.0}%\n", privilege_esc.detection_risk * 100.0));
        output.push_str("  Steps:\n");
        for step in &privilege_esc.steps {
            output.push_str(&format!("    • {}\n", step));
        }
        output.push_str("  Post-Exploitation Actions:\n");
        for action in &privilege_esc.post_exploitation_actions {
            output.push_str(&format!("    • {}\n", action));
        }
        output.push_str("\n");

        output.push_str("Phase 3: Backdoor Chain (Multi-Layer Persistence)\n");
        output.push_str(&format!("  Primary Backdoor: {}\n", backdoor_chain.primary_backdoor));
        output.push_str("  Secondary Backdoors:\n");
        for secondary in &backdoor_chain.secondary_backdoors {
            output.push_str(&format!("    • {}\n", secondary));
        }
        output.push_str(&format!("  Estimated Safe Persistence: {} days\n", backdoor_chain.estimated_persistence_days));
        output.push_str(&format!("  Detection Evasion Score: {:.0}%\n", backdoor_chain.detection_evasion_score * 100.0));
        output.push_str("  Failover Mechanisms:\n");
        for failover in &backdoor_chain.failover_mechanisms {
            output.push_str(&format!("    • {}\n", failover));
        }
        output.push_str("\n");

        output.push_str("Evidence Cleanup & Monitoring Evasion:\n");
        for cleanup in &backdoor_chain.evidence_cleanup_procedures {
            output.push_str(&format!("  • {}\n", cleanup));
        }

        output.push_str("\nDetection Risks:\n");
        for risk in &primary_mech.detection_risks {
            output.push_str(&format!("  • {}\n", risk));
        }

        output.push_str("\nBehavioral Indicators for Detection:\n");
        for indicator in &primary_mech.behavioral_indicators {
            output.push_str(&format!("  • {}\n", indicator));
        }

        output.push_str("\n========================================\n");
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_run_persistence() {
        let strategist = PersistenceStrategist;
        let mech = strategist.plan_persistence_mechanism("registry_run").unwrap();
        assert_eq!(mech.technique_id, "T1547.001");
        assert!(mech.reliability_score < 0.75);
    }

    #[test]
    fn test_scheduled_task_persistence() {
        let strategist = PersistenceStrategist;
        let mech = strategist.plan_persistence_mechanism("scheduled_task").unwrap();
        assert_eq!(mech.technique_id, "T1053.005");
        assert!(mech.reliability_score > 0.80);
    }

    #[test]
    fn test_wmi_event_persistence() {
        let strategist = PersistenceStrategist;
        let mech = strategist.plan_persistence_mechanism("wmi_event").unwrap();
        assert_eq!(mech.technique_id, "T1547.013");
        assert!(mech.reliability_score > 0.85);
    }

    #[test]
    fn test_backdoor_chain_enterprise() {
        let strategist = PersistenceStrategist;
        let chain = strategist.plan_backdoor_chain("enterprise").unwrap();
        assert!(!chain.primary_backdoor.is_empty());
        assert!(chain.secondary_backdoors.len() > 0);
        assert!(chain.estimated_persistence_days > 30);
    }

    #[test]
    fn test_privilege_escalation_uac() {
        let strategist = PersistenceStrategist;
        let privesc = strategist.plan_privilege_escalation("uac_bypass").unwrap();
        assert_eq!(privesc.escalation_id, "PRIVESC-UAC-001");
        assert!(privesc.success_probability > 0.7);
    }
}
