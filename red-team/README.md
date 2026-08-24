# 🎯 Red Team Framework - Attack Scenarios & Defense Validation

Comprehensive red team testing framework for simulating multi-stage attacks, mapping to MITRE ATT&CK techniques, and executing incident response drills.

**Version**: 1.0  
**Last Updated**: 2026-08-06  
**Status**: Production Ready for Authorized Testing

---

## 📋 Overview

This framework provides:

1. **Attack Scenarios** - Realistic multi-stage attack chains with MITRE ATT&CK mappings
2. **MITRE ATT&CK Framework** - Techniques, tactics, and detection methods
3. **Incident Response Drills** - Automated testing of detection, response, and recovery capabilities
4. **Detection Gap Analysis** - Identifies blindspots in current security controls
5. **Fix Tracking** - Prioritized fixes for detected gaps
6. **Intelligence-Led Testing (TLPT)** - Emulate the *specific* threat actors that
   target your sector, using their real documented TTPs — see
   [`intelligence-led/`](intelligence-led/README.md). This is the maturity
   upgrade over generic red teaming (the TIBER-EU / CBEST model): the adversary
   you emulate is chosen from evidence, not imagination.

### Current Scenarios

| Scenario | Difficulty | Duration | Success Rate | Coverage |
|----------|-----------|----------|--------------|----------|
| **APT-001** | Medium | 8 hours | 40-60% | Phishing → Ransomware (6 stages) |
| **APT-002** | Very High | 30 days | 70-95% | Supply Chain Attack (9 stages) |

---

## 🏗️ Directory Structure

```
red-team/
├── README.md (this file)
├── tools/                       (framework tooling)
│   ├── rt.py                    (unified Python CLI: rt.py <scenario|derive|recon|navigator>)
│   ├── attack.py                (shared: paths, JSON I/O, ATT&CK-ID helpers)
│   ├── scenario.py  derive.py  recon.py  navigator.py   (command modules)
│   └── hse/                     (Rust: Huntsman Search Engine — search the detection catalog)
│
├── scenarios/
│   ├── README.md (scenario overview)
│   ├── scenario-01-phishing-to-ransomware.json
│   ├── scenario-02-supply-chain-attack.json
│   └── [additional scenarios]
│
├── mitre-attack/
│   ├── framework.json (MITRE mappings, tactics, techniques)
│   └── navigator-layer.json (generated ATT&CK Navigator coverage layer)
│
├── incident-response/
│   └── drill-framework.json (6 IR drills mapped to scenarios)
│
├── intelligence-led/            (TLPT: actors, targeting, recon, detections, campaigns)
│
└── reports/                     (generated scenario/drill output — gitignored)
```

All commands run from the `red-team/` directory via the unified CLI, e.g.
`python3 tools/rt.py scenario --list`. Each module is also runnable standalone
(`python3 tools/scenario.py --list`).

---

## 🚀 Quick Start

### 1. List Available Scenarios

```bash
python3 tools/rt.py scenario --list
```

Output:
```
📋 Available Red Team Scenarios

  📌 APT-001
     Name: Phishing → Credential Theft → Lateral Movement → Ransomware
     Difficulty: Medium
     Duration: 8 hours
     Success Rate: 40-60%

  📌 APT-002
     Name: Supply Chain Attack → Persistent Access → Widespread Compromise
     Difficulty: Very High
     Duration: 30 days
     Success Rate: 70-95%
```

### 2. Run a Scenario

```bash
python3 tools/rt.py scenario --run scenario-01-phishing-to-ransomware
```

Output:
```
🎯 Running Scenario: Phishing → Credential Theft → Lateral Movement → Ransomware
   ID: APT-001
   Duration: 8 hours
   Expected Success Rate: 40-60%

[1/6] stage_1_initial_access
  MITRE Technique: T1566.002
  Tactic: Initial Access
  Success Rate: 15%
  Detection Points:
    - Email gateway: Suspicious sender, brand impersonation, link reputation
    - EDR: Unusual browser process spawning credential manager
    - SIEM: Comparison with legitimate O365 login failures
...
```

### 3. Generate Incident Response Drill

```bash
python3 tools/rt.py scenario --run scenario-01-phishing-to-ransomware --ir-drill
```

Output:
```
🔴 Generating IR Drill from Scenario: scenario-01-phishing-to-ransomware

📋 Drill Objectives:
  ☐ Detect phishing email before user clicks (Email security effectiveness)
  ☐ Detect credential harvesting form (Email gateway detection)
  ☐ Alert on impossible travel login (Azure AD conditional access)
  ☐ Block RDP lateral movement (Network segmentation)
  ☐ Detect scheduled task creation (EDR/SIEM response time)
  ☐ Prevent log clearing (Immutable logging effectiveness)
  ☐ Stop ransomware execution (EDR behavior detection)
  ☐ Recover from offline backup (RTO measurement)

✅ Drill plan saved: reports/ir-drill-scenario-01-phishing-to-ransomware-20260806.json
```

### 4. View MITRE ATT&CK Coverage

```bash
python3 tools/rt.py scenario --mitre-report
```

Output:
```
📊 MITRE ATT&CK Framework Coverage

  Initial Access
    Implementation: 6/13 (46%)
    Detection Difficulty: Medium

  Execution
    Implementation: 8/14 (57%)
    Detection Difficulty: Medium
...
Average Coverage: 65.2%
```

---

## 📊 Scenario Details

### APT-001: Phishing → Ransomware (8 hours)

**Attack Chain** (6 stages):

1. **Initial Access** (T1566.002 - Phishing Link)
   - Attacker sends phishing email with credential harvesting link
   - 15% success rate, 5 minutes to compromise
   - Detection: Email gateway spam filters, URL reputation

2. **Credential Access** (T1598.003 - Credential Harvesting)
   - User clicks link, enters credentials on fake O365 login form
   - 85% success rate if user clicks, 1 minute to capture
   - Detection: Azure AD impossible travel detection

3. **Lateral Movement** (T1021.001 - RDP)
   - Attacker uses stolen credentials to access internal systems
   - 70% success rate, 2 hours to pivot
   - Detection: EDR process analysis, network segmentation

4. **Persistence** (T1053.005 - Scheduled Task)
   - Attacker creates hidden backdoor task for continued access
   - 60% success rate, 3 minutes to install
   - Detection: Windows Event ID 106, EDR monitoring

5. **Defense Evasion** (T1070.001 - Log Deletion)
   - Attacker clears event logs to hide evidence
   - 50% success rate, 1 minute to clear
   - Detection: Centralized immutable logging

6. **Impact** (T1486 - Ransomware)
   - Attacker deploys ransomware, encrypts files, demands payment
   - 85% success rate, 15 minutes to deployment
   - Detection: EDR behavioral detection, offline backups for recovery

**Critical Gaps**:
- Credential theft not detected for 4-6 hours
- RDP lateral movement blends with normal traffic
- Persistence task creation not monitored
- Log clearing succeeds before centralization

**Time-to-Detection vs. Attacker Dwell Time**:
- Detection: 6 hours
- Response: 2 hours
- Attacker advantage: 4 hours to establish persistence

---

### APT-002: Supply Chain Attack (30 days)

**Attack Chain** (9 stages):

1. **Reconnaissance** - Identify popular open-source project (npm, PyPI, Maven)
2. **Compromise Maintainer** - Phish or social engineer project owner
3. **Inject Malicious Code** - Hidden backdoor in legitimate commit
4. **Release Malicious Version** - Publish to public registry
5. **Payload Activation** - Backdoor activates when package installed
6. **Credential Exfiltration** - Steal build secrets (AWS, GitHub tokens)
7. **Lateral Movement** - Access downstream systems using stolen credentials
8. **Persistent Access** - Install backdoor for long-term access
9. **Widespread Compromise** - Thousands of organizations compromised

**Success Rate by Detection Stage**:
- Stage 1-2: 10% if detected
- Stage 3-4: 30% if detected
- Stage 5-6: 75% if detected
- Stage 7-8: 98% if detected
- Stage 9: 100% (containment too late)

**Business Impact**: $1-50 billion (SolarWinds = $18B)

---

## 🔍 Detection Mapping

### MITRE ATT&CK Techniques → Detection Methods

#### T1566.002 (Phishing - Spearphishing Link)
- Email gateway URL reputation scanning
- Email sandbox detonation
- DMARC/SPF/DKIM verification
- **Effectiveness**: 60%, **False Positives**: 5%

#### T1598.003 (Phishing for Information - Credential Harvesting)
- Azure AD impossible travel detection
- Unusual device registration alerts
- MFA push authentication anomalies
- **Effectiveness**: 75%, **False Positives**: 10%

#### T1021.001 (Remote Services - RDP)
- Network flow analysis (unusual RDP sources)
- EDR process tree analysis
- Failed login attempt patterns
- **Effectiveness**: 70%, **False Positives**: 15%

#### T1053.005 (Scheduled Task/Job)
- Windows Event ID 106 monitoring
- Behavioral EDR detection
- Registry monitoring (HKLM\\Schedule)
- **Effectiveness**: 80%, **False Positives**: 3%

#### T1070.001 (Indicator Removal - Clear Logs)
- Windows Event ID 1102 alert
- Centralized immutable logging
- Event log timeline gap detection
- **Effectiveness**: 95%, **False Positives**: 1%

#### T1486 (Data Encrypted for Impact - Ransomware)
- EDR behavioral detection (mass encryption)
- SIEM file modification patterns
- Network egress monitoring
- **Effectiveness**: 85%, **False Positives**: 2%

---

## 🎯 Incident Response Drills

Six automated IR drills test detection, response, and recovery:

| Drill ID | Name | Scenario Stage | Current Score |
|----------|------|----------------|---|
| IR-Drill-001 | Phishing Detection | Initial Access | 35% |
| IR-Drill-002 | Credential Theft Response | Credential Access | 12% |
| IR-Drill-003 | Lateral Movement Containment | Lateral Movement | 5% |
| IR-Drill-004 | Persistence Removal | Persistence | 0% |
| IR-Drill-005 | Log Deletion Prevention | Defense Evasion | 0% |
| IR-Drill-006 | Ransomware Recovery | Impact | 10% |

**Target Scoring**: 85% overall  
**Current Overall**: 12%  
**Gap Analysis**: EDR, network segmentation, immutable logging not in place

---

## 🔐 Fix Roadmap

### Priority 1 (30 days)
- [ ] EDR detection of scheduled task creation (IR-Drill-004)
- [ ] Centralized immutable logging implementation (IR-Drill-005)
- [ ] Email sandbox for URL detonation (IR-Drill-001)

### Priority 2 (45 days)
- [ ] Azure AD conditional access configuration (IR-Drill-002)
- [ ] Network segmentation for RDP restriction (IR-Drill-003)
- [ ] Baseline RDP source IP alerting

### Priority 3 (90 days)
- [ ] Supply chain attack detection (APT-002 specific)
- [ ] SBOM verification in CI/CD pipeline
- [ ] Build secret rotation automation
- [ ] Backup recovery RTO validation (IR-Drill-006)

---

## 🛠️ Execution Framework

### Running a Scenario in Your Environment

```bash
# Option 1: Simulate scenario (analysis only, no real execution)
python3 tools/rt.py scenario --run scenario-01-phishing-to-ransomware

# Option 2: With network traffic capture (tcpdump/Wireshark)
python3 tools/rt.py scenario --run scenario-01-phishing-to-ransomware --record-traffic

# Option 3: With full log capture for forensics
python3 tools/rt.py scenario --run scenario-01-phishing-to-ransomware --capture-logs

# Option 4: Generate IR drill from scenario
python3 tools/rt.py scenario --run scenario-01-phishing-to-ransomware --ir-drill
```

### Pre-Drill Checklist

- [ ] Notify IR team and management
- [ ] Set up isolated lab environment (or agreed test window)
- [ ] Backup all production systems
- [ ] Verify SIEM/EDR are recording
- [ ] Prepare incident response runbook
- [ ] Have management approval to proceed

### During Drill

- [ ] Start traffic capture and log collection
- [ ] Inject scenario stages into test environment
- [ ] Record all detection alerts with timestamps
- [ ] Measure IR team response time
- [ ] Document automated response steps needed

### Post-Drill

- [ ] Calculate drill score vs. target metrics
- [ ] Identify detection gaps
- [ ] Interview IR team for lessons learned
- [ ] Generate fix task list
- [ ] Schedule follow-up drills for failed areas

---

## 📈 Effectiveness Metrics

Each scenario generates metrics:

```json
{
  "scenario": "APT-001",
  "total_stages": 6,
  "detection_gaps": 5,
  "time_to_detection_hours": 6,
  "time_to_response_hours": 2,
  "attacker_dwell_time_advantage_hours": 4,
  "success_rate_if_detected": {
    "stage_1": "0%",
    "stage_2": "15%",
    "stage_3": "40%",
    "stage_4": "70%",
    "stage_5": "85%",
    "stage_6": "95%"
  }
}
```

**Key Insight**: Detection timing matters. Early detection (Stage 1-2) reduces impact from 95% to 15%. Current 6-hour delay means attacker succeeds 70%+ of the time.

---

## 🔗 Integration with Other Tools

### SIEM/Logging Integration
- Feed scenario data to SIEM for playback
- Validate detection rules against scenarios
- Test correlation rules and workflows

### EDR Integration
- Configure EDR for scenario behavior
- Test detection rules and alerting
- Measure agent performance impact

### Threat Intelligence
- Export scenario IOCs to threat feed
- Test threat intelligence platform capabilities
- Validate detection rule updates

### SOAR Automation
- Automate incident response workflows
- Test playbook execution
- Measure time-to-fix

---

## 📚 Additional Scenarios (In Development)

- **Account Takeover via 2FA Bypass** (SMS interception, backup code abuse)
- **Insider Threat Detection** (Unusual data access patterns)
- **Ransomware-as-a-Service Distribution** (Affiliate network deployment)
- **API-Based Supply Chain Attack** (Dependency confusion attacks)
- **Hardware Supply Chain Compromise** (Firmware backdoors)

---

## 🤝 Authorized Use

This framework is intended for:

✅ **Authorized Security Testing**:
- Penetration testing engagements
- Red team exercises
- Incident response drills
- Security research and validation
- CTF competitions

❌ **Unauthorized Testing**:
- Attacks against systems without authorization
- Malware development for criminal purposes
- Credential harvesting in production
- Supply chain attacks on real targets

**Always obtain written authorization before testing.**

---

## 📖 References

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CIS Controls](https://www.cisecurity.org/controls)

---

**Last Updated**: 2026-08-06  
**Maintained By**: Red Team Framework  
**Next Review**: 2026-11-06 (quarterly)
