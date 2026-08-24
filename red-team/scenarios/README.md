# Red Team Attack Scenarios

Comprehensive multi-stage attack simulations for testing defense effectiveness across the full kill chain.

## Scenario Taxonomy

### By Attack Type
- **Initial Access** - Reconnaissance, phishing, supply chain, public exploits
- **Persistence** - Backdoors, scheduled tasks, registry modifications, web shells
- **Privilege Escalation** - Kernel exploits, credential theft, UAC bypass
- **Defense Evasion** - Log deletion, process injection, signed binary abuse
- **Lateral Movement** - Pass-the-hash, Kerberos exploitation, network pivoting
- **Exfiltration** - Data staging, compression, encryption, C2 communication

### By Industry Impact
- **Finance** - Account takeover, transaction fraud, credential harvesting
- **Healthcare** - Ransomware, patient data theft, system outage
- **Critical Infrastructure** - SCADA compromise, network segmentation bypass
- **Technology** - Supply chain attacks, developer environment compromise

### By Sophistication
- **Script Kiddie** - Known exploits, public tools, low OPSEC
- **Opportunistic Attacker** - Blended threats, credential reuse, basic evasion
- **Organized Crime** - Malware-as-a-Service, credential brokers, ransomware ops
- **State-Sponsored APT** - Multi-year campaigns, zero-days, supply chain targeting

## Scenario Structure

Each scenario includes:
- **Kill Chain** - MITRE ATT&CK technique mapping
- **Objectives** - What the attacker is trying to achieve
- **Entry Point** - How they get initial access
- **Progression** - Multi-stage attack flow
- **IOCs** - Indicators of compromise for detection
- **Defenses** - How to detect and block each stage
- **Success Criteria** - When red team achieves objective

## Running Scenarios

Run from the `red-team/` directory via the unified CLI:

```bash
# List available scenarios
python3 tools/rt.py scenario --list

# Execute a scenario (optionally noting external traffic/log capture)
python3 tools/rt.py scenario --run <stem> --record-traffic --capture-logs

# Generate an incident response drill from a scenario
python3 tools/rt.py scenario --run <stem> --ir-drill
```

## Detection Coverage Matrix

| Scenario | Detection Complexity | Time-to-Detect | Coverage |
|----------|-------------------|-----------------|----------|
| Phishing + Credential Theft | Low | 1-2 hours | Email gateway + SIEM |
| Lateral Movement + Persistence | Medium | 4-6 hours | EDR + Network monitoring |
| Ransomware Distribution | High | Minutes-Hours | Multi-layer (email + EDR + network) |
| Supply Chain Attack | Very High | Days-Weeks | Build monitoring + SBOM verification |
| Data Exfiltration | Medium-High | 2-24 hours | DLP + Egress monitoring |

---

**Last Updated**: 2026-08-06
**Framework Version**: 1.0
