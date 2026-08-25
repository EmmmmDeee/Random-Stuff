# Red-Team Framework: Unified Architecture & Execution Model

**Purpose**: Master consolidation document establishing cohesive data flows, cross-references, and unified execution model for the intelligence-led red-team framework.

**Date**: 2026-08-24  
**Status**: Consolidation Schema v1.0

---

## I. Unified Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    INTELLIGENCE-LED FRAMEWORK                       │
│                  (TLPT / TIBER-EU / CBEST Model)                   │
└─────────────────────────────────────────────────────────────────────┘

PHASE 1: INTELLIGENCE GATHERING & TARGETING
  ├─ threat-actors.json          ← profiles with TTPs, sectors, motivations
  ├─ targeting-model.json        ← sector↔actor mappings, priority scoring
  └─ attack-surface.json         ← reconnaissance exposure for target org

PHASE 2: SCENARIO DERIVATION & PLANNING
  ├─ rt.py derive                ← actor+sector → attack_chain generation
  ├─ scenario-01/02.json         ← executable attack scenarios with success rates
  └─ tti-report-template.md      ← threat intelligence basis for emulation

PHASE 3: EXECUTION & MEASUREMENT
  ├─ rt.py scenario --run        ← scenario execution with stage detection
  ├─ ir-drill framework          ← drill execution: detection→response→recovery
  └─ reports/ (generated)        ← execution outcomes + gap analysis

PHASE 4: DETECTION ENGINEERING
  ├─ C0062-ai-orchestrated.json  ← campaign TTP reference
  ├─ detections.json             ← hunt queries (H-##), correlations (C-##), baselines (B-##)
  ├─ hunt-queries.md             ← executable detection queries by tactic
  └─ correlation-and-coverage.md ← baseline per-entity rates, multi-signal detection

PHASE 5: FOOTPRINT REDUCTION
  ├─ rt.py recon --footprint-reduction  ← org's exposed attack surface
  ├─ self-audit.json/md          ← internal controls gap checklist
  └─ counter_measure (from attack-surface) ← fixes for each exposure

FRAMEWORK INTEGRATION & SEARCH
  └─ Huntsman Search Engine (HSE)
     ├─ detections.json    (tier=detection: H-##, C-##, B-##)
     ├─ self-audit.json    (tier=self-audit: SA-##)
     ├─ attack-surface.json (tier=recon: R-## with counter_measure)
     └─ unified search across all three tiers
```

---

## II. Data Entity Relationships & Cross-References

### A. Threat Actor → Targeting → Scenario Flow

**Entity: ThreatActor** (threat-actors.json)
```json
{
  "id": "APT29",
  "target_sectors": ["Government", "Technology"],
  "characteristic_ttps": [
    {"tactic": "Initial Access", "technique": "T1195.002"},
    {"tactic": "Credential Access", "technique": "T1528"}
  ]
}
```

**Entity: TargetingModel** (targeting-model.json)
```json
{
  "sector": "Government",
  "threats": [
    {"actor_id": "APT29", "probability": 0.95, "campaigns": ["C0062"]},
    {"actor_id": "LAZARUS", "probability": 0.60, "campaigns": []}
  ]
}
```

**Derivation: rt.py derive**
- **Input**: ThreatActor + Sector
- **Output**: AttackScenario with stages derived from actor's characteristic_ttps
- **Logic**: For each TTP → map to MITRE tactic → build scenario stage
- **Cross-ref**: Scenario.stages[] contain scenario_id → detection.json (what detects each stage)

### B. Scenario → Execution → Drill Measurement

**Entity: AttackScenario** (scenario-01/02.json)
```json
{
  "id": "scenario-01",
  "stages": [
    {
      "tactic": "Initial Access",
      "technique": "T1566.002",
      "action_description": "Send phishing email with credential harvesting link",
      "detection_points": [
        "Email gateway: URL reputation",
        "SIEM: Credential harvesting pattern"
      ]
    }
  ]
}
```

**Entity: IncidentResponseDrill** (drill-framework.json)
```json
{
  "drill_id": "IR-Drill-001",
  "scenario_source": "APT-001 (Stage 1)",
  "success_criteria": {
    "email_blocked_percent": 100,
    "alert_time_minutes": 5
  },
  "current_performance": {
    "email_blocked_percent": 70,
    "score": 35
  }
}
```

**Execution Flow**:
1. `rt.py scenario --run scenario-01` → inject stages
2. `rt.py scenario --run scenario-01 --ir-drill` → measure detection/response
3. **Cross-ref**: Each stage's detection_points → hunt-queries.md entry
4. **Outcome**: Drill score vs. success_criteria = gap analysis

### C. Campaign → Detection → Hunt Query Chain

**Entity: Campaign** (C0062-ai-orchestrated.json)
```json
{
  "techniques": [
    {
      "mitre_id": "T1119",
      "name": "Automated Collection",
      "detectable_in_victim_env": true,
      "detection_ref": "correlation A-02 (file-access spike above baseline)"
    }
  ]
}
```

**Entity: Detection** (detections.json)
```json
{
  "id": "A-02",
  "tier": "detection",
  "tactic": "Collection",
  "technique": "T1119",
  "detection_name": "File Access Spike Above Baseline",
  "data_source": "File system audit",
  "query": "...correlation logic...",
  "associated_campaigns": ["C0062"]
}
```

**Lookup Flow**:
- Campaign T1119 → detection_ref "A-02"
- HSE: `hse search "T1119"` → lists C0062, A-02 detection
- Hunt: `hse show A-02` → full query + how to tune

### D. Reconnaissance → Counter-Measure → Footprint-Reduction

**Entity: ReconTechnique** (attack-surface.json)
```json
{
  "id": "R-DNS",
  "mitre_id": "T1590.002",
  "what_it_reveals": "Subdomains, mail servers, DNS records",
  "counter_measure": "Audit external DNS for stale records; remove wildcards",
  "detection_signal": "Undetectable (passive)"
}
```

**Entity: SelfAudit** (self-audit.json)
```json
{
  "id": "SA-03",
  "control_name": "DNS Hygiene",
  "technique_covered": "T1590.002",
  "priority": "P1",
  "fix": "Audit external DNS; remove stale/dev records"
}
```

**Execution Flow**:
- `rt.py recon --footprint-reduction` → lists all exposures + counter_measures
- `rt.py recon --org Acme --security` → footprint report with fixes
- **Cross-ref**: R-DNS counter_measure = SA-03 fix
- HSE: `hse list --tier recon` → all 11 reconnaissance techniques
- HSE: `hse search "DNS"` → R-DNS + SA-03 + H-## detections if active scan

---

## III. Master Execution Framework

### Phase Workflow (Execution Sequence)

```
STEP 1: RECONNAISSANCE (Passive OSINT)
────────────────────────────────────
  $ rt.py recon --org "Acme Corp" --domain acme.example --plan
  
  OUTPUT: Recon checklist (what to review)
  
  SECURITY MODE:
  $ rt.py recon --org "Acme Corp" --domain acme.example --footprint-reduction
  
  OUTPUT: Footprint-reduction report (what to fix)
  CROSS-REF: Each R-## technique → counter_measure + SA-## self-audit mapping


STEP 2: THREAT INTELLIGENCE & TARGETING
────────────────────────────────────────
  Read: threat-actors.json (who targets your sector?)
  Read: targeting-model.json (priority scores for your sector)
  Read: tti-report-template.md (threat assessment basis)
  
  OUTPUT: Threat actor selection for emulation (e.g., APT29 for Government)


STEP 3: SCENARIO DERIVATION
─────────────────────────────
  $ rt.py derive --sector "Government" --actor "APT29" --build-scenario
  
  INPUT: ThreatActor TTPs + Sector recon exposure (R-DNS, R-EMAIL, etc.)
  LOGIC: Combine recon findings with actor techniques → attack chain
  OUTPUT: Derived scenario (custom for your org + threat)
  
  ALT: Use pre-built scenarios (scenario-01, scenario-02)


STEP 4: SCENARIO EXECUTION & MEASUREMENT
───────────────────────────────────────────
  $ rt.py scenario --run scenario-01
  
  DURING EXECUTION:
    - Inject stage 1 (phishing) → measure detection time
    - Inject stage 2 (credential theft) → measure response time
    - Inject stage 3-6 (lateral→ransomware) → measure containment
  
  OUTPUT: Execution report (detection gaps, dwell time, success rate per stage)
  CROSS-REF: Each stage → hunt-queries.md (what should detect it?)


STEP 5: INCIDENT RESPONSE DRILL
─────────────────────────────────
  $ rt.py scenario --run scenario-01 --ir-drill
  
  INPUT: scenario-01 stages + drill-framework.json drill definitions
  EXECUTION:
    - Pre-drill checklist (obtain management approval, backup systems)
    - During drill: inject + measure detection/response times
    - Post-drill: compare actual vs. success_criteria → gap analysis
  
  OUTPUT: Drill scores + fix priorities (P1/P2/P3)
  CROSS-REF: Gap analysis → MITRE techniques uncovered


STEP 6: DETECTION ENGINEERING & HUNT
──────────────────────────────────────
  $ hse search "T1119" (or scenario_id or campaign_id)
  
  RESULTS: All detections for that technique across tiers:
    - tier=detection: H-##, C-##, B-## (hunt queries, correlations, baselines)
    - tier=campaign: C0062 mapping
    - tier=recon: R-## (if active scanning)
  
  WORKFLOW:
    1. Identify uncovered technique from Step 5 gap analysis
    2. HSE search → find related detections / hunt queries
    3. Tune hunt query for your environment (see hunt-queries.md)
    4. Test in SIEM/EDR with scenario data from Step 4
    5. Update detections.json with tuned query


STEP 7: FOOTPRINT REDUCTION & REMEDIATION
───────────────────────────────────────────
  From Step 1: Use footprint-reduction report
  
  WORKFLOW:
    1. For each R-## exposure: read counter_measure field
    2. Cross-ref with self-audit.json (SA-##) for related control
    3. Prioritize by sector risk + actor targeting (from targeting-model.json)
    4. Execute fixes in order: rotate secrets → shrink surface → confirm detection
  
  VERIFICATION:
    $ rt.py recon --org "Acme" --footprint-reduction (re-run to confirm)


STEP 8: CONTINUOUS IMPROVEMENT LOOP
──────────────────────────────────────
  QUARTERLY:
    1. Re-run reconnaissance to identify new exposures
    2. Re-run scenario drill to measure improvement
    3. Update threat-actors.json / campaigns / detections with new TTPs
    4. Re-derive scenarios for new threat intelligence
    5. Tune detections for new behaviors
```

---

## IV. Unified Search & Discovery (Huntsman Search Engine)

### Three-Tier Catalog Model

**Tier 1: Detections** (`detections.json`)
- Hunt queries (H-##): specific data-source patterns
- Correlations (C-##): multi-signal detection
- Baselines (B-##): per-entity rate anomalies
- **Search by**: technique (T-code), tactic, keyword, data source
- **Returns**: Query text + tuning guidance + baseline

**Tier 2: Self-Audit** (`self-audit.json`)
- Internal controls checklist (SA-##)
- What to configure + how to verify
- **Search by**: control name, technique (T-code), priority
- **Returns**: Configuration steps + verification procedure + automated tests

**Tier 3: Reconnaissance** (`attack-surface.json`)
- Passive OSINT techniques (R-##) + counter-measures
- What adversary learns + how to block it
- **Search by**: exposure type, MITRE reconnaissance technique
- **Returns**: Exposure + counter-measure + footprint-reduction fix

### Example Unified Search Workflows

```bash
# Find all detections for a technique
$ hse search "T1119"
# Returns: A-02 (baseline), H-13 (hunt), C-01 (correlation), C0062 (campaign), R-## (recon)

# Find detections for a tactic
$ hse search "Collection"
# Returns: All H-##, C-##, B-## in Collection tactic, mapped to scenarios/campaigns

# List all reconnaissance exposures
$ hse list --tier recon
# Returns: R-01 through R-11, each with what_it_reveals + counter_measure

# Show complete entry with context
$ hse show H-14
# Returns: Hunt query (web-process-spawns-shell), 
#          data source (EDR process tree), 
#          tuning guidance,
#          related technique (T1190),
#          related campaign (C0062),
#          severity/false-positive rate

# Find self-audit controls
$ hse list --tier self-audit
# Returns: SA-01 through SA-##, with configuration steps + verification
```

---

## V. Data Flow Diagrams

### Reconnaissance → Scenario → Execution → Detection

```
attack-surface.json (org's passive exposure)
    ↓
    ├→ footprint-reduction (what to fix)
    ├→ RT-DNS, R-WHOIS, R-CERT, R-SCANDB (what adversary learns)
    └→ counter_measure fields (how to block it)
            ↓
            └→ self-audit.json mapping (SA-03 = DNS hygiene)

threat-actors.json (who targets your sector?)
    ↓
    ├→ characteristic_ttps (their observed techniques)
    ├→ campaigns (C0062: AI-orchestrated intrusion)
    └→ target_sectors (Government, Tech, Finance)
            ↓
            └→ targeting-model.json (probability score)
                    ↓
                    └→ rt.py derive --actor APT29 --sector Government
                            ↓
                            └→ scenario-01.json (derived: phishing→ransomware)
                                    ↓
                                    ├→ rt.py scenario --run scenario-01
                                    │   ↓
                                    │   └→ inject stages → measure detection
                                    │       (detection_gaps → fix_priorities)
                                    │
                                    └→ rt.py scenario --ir-drill
                                        ↓
                                        └→ drill score vs. success_criteria
                                            (current: 12%, target: 85%)
                                                ↓
                                                └→ drill-framework.json
                                                    (fix priorities P1/P2/P3)
```

### Detection Engineering Loop

```
C0062-ai-orchestrated.json (campaign with 25 techniques)
    ↓
    ├─→ T1119 Automated Collection
    │   ├─ detection_ref: "correlation A-02"
    │   ├─ detection_note: "machine-speed bulk collection"
    │   └─ detectable_in_victim_env: true
    │       ↓
    │       └─→ detections.json (A-02 entry)
    │           ├─ data_source: "File system audit"
    │           ├─ query: "per-entity file access rate anomaly"
    │           ├─ tuning: "baseline must exceed 3σ"
    │           └─ associated_campaigns: ["C0062"]
    │               ↓
    │               └─→ hunt-queries.md (A-02 section)
    │                   ├─ Exact query syntax for SIEM/EDR
    │                   ├─ False-positive tuning
    │                   ├─ Response action (isolate account)
    │                   └─ Test case (scenario-01 stage injection)
    │
    └─→ T1046 Network Service Discovery
        ├─ detection_ref: "east-west connection fan-out"
        ├─ detection_note: "machine-speed bulk discovery"
        └─ detectable_in_victim_env: true
            ↓
            └─→ detections.json (C-02 correlation entry)
                ├─ data_source: "Network flow"
                ├─ query: "single host connects to 50+ unique internal IPs in 5 min"
                ├─ tuning: "baseline per-host 1-5 unique, alert at 20+"
                └─ associated_campaigns: ["C0062"]
```

---

## VI. Cross-Reference Matrix

**Scenario Stage → Detection → Hunt Query → Drill Metric**

| Scenario | Stage | Technique | Tactic | Detection | Query | Drill | Status |
|----------|-------|-----------|--------|-----------|-------|-------|--------|
| APT-001 | 1 | T1566.002 | Initial Access | H-01 | Email URL reputation | IR-Drill-001 | ✅ Covered |
| APT-001 | 2 | T1598.003 | Credential Access | C-01 | Impossible travel → lateral movement | IR-Drill-002 | ⚠ Partial (50%) |
| APT-001 | 3 | T1021.001 | Lateral Movement | H-05, H-06 | RDP baseline anomaly | IR-Drill-003 | ❌ Uncovered |
| APT-001 | 4 | T1053.005 | Persistence | H-07 | Scheduled task creation (Event ID 106) | IR-Drill-004 | ❌ Uncovered |
| APT-001 | 5 | T1070.001 | Defense Evasion | H-12 | Centralized immutable logging | IR-Drill-005 | ❌ Uncovered |
| APT-001 | 6 | T1486 | Impact | H-16 | Mass file encryption behavior | IR-Drill-006 | ⚠ Partial (10%) |
| C0062 | Recon | T1595.002 | Reconnaissance | H-14 | Active scan rate anomaly | N/A | ✅ Covered |
| C0062 | Access | T1190 | Initial Access | H-15 | Web shell drop detection | N/A | ✅ Covered |
| C0062 | Collection | T1119 | Collection | A-02 | File access spike baseline | N/A | ⚠ Partial (60%) |
| C0062 | Exfil | T1567 | Exfiltration | H-13 | Cloud egress anomaly | N/A | ✅ Covered |

---

## VII. Consolidation Checklist

### Data Integrity
- [ ] All scenario stages have corresponding detection entries
- [ ] All threat-actor TTPs map to techniques in framework.json
- [ ] All drill objectives have associated hunt queries
- [ ] All reconnaissance techniques have counter-measures
- [ ] All campaigns cross-referenced to detections

### Execution Readiness
- [ ] rt.py scenario can execute all scenario-01, scenario-02, derived scenarios
- [ ] rt.py derive outputs executable scenarios (not just analysis)
- [ ] rt.py recon generates footprint-reduction reports
- [ ] Drill framework scores align with detection coverage
- [ ] HSE unified search works across all three tiers

### Documentation
- [ ] Phase workflow documented (reconnaissance → execution → detection)
- [ ] All CLI commands have examples + expected output
- [ ] Cross-references (T-code → detection → hunt → drill) documented
- [ ] Each tier (detection/self-audit/recon) has usage guide
- [ ] Integration points between tools clearly defined

### Automation
- [ ] Navigator layer auto-updates when campaigns added
- [ ] Scenario derivation runs deterministically from actor+sector
- [ ] Drill scoring auto-calculates from success_criteria + current_performance
- [ ] Detection queries testable against scenario execution logs

---

## VIII. Governance & Maintenance

### Quarterly Update Cycle

**Q1**: Reconnaissance audit + footprint-reduction
- Update attack-surface.json exposures
- Verify counter-measures are current
- Re-run self-audit controls

**Q2**: Threat actor refresh + scenario re-derivation
- Update threat-actors.json with new campaigns
- Re-derive scenarios for current threat landscape
- Add new C#### campaign profiles

**Q3**: Detection engineering + hunt query tuning
- Tune detections based on false-positive feedback
- Add new baselines for new techniques
- Test against scenario executions

**Q4**: Full drill cycle + strategic planning
- Execute all IR drills (APT-001, APT-002, derived)
- Measure improvement vs. baseline (currently 12%, target 85%)
- Plan next-year priorities based on gap analysis

### Version Management

- **framework.json**: MITRE ATT&CK version + date
- **threat-actors.json**: Last updated date + data source
- **scenarios**: Version tracking within each JSON
- **drills**: Execution history in reports/ directory
- **detections.json**: Query version + last tuning date

---

## IX. Next Steps for Full Consolidation

1. **Unified Index Generator** (`rt.py index`)
   - Scan all entities (actors, scenarios, campaigns, detections, drills)
   - Build consolidated cross-reference matrix
   - Output: index.json with all relationships

2. **Scenario Validation** (`rt.py validate`)
   - Verify each scenario stage has detection coverage
   - Flag uncovered techniques
   - Generate "gaps" report

3. **Drill Reconciliation** (`rt.py reconcile`)
   - Map each drill objective to scenario stage
   - Match drill success_criteria to detection effectiveness
   - Auto-calculate drill score from detections.json coverage

4. **HSE Integration** (in-progress)
   - Embed all three tiers into HSE binary
   - Unified search + discovery
   - CLI commands: `hse search`, `hse list`, `hse show`, `hse hunt`

5. **Automated Testing** (`rt.py test`)
   - Execute scenario in lab environment
   - Capture logs + EDR data
   - Validate detection queries against real data
   - Report: detection coverage % + false-positive rate

---

## Summary

This consolidation establishes the red-team framework as a **unified, interdependent system**:

- **Intelligence phase** (threat-actors + targeting) informs **emulation** (scenarios + derivation)
- **Emulation** generates **execution events** (stage injection + detection opportunities)
- **Execution** drives **detection engineering** (hunt query validation + tuning)
- **Detections** enable **remediation** (footprint reduction + self-audit fixes)
- **HSE** unifies **search & discovery** across all components

The framework moves from ad-hoc red teaming to **systematic, data-driven security validation** aligned with TLPT/TIBER-EU methodology.

---

**Document Version**: 1.0  
**Last Updated**: 2026-08-24  
**Next Review**: 2026-11-24 (quarterly)
