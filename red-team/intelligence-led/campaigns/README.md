# Campaigns

Documented, named intrusion **campaigns** (MITRE ATT&CK `Cxxxx`) mapped into the
intelligence-led framework. A campaign is a real, time-bounded set of activity
attributed to an actor — more concrete than a threat-actor profile, because the
TTPs are the ones actually observed in that operation.

Each campaign profile carries, per technique: the ATT&CK ID, tactic, how it was
used in the campaign, whether it's **detectable in the victim environment**, and
a `detection_ref` pointing at the hunt/correlation query that catches it.

## Campaigns covered

| ID | Name | Actor | When | Note |
|----|------|-------|------|------|
| [C0062](C0062-ai-orchestrated.json) | AI-orchestrated Campaign | GTG-1002 (China-nexus) | Sep 2025 | AI-agent-driven intrusion of ~30 orgs |

## Why C0062 is worth modeling

It's the **AI-orchestrated** threat class: human operators drove AI agents +
tooling to run reconnaissance → exploitation → lateral movement → credential
harvesting → collection → exfiltration with minimal human involvement, against
~30 technology, financial, chemical, and government targets.

The security insight isn't exotic tradecraft — it's **tempo and volume**:

- **The kill chain is conventional and detectable.** 20 of its 26 techniques are
  observable in the victim environment (the other 6 are resource-development:
  obtaining AI/tooling, building exploits — invisible to the target). Existing
  detections still apply.
- **AI collapses the timeline.** Recon-to-exfil runs at machine speed, so the
  gap between "alert fires" and "attacker has already moved on" shrinks. The fix
  is *latency*: faster alerting and automated containment, not new signatures.
- **Volume anomalies beat single signals.** Machine-speed bulk collection
  (T1119) and east-west fan-out (T1046/T1049) are the clearest tells. Per-entity
  baselines (`detection-mapping/correlation-and-coverage.md` A-02) catch what
  human-paced thresholds miss.

## Highest-value detections for C0062

| Campaign TTP | Detect with |
|--------------|-------------|
| T1119 Automated Collection | A-02 file-access spike above the account's own baseline — the clearest AI-tempo tell |
| T1190 SSRF exploit | H-14 web-process-spawns-shell / H-15 web-shell drop |
| T1136.001 Local backdoor account | Windows Event ID 4720 on servers |
| T1078 Valid Accounts | C-01 risky-sign-in → lateral-movement correlation |
| T1567 Exfil over web service | H-13 cloud-exfil egress anomaly |

## How campaigns feed the pipeline

```
campaigns/  ──►  (its TTPs)  ──►  Navigator layer (coverage heatmap)
    │                          └►  detection-mapping (do we catch each TTP?)
    └──►  emulation plan (which observed TTPs to exercise, in order)
```

Adding a campaign's techniques automatically folds them into the ATT&CK
Navigator coverage heatmap — regenerate it after adding one:

```bash
python3 tools/rt.py navigator   # from the red-team/ directory
```

## Source & caution

All data is from public MITRE ATT&CK campaign pages
(`https://attack.mitre.org/campaigns/<ID>/`). Profiles support security
emulation and detection engineering — they are not attribution claims about any
specific real-world incident.

---

**Last Updated**: 2026-08-24
