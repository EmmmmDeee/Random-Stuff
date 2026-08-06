# 🎯 Intelligence-Led Testing (TLPT)

Threat-Led Penetration Testing (TLPT) is the most mature form of adversary
emulation. Instead of testing against a *generic* attacker, you emulate the
**specific threat actors that actually target your sector**, using their real
observed tactics, techniques, and procedures (TTPs).

This is the model behind the two main regulatory frameworks:

- **TIBER-EU** (Threat Intelligence-Based Ethical Red-teaming) — European Central Bank framework for financial entities
- **CBEST** — Bank of England / UK financial regulator framework

Both share the same core idea: **threat intelligence drives the test**, not the
tester's imagination.

---

## Why It's Better Than Generic Red Teaming

| Dimension | Generic Red Team | Intelligence-Led (TLPT) |
|-----------|-----------------|------------------------|
| Adversary model | Tester's choice | Real actors targeting your sector |
| TTPs used | Whatever works | The specific TTPs those actors use |
| Realism | Plausible | Evidence-based |
| Prioritization | Ad-hoc | Driven by actual threat likelihood |
| Detection value | "Can we catch attacks?" | "Can we catch *the attacks that will come*?" |

A generic red team might spend effort on techniques your real adversaries never
use, while missing the ones they favor. Intelligence-led testing aligns your
defensive investment with your actual threat landscape.

---

## The TLPT Process (5 Phases)

```
┌─────────────────────────────────────────────────────────────┐
│  1. SCOPING                                                   │
│     Define critical functions, systems, and the "flags"      │
│     (objectives) the red team will try to reach.             │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  2. THREAT INTELLIGENCE (TI Phase)                            │
│     Produce a Targeted Threat Intelligence (TTI) report:     │
│     - Which threat actors target this sector/org?            │
│     - What are their goals, TTPs, and past campaigns?       │
│     - Build attack scenarios grounded in that intel.        │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  3. RED TEAM (Emulation Phase)                               │
│     Execute the intel-derived scenarios against production   │
│     (with tight control), emulating the chosen actors.      │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  4. PURPLE TEAM / REPLAY                                      │
│     Walk the blue team through each TTP, confirm what was    │
│     detected vs. missed, and tune detections.               │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  5. REMEDIATION & CLOSURE                                     │
│     Prioritized fixes, re-test of failed detections,        │
│     and a maturity assessment.                              │
└─────────────────────────────────────────────────────────────┘
```

The distinguishing phase is **#2**. Everything the red team does flows from a
threat intelligence report, not from a generic playbook.

---

## How This Directory Implements It

```
intelligence-led/
├── README.md                  (this file — the TLPT method)
├── threat-actors.json         (adversary profiles: goals, sectors, TTPs)
├── targeting-model.json       (sector → likely-adversary mapping + scoring)
├── tti-report-template.md     (Targeted Threat Intelligence report template)
└── derive-scenario.py         (turn a threat actor profile into a test scenario)
```

### Workflow

```bash
# 1. Find out which actors most likely target your sector
python3 derive-scenario.py --sector finance --rank

# 2. Generate a Targeted Threat Intelligence summary for an actor
python3 derive-scenario.py --actor APT29 --tti

# 3. Derive an executable test scenario from that actor's real TTPs
python3 derive-scenario.py --actor FIN7 --build-scenario
```

The derived scenario plugs into the existing `run-scenario.py` runner, so an
intelligence-led scenario is tested exactly like the hand-authored APT-001/002
scenarios — the difference is *where the scenario comes from*.

---

## Threat Actor Attribution — A Caution

Attribution is hard and often uncertain. The profiles here are built from
**publicly documented** threat intelligence (MITRE ATT&CK Groups, vendor
reports, government advisories). They are useful for emulation and detection
engineering, but:

- Group names overlap across vendors (APT29 = Cozy Bear = Nobelium = Midnight Blizzard)
- TTPs evolve; a profile is a snapshot, not a permanent truth
- Emulating an actor's TTPs ≠ attributing a real incident to them

Use these profiles to answer *"can we detect the techniques this actor is known
for?"* — not to make attribution claims.

---

## Data Sources

All actor data is derived from public, defensive-security sources:

- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [CISA Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [TIBER-EU Framework](https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html)
- [CBEST Framework](https://www.bankofengland.co.uk/financial-stability/operational-resilience-of-the-financial-sector)

---

**Last Updated**: 2026-08-06
**Framework Version**: 1.0
