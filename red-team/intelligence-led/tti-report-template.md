# Targeted Threat Intelligence (TTI) Report

> The TTI report is the deliverable of the Threat Intelligence phase. Everything
> the red team does in the emulation phase must trace back to this document.

---

## 1. Engagement Context

| Field | Value |
|-------|-------|
| Organization / sector | _e.g. Regional bank / Financial Services_ |
| Critical functions in scope | _e.g. Payments, customer portal, core banking_ |
| Assessment window | _dates_ |
| Regulatory framework (if any) | _TIBER-EU / CBEST / internal_ |

---

## 2. Threat Landscape Summary

Which adversaries realistically target this organization, and why?

- **Sector targeting**: _which threat actors have a documented history against this sector_
- **Geographic / geopolitical factors**: _relevant nation-state interest, if any_
- **Recent activity**: _campaigns in the last 12-24 months affecting peers_

Use `rt derive --sector <sector>` to seed this section.

---

## 3. Prioritized Threat Actors

For each selected actor (top 1-3 by relevance):

### Actor: _<ID / alias>_

| Field | Value |
|-------|-------|
| Attribution | _from public sources_ |
| MITRE Group ID | _Gxxxx_ |
| Motivation | _espionage / financial / disruption_ |
| Sophistication | _APT / organized crime / etc._ |
| Why this org | _specific rationale tying actor to this target_ |

**Signature behaviors to emulate:**
- _behavior 1_
- _behavior 2_

**Characteristic TTPs (MITRE-mapped):**

| Tactic | Technique | ID | Emulation note |
|--------|-----------|----|----|
| Initial Access | _..._ | Txxxx | _..._ |
| ... | ... | ... | ... |

Use `rt derive --actor <ID> --tti` to populate this.

---

## 4. Derived Attack Scenarios

Concrete, executable scenarios built from the actors above. Each should specify:

- **Entry point** grounded in the actor's real initial-access tradecraft
- **Objective / flag** (what reaching it proves)
- **Stage-by-stage TTP chain** (MITRE IDs)
- **Expected detection opportunities** at each stage

Use `rt derive --actor <ID> --build-scenario` to generate a scenario
skeleton, then flesh out org-specific detail.

---

## 5. Detection Mapping (Purple-Team Prep)

The payoff of intelligence-led testing: for **every** emulated TTP, name the
detection that *should* catch it, so the purple-team replay can confirm or deny.

| TTP (ID) | Expected detection source | Rule / query | Fired? (post-test) |
|----------|--------------------------|--------------|--------------------|
| Txxxx | _SIEM / EDR / email gw_ | _rule name_ | ☐ |

---

## 6. Assumptions & Caveats

- Attribution is uncertain; profiles are emulation aids, not attribution claims.
- TTPs are a snapshot and evolve — revalidate before each engagement.
- Scope constraints / rules of engagement: _..._

---

**Prepared by**: _TI provider_
**Date**: _..._
**Classification**: _handling instructions_
