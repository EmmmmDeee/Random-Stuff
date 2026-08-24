# 🔭 Intelligence-Led Reconnaissance (OSINT Phase)

Reconnaissance is the opening phase of an intelligence-led engagement — the
TIBER-EU / CBEST "Threat Intelligence" phase, and the MITRE ATT&CK
**Reconnaissance** tactic (TA0043). Before emulating an actor, an authorized red
team maps the target's *externally visible attack surface* the way a real
adversary would, so the emulation is grounded in what an attacker could actually
discover.

This directory implements that phase as a **planner and footprint-reduction
tool** — it produces the recon *plan* and the corresponding *security*
recommendations. It does **not** perform collection.

---

## ⛔ Authorization Gate — read first

This models the recon phase of a **contracted, authorized** security engagement.
It is **not** a tool for profiling non-consenting people or organizations.

Before any recon activity:

- [ ] **Signed authorization** from the target organization (or you are the target)
- [ ] **Defined scope** — exactly which domains, IP ranges, and org names are in scope
- [ ] **Rules of Engagement (RoE)** — passive vs. active limits, timing, contacts
- [ ] **Passive by default** — active techniques (anything that touches target
      infrastructure, e.g. port/vuln scanning) require *explicit* written approval
- [ ] **Legal review** where required (data-protection law governs personal-data handling)

Active scanning of systems you are not authorized to test is unlawful in most
jurisdictions. Passive OSINT still carries privacy obligations. When in doubt,
stay passive and consult the engagement's legal/compliance contact.

---

## Passive vs. Active

| | Passive | Active |
|-|---------|--------|
| **Touches target?** | No — queries third-party/open sources | Yes — sends packets to target infra |
| **Detectable by target?** | Essentially no | Yes (IDS/firewall/rate limits) |
| **Authorization** | In scope by default | Requires **explicit** RoE approval |
| **Examples** | DNS/WHOIS/CT logs, scan databases (Shodan), breach corpora, public repos | Port scanning, vuln scanning, service probing |

The framework defaults to **passive**. Active techniques are flagged
`requires_explicit_authorization` and excluded from a generated plan unless you
pass the explicit authorization flag.

---

## The dual-use principle (why this is defensively anchored)

Every recon technique in [`attack-surface.json`](attack-surface.json) carries
three fields beyond the offensive description:

- **`defensive_counter`** — how the target reduces or removes that exposure
- **`detection_signal`** — whether the target can even *see* this recon (mostly
  they can't — which is the teaching point: passive OSINT is countered by
  *footprint reduction*, not detection)
- **`mitre_id`** — the ATT&CK Reconnaissance technique it emulates

So the same run produces two artifacts: the **recon checklist** (offensive plan)
and the **footprint-reduction report** (security fixes). A blue team can
run this against their *own* org to find what they're leaking.

---

## Techniques covered (mapped to ATT&CK TA0043)

| ID | Technique | ATT&CK | Passive/Active |
|----|-----------|--------|----------------|
| R-DNS | Domain & DNS enumeration | T1590.002 | Passive |
| R-WHOIS | WHOIS / registration data | T1596.002 | Passive |
| R-CERT | TLS certificate-transparency mining | T1596.003 | Passive |
| R-SCANDB | Internet scan-database lookup (Shodan/Censys) | T1596.005 | Passive |
| R-SCAN-ACTIVE | Active port/vuln scanning | T1595.002 | **Active** ⚠ |
| R-EMAIL | Email & naming-convention harvesting | T1589.002 | Passive |
| R-BREACH | Breach-corpus credential-exposure review | T1589.001 | Passive |
| R-CODE | Public code-repo & secrets review | T1593.003 | Passive |
| R-SOCIAL | Social media & employee profiling | T1593.001 | Passive |
| R-ORG | Organizational & business-tempo profiling | T1591.003 | Passive |
| R-OWNED-WEB | Victim-owned website content review | T1594 | Passive |

---

## Usage

The planner takes an **authorized scope** and emits a structured plan. It never
contacts a target — it organizes *what an authorized tester would review* and the
*security fixes* for each.

Run from the `red-team/` directory:

```bash
# Passive-only recon plan for an authorized scope
python3 tools/rt.py recon --org "Acme Corp" --domain acme.example --plan

# Include active techniques (ONLY with signed authorization)
python3 tools/rt.py recon --org "Acme Corp" --domain acme.example --plan --authorize-active

# Security mode: generate the footprint-reduction report for your OWN org
python3 tools/rt.py recon --org "Acme Corp" --domain acme.example --security
```

The `--security` report is the recommended starting point if you own the
domain: it tells you what you're leaking and how to close it, without planning
any offensive activity at all.

For an **individual** footprint check (yourself, on your own accounts), see
[`self-audit.md`](self-audit.md) — a run-it-yourself checklist that surfaces the
same exposures a passive OSINT pass would (breaches, leaked secrets, public PII,
cert/DNS leaks) with the fix for each. It is a self-audit, not reconnaissance on
anyone; the framework performs no collection against people.

---

## Where recon feeds the rest of the framework

```
reconnaissance/  ──►  threat-actors.json  ──►  rt derive  ──►  rt scenario --run
   (what the           (who targets us)        (build emulation)       (execute + measure)
    adversary
    can see)
        │
        └──►  footprint-reduction report  ──►  hunt-queries.md / correlation-and-coverage.md
              (shrink the attack surface)       (detect what recon you CAN see — active scans)
```

Recon defines the realistic entry points; the actor profiles say who would use
them; scenario derivation turns that into an emulation; the detection layers
confirm you'd catch it. The **footprint-reduction report** closes the loop on the
passive exposure that detection alone can't catch.

---

## Data sources & references

- [MITRE ATT&CK: Reconnaissance (TA0043)](https://attack.mitre.org/tactics/TA0043/)
- [OSINT Framework](https://osintframework.com/)
- [PTES — Intelligence Gathering](http://www.pentest-standard.org/index.php/Intelligence_Gathering)
- [TIBER-EU Framework](https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html)

---

**Last Updated**: 2026-08-06
**Framework Version**: 1.0
