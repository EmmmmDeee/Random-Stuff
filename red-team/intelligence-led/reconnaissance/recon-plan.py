#!/usr/bin/env python3
"""
Intelligence-Led Reconnaissance Planner

Generates the recon PLAN and the defensive footprint-reduction REPORT for the
Reconnaissance phase (MITRE ATT&CK TA0043) of an AUTHORIZED engagement.

IMPORTANT — this tool PLANS and ADVISES. It performs NO collection: no network
requests, no scraping, no queries against any target. It organizes what an
authorized tester would review and the defensive fix for each item.

Usage:
    recon-plan.py --org "Acme Corp" --domain acme.example --plan
    recon-plan.py --org "Acme Corp" --domain acme.example --plan --authorize-active
    recon-plan.py --org "Acme Corp" --domain acme.example --defensive
"""

import json
import argparse
from pathlib import Path

HERE = Path(__file__).parent
SURFACE_FILE = HERE / "attack-surface.json"


def load_techniques():
    with open(SURFACE_FILE) as f:
        return json.load(f)["recon_techniques"]


def _authorization_banner(org, domain, active):
    print("=" * 70)
    print("  AUTHORIZATION REQUIRED — authorized engagements only")
    print("=" * 70)
    print(f"  Scope org:    {org}")
    print(f"  Scope domain: {domain}")
    print(f"  Mode:         {'PASSIVE + ACTIVE' if active else 'PASSIVE only'}")
    print()
    print("  Confirm before proceeding:")
    print("    [ ] Signed authorization from the target organization")
    print("    [ ] This org/domain is explicitly in the defined scope")
    print("    [ ] Rules of Engagement reviewed (timing, contacts, limits)")
    if active:
        print("    [ ] ACTIVE techniques EXPLICITLY approved in writing (RoE)")
        print("        Active scanning of unauthorized systems is unlawful.")
    print("    [ ] Legal/compliance sign-off where personal data is involved")
    print("=" * 70)
    print()


def generate_plan(org, domain, authorize_active):
    techniques = load_techniques()

    _authorization_banner(org, domain, authorize_active)

    included = []
    skipped_active = []
    for t in techniques:
        if t["activity"] == "active" and not authorize_active:
            skipped_active.append(t)
        else:
            included.append(t)

    print(f"🔭 RECON PLAN for {org} ({domain})\n")
    print(f"   {len(included)} techniques in plan"
          + (f", {len(skipped_active)} active technique(s) EXCLUDED "
             "(pass --authorize-active with signed approval)"
             if skipped_active else "")
          + "\n")

    for t in included:
        flag = "⚠ ACTIVE" if t["activity"] == "active" else "passive"
        print(f"  ☐ [{t['id']}] {t['name']}  ({flag})")
        print(f"      ATT&CK:   {t['mitre_id']} — {t['mitre_name']}")
        print(f"      Reveals:  {t['what_it_reveals']}")
        print(f"      Sources:  {', '.join(t['open_sources'])}")
        print(f"      Detectable by target: {t['detection_signal']}")
        print()

    if skipped_active:
        print("  ── EXCLUDED (active — needs explicit authorization) ──")
        for t in skipped_active:
            print(f"     • [{t['id']}] {t['name']} ({t['mitre_id']})")
        print()

    print("  ℹ️  Every technique above has a defensive counter-measure — run")
    print("      with --defensive to generate the footprint-reduction report.")


def generate_defensive(org, domain):
    techniques = load_techniques()

    print("=" * 70)
    print(f"  FOOTPRINT-REDUCTION REPORT — {org} ({domain})")
    print("  What an adversary can learn about you, and how to shut it down.")
    print("=" * 70)
    print()

    # Passive exposure is the priority: it is undetectable, so the only defense
    # is removing the exposure.
    passive = [t for t in techniques if t["activity"] == "passive"]
    active = [t for t in techniques if t["activity"] == "active"]

    print("  PASSIVE EXPOSURE (undetectable — must be REDUCED, not just watched)\n")
    for t in passive:
        print(f"  ▸ {t['name']}  [{t['mitre_id']}]")
        print(f"      Exposure: {t['what_it_reveals']}")
        print(f"      FIX:      {t['defensive_counter']}")
        print()

    print("  ACTIVE RECON (detectable — verify your controls FIRE)\n")
    for t in active:
        print(f"  ▸ {t['name']}  [{t['mitre_id']}]")
        print(f"      FIX:      {t['defensive_counter']}")
        print(f"      DETECT:   {t['detection_signal']}")
        print()

    print("  PRIORITY ORDER:")
    print("    1. Rotate/close anything in R-CODE (leaked secrets) and R-BREACH")
    print("       (exposed creds) — these are directly exploitable today.")
    print("    2. Shrink R-SCANDB / R-DNS / R-CERT surface (exposed services,")
    print("       stale hosts, internal names in certs).")
    print("    3. Confirm active-scan detection (R-SCAN-ACTIVE) actually alerts.")


def main():
    parser = argparse.ArgumentParser(
        description="Intelligence-led reconnaissance PLANNER (no collection performed)"
    )
    parser.add_argument("--org", required=True, help="In-scope organization name")
    parser.add_argument("--domain", required=True, help="In-scope domain")
    parser.add_argument("--plan", action="store_true", help="Generate the recon plan")
    parser.add_argument("--authorize-active", action="store_true",
                        help="Include active techniques (requires signed authorization)")
    parser.add_argument("--defensive", action="store_true",
                        help="Generate the footprint-reduction report for your own org")

    args = parser.parse_args()

    if args.defensive:
        generate_defensive(args.org, args.domain)
    elif args.plan:
        generate_plan(args.org, args.domain, args.authorize_active)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
