"""
`rt recon` — reconnaissance PLANNER for the Recon phase (MITRE ATT&CK TA0043)
of an AUTHORIZED engagement.

Performs NO collection: no network requests, no scraping, no queries against any
target. It organizes what an authorized tester would review and the security
fix for each item.
"""

import argparse

import attack


def _techniques():
    data = attack.load_json(attack.ATTACK_SURFACE_FILE) or {"recon_techniques": []}
    return data["recon_techniques"]


def _authorization_banner(org, domain, active):
    print("=" * 70)
    print("  AUTHORIZATION REQUIRED — authorized engagements only")
    print("=" * 70)
    print(f"  Scope org:    {org}")
    print(f"  Scope domain: {domain}")
    print(f"  Mode:         {'PASSIVE + ACTIVE' if active else 'PASSIVE only'}\n")
    print("  Confirm before proceeding:")
    print("    [ ] Signed authorization from the target organization")
    print("    [ ] This org/domain is explicitly in the defined scope")
    print("    [ ] Rules of Engagement reviewed (timing, contacts, limits)")
    if active:
        print("    [ ] ACTIVE techniques EXPLICITLY approved in writing (RoE)")
        print("        Active scanning of unauthorized systems is unlawful.")
    print("    [ ] Legal/compliance sign-off where personal data is involved")
    print("=" * 70 + "\n")


def generate_plan(org, domain, authorize_active):
    techniques = _techniques()
    _authorization_banner(org, domain, authorize_active)

    included, skipped = [], []
    for t in techniques:
        (skipped if t["activity"] == "active" and not authorize_active else included).append(t)

    print(f"🔭 RECON PLAN for {org} ({domain})\n")
    note = (f", {len(skipped)} active technique(s) EXCLUDED "
            "(pass --authorize-active with signed approval)" if skipped else "")
    print(f"   {len(included)} techniques in plan{note}\n")

    for t in included:
        flag = "⚠ ACTIVE" if t["activity"] == "active" else "passive"
        print(f"  ☐ [{t['id']}] {t['name']}  ({flag})")
        print(f"      ATT&CK:   {t['mitre_id']} — {t['mitre_name']}")
        print(f"      Reveals:  {t['what_it_reveals']}")
        print(f"      Sources:  {', '.join(t['open_sources'])}")
        print(f"      Detectable by target: {t['detection_signal']}\n")

    if skipped:
        print("  ── EXCLUDED (active — needs explicit authorization) ──")
        for t in skipped:
            print(f"     • [{t['id']}] {t['name']} ({t['mitre_id']})")
        print()
    print("  ℹ️  Every technique has a security counter-measure — run with "
          "--footprint-reduction for the footprint-reduction report.")


def generate_footprint_reduction(org, domain):
    techniques = _techniques()
    print("=" * 70)
    print(f"  FOOTPRINT-REDUCTION REPORT — {org} ({domain})")
    print("  What an adversary can learn about you, and how to shut it down.")
    print("=" * 70 + "\n")

    passive = [t for t in techniques if t["activity"] == "passive"]
    active = [t for t in techniques if t["activity"] == "active"]

    print("  PASSIVE EXPOSURE (undetectable — must be REDUCED, not just watched)\n")
    for t in passive:
        print(f"  ▸ {t['name']}  [{t['mitre_id']}]")
        print(f"      Exposure: {t['what_it_reveals']}")
        print(f"      FIX:      {t['counter_measure']}\n")

    print("  ACTIVE RECON (detectable — verify your controls FIRE)\n")
    for t in active:
        print(f"  ▸ {t['name']}  [{t['mitre_id']}]")
        print(f"      FIX:      {t['counter_measure']}")
        print(f"      DETECT:   {t['detection_signal']}\n")

    print("  PRIORITY ORDER:")
    print("    1. Rotate/close leaked secrets (R-CODE) and exposed creds (R-BREACH)"
          " — exploitable today.")
    print("    2. Shrink R-SCANDB / R-DNS / R-CERT surface (services, stale hosts, cert names).")
    print("    3. Confirm active-scan detection (R-SCAN-ACTIVE) actually alerts.")


# --- CLI wiring -------------------------------------------------------------
def add_arguments(p):
    p.add_argument("--org", required=True, help="In-scope organization name")
    p.add_argument("--domain", required=True, help="In-scope domain")
    p.add_argument("--plan", action="store_true", help="Generate the recon plan")
    p.add_argument("--authorize-active", action="store_true",
                   help="Include active techniques (requires signed authorization)")
    p.add_argument("--footprint-reduction", action="store_true",
                   help="Footprint-reduction report for your own org")


def handle(args):
    if args.footprint_reduction:
        generate_footprint_reduction(args.org, args.domain)
    elif args.plan:
        generate_plan(args.org, args.domain, args.authorize_active)
    else:
        print("Provide --plan or --footprint-reduction (with --org and --domain)")


def register(subparsers):
    p = subparsers.add_parser("recon", help="Recon planner + footprint-reduction (no collection)")
    add_arguments(p)
    p.set_defaults(func=handle)


def main():
    p = argparse.ArgumentParser(description="Reconnaissance planner (no collection performed)")
    add_arguments(p)
    handle(p.parse_args())


if __name__ == "__main__":
    main()
