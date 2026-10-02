"""
`rt derive` — intelligence-led scenario derivation: rank actors by sector,
print Targeted Threat Intelligence, and derive scenarios from actor TTPs.
"""

import argparse

import attack


def _actors():
    data = attack.load_json(attack.THREAT_ACTORS_FILE) or {"threat_actors": []}
    return {a["id"]: a for a in data["threat_actors"]}


def rank_sector(sector):
    targeting = attack.load_json(attack.TARGETING_FILE)
    if not targeting:
        return
    sectors = targeting["sectors"]
    if sector not in sectors:
        print(f"❌ Unknown sector '{sector}'. Known sectors:")
        for key, val in sectors.items():
            print(f"   - {key} ({val['display_name']})")
        return

    info = sectors[sector]
    print(f"\n🎯 Threat Ranking for: {info['display_name']}\n")
    print(f"   Primary threat themes: {', '.join(info['primary_threat_themes'])}\n")
    print("   Emulate in this order (highest probability first):\n")
    for rank, threat in enumerate(info["top_threats"], 1):
        print(f"   {rank}. {threat['actor']}  (relevance {threat['relevance_score']}/10)")
        print(f"      {threat['rationale']}\n")
    print("   Guidance:")
    for line in targeting["selection_guidance"]["coverage_strategy"]:
        print(f"     • {line}")
    print()


def print_tti(actor_id):
    actor = _actors().get(actor_id)
    if not actor:
        print(f"❌ Unknown actor '{actor_id}'. Known actors: {', '.join(_actors())}")
        return

    bar = "=" * 62
    print(f"\n{bar}\n  TARGETED THREAT INTELLIGENCE — {actor['id']}\n{bar}\n")
    print(f"  Aliases:        {', '.join(actor['aliases'])}")
    print(f"  Attribution:    {actor['attributed_to']}")
    print(f"  MITRE Group:    {actor['mitre_group_id']}")
    print(f"  Sophistication: {actor['sophistication']}")
    print(f"  Motivation:     {actor['primary_motivation']}")
    print(f"  Target sectors: {', '.join(actor['target_sectors'])}\n")
    print("  Notable campaigns:")
    for c in actor["notable_campaigns"]:
        print(f"    - {c}")
    print("\n  Signature behaviors (what makes them recognizable):")
    for b in actor["signature_behaviors"]:
        print(f"    - {b}")
    print("\n  Characteristic TTPs (emulate these):")
    for ttp in actor["characteristic_ttps"]:
        note = f" — {ttp['notes']}" if ttp.get("notes") else ""
        print(f"    [{ttp['technique']}] {ttp['tactic']}: {ttp['name']}{note}")
    print(f"\n  Emulation difficulty: {actor['emulation_difficulty']}\n{bar}\n")


def build_scenario(actor_id):
    actor = _actors().get(actor_id)
    if not actor:
        print(f"❌ Unknown actor '{actor_id}'. Known actors: {', '.join(_actors())}")
        return

    chain = {}
    for i, ttp in enumerate(actor["characteristic_ttps"], 1):
        key = f"stage_{i}_{ttp['tactic'].lower().replace(' ', '_')}"
        chain[key] = {
            "technique": ttp["name"],
            "mitre_id": ttp["technique"],
            "description": ttp.get("notes", f"{actor['id']} uses {ttp['name']}"),
            "tactics": [ttp["tactic"]],
            "detection_points": [
                f"Map a detection rule to {ttp['technique']} ({ttp['name']})",
                "Confirm the rule fires in the purple-team replay",
            ],
        }

    scenario = {
        "metadata": {
            "name": f"Intelligence-Led Emulation — {actor['id']}",
            "scenario_id": f"TLPT-{actor['id']}",
            "derived_from": actor["mitre_group_id"],
            "difficulty": actor["emulation_difficulty"],
            "realistic_success_rate": "sector-dependent",
            "industry_targets": actor["target_sectors"],
            "attribution_caution": "Emulates documented TTPs; not an attribution claim.",
            "source": "Derived from threat-actors.json (public threat intelligence)",
        },
        "attack_chain": chain,
        "cross_kill_chain_analysis": {
            "critical_detection_gaps": [{
                "gap": f"Unverified detection coverage for {actor['id']} signature TTPs",
                "impact": "Cannot confirm the org would catch this actor's real playbook",
                "fix": "Purple-team replay: map + test a detection for each TTP above",
            }],
        },
        "incident_response_drill_objectives": [
            f"Detect {ttp['technique']} ({ttp['name']})"
            for ttp in actor["characteristic_ttps"]
        ],
    }

    out = attack.SCENARIOS_DIR / f"scenario-tlpt-{actor_id.lower()}.json"
    attack.dump_json(scenario, out)
    print(f"\n✅ Derived scenario written: {out}")
    print(f"   {len(chain)} stages built from {actor['id']}'s documented TTPs.")
    print(f"\n   Run it:  python3 tools/rt.py scenario --run {out.stem}\n")


# --- CLI wiring -------------------------------------------------------------
def add_arguments(p):
    p.add_argument("--sector", help="Rank likely actors for a sector")
    p.add_argument("--actor", help="Threat actor ID (e.g. APT29, FIN7)")
    p.add_argument("--tti", action="store_true", help="With --actor: print TTI summary (default)")
    p.add_argument("--build-scenario", action="store_true", help="With --actor: derive a scenario")


def handle(args):
    if args.sector:
        rank_sector(args.sector)
    elif args.actor and args.build_scenario:
        build_scenario(args.actor)
    elif args.actor:
        print_tti(args.actor)
    else:
        print("Provide --sector <s> or --actor <id> [--build-scenario]")


def register(subparsers):
    p = subparsers.add_parser("derive", help="Rank actors / TTI / derive scenario")
    add_arguments(p)
    p.set_defaults(func=handle)


def main():
    p = argparse.ArgumentParser(description="Intelligence-led scenario derivation")
    add_arguments(p)
    handle(p.parse_args())


if __name__ == "__main__":
    main()
