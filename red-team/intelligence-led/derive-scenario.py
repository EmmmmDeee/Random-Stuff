#!/usr/bin/env python3
"""
Intelligence-Led Scenario Derivation

Turns publicly documented threat-actor profiles into prioritized, executable
test scenarios — the core of Threat-Led Penetration Testing (TLPT).

Usage:
    derive-scenario.py --sector finance --rank
    derive-scenario.py --actor APT29 --tti
    derive-scenario.py --actor FIN7 --build-scenario
"""

import json
import argparse
from pathlib import Path

HERE = Path(__file__).parent
ACTORS_FILE = HERE / "threat-actors.json"
TARGETING_FILE = HERE / "targeting-model.json"
# Derived scenarios are written next to the hand-authored ones so the existing
# run-scenario.py runner can execute them unchanged.
SCENARIOS_DIR = HERE.parent / "scenarios"


def load_actors():
    with open(ACTORS_FILE) as f:
        return {a["id"]: a for a in json.load(f)["threat_actors"]}


def load_targeting():
    with open(TARGETING_FILE) as f:
        return json.load(f)


def rank_sector(sector):
    """Show which actors most likely target a sector."""
    targeting = load_targeting()
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
    """Print a Targeted Threat Intelligence summary for an actor."""
    actors = load_actors()
    actor = actors.get(actor_id)
    if not actor:
        print(f"❌ Unknown actor '{actor_id}'. Known actors: {', '.join(actors)}")
        return

    print(f"\n{'=' * 62}")
    print(f"  TARGETED THREAT INTELLIGENCE — {actor['id']}")
    print(f"{'=' * 62}\n")
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

    print(f"\n  Emulation difficulty: {actor['emulation_difficulty']}")
    print(f"{'=' * 62}\n")


def build_scenario(actor_id):
    """Derive a run-scenario.py-compatible scenario from an actor's real TTPs."""
    actors = load_actors()
    actor = actors.get(actor_id)
    if not actor:
        print(f"❌ Unknown actor '{actor_id}'. Known actors: {', '.join(actors)}")
        return

    attack_chain = {}
    for i, ttp in enumerate(actor["characteristic_ttps"], 1):
        stage_key = f"stage_{i}_{ttp['tactic'].lower().replace(' ', '_')}"
        attack_chain[stage_key] = {
            "technique": ttp["name"],
            "mitre_id": ttp["technique"],
            "description": ttp.get("notes", f"{actor['id']} uses {ttp['name']}"),
            "tactics": [ttp["tactic"]],
            "detection_points": [
                f"Map a detection rule to {ttp['technique']} ({ttp['name']})",
                "Confirm the rule fires in the purple-team replay"
            ]
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
            "source": "Derived from threat-actors.json (public threat intelligence)"
        },
        "attack_chain": attack_chain,
        "cross_kill_chain_analysis": {
            "critical_detection_gaps": [
                {
                    "gap": f"Unverified detection coverage for {actor['id']} signature TTPs",
                    "impact": "Cannot confirm the org would catch this actor's real playbook",
                    "fix": "Purple-team replay: map + test a detection for each TTP above"
                }
            ]
        },
        "incident_response_drill_objectives": [
            f"Detect {ttp['technique']} ({ttp['name']})"
            for ttp in actor["characteristic_ttps"]
        ]
    }

    out_file = SCENARIOS_DIR / f"scenario-tlpt-{actor_id.lower()}.json"
    with open(out_file, "w") as f:
        json.dump(scenario, f, indent=2)

    print(f"\n✅ Derived scenario written: {out_file}")
    print(f"   {len(attack_chain)} stages built from {actor['id']}'s documented TTPs.")
    print(f"\n   Run it with the existing runner:")
    print(f"     python3 ../run-scenario.py --scenario {out_file.stem}\n")


def main():
    parser = argparse.ArgumentParser(description="Intelligence-Led Scenario Derivation (TLPT)")
    parser.add_argument("--sector", type=str, help="Rank likely actors for a sector")
    parser.add_argument("--rank", action="store_true", help="Show ranked actors (with --sector)")
    parser.add_argument("--actor", type=str, help="Threat actor ID (e.g. APT29, FIN7)")
    parser.add_argument("--tti", action="store_true", help="Print Targeted Threat Intelligence (with --actor)")
    parser.add_argument("--build-scenario", action="store_true", help="Derive a test scenario (with --actor)")

    args = parser.parse_args()

    if args.sector:
        rank_sector(args.sector)
    elif args.actor and args.tti:
        print_tti(args.actor)
    elif args.actor and args.build_scenario:
        build_scenario(args.actor)
    elif args.actor:
        # Default action for --actor is the TTI summary
        print_tti(args.actor)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
