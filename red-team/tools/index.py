#!/usr/bin/env python3
"""
`rt index` — unified framework index generator.

Scans all framework entities (threat actors, scenarios, campaigns, detections,
drills) and builds a consolidated cross-reference index showing relationships
between actors → scenarios → drills → detections → hunt queries.

Output: index.json with complete dependency graph.
"""

import argparse
import json
from pathlib import Path

import attack


def _load_all_entities():
    """Load all framework entities into memory."""
    entities = {
        "threat_actors": attack.load_json(attack.THREAT_ACTORS_FILE) or {"threat_actors": []},
        "targeting_model": attack.load_json(attack.TARGETING_MODEL_FILE) or {"sectors": []},
        "scenarios": {},
        "campaigns": {},
        "drills": attack.load_json(attack.DRILL_FRAMEWORK_FILE) or {"drill_types": []},
        "detections": attack.load_json(attack.DETECTIONS_FILE) or {"detections": []},
        "recon_techniques": attack.load_json(attack.ATTACK_SURFACE_FILE) or {"recon_techniques": []},
        "self_audit": attack.load_json(attack.SELF_AUDIT_FILE) or {"controls": []},
    }

    # Load all scenarios
    for scenario_file in Path(attack.SCENARIOS_DIR).glob("scenario-*.json"):
        scenario = attack.load_json(str(scenario_file))
        if scenario:
            entities["scenarios"][scenario.get("id")] = scenario

    # Load all campaigns
    for campaign_file in Path(attack.CAMPAIGNS_DIR).glob("C*.json"):
        campaign = attack.load_json(str(campaign_file))
        if campaign:
            entities["campaigns"][campaign.get("campaign", {}).get("id")] = campaign

    return entities


def _build_technique_index(entities):
    """Build index: technique → [actors, scenarios, drills, detections, campaigns]."""
    index = {}

    # From threat actors
    for actor in entities["threat_actors"].get("threat_actors", []):
        for ttp in actor.get("characteristic_ttps", []):
            technique = ttp.get("technique")
            if technique not in index:
                index[technique] = {
                    "id": technique,
                    "name": ttp.get("name"),
                    "tactic": ttp.get("tactic"),
                    "actors": [],
                    "scenarios": [],
                    "drills": [],
                    "detections": [],
                    "campaigns": [],
                    "recon": [],
                }
            if actor.get("id") not in index[technique]["actors"]:
                index[technique]["actors"].append(actor.get("id"))

    # From scenarios
    for scenario_id, scenario in entities["scenarios"].items():
        for stage in scenario.get("stages", []):
            technique = stage.get("technique")
            if technique not in index:
                index[technique] = {
                    "id": technique,
                    "name": stage.get("name"),
                    "tactic": stage.get("tactic"),
                    "actors": [],
                    "scenarios": [],
                    "drills": [],
                    "detections": [],
                    "campaigns": [],
                    "recon": [],
                }
            if scenario_id not in index[technique]["scenarios"]:
                index[technique]["scenarios"].append(scenario_id)

    # From drills
    for drill in entities["drills"].get("drill_types", []):
        scenario_source = drill.get("scenario_source", "").split(" ")[0]  # e.g., "APT-001"
        for objective in drill.get("objectives", []):
            # Drills reference scenario stages indirectly
            if scenario_source not in index:
                index[scenario_source] = {
                    "id": scenario_source,
                    "drills": [drill.get("drill_id")],
                }
            elif drill.get("drill_id") not in index.get(scenario_source, {}).get("drills", []):
                index[scenario_source]["drills"].append(drill.get("drill_id"))

    # From detections
    for detection in entities["detections"].get("detections", []):
        technique = detection.get("technique")
        if technique not in index:
            index[technique] = {
                "id": technique,
                "name": detection.get("detection_name"),
                "tactic": detection.get("tactic"),
                "actors": [],
                "scenarios": [],
                "drills": [],
                "detections": [],
                "campaigns": [],
                "recon": [],
            }
        if detection.get("id") not in index[technique]["detections"]:
            index[technique]["detections"].append(detection.get("id"))

    # From campaigns
    for campaign_id, campaign in entities["campaigns"].items():
        for technique in campaign.get("techniques", []):
            tech_id = technique.get("mitre_id")
            if tech_id not in index:
                index[tech_id] = {
                    "id": tech_id,
                    "name": technique.get("name"),
                    "tactic": technique.get("tactic"),
                    "actors": [],
                    "scenarios": [],
                    "drills": [],
                    "detections": [],
                    "campaigns": [],
                    "recon": [],
                }
            if campaign_id not in index[tech_id]["campaigns"]:
                index[tech_id]["campaigns"].append(campaign_id)

    # From reconnaissance
    for recon in entities["recon_techniques"].get("recon_techniques", []):
        technique = recon.get("mitre_id")
        if technique not in index:
            index[technique] = {
                "id": technique,
                "name": recon.get("name"),
                "tactic": "Reconnaissance",
                "actors": [],
                "scenarios": [],
                "drills": [],
                "detections": [],
                "campaigns": [],
                "recon": [],
            }
        if recon.get("id") not in index[technique]["recon"]:
            index[technique]["recon"].append(recon.get("id"))

    return index


def _build_coverage_matrix(entities):
    """Build coverage matrix: scenario stage → detection coverage."""
    matrix = []

    for scenario_id, scenario in entities["scenarios"].items():
        for stage in scenario.get("stages", []):
            technique = stage.get("technique")

            # Find detections for this technique
            detections_for_technique = [
                d.get("id") for d in entities["detections"].get("detections", [])
                if d.get("technique") == technique
            ]

            coverage = {
                "scenario": scenario_id,
                "stage": stage.get("stage_id"),
                "technique": technique,
                "tactic": stage.get("tactic"),
                "detections": detections_for_technique,
                "coverage_percent": min(100, len(detections_for_technique) * 25),  # Rough estimate
            }
            matrix.append(coverage)

    return matrix


def generate_index(output_file=None):
    """Generate unified framework index."""
    entities = _load_all_entities()
    technique_index = _build_technique_index(entities)
    coverage_matrix = _build_coverage_matrix(entities)

    index = {
        "metadata": {
            "description": "Unified framework index mapping all entities (actors, scenarios, campaigns, drills, detections, reconnaissance)",
            "generated": attack.TIMESTAMP,
            "version": "1.0",
        },
        "statistics": {
            "threat_actors": len(entities["threat_actors"].get("threat_actors", [])),
            "scenarios": len(entities["scenarios"]),
            "campaigns": len(entities["campaigns"]),
            "drills": len(entities["drills"].get("drill_types", [])),
            "detections": len(entities["detections"].get("detections", [])),
            "recon_techniques": len(entities["recon_techniques"].get("recon_techniques", [])),
            "self_audit_controls": len(entities["self_audit"].get("controls", [])),
            "unique_techniques": len(technique_index),
        },
        "technique_index": technique_index,
        "coverage_matrix": coverage_matrix,
    }

    output = output_file or attack.INDEX_FILE
    with open(output, "w") as f:
        json.dump(index, f, indent=2)

    print(f"✅ Framework index generated: {output}\n")
    print(f"  Threat actors:     {index['statistics']['threat_actors']}")
    print(f"  Scenarios:         {index['statistics']['scenarios']}")
    print(f"  Campaigns:         {index['statistics']['campaigns']}")
    print(f"  Drills:            {index['statistics']['drills']}")
    print(f"  Detections:        {index['statistics']['detections']}")
    print(f"  Recon techniques:  {index['statistics']['recon_techniques']}")
    print(f"  Unique techniques: {index['statistics']['unique_techniques']}\n")


# --- CLI wiring ---------------------------------------------------------------
def add_arguments(p):
    p.add_argument("--output", help="Output file (default: mitre-attack/index.json)")


def handle(args):
    generate_index(args.output)


def register(subparsers):
    p = subparsers.add_parser("index", help="Generate unified framework index")
    add_arguments(p)
    p.set_defaults(func=handle)


def main():
    p = argparse.ArgumentParser(description="Generate unified framework index")
    add_arguments(p)
    handle(p.parse_args())


if __name__ == "__main__":
    main()
