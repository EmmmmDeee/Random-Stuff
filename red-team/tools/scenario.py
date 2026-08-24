#!/usr/bin/env python3
"""
`rt scenario` — list, run, and drill attack scenarios; report ATT&CK coverage.

Refactored for unified entity loading, cross-referencing, and comprehensive metrics.
"""

import argparse
from datetime import datetime

import attack


def _duration_display(meta):
    """Human-readable duration whether the scenario uses hours or days."""
    if meta.get("estimated_duration_hours") is not None:
        return f"{meta['estimated_duration_hours']} hours"
    if meta.get("estimated_duration_days") is not None:
        return f"{meta['estimated_duration_days']} days"
    return "Unknown"


def _to_hours(analysis, base):
    """Read <base>_hours or <base>_days, normalized to hours (or None)."""
    if analysis.get(f"{base}_hours") is not None:
        return analysis[f"{base}_hours"]
    if analysis.get(f"{base}_days") is not None:
        return analysis[f"{base}_days"] * 24
    return None


def list_scenarios():
    """List all available attack scenarios with metadata."""
    scenarios = attack.load_scenarios()
    if not scenarios:
        print("❌ No scenarios found")
        return

    print("\n📋 Available Red Team Scenarios\n")
    for scenario_id, scenario in sorted(scenarios.items()):
        meta = scenario.get("metadata", {})
        print(f"  📌 {scenario_id}")
        print(f"     Name: {meta.get('name', 'Unknown')}")
        print(f"     Difficulty: {meta.get('difficulty', 'Unknown')}")
        print(f"     Duration: {_duration_display(meta)}")
        print(f"     Success Rate: {meta.get('realistic_success_rate', 'Unknown')}")

        # Show stage count and techniques
        stages = scenario.get("stages", [])
        techniques = [s.get("technique") for s in stages]
        print(f"     Stages: {len(stages)} | Techniques: {', '.join(techniques)}")

        # Cross-reference to detections
        covered = sum(1 for t in techniques if attack.detections_for_technique(t))
        print(f"     Detection Coverage: {covered}/{len(techniques)}\n")


def run_scenario(scenario_id, record_traffic=False, capture_logs=False):
    """Execute an attack scenario and record execution metrics."""
    scenarios = attack.load_scenarios()
    scenario = scenarios.get(scenario_id)

    if not scenario:
        print(f"❌ Scenario not found: {scenario_id}")
        return

    if record_traffic:
        print("ℹ️  --record-traffic requested (not implemented; capture "
              "externally, e.g. tcpdump/Wireshark)")
    if capture_logs:
        print("ℹ️  --capture-logs requested (not implemented; collect logs "
              "externally during the run)")

    meta = scenario.get("metadata", {})
    print(f"\n🎯 Running Scenario: {meta.get('name')}")
    print(f"   ID: {scenario_id}")
    print(f"   Duration: {_duration_display(meta)}")
    print(f"   Expected Success Rate: {meta.get('realistic_success_rate')}\n")

    stages = scenario.get("stages", [])
    print(f"📊 Execution Plan: {len(stages)} stages\n")

    coverage_map = {}
    for i, stage in enumerate(stages, 1):
        technique = stage.get("technique")
        tactic = stage.get("tactic")
        action = stage.get("action_description", "Execute")

        detections = attack.detections_for_technique(technique)
        coverage_map[technique] = detections

        print(f"[{i}/{len(stages)}] {tactic}: {technique}")
        print(f"  Action: {action}")
        print(f"  Success Rate: {stage.get('success_rate_percent', 'Unknown')}%")
        print(f"  Detection Points: {len(stage.get('detection_points', []))} ")
        for det in stage.get("detection_points", []):
            print(f"    - {det}")
        if detections:
            print(f"  Detections Available: {', '.join(d.get('id') for d in detections)}")
        else:
            print(f"  ⚠️  No detections found for {technique}")
        print()

    _write_scenario_report(scenario, scenario_id, coverage_map)


def _write_scenario_report(scenario, scenario_id, coverage_map):
    """Write scenario execution report to reports directory."""
    attack.REPORTS_DIR.mkdir(exist_ok=True)
    analysis = scenario.get("cross_kill_chain_analysis", {})

    # Calculate coverage percentage
    total_techniques = len(coverage_map)
    covered_techniques = sum(1 for detections in coverage_map.values() if detections)
    coverage_percent = (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0

    report = {
        "metadata": {
            "generated": attack.TIMESTAMP,
            "scenario_id": scenario_id,
            "status": "SIMULATED",
        },
        "execution_metrics": {
            "total_stages": len(scenario.get("stages", [])),
            "unique_techniques": total_techniques,
            "techniques_covered_by_detections": covered_techniques,
            "detection_coverage_percent": coverage_percent,
            "detection_gaps": total_techniques - covered_techniques,
        },
        "timing_metrics": {
            "time_to_detection_hours": _to_hours(analysis, "time_to_detection"),
            "time_to_response_hours": _to_hours(analysis, "time_to_response"),
            "attacker_dwell_time_advantage_hours": _to_hours(analysis, "dwell_time_advantage"),
        },
        "technique_coverage": coverage_map,
    }

    filename = f"scenario-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    attack.dump_json(report, attack.REPORTS_DIR / filename)
    print(f"✅ Report saved: {attack.REPORTS_DIR / filename}")


def generate_ir_drill(scenario_id):
    """Generate incident response drill from scenario."""
    scenarios = attack.load_scenarios()
    scenario = scenarios.get(scenario_id)
    drills = attack.load_drills()

    if not scenario or not drills:
        print(f"❌ Scenario or drills not found")
        return

    print(f"\n🔴 Generating IR Drill from Scenario: {scenario_id}\n")

    stages = scenario.get("stages", [])
    objectives = [f"Detect and respond to {s.get('tactic')}: {s.get('technique')}"
                  for s in stages]

    print("📋 Drill Objectives:")
    for obj in objectives:
        print(f"  ☐ {obj}")

    attack.REPORTS_DIR.mkdir(exist_ok=True)
    drill_id = f"ir-drill-{scenario_id}-{datetime.now().strftime('%Y%m%d')}"

    # Map to existing drill framework
    mapped_drills = []
    for drill in drills.get("drill_types", []):
        if drill.get("scenario_source").startswith(scenario_id.split("-")[0]):
            mapped_drills.append(drill.get("drill_id"))

    plan = {
        "metadata": {
            "generated": attack.TIMESTAMP,
            "drill_id": drill_id,
            "scenario_source": scenario_id,
            "mapped_drills": mapped_drills,
        },
        "objectives": objectives,
        "execution_steps": [
            "1. Notify IR team of drill start",
            "2. Activate SIEM/EDR monitoring for scenario",
            "3. Inject scenario stages into test environment",
            "4. Record detection times for each stage",
            "5. Measure IR response time and effectiveness",
            "6. Document any detection gaps",
            "7. Generate post-drill report with improvement recommendations",
        ],
    }

    attack.dump_json(plan, attack.REPORTS_DIR / f"{drill_id}.json")
    print(f"\n✅ Drill plan saved: {attack.REPORTS_DIR / (drill_id + '.json')}")
    print(f"   Mapped to {len(mapped_drills)} existing drills")


def mitre_report():
    """Generate MITRE ATT&CK coverage report for all scenarios."""
    scenarios = attack.load_scenarios()
    framework = attack.load_mitre_framework()

    if not scenarios or not framework:
        print("❌ Scenarios or MITRE framework not found")
        return

    # Collect all techniques used in scenarios
    technique_usage = {}
    for scenario_id, scenario in scenarios.items():
        for stage in scenario.get("stages", []):
            technique = stage.get("technique")
            if technique not in technique_usage:
                technique_usage[technique] = []
            technique_usage[technique].append(scenario_id)

    # Calculate tactic coverage
    tactic_coverage = {}
    for tactic in attack.ATTACK_TACTICS:
        techniques = attack.techniques_by_tactic(tactic)
        implemented = sum(1 for t in techniques if t.get("id") in technique_usage)
        total = len(techniques)
        coverage_pct = (implemented / total * 100) if total > 0 else 0
        tactic_coverage[tactic] = {
            "implemented": implemented,
            "total": total,
            "coverage_percent": coverage_pct,
        }

    print("\n📊 MITRE ATT&CK Framework Coverage Report\n")
    total_coverage = 0.0
    for tactic, cov in tactic_coverage.items():
        print(f"  {tactic}")
        print(f"    Implementation: {cov['implemented']}/{cov['total']} "
              f"({cov['coverage_percent']:.1f}%)")
        total_coverage += cov["coverage_percent"]

    avg_coverage = (total_coverage / len(attack.ATTACK_TACTICS)) if attack.ATTACK_TACTICS else 0
    print(f"\n  Overall Coverage: {avg_coverage:.1f}%")
    print(f"  Techniques Implemented: {len(technique_usage)}")


# --- CLI wiring -----------------------------------------------------------
def add_arguments(p):
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true", help="List available scenarios")
    g.add_argument("--run", metavar="ID", help="Run a scenario by ID")
    g.add_argument("--mitre-report", action="store_true", help="ATT&CK coverage report")
    p.add_argument("--ir-drill", action="store_true", help="With --run: generate an IR drill")
    p.add_argument("--record-traffic", action="store_true", help="With --run: note traffic capture")
    p.add_argument("--capture-logs", action="store_true", help="With --run: note log capture")


def handle(args):
    if args.list:
        list_scenarios()
    elif args.mitre_report:
        mitre_report()
    elif args.run:
        if args.ir_drill:
            generate_ir_drill(args.run)
        else:
            run_scenario(args.run, args.record_traffic, args.capture_logs)


def register(subparsers):
    p = subparsers.add_parser("scenario", help="List/run scenarios; ATT&CK coverage")
    add_arguments(p)
    p.set_defaults(func=handle)


def main():
    p = argparse.ArgumentParser(description="Attack scenario runner")
    add_arguments(p)
    handle(p.parse_args())


if __name__ == "__main__":
    main()
