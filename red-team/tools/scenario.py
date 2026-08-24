"""
`rt scenario` — list, run, and drill attack scenarios; report ATT&CK coverage.
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


def _load_scenario(stem):
    return attack.load_json(attack.SCENARIOS_DIR / f"{stem}.json")


def list_scenarios():
    scenarios = sorted(attack.SCENARIOS_DIR.glob("scenario-*.json"))
    if not scenarios:
        print("❌ No scenarios found")
        return
    print("\n📋 Available Red Team Scenarios\n")
    for f in scenarios:
        meta = (attack.load_json(f) or {}).get("metadata", {})
        print(f"  📌 {meta.get('scenario_id', 'UNKNOWN')} "
              f"(run with: --run {f.stem})")
        print(f"     Name: {meta.get('name', 'Unknown')}")
        print(f"     Difficulty: {meta.get('difficulty', 'Unknown')}")
        print(f"     Duration: {_duration_display(meta)}")
        print(f"     Success Rate: {meta.get('realistic_success_rate', 'Unknown')}\n")


def run_scenario(stem, record_traffic=False, capture_logs=False):
    scenario = _load_scenario(stem)
    if not scenario:
        return

    if record_traffic:
        print("ℹ️  --record-traffic requested (not implemented; capture "
              "externally, e.g. tcpdump/Wireshark)")
    if capture_logs:
        print("ℹ️  --capture-logs requested (not implemented; collect logs "
              "externally during the run)")

    meta = scenario.get("metadata", {})
    print(f"\n🎯 Running Scenario: {meta.get('name')}")
    print(f"   ID: {meta.get('scenario_id')}")
    print(f"   Duration: {_duration_display(meta)}")
    print(f"   Expected Success Rate: {meta.get('realistic_success_rate')}\n")

    chain = scenario.get("attack_chain", {})
    for i, (key, stage) in enumerate(chain.items(), 1):
        print(f"[{i}/{len(chain)}] {key}")
        print(f"  MITRE Technique: {stage.get('mitre_id')}")
        print(f"  Tactic: {stage.get('tactics', [])}")
        impl = stage.get("implementation", {})
        print(f"  Success Rate: {impl.get('success_rate_percent', 'Unknown')}%")
        for det in stage.get("detection_points", []):
            print(f"    - {det}")
        print()

    _write_scenario_report(scenario, stem)


def _write_scenario_report(scenario, stem):
    attack.REPORTS_DIR.mkdir(exist_ok=True)
    analysis = scenario.get("cross_kill_chain_analysis", {})
    report = {
        "scenario": scenario.get("metadata", {}).get("name"),
        "scenario_id": stem,
        "status": "SIMULATED",
        "metrics": {
            "total_stages": len(scenario.get("attack_chain", {})),
            "detection_gaps": len(analysis.get("critical_detection_gaps", [])),
            "time_to_detection_hours": _to_hours(analysis, "time_to_detection"),
            "time_to_response_hours": _to_hours(analysis, "time_to_response"),
            "attacker_dwell_time_advantage_hours": _to_hours(analysis, "dwell_time_advantage"),
        },
    }
    # Timestamped filename; stamped at call time (scripts, not the workflow, run this).
    name = f"scenario-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    attack.dump_json(report, attack.REPORTS_DIR / name)
    print(f"✅ Report saved: {attack.REPORTS_DIR / name}")


def generate_ir_drill(stem):
    scenario = _load_scenario(stem)
    drills = attack.load_json(attack.DRILL_FRAMEWORK_FILE)
    if not scenario or not drills:
        return

    print(f"\n🔴 Generating IR Drill from Scenario: {stem}\n")
    objectives = scenario.get("incident_response_drill_objectives", [])
    print("📋 Drill Objectives:")
    for obj in objectives:
        print(f"  ☐ {obj}")

    attack.REPORTS_DIR.mkdir(exist_ok=True)
    plan = {
        "drill_id": f"ir-drill-{stem}-{datetime.now().strftime('%Y%m%d')}",
        "scenario_source": stem,
        "objectives": objectives,
        "execution_steps": [
            "1. Notify IR team of drill start",
            "2. Activate SIEM/EDR monitoring for scenario",
            "3. Inject scenario stages into test environment",
            "4. Record detection times for each stage",
            "5. Measure IR response time and effectiveness",
            "6. Generate post-drill report",
        ],
    }
    attack.dump_json(plan, attack.REPORTS_DIR / f"{plan['drill_id']}.json")
    print(f"\n✅ Drill plan saved: {attack.REPORTS_DIR / (plan['drill_id'] + '.json')}")


def mitre_report():
    framework = attack.load_json(attack.MITRE_FRAMEWORK_FILE)
    if not framework:
        return
    print("\n📊 MITRE ATT&CK Framework Coverage\n")
    tactics = framework.get("tactic_coverage", [])
    total = 0.0
    for t in tactics:
        cov = (t.get("techniques_implemented", 0) / t.get("techniques_total", 1)) * 100
        total += cov
        print(f"  {t.get('tactic', 'Unknown')}")
        print(f"    Implementation: {t.get('techniques_implemented')}/"
              f"{t.get('techniques_total')} ({cov:.1f}%)")
        print(f"    Detection Difficulty: {t.get('detection_difficulty')}\n")
    print(f"Average Coverage: {(total / len(tactics)) if tactics else 0:.1f}%")


# --- CLI wiring -------------------------------------------------------------
def add_arguments(p):
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true", help="List available scenarios")
    g.add_argument("--run", metavar="STEM", help="Run a scenario by file stem")
    g.add_argument("--mitre-report", action="store_true", help="ATT&CK coverage report")
    p.add_argument("--ir-drill", action="store_true", help="With --run: generate an IR drill instead")
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
