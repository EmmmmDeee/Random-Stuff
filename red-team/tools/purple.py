"""
`rt purple` — purple-team scoring engine.

Compares the red-team framework's TTP catalog against a detection coverage file
and produces a prioritized gap report. The coverage file is a simple JSON map of
MITRE technique IDs to detection confidence (0-100). If no coverage file is
provided, the tool generates an empty template.
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import attack


def _all_techniques():
    """Collect every ATT&CK technique ID referenced in the red-team framework."""
    techniques = set()
    for path in sorted(attack.RED_TEAM_DIR.rglob("*")):
        if not path.is_file() or path.suffix not in {".json", ".md"}:
            continue
        if path == attack.NAVIGATOR_LAYER_FILE:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for tid in attack.extract_techniques(text):
            techniques.add(tid)
    return techniques


def _load_coverage(coverage_path):
    """Load technique -> detection-confidence map from JSON path or dict."""
    if isinstance(coverage_path, dict):
        return coverage_path
    if not Path(coverage_path).exists():
        return {}
    data = json.loads(Path(coverage_path).read_text(encoding="utf-8"))
    return data.get("coverage", data)


def _generate_template_data():
    """Return empty coverage template data without writing to disk."""
    techniques = sorted(_all_techniques())
    return {
        "_metadata": {
            "description": "Detection coverage map for purple-team scoring. confidence 0-100; null/omitted = unknown.",
            "generated": "auto",
        },
        "coverage": {tid: None for tid in techniques},
    }


def generate_template(output_path):
    """Write an empty coverage template for the user to fill in."""
    template = _generate_template_data()
    techniques = template["coverage"]
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8")
    print(f"✅ Coverage template written: {out}")
    print(f"   {len(techniques)} techniques; fill in confidence values and re-run --score.")


def score_coverage(coverage_path):
    """Score framework technique coverage and report gaps."""
    techniques = _all_techniques()
    coverage = _load_coverage(coverage_path)

    scored = {tid: coverage.get(tid) for tid in techniques}
    numeric = [v for v in scored.values() if isinstance(v, (int, float))]
    missing = [tid for tid, v in scored.items() if v is None]
    zero = [tid for tid, v in scored.items() if v == 0]
    weak = [tid for tid, v in scored.items() if isinstance(v, (int, float)) and 0 < v < 50]

    total = len(techniques)
    covered_count = len(numeric)
    avg = sum(numeric) / len(numeric) if numeric else 0

    print("\n📊 Purple-Team Coverage Score\n")
    print(f"   Techniques in framework: {total}")
    print(f"   With coverage scores:    {covered_count} ({covered_count/total*100:.1f}%)")
    print(f"   Unscored / unknown:      {len(missing)}")
    print(f"   Average confidence:      {avg:.1f}/100")
    print(f"   Zero coverage:           {len(zero)}")
    print(f"   Weak coverage (1-49):    {len(weak)}\n")

    print("🔴 Priority gaps (zero coverage):")
    for tid in sorted(zero)[:20]:
        print(f"   {tid}")
    if len(zero) > 20:
        print(f"   ... and {len(zero)-20} more")

    print("\n🟡 Weak coverage (1-49):")
    for tid in sorted(weak)[:20]:
        print(f"   {tid} ({scored[tid]})")
    if len(weak) > 20:
        print(f"   ... and {len(weak)-20} more")

    print("\n⚪ Unscored / needs assessment:")
    for tid in sorted(missing)[:20]:
        print(f"   {tid}")
    if len(missing) > 20:
        print(f"   ... and {len(missing)-20} more")

    # Save report.
    attack.REPORTS_DIR.mkdir(exist_ok=True)
    report_path = attack.REPORTS_DIR / "purple-team-score.json"
    report = {
        "generated": "auto",
        "summary": {
            "total_techniques": total,
            "covered": covered_count,
            "average_confidence": round(avg, 2),
            "zero_coverage": zero,
            "weak_coverage": weak,
            "unscored": missing,
        },
    }
    attack.dump_json(report, report_path)
    print(f"\n✅ Report saved: {report_path}")
    return report["summary"]


# --- CLI wiring -------------------------------------------------------------
def add_arguments(p):
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--template", metavar="PATH", help="Generate an empty coverage template")
    g.add_argument("--score", metavar="PATH", help="Score coverage from a filled JSON file")


def handle(args):
    if args.template:
        generate_template(args.template)
    elif args.score:
        score_coverage(Path(args.score))


def register(subparsers):
    p = subparsers.add_parser(
        "purple",
        help="Purple-team detection-coverage scoring and gap analysis",
    )
    add_arguments(p)
    p.set_defaults(func=handle)


def main():
    p = argparse.ArgumentParser(description="Purple-team scoring engine")
    add_arguments(p)
    handle(p.parse_args())


if __name__ == "__main__":
    sys.exit(main())
