"""
`rt crosscheck` — derive detection-test suggestions from operator artifacts.

Reads artifact JSON produced by `rt operator` and suggests YARA or Suricata
tests that a defender could write to detect that artifact. This closes the
purple-team loop: offensive scaffolding -> detection requirements.
"""

import argparse
import json
from pathlib import Path


YARA_TEMPLATE = """rule redteam_{safe_name}
{{
    meta:
        description = "Detects authorized purple-team artifact: {name}"
        technique = "{technique}"
    strings:
        $a = "{needle}"
    condition:
        any of them
}}
"""

SURICATA_TEMPLATE = """alert http any any -> any any (msg:"REDTEAM {technique} artifact beacon"; \\
    content:"{needle}"; http_header; \\
    sid:{sid}; rev:1;)
"""


def _safe_name(name):
    return "".join(c if c.isalnum() else "_" for c in name).lower()[:40]


def suggest_tests(artifact_path, output_path=None):
    data = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
    technique = data.get("technique", "UNKNOWN")
    name = data.get("task_name") or data.get("filename") or technique
    needle = ""

    if "command_line" in data:
        needle = data["command_line"][:60]
    elif "macro_placeholder" in data:
        needle = data["macro_placeholder"][:60].replace("\\", "\\\\").replace('"', '\\"')
    elif "example_beacon_url" in data:
        needle = data["example_beacon_url"]
    else:
        needle = json.dumps(data)[:60]

    yara = YARA_TEMPLATE.format(
        safe_name=_safe_name(name),
        name=name,
        technique=technique,
        needle=needle.replace('"', '\\"'),
    )
    suricata = SURICATA_TEMPLATE.format(
        technique=technique,
        needle=needle.replace('"', '\\"'),
        sid=1000000 + hash(artifact_path) % 900000,
    )

    report = {
        "technique": technique,
        "artifact": str(artifact_path),
        "yara_rule": yara,
        "suricata_rule": suricata,
        "recommendation": f"Use these rules in detection/tests/ to validate coverage for {technique}.",
    }

    print(json.dumps(report, indent=2))
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\n✅ Crosscheck suggestions written: {out}")
    return report


def register(subparsers):
    p = subparsers.add_parser("crosscheck", help="Derive detection-test suggestions from operator artifacts")
    add_arguments(p)
    p.set_defaults(func=handle)


# --- CLI wiring -------------------------------------------------------------
def add_arguments(p):
    p.add_argument("--artifact", required=True, help="Path to operator artifact JSON")
    p.add_argument("-o", "--output", help="Write suggestions to this path")


def handle(args):
    suggest_tests(args.artifact, args.output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Derive detection tests from artifacts")
    add_arguments(parser)
    handle(parser.parse_args())
