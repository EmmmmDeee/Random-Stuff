"""
Shared library for the red-team framework tooling.

Centralizes what the individual command modules used to each re-implement:
repository paths, JSON loading, and MITRE ATT&CK technique-ID handling.
"""

import json
import re
from pathlib import Path

# --- Repository layout (single source of truth for paths) ------------------
TOOLS_DIR = Path(__file__).resolve().parent
RED_TEAM_DIR = TOOLS_DIR.parent

SCENARIOS_DIR = RED_TEAM_DIR / "scenarios"
MITRE_DIR = RED_TEAM_DIR / "mitre-attack"
DRILLS_DIR = RED_TEAM_DIR / "incident-response"
INTEL_DIR = RED_TEAM_DIR / "intelligence-led"
RECON_DIR = INTEL_DIR / "reconnaissance"
DETECTION_DIR = INTEL_DIR / "detection-mapping"
CAMPAIGNS_DIR = INTEL_DIR / "campaigns"
REPORTS_DIR = RED_TEAM_DIR / "reports"

# Common data files
THREAT_ACTORS_FILE = INTEL_DIR / "threat-actors.json"
TARGETING_FILE = INTEL_DIR / "targeting-model.json"
ATTACK_SURFACE_FILE = RECON_DIR / "attack-surface.json"
MITRE_FRAMEWORK_FILE = MITRE_DIR / "framework.json"
DRILL_FRAMEWORK_FILE = DRILLS_DIR / "drill-framework.json"
NAVIGATOR_LAYER_FILE = MITRE_DIR / "navigator-layer.json"

# --- MITRE ATT&CK helpers ---------------------------------------------------
# Enterprise technique / sub-technique IDs: TNNNN or TNNNN.NNN
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# ATT&CK Enterprise tactics in kill-chain order.
ATTACK_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


def load_json(path):
    """Load a JSON file, returning None (with a message) if it's missing."""
    path = Path(path)
    if not path.exists():
        print(f"❌ Not found: {path}")
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def dump_json(obj, path):
    """Write pretty JSON with a trailing newline."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")


def extract_techniques(text):
    """Return all ATT&CK technique IDs mentioned in a string."""
    return TECHNIQUE_RE.findall(text)


def attack_url(technique_id):
    """Canonical attack.mitre.org URL for a technique or sub-technique ID."""
    base, _, sub = technique_id.partition(".")
    if sub:
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{base}/"
