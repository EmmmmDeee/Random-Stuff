"""
Shared library for the red-team framework tooling.

Centralizes what the individual command modules used to each re-implement:
repository paths, JSON loading, and MITRE ATT&CK technique-ID handling.
"""

import json
import re
from datetime import datetime
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
TARGETING_MODEL_FILE = INTEL_DIR / "targeting-model.json"
ATTACK_SURFACE_FILE = RECON_DIR / "attack-surface.json"
SELF_AUDIT_FILE = RECON_DIR / "self-audit.json"
MITRE_FRAMEWORK_FILE = MITRE_DIR / "framework.json"
NAVIGATOR_LAYER_FILE = MITRE_DIR / "navigator-layer.json"
INDEX_FILE = MITRE_DIR / "index.json"
DRILL_FRAMEWORK_FILE = DRILLS_DIR / "drill-framework.json"
DETECTIONS_FILE = DETECTION_DIR / "detections.json"

# Timestamp for generated files
TIMESTAMP = datetime.utcnow().isoformat() + "Z"

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


# --- Consolidated entity loaders (cache-aware) -----------------------------------
_ENTITY_CACHE = {}


def load_threat_actors():
    """Load threat actor profiles (cached)."""
    if "threat_actors" not in _ENTITY_CACHE:
        data = load_json(THREAT_ACTORS_FILE) or {"threat_actors": []}
        _ENTITY_CACHE["threat_actors"] = data
    return _ENTITY_CACHE["threat_actors"]


def load_targeting_model():
    """Load sector↔threat actor targeting model (cached)."""
    if "targeting_model" not in _ENTITY_CACHE:
        data = load_json(TARGETING_MODEL_FILE) or {"sectors": []}
        _ENTITY_CACHE["targeting_model"] = data
    return _ENTITY_CACHE["targeting_model"]


def load_scenarios():
    """Load all attack scenarios (cached)."""
    if "scenarios" not in _ENTITY_CACHE:
        scenarios = {}
        for scenario_file in Path(SCENARIOS_DIR).glob("scenario-*.json"):
            scenario = load_json(str(scenario_file))
            if scenario:
                scenarios[scenario.get("id")] = scenario
        _ENTITY_CACHE["scenarios"] = scenarios
    return _ENTITY_CACHE["scenarios"]


def load_campaigns():
    """Load all MITRE campaigns (cached)."""
    if "campaigns" not in _ENTITY_CACHE:
        campaigns = {}
        for campaign_file in Path(CAMPAIGNS_DIR).glob("C*.json"):
            campaign = load_json(str(campaign_file))
            if campaign:
                campaign_id = campaign.get("campaign", {}).get("id")
                campaigns[campaign_id] = campaign
        _ENTITY_CACHE["campaigns"] = campaigns
    return _ENTITY_CACHE["campaigns"]


def load_detections():
    """Load all detections (hunt queries, correlations, baselines) — cached."""
    if "detections" not in _ENTITY_CACHE:
        data = load_json(DETECTIONS_FILE) or {"detections": []}
        _ENTITY_CACHE["detections"] = data
    return _ENTITY_CACHE["detections"]


def load_drills():
    """Load IR drill framework (cached)."""
    if "drills" not in _ENTITY_CACHE:
        data = load_json(DRILL_FRAMEWORK_FILE) or {"drill_types": []}
        _ENTITY_CACHE["drills"] = data
    return _ENTITY_CACHE["drills"]


def load_recon_techniques():
    """Load reconnaissance exposure techniques (cached)."""
    if "recon" not in _ENTITY_CACHE:
        data = load_json(ATTACK_SURFACE_FILE) or {"recon_techniques": []}
        _ENTITY_CACHE["recon"] = data
    return _ENTITY_CACHE["recon"]


def load_self_audit():
    """Load self-audit controls (cached)."""
    if "self_audit" not in _ENTITY_CACHE:
        data = load_json(SELF_AUDIT_FILE) or {"controls": []}
        _ENTITY_CACHE["self_audit"] = data
    return _ENTITY_CACHE["self_audit"]


def load_mitre_framework():
    """Load MITRE ATT&CK framework (cached)."""
    if "framework" not in _ENTITY_CACHE:
        data = load_json(MITRE_FRAMEWORK_FILE) or {"techniques": []}
        _ENTITY_CACHE["framework"] = data
    return _ENTITY_CACHE["framework"]


def clear_cache():
    """Clear entity cache (useful for testing)."""
    _ENTITY_CACHE.clear()


# --- Technique utilities -------------------------------------------------------
def technique_by_id(technique_id, tactic=None):
    """Lookup a technique in the framework by ID, optionally filtered by tactic."""
    framework = load_mitre_framework()
    for technique in framework.get("techniques", []):
        if technique.get("id") == technique_id:
            if tactic is None or technique.get("tactic") == tactic:
                return technique
    return None


def techniques_by_tactic(tactic):
    """Get all techniques for a given tactic."""
    framework = load_mitre_framework()
    return [t for t in framework.get("techniques", []) if t.get("tactic") == tactic]


def detections_for_technique(technique_id):
    """Get all detections (H-##, C-##, B-##) that cover a technique."""
    detections = load_detections()
    return [d for d in detections.get("detections", []) if d.get("technique") == technique_id]


def scenarios_for_technique(technique_id):
    """Get all scenarios that include a technique."""
    scenarios = load_scenarios()
    matching = []
    for scenario_id, scenario in scenarios.items():
        for stage in scenario.get("stages", []):
            if stage.get("technique") == technique_id:
                matching.append((scenario_id, stage))
                break
    return matching


def campaigns_for_technique(technique_id):
    """Get all campaigns that employ a technique."""
    campaigns = load_campaigns()
    matching = []
    for campaign_id, campaign in campaigns.items():
        for tech in campaign.get("techniques", []):
            if tech.get("mitre_id") == technique_id:
                matching.append((campaign_id, tech))
                break
    return matching
