#!/usr/bin/env python3
"""Generate intel/iocs_stix.json (STIX 2.1) from intel/iocs.csv.

intel/iocs.csv is the single source of truth; the STIX bundle is derived from it
so the two feeds cannot silently drift apart.

    python3 tools/build_stix.py            # (re)write intel/iocs_stix.json
    python3 tools/build_stix.py --check    # exit 1 if the bundle is out of date
    python3 tools/build_stix.py --check --validate
                                           # also validate every STIX pattern
                                           # (requires: pip install stix2-patterns)

Every CSV row is either emitted as a STIX Indicator or explicitly excluded by
type (see EXCLUDED); an unknown type is an error, never a silent drop.

Object ids, `created` and `valid_from` are preserved from the existing bundle so
re-imports into MISP/TAXII update objects instead of duplicating them;
`modified` is bumped only when an object's content actually changes.

Exit: 0 = ok / up to date, 1 = bundle out of date (--check) or invalid pattern
(--validate), 2 = usage/input error.
"""
import argparse
import csv
import json
import os
import sys
import uuid
from datetime import datetime, timezone

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CSV_PATH = os.path.join(ROOT, "intel", "iocs.csv")
STIX_PATH = os.path.join(ROOT, "intel", "iocs_stix.json")

# Deterministic ids for objects that are new to the bundle.
NAMESPACE = uuid.UUID("5d3a4f0e-2b8c-4a51-9b0e-6c0f6b9f1a7d")

# STIX 2.1 Appendix A "None/Low/Med/High" confidence scale.
CONFIDENCE = {"high": 85, "medium": 50, "low": 15}

# CSV `malware` column -> STIX Malware SDO (family) the indicator `indicates`.
FAMILIES = {
    "DroidJack": {"name": "DroidJack", "x_platform": "android"},
    "Blackshades": {"name": "Blackshades NET", "x_platform": "windows"},
}

# CSV types with no specific, low-false-positive STIX 2.1 pattern. They stay in
# the CSV and are covered by the detection content named here.
EXCLUDED = {
    "port": "a port alone is not specific to the malware; see "
            "detection/droidjack_suricata.rules",
    "regkey": "generic autostart locations present on every Windows host; key "
              "existence is not an indicator",
    "package": "STIX 2.1 has no cyber-observable for Android package names; see "
               "detection/droidjack.yar",
}


def stix_str(value):
    """Quote a value as a STIX pattern string literal."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def literal_regex(value):
    """PCRE that matches `value` literally (escape every non-alphanumeric)."""
    return "".join(c if c.isalnum() or c == "_" else "\\" + c for c in value)


PATTERNS = {
    "sha256": lambda v: "[file:hashes.'SHA-256' = %s]" % stix_str(v.lower()),
    "md5": lambda v: "[file:hashes.MD5 = %s]" % stix_str(v.lower()),
    "imphash": lambda v: "[file:hashes.'imphash' = %s]" % stix_str(v.lower()),
    "domain": lambda v: "[domain-name:value = %s]" % stix_str(v),
    "url": lambda v: "[url:value = %s]" % stix_str(v),
    "string": lambda v: "[artifact:payload_bin MATCHES %s]" % stix_str(literal_regex(v)),
    "filemarker": lambda v: "[artifact:payload_bin MATCHES %s]" % stix_str(literal_regex(v)),
    "section": lambda v: ("[file:extensions.'windows-pebinary-ext'.sections[*].name = %s]"
                          % stix_str(v)),
}


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(2)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "000Z"


def read_rows():
    with open(CSV_PATH, newline="") as f:
        rows = list(csv.DictReader(f))
    for n, row in enumerate(rows, start=2):
        kind = (row.get("type") or "").strip()
        if not (row.get("value") or "").strip():
            die("%s:%d: empty value" % (CSV_PATH, n))
        if kind not in PATTERNS and kind not in EXCLUDED:
            die("%s:%d: unknown indicator type %r (map it in PATTERNS or EXCLUDED)"
                % (CSV_PATH, n, kind))
        conf = (row.get("confidence") or "").strip().lower()
        if conf not in CONFIDENCE:
            die("%s:%d: unknown confidence %r" % (CSV_PATH, n, conf))
    return rows


def load_existing():
    try:
        with open(STIX_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"type": "bundle", "objects": []}


def finalize(obj, old, stamp):
    """Carry id/created over from `old`; bump `modified` only on real change."""
    if old is None:
        obj["created"] = obj["modified"] = stamp
    else:
        obj["id"], obj["created"] = old["id"], old["created"]
        obj["modified"] = old.get("modified", old["created"])
        same = {k: v for k, v in old.items() if k != "modified"}
        if obj["type"] == "indicator":
            obj["valid_from"] = old.get("valid_from", old["created"])
        if {k: v for k, v in obj.items() if k != "modified"} != same:
            obj["modified"] = stamp
    if obj["type"] == "indicator" and "valid_from" not in obj:
        obj["valid_from"] = obj["created"]
    return obj


def ordered(obj, keys):
    return {k: obj[k] for k in keys if k in obj}


def build(rows, existing):
    stamp = now()
    objs = existing.get("objects", [])
    old_malware = {o["name"]: o for o in objs if o.get("type") == "malware"}
    old_ind = {o["pattern"]: o for o in objs if o.get("type") == "indicator"}
    old_rel = {(o["source_ref"], o["target_ref"]): o
               for o in objs if o.get("type") == "relationship"}

    malware, indicators, relationships = {}, [], []
    for fam in FAMILIES.values():
        obj = {
            "type": "malware",
            "spec_version": "2.1",
            "id": "malware--%s" % uuid.uuid5(NAMESPACE, "malware:" + fam["name"]),
            "name": fam["name"],
            "is_family": True,
            "malware_types": ["remote-access-trojan"],
            "x_platform": fam["x_platform"],
        }
        obj = finalize(obj, old_malware.get(fam["name"]), stamp)
        malware[fam["name"]] = ordered(obj, [
            "type", "spec_version", "id", "created", "modified", "name",
            "is_family", "malware_types", "x_platform"])

    seen = set()
    for row in rows:
        kind, value = row["type"].strip(), row["value"].strip()
        if kind in EXCLUDED:
            continue
        pattern = PATTERNS[kind](value)
        if pattern in seen:
            die("duplicate indicator in %s: %s" % (CSV_PATH, pattern))
        seen.add(pattern)
        label = row["malware"].strip()
        context = (row.get("context") or "").strip()
        conf = row["confidence"].strip().lower()
        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--%s" % uuid.uuid5(NAMESPACE, "indicator:" + pattern),
            "name": "%s %s: %s" % (label, kind, context or value),
            "description": "intel/iocs.csv %s row (malware=%s, confidence=%s)"
                           % (kind, label, conf),
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "confidence": CONFIDENCE[conf],
            "labels": ["malicious-activity"],
        }
        obj = ordered(finalize(obj, old_ind.get(pattern), stamp), [
            "type", "spec_version", "id", "created", "modified", "name",
            "description", "indicator_types", "pattern", "pattern_type",
            "valid_from", "confidence", "labels"])
        indicators.append(obj)

        fam = FAMILIES.get(label)
        if fam is None:
            continue
        target = malware[fam["name"]]["id"]
        rel = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--%s" % uuid.uuid5(
                NAMESPACE, "relationship:%s:%s" % (obj["id"], target)),
            "relationship_type": "indicates",
            "source_ref": obj["id"],
            "target_ref": target,
        }
        rel = finalize(rel, old_rel.get((obj["id"], target)), stamp)
        relationships.append(ordered(rel, [
            "type", "spec_version", "id", "created", "modified",
            "relationship_type", "source_ref", "target_ref"]))

    bundle_id = existing.get("id") or "bundle--%s" % uuid.uuid5(NAMESPACE, "bundle")
    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": list(malware.values()) + indicators + relationships,
    }
    return json.dumps(bundle, indent=2, ensure_ascii=False) + "\n"


def validate(text):
    try:
        from stix2patterns.validator import run_validator
    except ImportError:
        die("--validate requires stix2-patterns (pip install stix2-patterns)")
    bad = 0
    for obj in json.loads(text)["objects"]:
        if obj["type"] == "indicator":
            errors = run_validator(obj["pattern"], stix_version="2.1")
            if errors:
                print("invalid pattern %s: %s" % (obj["pattern"], errors))
                bad += 1
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="do not write; exit 1 if intel/iocs_stix.json is out of date")
    ap.add_argument("--validate", action="store_true",
                    help="validate every STIX pattern (requires stix2-patterns)")
    args = ap.parse_args()

    rows = read_rows()
    existing = load_existing()
    text = build(rows, existing)

    status = 0
    if args.validate and validate(text):
        status = 1

    current = ""
    if os.path.exists(STIX_PATH):
        with open(STIX_PATH) as f:
            current = f.read()
    emitted = sum(1 for r in rows if r["type"].strip() not in EXCLUDED)
    excluded = len(rows) - emitted
    if args.check:
        if current != text:
            print("intel/iocs_stix.json is out of date with intel/iocs.csv; "
                  "run: python3 tools/build_stix.py")
            return 1
        print("intel/iocs_stix.json is in sync: %d CSV rows -> %d indicators "
              "(%d excluded by type: %s)"
              % (len(rows), emitted, excluded, ", ".join(sorted(EXCLUDED))))
        return status
    if current != text:
        with open(STIX_PATH, "w") as f:
            f.write(text)
        print("wrote intel/iocs_stix.json: %d indicators" % emitted)
    else:
        print("intel/iocs_stix.json already up to date")
    return status


if __name__ == "__main__":
    sys.exit(main())
