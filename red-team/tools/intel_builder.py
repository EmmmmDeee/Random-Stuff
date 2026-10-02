"""
`rt intel` — authorized adversary-campaign intelligence builder.

Produces STIX 2.1-style Indicator, Threat-Actor, and Relationship objects for
legitimate purple-team exercises. All infrastructure values are placeholders or
user-supplied decoys; no real C2 is created.
"""

import argparse
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

import attack


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _id(kind, name):
    return f"{kind}--{secrets.token_hex(16)}"


def build_campaign(args):
    """Build a JSON bundle of STIX-ish campaign objects."""
    actor_id = _id("threat-actor", args.actor)
    campaign_id = _id("campaign", args.name)
    indicator_id = _id("indicator", args.ioc)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{secrets.token_hex(16)}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "threat-actor",
                "id": actor_id,
                "name": args.actor,
                "description": f"Simulated threat actor for authorized exercise {args.name}.",
                "created": _now(),
                "modified": _now(),
                "is_family": False,
                "resource_level": "organization",
                "sophistication": args.sophistication,
            },
            {
                "type": "campaign",
                "id": campaign_id,
                "name": args.name,
                "description": args.description or f"Authorized purple-team campaign {args.name}.",
                "created": _now(),
                "modified": _now(),
                "first_seen": _now(),
            },
            {
                "type": "indicator",
                "id": indicator_id,
                "name": f"Decoy IOC for {args.name}",
                "pattern": f"[file:name = '{args.ioc}']",
                "pattern_type": "stix",
                "valid_from": _now(),
                "created": _now(),
                "modified": _now(),
            },
            {
                "type": "relationship",
                "id": _id("relationship", "attributed-to"),
                "relationship_type": "attributed-to",
                "source_ref": campaign_id,
                "target_ref": actor_id,
                "created": _now(),
                "modified": _now(),
            },
            {
                "type": "relationship",
                "id": _id("relationship", "indicates"),
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": campaign_id,
                "created": _now(),
                "modified": _now(),
            },
        ],
    }
    return bundle


def _emit(bundle, output_path=None):
    text = json.dumps(bundle, indent=2)
    print(text)
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
        print(f"\n✅ Campaign intel bundle written: {out}")


def register(subparsers):
    p = subparsers.add_parser("intel", help="Build authorized adversary-campaign intel bundles")
    add_arguments(p)
    p.set_defaults(func=handle)


# --- CLI wiring -------------------------------------------------------------
def add_arguments(p):
    p.add_argument("--name", required=True, help="Campaign name")
    p.add_argument("--actor", required=True, help="Threat actor alias")
    p.add_argument("--ioc", required=True, help="Decoy IOC filename/hash")
    p.add_argument("--description", help="Campaign description")
    p.add_argument(
        "--sophistication",
        default="intermediate",
        choices=["minimal", "intermediate", "advanced", "strategic"],
        help="Actor sophistication level",
    )
    p.add_argument("-o", "--output", help="Write bundle to this path")


def handle(args):
    bundle = build_campaign(args)
    _emit(bundle, args.output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Authorized adversary-campaign intel builder")
    add_arguments(parser)
    handle(parser.parse_args())
