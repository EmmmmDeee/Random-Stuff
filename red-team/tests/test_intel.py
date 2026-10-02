#!/usr/bin/env python3
"""Tests for red-team/tools/intel_builder.py"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import intel_builder


class TestIntelBuilder(unittest.TestCase):
    def test_build_campaign_structure(self):
        args = type("Args", (), {
            "name": "OpTest",
            "actor": "Alpha",
            "ioc": "decoy.exe",
            "description": "Test campaign",
            "sophistication": "advanced",
        })()
        bundle = intel_builder.build_campaign(args)
        self.assertEqual(bundle["type"], "bundle")
        self.assertEqual(bundle["spec_version"], "2.1")
        types = {obj["type"] for obj in bundle["objects"]}
        self.assertEqual(types, {"threat-actor", "campaign", "indicator", "relationship"})

    def test_campaign_relationships(self):
        args = type("Args", (), {
            "name": "OpTest",
            "actor": "Alpha",
            "ioc": "decoy.exe",
            "description": None,
            "sophistication": "intermediate",
        })()
        bundle = intel_builder.build_campaign(args)
        rels = [obj for obj in bundle["objects"] if obj["type"] == "relationship"]
        types = {r["relationship_type"] for r in rels}
        self.assertIn("attributed-to", types)
        self.assertIn("indicates", types)

    def test_write_output_file(self):
        args = type("Args", (), {
            "name": "OpTest",
            "actor": "Alpha",
            "ioc": "decoy.exe",
            "description": None,
            "sophistication": "minimal",
            "output": None,
        })()
        with tempfile.TemporaryDirectory() as td:
            args.output = str(Path(td) / "intel.json")
            intel_builder.handle(args)
            self.assertTrue(Path(args.output).exists())
            data = json.loads(Path(args.output).read_text(encoding="utf-8"))
            self.assertEqual(data["type"], "bundle")


if __name__ == "__main__":
    unittest.main()
