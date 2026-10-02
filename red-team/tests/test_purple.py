#!/usr/bin/env python3
"""Tests for red-team/tools/purple.py"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import purple


class TestPurple(unittest.TestCase):
    def test_generate_template_structure(self):
        data = purple._generate_template_data()
        template = data["coverage"]
        self.assertIsInstance(template, dict)
        self.assertGreater(len(template), 100)
        self.assertTrue(all(t.startswith("T") for t in template))
        self.assertTrue(all(v is None for v in template.values()))

    def test_score_coverage_all_zero(self):
        coverage = {"T1003": 0, "T1055": 0}
        report = purple.score_coverage(coverage)
        # total_techniques is derived from the full framework catalog, not the input map.
        self.assertEqual(report["covered"], 2)
        self.assertEqual(report["average_confidence"], 0.0)
        self.assertEqual(sorted(report["zero_coverage"]), ["T1003", "T1055"])

    def test_score_coverage_mixed(self):
        coverage = {"T1003": 0, "T1055": 25, "T1059": 80}
        report = purple.score_coverage(coverage)
        self.assertEqual(report["weak_coverage"], ["T1055"])
        self.assertEqual(report["average_confidence"], 35.0)

    def test_score_coverage_filters_unknown(self):
        coverage = {"T9999.999": 50}
        report = purple.score_coverage(coverage)
        self.assertEqual(report["total_techniques"], len(purple._generate_template_data()["coverage"]))
        # Unknown technique IDs are ignored; coverage map only contains framework techniques.
        self.assertEqual(report["covered"], 0)

    def test_template_roundtrip(self):
        template = purple._generate_template_data()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "coverage.json"
            path.write_text(json.dumps(template), encoding="utf-8")
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded, template)


if __name__ == "__main__":
    unittest.main()
