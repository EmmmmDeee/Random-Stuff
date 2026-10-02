#!/usr/bin/env python3
"""Tests for red-team/tools/report_generator.py"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import report_generator


class TestReportGenerator(unittest.TestCase):
    def _log(self):
        return {
            "authorization": "authorized-purple-team-simulation",
            "actions": [
                {"technique": "T1059.001", "command_line": "powershell.exe -enc SGVsbG8="},
                {"technique": "T1204.002", "child": "powershell.exe"},
            ],
        }

    def test_extract_techniques(self):
        techniques = report_generator._extract_techniques(self._log()["actions"])
        self.assertEqual(sorted(techniques), ["T1059.001", "T1204.002"])

    def test_recommendations(self):
        recs = report_generator._recommendations({"T1059.001": [], "T1071.004": []})
        self.assertTrue(any("PowerShell" in r for r in recs))
        self.assertTrue(any("DNS" in r for r in recs))

    def test_generate_report_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = Path(td) / "log.json"
            log_path.write_text(json.dumps(self._log()), encoding="utf-8")
            out_path = Path(td) / "report.md"
            report_generator.generate_report(log_path, out_path)
            self.assertTrue(out_path.exists())
            content = out_path.read_text(encoding="utf-8")
            self.assertIn("Purple-Team Activity Report", content)
            self.assertIn("T1059.001", content)


if __name__ == "__main__":
    unittest.main()
