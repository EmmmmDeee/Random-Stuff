#!/usr/bin/env python3
"""Tests for red-team/tools/crosscheck.py"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import crosscheck


class TestCrosscheck(unittest.TestCase):
    def _artifact(self, **fields):
        return {"technique": fields.get("technique", "T1059.001"), **fields}

    def test_suggest_tests_cradle(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "artifact.json"
            path.write_text(json.dumps(self._command_artifact()), encoding="utf-8")
            result = crosscheck.suggest_tests(path)
            self.assertEqual(result["technique"], "T1059.001")
            self.assertIn("yara_rule", result)
            self.assertIn("suricata_rule", result)
            self.assertIn("powershell.exe", result["yara_rule"])

    def test_suggest_tests_macro(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "artifact.json"
            path.write_text(json.dumps(self._macro_artifact()), encoding="utf-8")
            result = crosscheck.suggest_tests(path)
            self.assertEqual(result["technique"], "T1204.002")
            self.assertIn("AutoOpen", result["yara_rule"])

    def test_output_file(self):
        with tempfile.TemporaryDirectory() as td:
            in_path = Path(td) / "artifact.json"
            out_path = Path(td) / "cross.json"
            in_path.write_text(json.dumps(self._command_artifact()), encoding="utf-8")
            crosscheck.suggest_tests(in_path, out_path)
            self.assertTrue(out_path.exists())
            data = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(data["technique"], "T1059.001")

    def _command_artifact(self):
        return {"technique": "T1059.001", "command_line": "powershell.exe -enc SGVsbG8="}

    def _macro_artifact(self):
        return {"technique": "T1204.002", "macro_placeholder": "Sub AutoOpen()\nEnd Sub"}


if __name__ == "__main__":
    unittest.main()
