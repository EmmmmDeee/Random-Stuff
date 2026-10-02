#!/usr/bin/env python3
"""Tests for the red-team operator artifact generator.

Run from the repo root: python3 -m pytest red-team/tests/test_operator.py
"""

import base64
import json
import subprocess
import sys
from pathlib import Path

import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "red-team" / "tools"


class TestOperator(unittest.TestCase):

    @staticmethod
    def _run(*args):
        cmd = [sys.executable, str(TOOLS / "operator_mod.py"), *args]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return proc.stdout, proc.stderr

    @staticmethod
    def _extract_json(stdout):
        """Parse the JSON block printed after the authorization banner."""
        lines = stdout.splitlines()
        # JSON starts after the banner; find the first '{' line.
        start = next(i for i, line in enumerate(lines) if line.strip().startswith("{"))
        return json.loads("\n".join(lines[start:]))

    def test_cradle_generates_expected_fields(self):
        out, _ = self._run("cradle", "--url", "http://test.example/payload.ps1")
        data = self._extract_json(out)
        self.assertEqual(data["technique"], "T1059.001")
        self.assertIn("Invoke-WebRequest", data["cleartext"])
        self.assertTrue(data["command_line"].startswith("powershell.exe -nop -w hidden -enc"))
        # Verify the base64 is a valid UTF-16-LE encoded PowerShell command.
        decoded = base64.b64decode(data["encoded_command"]).decode("utf-16-le")
        self.assertEqual(decoded, data["cleartext"])

    def test_persistence_generates_schtasks_command(self):
        out, _ = self._run("persistence", "--name", "RedTeamTest")
        data = self._extract_json(out)
        self.assertEqual(data["technique"], "T1053.005")
        self.assertEqual(data["task_name"], "RedTeamTest")
        self.assertIn("schtasks /create /tn RedTeamTest", data["command_line"])
        self.assertIn("powershell.exe -nop -w hidden -enc", data["command_line"])

    def test_lure_generates_macro_template(self):
        out, _ = self._run("lure", "--actor", "HelpDesk", "--pretext", "password reset")
        data = self._extract_json(out)
        self.assertEqual(data["technique"], "T1204.002")
        self.assertIn("HelpDesk", data["subject"])
        self.assertEqual(data["filename"], "password_reset.docm")
        self.assertIn("AutoOpen", data["macro_placeholder"])
        self.assertIn("authorized", data["macro_placeholder"].lower())

    def test_c2_generates_beacon_profile(self):
        out, _ = self._run("c2", "--domain", "beacon.example", "--jitter", "25")
        data = self._extract_json(out)
        self.assertEqual(data["technique"], "T1071")
        self.assertEqual(data["c2_host"], "beacon.example")
        self.assertEqual(data["jitter_percent"], 25)
        self.assertEqual(data["beacon_interval_seconds"], 60)
        self.assertIn("example_beacon_url", data)

    def test_cradle_writes_output_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out_path = Path(td) / "cradle.json"
            self._run("cradle", "--url", "http://test.example/payload.ps1", "-o", str(out_path))
            self.assertTrue(out_path.exists())
            data = json.loads(out_path.read_text())
            self.assertEqual(data["technique"], "T1059.001")


if __name__ == "__main__":
    unittest.main()
