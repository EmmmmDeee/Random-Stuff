#!/usr/bin/env python3
"""Tests for red-team/tools/simulate.py"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import simulate


class TestSimulate(unittest.TestCase):
    def test_authorization_required(self):
        result = subprocess.run(
            [sys.executable, "-m", "simulate", "drop-decoy"],
            cwd=str(Path(__file__).resolve().parent.parent / "tools"),
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--i-authorize-this-is-my-system", result.stderr)

    def test_drop_decoy_writes_marker(self):
        with tempfile.TemporaryDirectory() as td:
            args = type("Args", (), {
                "i_authorize_this_is_my_system": True,
                "dir": td,
                "interpreter": None,
                "domains": None,
                "name": None,
            })()
            result = simulate.simulate_drop_malware_decoy(args)
            self.assertEqual(result["technique"], "T1204")
            self.assertTrue(Path(result["path"]).exists())
            content = Path(result["path"]).read_text(encoding="utf-8")
            self.assertIn("benign decoy", content.lower())

    def test_office_spawn_marker(self):
        args = type("Args", (), {
            "i_authorize_this_is_my_system": True,
            "dir": None,
            "interpreter": "sh",
            "domains": None,
            "name": None,
        })()
        result = simulate.simulate_office_spawns_shell(args)
        self.assertEqual(result["technique"], "T1204.002")
        self.assertEqual(result["child"], "sh")
        self.assertIn("redteam-simulation-office-spawn-", result["marker"])

    def test_dns_queries_default(self):
        args = type("Args", (), {
            "i_authorize_this_is_my_system": True,
            "dir": None,
            "interpreter": None,
            "domains": None,
            "name": None,
        })()
        result = simulate.simulate_dns_queries(args)
        self.assertEqual(result["technique"], "T1071.004")
        self.assertEqual(result["domains"], ["sim-c2.example"])

    def test_chain_runs_without_error(self):
        with tempfile.TemporaryDirectory() as td:
            args = type("Args", (), {
                "i_authorize_this_is_my_system": True,
                "action": "chain",
                "delay": 0.0,
                "dir": td,
                "interpreter": "sh",
                "domains": "a.example,b.example",
                "name": "test-task",
                "output": None,
            })()
            simulate.handle(args)


if __name__ == "__main__":
    unittest.main()
