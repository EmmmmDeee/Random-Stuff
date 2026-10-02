#!/usr/bin/env python3
"""Proof obligation for tools/sweep.sh.

Verifies that the ripgrep-based literal sweep:
  1. Detects every content-scannable IOC type from intel/iocs.csv
     (domain, url, string, package, section, filemarker) in synthetic files.
  2. Returns exit code 1 when indicators are found.
  3. Returns exit code 0 on clean directories.
  4. Treats a missing IOC feed as a runtime error (exit 2).

Requires: ripgrep (rg) on PATH. No real malware samples are used.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Tuple

ROOT = Path(__file__).resolve().parents[2]
SWEEP = ROOT / "tools" / "sweep.sh"
FEED = ROOT / "intel" / "iocs.csv"


def run(args: Iterable[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> Tuple[int, str, str]:
    """Run the sweep script and return (returncode, stdout, stderr)."""
    proc = subprocess.run(
        [str(SWEEP), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
        env=env,
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_sweep_script_exists() -> None:
    assert SWEEP.is_file(), f"sweep script not found: {SWEEP}"
    print(f"PASS: sweep script exists at {SWEEP}")


def test_detects_scannable_literals() -> None:
    """Each content-scannable IOC type must be detected in a synthetic file."""
    cases: list[Tuple[str, str, str]] = [
        ("domain.txt", "droidjack.net", "check droidjack.net here"),
        ("url.txt", "http://www.droidjack.net/storeReport.php", "POST http://www.droidjack.net/storeReport.php"),
        ("string.txt", "DJ_GooDbYe:(", "token DJ_GooDbYe:( end"),
        ("package.txt", "net.droidjack.server", "package net.droidjack.server"),
        ("filemarker.txt", "DownloadExecute.bss", "stub DownloadExecute.bss"),
        ("section.txt", ".mackt", ".mackt section"),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for name, _needle, body in cases:
            (tmp_path / name).write_text(body, encoding="utf-8")

        rc, out, err = run([str(tmp_path)])
        assert rc == 1, f"expected exit 1 on indicator hits, got {rc} (stderr: {err!r})"
        combined = out + err
        for _name, needle, _body in cases:
            assert needle in combined, f"missing expected hit: {needle!r}"
        print("PASS: sweep detects all content-scannable IOC literals")


def test_clean_directory_returns_zero() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "benign.txt").write_text("this is completely unrelated content\n", encoding="utf-8")
        rc, _out, _err = run([str(tmp_path)])
        assert rc == 0, f"expected exit 0 on clean input, got {rc}"
        print("PASS: sweep returns 0 on clean directory")


def test_missing_feed_is_runtime_error() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        env = os.environ.copy()
        env["IOC_FEED"] = "/nonexistent/iocs.csv"
        rc, _out, _err = run([str(tmp)], env=env)
        assert rc == 2, f"expected exit 2 on missing feed, got {rc}"
        print("PASS: sweep returns 2 when IOC feed is missing")


def _ripgrep_available() -> bool:
    return subprocess.run(["sh", "-c", "command -v rg"], capture_output=True).returncode == 0


def main() -> int:
    if not _ripgrep_available():
        print("error: ripgrep (rg) is required", file=sys.stderr)
        return 2

    tests = [
        test_sweep_script_exists,
        test_detects_scannable_literals,
        test_clean_directory_returns_zero,
        test_missing_feed_is_runtime_error,
    ]
    for t in tests:
        try:
            t()
        except AssertionError as e:
            print(f"FAIL: {t.__name__}: {e}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
