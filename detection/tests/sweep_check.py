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
import os
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SWEEP = os.path.join(ROOT, "tools", "sweep.sh")
FEED = os.path.join(ROOT, "intel", "iocs.csv")


def run(args, cwd=None):
    proc = subprocess.run([SWEEP] + args, capture_output=True, text=True, cwd=cwd)
    return proc.returncode, proc.stdout, proc.stderr


def test_detects_scannable_literals():
    with tempfile.TemporaryDirectory() as tmp:
        # Each synthetic file contains one class of literal IOC.
        cases = [
            ("domain.txt", "check droidjack.net here"),
            ("url.txt", "POST http://www.droidjack.net/storeReport.php"),
            ("string.txt", "token DJ_GooDbYe:( end"),
            ("package.txt", "package net.droidjack.server"),
            ("filemarker.txt", "stub DownloadExecute.bss"),
            ("section.txt", ".mackt section"),
        ]
        for name, body in cases:
            with open(os.path.join(tmp, name), "w") as f:
                f.write(body)

        rc, out, err = run([tmp])
        assert rc == 1, "expected exit 1 on indicator hits, got %d (stderr: %r)" % (rc, err)
        for _, body in cases:
            needle = body.split()[-1] if body.split()[-1] != "here" else "droidjack.net"
            # Search for the exact IOC literal in the combined output.
            assert needle in out or needle in err, "missing expected hit: %r" % needle
        print("PASS: sweep detects all content-scannable IOC literals")


def test_clean_directory_returns_zero():
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "benign.txt"), "w") as f:
            f.write("this is completely unrelated content\n")
        rc, _, _ = run([tmp])
        assert rc == 0, "expected exit 0 on clean input, got %d" % rc
        print("PASS: sweep returns 0 on clean directory")


def test_missing_feed_is_runtime_error():
    with tempfile.TemporaryDirectory() as tmp:
        env = os.environ.copy()
        env["IOC_FEED"] = "/nonexistent/iocs.csv"
        proc = subprocess.run([SWEEP, tmp], capture_output=True, text=True, env=env)
        assert proc.returncode == 2, "expected exit 2 on missing feed, got %d" % proc.returncode
        print("PASS: sweep returns 2 when IOC feed is missing")


def test_sweep_script_exists():
    assert os.path.isfile(SWEEP), "sweep script not found: %s" % SWEEP
    print("PASS: sweep script exists at %s" % SWEEP)


def main():
    if subprocess.run(["sh", "-c", "command -v rg"], capture_output=True).returncode != 0:
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
            print("FAIL: %s: %s" % (t.__name__, e), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
