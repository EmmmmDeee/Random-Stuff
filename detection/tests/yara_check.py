#!/usr/bin/env python3
"""Compile every detection/*.yar rule file and prove it does not false-positive
on this repository's own content (analysis docs, IOC feeds, tooling).

The documentation quotes every indicator the rules key on, so this is the
adversarial negative set: a rule that fires on prose would fire on any report,
paste or wiki page that discusses the malware.

Compilation warnings are treated as errors. Requires: yara-python.
Exit 0 = pass, 1 = fail, 2 = setup error.
"""
import glob
import os
import subprocess
import sys

try:
    import yara
except ImportError:
    print("error: yara-python is required (pip install yara-python)", file=sys.stderr)
    sys.exit(2)

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def tracked_files():
    out = subprocess.run(["git", "-C", ROOT, "ls-files", "-z"],
                         capture_output=True, check=True).stdout
    return [os.path.join(ROOT, p) for p in out.decode().split("\0") if p]


def main():
    rule_files = sorted(glob.glob(os.path.join(ROOT, "detection", "*.yar")))
    if not rule_files:
        print("error: no detection/*.yar files found", file=sys.stderr)
        return 2
    files = tracked_files()
    ok = True
    for rf in rule_files:
        name = os.path.relpath(rf, ROOT)
        try:
            rules = yara.compile(filepath=rf, error_on_warning=True)
        except yara.Error as e:
            print("FAIL: %s does not compile cleanly: %s" % (name, e))
            ok = False
            continue
        count = sum(1 for _ in rules)
        if count == 0:
            print("FAIL: %s defines no rules" % name)
            ok = False
            continue
        hits = []
        for path in files:
            if os.path.isfile(path):
                hits += ["%s:%s" % (os.path.relpath(path, ROOT), m.rule)
                         for m in rules.match(path)]
        if hits:
            print("FAIL: %s false-positives on repository files: %s" % (name, hits))
            ok = False
        else:
            print("PASS: %s (%d rules) compiles; 0 matches across %d repository files"
                  % (name, count, len(files)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
