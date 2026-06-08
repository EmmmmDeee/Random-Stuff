#!/usr/bin/env bash
# Fast literal-IOC sweep using ripgrep (BurntSushi's tool).
# Catches the provided malware by its plaintext indicators in one parallel pass.
#
#   tools/sweep.sh <path> [path ...]
#
# Indicators are read from intel/iocs.csv (the single source of truth) — the
# content-scannable rows (domain/url/string/package/filemarker/section), matched
# as literals. This stays in sync with ioc-scanner automatically.
#
# Exit: 0 = clean, 1 = indicator(s) found, 2 = usage/runtime error.
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <path> [path ...]" >&2
  exit 2
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "error: ripgrep (rg) is required" >&2
  exit 2
fi

# Locate the IOC feed relative to this script (resolves symlinks).
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
feed="${IOC_FEED:-$script_dir/../intel/iocs.csv}"
if [ ! -r "$feed" ]; then
  echo "error: IOC feed not found/readable: $feed (set IOC_FEED to override)" >&2
  exit 2
fi

# Extract literal indicator values from content-scannable rows.
# CSV columns: type,value,malware,context,confidence
mapfile -t values < <(
  awk -F',' '
    NR > 1 && $1 ~ /^(domain|url|string|package|section|filemarker)$/ && $2 != "" { print $2 }
  ' "$feed"
)

if [ "${#values[@]}" -eq 0 ]; then
  echo "error: no scannable indicators in $feed" >&2
  exit 2
fi

# -F: fixed-string (literal) matching — values are IOC literals, not regex.
args=()
for v in "${values[@]}"; do args+=(-e "$v"); done

# Run ripgrep, capturing its exit code explicitly so we can tell
# "no match" (1) apart from a real error (>=2) — the bug in the old version.
# -uuu: ignore .gitignore, include hidden + binary files.
set +e
rg -uuu -F -i --no-heading --line-number "${args[@]}" "$@"
rc=$?
set -e

case "$rc" in
  0)
    echo "[!] indicators found — treat the above files as suspected malware" >&2
    exit 1
    ;;
  1)
    echo "[ok] no indicators found (${#values[@]} indicators checked)" >&2
    exit 0
    ;;
  *)
    echo "error: ripgrep failed (exit $rc)" >&2
    exit 2
    ;;
esac
