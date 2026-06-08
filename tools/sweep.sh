#!/usr/bin/env bash
# Fast literal-IOC sweep using ripgrep (BurntSushi's tool).
# Catches the provided malware by its plaintext indicators in one parallel pass.
#
#   tools/sweep.sh <path> [path ...]
#
# Exit: 1 if any indicator is found, 0 if clean, 2 on usage error.
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <path> [path ...]" >&2
  exit 2
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "error: ripgrep (rg) is required" >&2
  exit 2
fi

# Literal indicators (case-insensitive). Keep in sync with intel/iocs.csv.
PATTERNS=(
  'droidjack\.net'
  'DJ_GooDbYe:\('
  'net[./]droidjack[./]server'
  'storeReport\.php'
  '/Access/DJ'
  'SandroRat_Contacts_Database'
  'RecordedCallLogsTable'
  'com\.whatsapp/databases/msgstore\.db'
  'bshades\.eu'
  'DownloadExecute\.bss'
  'Blackshades Project'
  'cracked by MaxXor'
)

args=()
for p in "${PATTERNS[@]}"; do args+=(-e "$p"); done

# -uuu: don't respect .gitignore, include hidden + binary files.
if rg -uuu -i --no-heading --line-number "${args[@]}" "$@"; then
  echo "[!] indicators found — treat the above files as suspected malware" >&2
  exit 1
else
  echo "[ok] no indicators found" >&2
  exit 0
fi
