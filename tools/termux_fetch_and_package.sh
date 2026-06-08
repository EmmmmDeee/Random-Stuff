#!/data/data/com.termux/files/usr/bin/bash
# Termux (Android aarch64, no root) — fetch the MEGA folder and produce a single
# AES-256 password-protected .7z for safe at-rest storage / later sandbox analysis.
#
#   bash termux_fetch_and_package.sh
#
# Output: QUARANTINE_fraudbible_samples.7z   (password: infected)
#
# WARNING: downloads LIVE MALWARE, including an Android RAT (SandroRat.apk).
# It cannot run on its own — never tap-install any .apk it produces. Your
# phone's Play Protect/AV may flag it; that is correct, let it.
set -euo pipefail

LINK="https://mega.nz/folder/ist0nKTI#HheszXtDW361JnbB0EAkNg"
OUTDIR="mega_download"
ARCHIVE="QUARANTINE_fraudbible_samples.7z"
PASS="infected"

# Resolve the script's own directory robustly (not via $0/cwd) so the sibling
# downloader is found no matter how the script is invoked.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
downloader="$script_dir/mega_folder_dl.py"
if [ ! -f "$downloader" ]; then
  echo "error: downloader not found next to this script: $downloader" >&2
  exit 2
fi

echo "[*] Installing dependencies (python, p7zip, clang for pycryptodome)..."
if command -v pkg >/dev/null 2>&1; then
  pkg update -y
  pkg install -y python p7zip clang
else
  echo "    note: 'pkg' not found — not a Termux environment? Skipping install," >&2
  echo "    will rely on python/7z already being on PATH." >&2
fi
python -m pip install --upgrade pip
python -m pip install pycryptodome

# Fail early with a clear message if the toolchain isn't actually usable.
for tool in python 7z sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: required tool '$tool' is not on PATH after install" >&2
    exit 2
  fi
done

echo "[*] Granting Termux storage access (approve the prompt if it appears)..."
if command -v termux-setup-storage >/dev/null 2>&1; then
  termux-setup-storage || true
fi

echo "[*] Downloading folder into ./$OUTDIR ..."
python "$downloader" "$LINK" "$OUTDIR"

echo "[*] Packaging into encrypted archive (AES-256, encrypted headers)..."
rm -f "$ARCHIVE"
7z a -t7z -p"$PASS" -mhe=on -mx=5 "$ARCHIVE" "$OUTDIR" >/dev/null

echo "[*] Verifying integrity..."
if 7z t "$ARCHIVE" -p"$PASS" >/dev/null 2>&1; then
  echo "    OK — archive integrity verified"
else
  echo "error: archive failed integrity check; not safe to rely on" >&2
  exit 1
fi

echo "[*] Outer SHA-256:"
sha256sum "$ARCHIVE"

cat <<EOF

[*] Done. Encrypted archive: $ARCHIVE  (password: $PASS)
    Move it to ~/storage/shared or your SD card, then DELETE the raw
    download so no unencrypted samples remain on the phone:
        mv $ARCHIVE ~/storage/shared/
        rm -rf $OUTDIR
    Keep the password and notes separate. Do NOT extract without a sandbox.
EOF
