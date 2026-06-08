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
set -e

LINK="https://mega.nz/folder/ist0nKTI#HheszXtDW361JnbB0EAkNg"
OUTDIR="mega_download"
ARCHIVE="QUARANTINE_fraudbible_samples.7z"
PASS="infected"

echo "[*] Installing dependencies (python, p7zip, clang for pycryptodome)..."
pkg update -y
pkg install -y python p7zip clang
pip install --upgrade pip
pip install pycryptodome

echo "[*] Granting Termux storage access (approve the prompt if it appears)..."
termux-setup-storage || true

echo "[*] Downloading folder into ./$OUTDIR ..."
python "$(dirname "$0")/mega_folder_dl.py" "$LINK" "$OUTDIR"

echo "[*] Packaging into encrypted archive (AES-256, encrypted headers)..."
rm -f "$ARCHIVE"
7z a -t7z -p"$PASS" -mhe=on -mx=5 "$ARCHIVE" "$OUTDIR"

echo "[*] Verifying integrity..."
7z t "$ARCHIVE" -p"$PASS" >/dev/null && echo "    OK"

echo "[*] Outer SHA-256:"
sha256sum "$ARCHIVE"

echo
echo "[*] Done. Encrypted archive: $ARCHIVE  (password: $PASS)"
echo "    Move it to ~/storage/shared or your SD card, then DELETE the raw"
echo "    download so no unencrypted samples remain on the phone:"
echo "        mv $ARCHIVE ~/storage/shared/"
echo "        rm -rf $OUTDIR"
echo "    Keep the password and notes separate. Do NOT extract without a sandbox."
