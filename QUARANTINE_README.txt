QUARANTINED MALWARE ARCHIVE — HANDLING INSTRUCTIONS
====================================================
Created: 2026-06-08

FILE:        QUARANTINE_fraudbible_samples.7z
SIZE:        ~3.0 GB
CONTENTS:    64 files (the full "Fraud Bible 2020 / Methods Pack" MEGA folder)
ENCRYPTION:  7z / AES-256, encrypted headers (-mhe=on)
PASSWORD:    infected        <-- industry-standard malware-transport password
OUTER SHA-256: 575f4bda12fd3031b7edbb604172799e49cf5ecac866021476e16230d7acfc25

!!  CONTAINS LIVE MALWARE  !!
  - Blackshades NET (Windows RAT)  -> client.exe
  - DroidJack / SandroRat (Android RAT) -> SandroRat.apk
  - Multiple cracked-software RARs with crack/keygen executables (assume malicious)
  - Fraud/identity-theft how-to documents + an explosives-manufacturing PDF
  See MALWARE_ANALYSIS.md for full hashes, capabilities, and C2 IOCs.

WHY PASSWORD-PROTECTED
  The AES encryption means AV/EDR and file managers cannot auto-scan, auto-extract,
  or accidentally execute the contents in transit or at rest. Extraction is a
  deliberate, autonomous act. Nothing detonates by simply having the archive on disk.

SAFE TRANSFER & HANDLING
  1. Move the .7z between machines as-is (USB, scp, etc.). Do NOT extract on any
     host you care about.
  2. Before opening, verify the transfer with the OUTER SHA-256 above:
        sha256sum QUARANTINE_fraudbible_samples.7z
  3. Extract ONLY inside an isolated, offline analysis VM/container with no
     mounted host drives and no network (or a sinkholed/controlled network):
        7z x QUARANTINE_fraudbible_samples.7z -pinfected
  4. Keep the Windows PE samples to a disposable Windows VM and the APK to an
     Android emulator with no real accounts. Snapshot before, revert after.
  5. Never run the binaries on a daily-driver host. Never commit them to a
     public/synced repository.

DO NOT:
  - Double-click or extract on your own device.
  - Disable AV to "make it work" — keep AV on; if it quarantines, that's correct.
  - Re-upload the cleartext samples anywhere public.
