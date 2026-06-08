# Fraud Bible 2020 — Defensive Analysis

Static, defensive analysis of a malware/fraud collection ("Fraud Bible 2020 /
Methods Pack", 64 files) recovered for security research. **No malware samples,
binaries, decompiled source trees, or harmful instructional content are stored in
this repository** — those are quarantined in a gitignored, AES-256 encrypted
archive. What lives here is analysis: hashes, classifications, capabilities, IOCs,
and handling guidance.

## Contents

| Document | Purpose |
|---|---|
| [`CATEGORISED_LIST.md`](CATEGORISED_LIST.md) | All 64 files grouped into 16 threat categories (names only) |
| [`FILE_STRUCTURE.md`](FILE_STRUCTURE.md) | Directory structure with sizes and detected types |
| [`FILE_MANIFEST.md`](FILE_MANIFEST.md) | Per-file SHA-256, type, active-content verdict, category |
| [`ANALYSIS_INDEX.md`](ANALYSIS_INDEX.md) | Index of the per-file deep-dive docs |
| [`analysis/`](analysis/) | One document per file: identity, classification, function, handling |
| [`MALWARE_ANALYSIS.md`](MALWARE_ANALYSIS.md) | Deep dive: Blackshades & DroidJack RATs (hashes, capabilities, C2) |
| [`SOURCE_LEVEL_ANALYSIS.md`](SOURCE_LEVEL_ANALYSIS.md) | Annotated decompiled behavior of the Android RAT |
| [`tools/`](tools/) | Scripts to rebuild the encrypted sample archive on an isolated host |

## Key findings

- **2 live RATs:** Blackshades NET (Windows, VB6) and DroidJack/SandroRat (Android).
- **9 of 64 files carry active/executable content** (RAT archives, crack/keygen
  RARs, and 3 PDFs with `/JS`/`/OpenAction`); the other 55 are inert text/documents.
- Full hashes and C2 indicators (`droidjack.net`, TCP/1337, `DJ_GooDbYe:(`,
  `bshades.eu`, `*.no-ip.*`) are in the manifest and malware analysis.

## Handling rules

- The actual samples are **not** in git. They sit in `QUARANTINE_fraudbible_samples.7z`
  (AES-256, password `infected`), which is gitignored.
- Detonate only in an isolated, offline sandbox VM. Never run anything on a host
  you control, and never republish the underlying material.

## Scope

This repository is for **defensive** purposes: detection, threat intelligence, and
safe handling. It deliberately excludes operational criminal instructions and
working malware.
