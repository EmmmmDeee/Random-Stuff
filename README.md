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
| [`DISPARITY.md`](DISPARITY.md) | **Start here for the critique** — amateur offense vs. professional engineering/defense, organized |
| [`AMATEUR_TRADECRAFT.md`](AMATEUR_TRADECRAFT.md) | Methods & functionality critique (tradecraft) |
| [`CODE_REVIEW.md`](CODE_REVIEW.md) | Code-style critique (19 findings) |
| [`RUST_PERSPECTIVE.md`](RUST_PERSPECTIVE.md) | Defects ranked + idiomatic-Rust contrast + measured benchmark |
| [`MALWARE_ANALYSIS.md`](MALWARE_ANALYSIS.md) | Deep dive: Blackshades & DroidJack RATs (hashes, capabilities, C2) |
| [`SOURCE_LEVEL_ANALYSIS.md`](SOURCE_LEVEL_ANALYSIS.md) | Annotated decompiled behavior of the Android RAT |
| [`ATTACK_MAPPING.md`](ATTACK_MAPPING.md) | MITRE ATT&CK technique mapping for both RATs |
| [`detection/`](detection/) | YARA rules + Suricata/Snort signatures (validated against the samples) |
| [`intel/`](intel/) | Machine-readable IOC feed: `iocs.csv` and STIX 2.1 `iocs_stix.json` |
| [`tools/`](tools/) | Scripts to rebuild the encrypted sample archive on an isolated host |

## Detection & threat-intel package

- **Host detection:** `detection/droidjack.yar`, `detection/blackshades.yar` —
  tested to match the real samples and to *not* false-positive on these docs.
- **Network detection:** `detection/droidjack_suricata.rules` — C2 domain, URIs,
  KryoNet token, dynamic-DNS family.
- **Intel feeds:** `intel/iocs.csv` (18 indicators) and `intel/iocs_stix.json`
  (STIX 2.1 bundle, ready for MISP/TAXII import).
- **Coverage map:** `ATTACK_MAPPING.md` ties every capability to a MITRE ATT&CK ID.

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
