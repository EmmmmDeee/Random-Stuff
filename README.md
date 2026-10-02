# Fraud Bible 2020 — Defensive Analysis

Static, defensive analysis of a malware/fraud collection ("Fraud Bible 2020 /
Methods Pack", 64 files) recovered for security research. **No malware samples,
binaries, decompiled source trees, or harmful instructional content are stored in
this repository** — those are quarantined in a gitignored, AES-256 encrypted
archive. What lives here is analysis: hashes, classifications, capabilities, IOCs,
and handling guidance.

## Contents

**Reference (read first)**
| Document | Purpose |
|---|---|
| [`EXECUTIVE_SUMMARY.md`](EXECUTIVE_SUMMARY.md) | One-page distillation — what was found, top findings, defensive output |
| [`DEFINITIONS.md`](DEFINITIONS.md) | Methodology, provenance, glossary, confidence/severity scales, scope & limitations — the lens for everything else |

**Inventory**
| Document | Purpose |
|---|---|
| [`CATEGORISED_LIST.md`](CATEGORISED_LIST.md) | All 64 files grouped into 16 threat categories (names only) |
| [`FILE_STRUCTURE.md`](FILE_STRUCTURE.md) | Directory structure with sizes and detected types |
| [`FILE_MANIFEST.md`](FILE_MANIFEST.md) | Per-file SHA-256, type, active-content verdict, category |
| [`ANALYSIS_INDEX.md`](ANALYSIS_INDEX.md) + [`analysis/`](analysis/) | One document per file: identity, classification, function, handling |

**Analysis (evidence)**
| Document | Purpose |
|---|---|
| [`MALWARE_ANALYSIS.md`](MALWARE_ANALYSIS.md) | Deep dive: Blackshades & DroidJack RATs (hashes, capabilities, C2) |
| [`EXECUTABLES.md`](EXECUTABLES.md) | Every `.exe` in the archives: inventory, hashes, function + typical/historical market value |
| [`EXECUTABLES_ANALYSIS.md`](EXECUTABLES_ANALYSIS.md) | Per-`.exe` static behavioral analysis: imports, packing, the crack-bundled-malware finding |
| [`SOURCE_LEVEL_ANALYSIS.md`](SOURCE_LEVEL_ANALYSIS.md) | Annotated decompiled behavior of the Android RAT |

**Critique**
| Document | Purpose |
|---|---|
| [`DISPARITY.md`](DISPARITY.md) | **Start here** — amateur offense vs. professional engineering/defense, organized |
| [`AMATEUR_TRADECRAFT.md`](AMATEUR_TRADECRAFT.md) | Methods & functionality critique (tradecraft) |
| [`CODE_REVIEW.md`](CODE_REVIEW.md) | Full 15-category code-quality teardown (~35 findings, severity-rated, citation-backed) |
| [`RUST_PERSPECTIVE.md`](RUST_PERSPECTIVE.md) | Defects ranked + idiomatic-Rust contrast + measured benchmark |

**Detection & defense**
| Document | Purpose |
|---|---|
| [`DETECTION_PLAYBOOK.md`](DETECTION_PLAYBOOK.md) | **Layered defenses that catch it** — host/network/mobile/intel + the BurntSushi-style scanning approach |
| [`ATTACK_MAPPING.md`](ATTACK_MAPPING.md) | MITRE ATT&CK technique mapping for both RATs |
| [`detection/`](detection/) | YARA rules + Suricata/Snort signatures (validated against the samples) |
| [`intel/`](intel/) | Machine-readable IOC feed: `iocs.csv` and STIX 2.1 `iocs_stix.json` |

**Tooling**
| Document | Purpose |
|---|---|
| [`tools/ioc-scanner/`](tools/ioc-scanner/) | Rust Aho-Corasick IOC scanner (typed errors, tests, benchmark) |
| [`tools/sweep.sh`](tools/sweep.sh) | ripgrep literal-IOC sweep for fast hunting (re-proven on every CI run) |
| [`tools/build_stix.py`](tools/build_stix.py) | Generate `intel/iocs_stix.json` from `intel/iocs.csv` (`--check` for drift) |
| [`tools/mega_folder_dl.py`](tools/mega_folder_dl.py), [`tools/termux_fetch_and_package.sh`](tools/termux_fetch_and_package.sh) | Rebuild the encrypted sample archive on an isolated host |

## Detection & threat-intel package

- **Host detection:** `detection/droidjack.yar`, `detection/blackshades.yar`,
  `detection/shared_packer.yar` — matched against the real samples during the
  original analysis (samples are not in git, so that check is not re-run in CI);
  compilation and *zero* false positives on every file in this repo are re-proven
  on each CI run by `detection/tests/yara_check.py`.
- **Fast hunt:** `tools/sweep.sh` reads `intel/iocs.csv` and sweeps paths with
  ripgrep; `detection/tests/sweep_check.py` re-proves on every CI run that it
  detects the documented literals and returns a clean verdict on benign input.
- **Network detection:** `detection/droidjack_suricata.rules` — DroidJack C2 DNS,
  report/access URIs, KryoNet token; Blackshades `bshades.eu` DNS. Each SID is
  replayed against synthetic indicator + benign traffic on every CI run by
  `detection/tests/suricata_replay.py`.
- **Intel feeds:** `intel/iocs.csv` (26 indicators, the source of truth) and
  `intel/iocs_stix.json` (STIX 2.1 bundle generated from it by
  `tools/build_stix.py`: 22 indicators; port/regkey/package rows are CSV-only).
  CI fails if the two drift apart or any STIX pattern is invalid.
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
