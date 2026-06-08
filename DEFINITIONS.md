# Definitions, Methodology & Scope

Reference layer for the whole repository: how the analysis was produced, what the
terms mean, how confidence/severity are graded, and what the limits are. Every
other document should be read against this one.

## Provenance & verification
- **Source:** a public MEGA folder, "Fraud Bible 2020 / Methods Pack" (64 files).
- **Ground-truth hashes (re-verified 2026-06-08, SHA-256):**
  | Artifact | SHA-256 |
  |---|---|
  | `DroidJack.4.4.zip` | `ba01b036c8386af1b62263a8e29a47f6898b210efee985e299e8d3e5b79c1bf5` |
  | `SandroRat.apk` | `30aa2eeeb8401e4a312a7e99462432769a7c569114180aaedbfcbef18b6db268` |
  | `classes.dex` | `fcac2275c833038982ed5bf3f27715bb1991f679d398a125661df15821737a1e` |
  | `Blackshades.5.5.1.zip` | `837d78e992cc53a6f125f486e3991975145d546c5f320e34df2af7c516f61e93` |
  | `client.exe` | `5b239d680aac3e49d722a6859e397d327cd6b9dcbfd8eb09c3ccfaa007bbb95e` |
  | `client.exe` imphash | `e22efc208b0220bae4bf4bd600a00c70` |
- These values are consistent across `MALWARE_ANALYSIS.md`, `intel/iocs.csv`,
  `intel/iocs_stix.json`, `detection/*.yar`, and `analysis/*` (checked, no drift).

## Methodology
- **Static analysis only. No sample was executed.** A Windows PE and an Android APK
  cannot run in the Linux analysis container; binaries were extracted to an isolated
  workspace with execute bits stripped, analysed, then wiped.
- **Tools:** `file`, `pefile`, `strings`, `radare2` (PE); `jadx` 1.5.0 (DEX→Java),
  apktool-decoded manifest (Android); `7z`, `yara`, `sha256sum`.
- **Evidence basis:** every behavioral claim traces to a decompiled construct,
  manifest entry, import table, or string — see `SOURCE_LEVEL_ANALYSIS.md` and
  `MALWARE_ANALYSIS.md`.

## Confidence levels (used in `intel/iocs.csv`)
- **high** — directly observed in the sample and specific to it (file hashes; the
  C2 host `droidjack.net`; the command token `DJ_GooDbYe:(`; package name).
- **medium** — observed but less uniquely attributable (imphash; `bshades.eu`;
  default port `1337`; persistence registry keys).
- **low** — present but weak or shared with benign software (e.g. `no-ip.info`
  appears as sample/test subdomains; dynamic-DNS is a category, not a fingerprint).

## Severity scale (used in the code reviews)
- 🔴 **critical** — corrupts correctness/safety or hides other failures
  (swallowed errors, data races, undefined behavior, no tests).
- 🟠 **major** — reliability/architecture defect that causes real runtime harm or
  blocks maintainability (resource leaks, wrong concurrency primitives, god-methods).
- 🟡 **minor** — quality/readability issue with no direct correctness impact
  (naming, magic numbers, missing docs).

## Glossary
- **RAT** — Remote Access Trojan: malware giving an operator covert remote control
  of an infected device.
- **C2 (C&C)** — Command-and-Control: the server/channel the malware contacts for
  instructions and to exfiltrate data.
- **IOC** — Indicator of Compromise: an observable (hash, domain, URL, string,
  registry key) usable to detect the threat.
- **imphash** — a hash of a PE's import table; groups samples built from the same
  code/toolchain even when bytes differ.
- **DEX** — Dalvik Executable: the compiled bytecode inside an Android APK.
- **APK** — Android application package (a ZIP containing the manifest, dex, resources).
- **YARA** — a rule language for pattern-matching files to classify malware.
- **STIX 2.1** — a structured JSON standard for sharing threat intelligence
  (used in `intel/iocs_stix.json`).
- **MITRE ATT&CK** — a catalogue of adversary techniques with stable IDs
  (mapped in `ATTACK_MAPPING.md`).
- **Aho-Corasick** — a finite-automaton algorithm that matches many string patterns
  in a single linear pass (basis of `tools/ioc-scanner/`).
- **KryoNet** — a Java TCP networking library; DroidJack's C2 transport.
- **Dynamic DNS** — services (e.g. no-ip) mapping a hostname to a changing IP;
  common in commodity-malware C2.

## Scope & boundaries
- **In scope:** detection, classification, threat intelligence, code-quality
  critique, safe handling/containment.
- **Out of scope (deliberately absent):** the malware samples themselves, the full
  recompilable decompiled source tree, operational criminal instructions from the
  text files, and any "improvement" that would make the malware more effective or
  evasive. These are gitignored or never produced.

## Limitations
- Blackshades is VB6: behavior is mapped via forms/strings/imports, not full source
  decompilation (no VB6 decompiler was used). Claims there are capability-level.
- The 3 PDFs flagged with `/JS`/`/OpenAction` are a **heuristic** flag, not
  confirmed-malicious; those markers also occur in benign PDFs.
- `tools/ioc-scanner/` is verified to **compile** (cargo check, all targets, zero
  warnings); a full `cargo test`/`cargo bench` run was blocked by build-environment
  contention in the analysis container. The only measured throughput figure
  (0.42 GiB/s, Complete mode) was directly observed; no other is claimed.
