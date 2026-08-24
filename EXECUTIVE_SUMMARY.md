# Executive Summary

One-page distillation of the security analysis. Full detail is indexed in
[`README.md`](README.md); methodology and terms are in [`DEFINITIONS.md`](DEFINITIONS.md).

## What this is
A static, **security** analysis of a 64-file malware/fraud collection ("Fraud
Bible 2020 / Methods Pack"). The repository contains **only analysis** — hashes,
classifications, detection rules, and critique. No malware samples, recompilable
decompiled source, or operational criminal instructions are included (all
gitignored). No sample was executed.

## What was in the collection
- **2 live remote-access trojans:** Blackshades NET (Windows, VB6) and
  DroidJack/SandroRat (Android).
- **Cracked/pirated software** with crack-and-keygen executables.
- **~50 text/PDF how-tos** for fraud, carding, ransomware distribution, identity
  theft, drugs, counterfeiting, and an explosives PDF (characterised, not reproduced).
- **9 of 64 files carry active/executable content; 55 are inert** (content-only risk).

## Top findings
1. **A crack is actually a malware dropper.** `vcscore.exe` (shipped as a
   voice-changer "crack") imports a full process-injection + persistence toolkit and
   is packed — a suspected injector, not a patcher. *(`EXECUTABLES_ANALYSIS.md`)*
2. **Cross-sample link:** the non-standard `.mackt` PE section appears in **both**
   the Blackshades RAT and that crack — a shared protector/cracking tool, now a YARA
   hunting pivot. *(`detection/shared_packer.yar`)*
3. **The malware is amateur and trivially detectable.** Everything important is
   hardcoded in plaintext (C2 `droidjack.net`, token `DJ_GooDbYe:(`, the brand in the
   package name), with swallowed errors, data races, and zero tests.
   *(`CODE_REVIEW.md`, `AMATEUR_TRADECRAFT.md`, `DISPARITY.md`)*
4. **Economics confirm "commodity, not capability":** the RAT was the *cheapest*
   item (~$40) and even it is a cracked copy; the expensive software (~$500–$700) is
   pirated. Nothing was paid for. *(`EXECUTABLES.md`)*

## Security output (ready to deploy)
- **Detection:** YARA (host) + Suricata (network), validated against the samples
  *(`detection/`)*.
- **Intelligence:** IOC feed as CSV and STIX 2.1; MITRE ATT&CK mapping
  *(`intel/`, `ATTACK_MAPPING.md`)*.
- **Playbook & tooling:** layered detection guide *(`DETECTION_PLAYBOOK.md`)*, a
  tested Rust Aho-Corasick IOC scanner and a ripgrep sweep *(`tools/`)*.

## Bottom line
Two real but **commodity, amateurishly-built** RATs plus a free fraud toolkit,
assembled by an operator who bought cheap or pirated everything. Its defining
weakness — plaintext indicators and naive literal matching — is exactly what makes
**correct, linear-time detection trivial**, which is what the `detection/`,
`intel/`, and `tools/` artifacts deliver.
