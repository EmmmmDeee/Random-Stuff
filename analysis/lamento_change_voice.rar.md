# lamento change voice.rar

## Identity
- **Filename:** `lamento change voice.rar`
- **Size:** 18,521,593 bytes
- **Detected type:** RAR archive data, v4, os: Win32
- **SHA-256:** `ff8a7c51c91cae31c039f14dba15c8b9598b5bf09ee7e1bf6162f9f5c3339d43`

## Classification
- **Category:** Pirated software with a malware-bundled crack
- **Safety verdict:** ACTIVE — archive contains executables (one is a suspected injector)

## Description / function
Cracked copy of Audio4Fun "AV Voice Changer Software Diamond 7.0.29": an installer
(`VCS_Diamond.7.0.29.exe`) plus a crack (`Crack/vcscore.exe`).

**Key finding (see `EXECUTABLES_ANALYSIS.md`):** the crack `vcscore.exe`
(SHA-256 `1573c264…c5ea49`) is **not just a patcher — it imports a full
process-injection + persistence toolkit** (`CreateRemoteThread`,
`WriteProcessMemory`, `VirtualAllocEx`, `OpenProcess`, `SetWindowsHookExA`,
`RegSetValueExA`, `InternetOpenA`, `CreateMutexA`) and is packed (`.texta`
entropy 8.00). It also carries the non-standard **`.mackt` section shared with the
Blackshades RAT** (`client.exe`), pointing to a common protector/cracking tool.
Verdict: **suspected malware dropper/injector** disguised as a crack — confirm
dynamically in a sandbox. Detected by `detection/shared_packer.yar`.

## Handling guidance
- Treat as DANGEROUS — higher priority than a typical pirated installer because the
  crack exhibits a code-injection signature. Keep inside the encrypted archive; only
  open in an isolated, offline sandbox VM. Never execute on a host you control.

