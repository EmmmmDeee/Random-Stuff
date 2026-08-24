# Per-Executable Behavioral Analysis

Static analysis of every `.exe` recovered from the archives — imports, import hash,
section entropy (packing), and behavioral signatures. **No binary was executed;**
each was extracted to an isolated workspace with execute bits stripped, analysed
(`pefile`, `strings`, entropy), then wiped.

This is *analysis* (what each binary is and does). It is **not** a reconstructed
source decompilation — see the note in the commit history on why complete source
recovery of malware/crack/fraud tooling is out of scope.

## Summary table

| Binary | SHA-256 | imphash | Packed? | Verdict |
|---|---|---|---|---|
| `client.exe` (Blackshades) | `5b239d68…f61e93` | `e22efc20…00c70` | VB6 (runtime-resolved) | RAT controller/builder |
| `Registrator.exe` | `71894e21…4e7efb` | `7e753ff6…1060db` | no | OCX registrar helper |
| `upx.exe` | `aab1c02a…42e2da6` | `a75d408d…a28da` | UPX (it *is* UPX) | Legit open-source packer, bundled |
| `BlackShades Emulator.exe` | `9cf361a5…96eb1f` | `9dd8c0ff…40f983` | yes (.rsrc 7.99) | **License crack** (anti-debug) |
| `AIDC Enterprise Setup.exe` | `72e443e0…dbb5a4` | `47913b68…7249bc` | UPX (7.92) | Installer for fake-ID software |
| `Advanced ID Creator.exe` | `11c03bdb…ac83f1` | `f34d5f2d…f5a744` | no (.NET) | Cracked fake-ID app |
| `CLiPW.exe` | `6ff90c64…b586d0` | `f34d5f2d…f5a744` | yes (.text 7.29) | Crack / patcher |
| `VCS_Diamond.7.0.29.exe` | `caf8652a…860193` | `a604c6ea…81f77` | yes (.rsrc 8.00) | Installer for voice-changer |
| `vcscore.exe` | `1573c264…c5ea49` | `57468a4a…6bf159` | yes (.texta 8.00) | **"Crack" with injection capability** ⚠ |
| `Amazon Receipt Generator.exe` | *(encrypted RAR — N/A)* | — | — | Fake-receipt fraud tool |
| `PRG.exe` | *(encrypted RAR — N/A)* | — | — | Fake PayPal-receipt fraud tool |

---

## Key findings

### ⚠ 1. The "voice-changer crack" is a malware carrier
`vcscore.exe` (shipped as the crack for AV Voice Changer Diamond) imports a complete
**process-injection and persistence toolkit**:
`CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx`, `OpenProcess`,
`SetWindowsHookExA`, plus `RegCreateKeyExA`/`RegSetValueExA` (persistence),
`InternetOpenA` (network), and `CreateMutexA` (single-instance — typical of bots).
It is also packed (`.texta` entropy 8.00).

A legitimate audio "crack" has no reason to inject code into other processes,
install registry persistence, or call out to the network. This is the textbook
"cracks bundle malware" pattern — now evidenced statically. **Verdict: suspected
malware dropper/injector; confirm dynamically in a sandbox.** (Static imports are
strong evidence but not execution proof.)

### 2. Shared `.mackt` section links the RAT and the crack
A non-standard `.mackt` section appears in **both** `client.exe` (Blackshades RAT)
**and** `vcscore.exe` (voice-changer crack). That shared, unusual section name
points to a **common protector/cracking tool** applied to both — a cross-sample
correlation that ties otherwise-unrelated files in this pack to the same tooling.

### 3. Almost everything is packed (intentional opacity)
- Installers (`AIDC Enterprise Setup.exe`, `upx.exe`) use **UPX** (UPX0/UPX1).
- Cracks (`BlackShades Emulator.exe`, `CLiPW.exe`, `vcscore.exe`) use high-entropy
  custom packing (resource/code sections at 7.3–8.0).
High entropy = limited static visibility by design; full behavior needs unpacking in
a sandbox.

### 4. The RAT's own crack uses anti-analysis
`BlackShades Emulator.exe` (the license bypass for Blackshades) imports
`IsDebuggerPresent` and packs its resources — i.e. the *crack* itself resists
analysis. Consistent with the earlier finding that the operator ran a pirated copy
of the malware.

### 5. imphash collision: AIDC app ↔ CLiPW
`Advanced ID Creator.exe` and `CLiPW.exe` share imphash `f34d5f2d…f5a744`. Tiny
import tables (common for .NET/loader stubs) can collide, but it suggests they were
produced by the same toolchain/stub — useful for clustering.

### 6. `client.exe` (Blackshades) — confirmed VB6
imphash `e22efc20…00c70`, `msvbvm60`-only imports (APIs resolved at runtime through
the VB runtime, hiding them from the import table), and the tampered section layout
(`.mackt`, unnamed first section). Full capability map in `MALWARE_ANALYSIS.md`.

### ⚠ 8. The receipt fraud kit is the only password-protected archive
`Receipt pack.rar` alone is **encrypted** (RAR 2.9, `Encrypted = +`) — its file data
is password-locked, so the two generator exes can't be extracted or hashed.
Filenames remain readable and reveal a template-driven forgery kit: cloned **PayPal**
page assets (`paypal.css`, `paypal_logo.gif`, `pp_main.js`, a spoofed `regnet.htm`),
a Microsoft receipt PSD (`pidback.psd`), and `Receipt Template.docx/.pdf`. That the
fraud tooling — and *only* the fraud tooling — is password-protected suggests it was
the "paid"/gated item in the pack, distributed more carefully than the free RAT.

### 7. `upx.exe` — the packer itself
The standard open-source UPX executable (UPX0/UPX1 at 8.00, `VirtualProtect` unpack
stub). Bundled so the operator can pack their own stubs. Not malicious by itself;
its *presence* signals intent.

---

## Security takeaways
- **Blocklist all hashes/imphashes above** (EDR/AV/VT). The imphashes catch
  recompiled or repacked variants better than file hashes alone.
- **`vcscore.exe` is the highest-priority item after the RAT**: treat as a
  suspected injector, detonate only in an isolated sandbox, and watch for
  process-injection + registry-Run persistence + outbound HTTP.
- **Hunt for `.mackt`**: the shared section name is a cheap YARA pivot to find other
  files touched by the same protector.
- These executable IOCs complement `intel/iocs.csv` and the YARA rules in
  `detection/`.

> Reminder: this characterises the binaries for defense. It does not reproduce the
> crack/fraud/RAT logic as source.
