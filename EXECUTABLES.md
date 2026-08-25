# The Executables (.exe) in the Upload — Inventory, Function & Market Value

A focused look at the Windows `.exe` files inside the archives: what each is, its
SHA-256 (extracted, never executed), and the **typical/historical price** of the
tool it belongs to. Prices are reported/retail figures for context — historical
threat intelligence, not a buying guide.

> Security scope. Hashes are IOC-grade identifiers. No executable was run; all were
> extracted to an isolated workspace with execute bits stripped, then wiped.

## Inventory

### Blackshades.5.5.1.zip — the actual RAT toolkit
| File | Size | SHA-256 (first 32) | Role |
|---|---|---|---|
| `client.exe` | 5,221,030 | `5b239d680aac3e49d722a6859e397d32` | The RAT controller/builder (VB6) |
| `data/Registrator.exe` | 56,440 | `71894e21a2d7ecd52ed8ee06c8634b55` | Registers the bundled OCX controls |
| `data/upx.exe` | 271,872 | `aab1c02a436a5293026362a3b31127bd` | **UPX packer** — bundled to compress/obfuscate stubs |
| `Crack/BlackShades Emulator.exe` | 203,264 | `9cf361a5e3f8e3176ba3e3002316753d` | **License crack** / activation emulator |

Tells: shipping `upx.exe` shows the operator's intended pack-the-stub workflow; the
"Emulator" is the crack that bypasses Blackshades' own licensing — i.e. this is a
*pirated copy of malware*.

### Advanced_ID_Creator_..._by_Luis.rar — fake-ID software (cracked)
| File | Size | SHA-256 (first 32) | Role |
|---|---|---|---|
| `AIDC Enterprise Setup.exe` | 8,716,215 | `72e443e0127649a840d22b2ae1223ff4` | Installer |
| `Crack/Advanced ID Creator.exe` | 4,243,456 | `11c03bdb2a8ea3cfd45c6f96da2032ec` | Cracked main application |
| `Crack/CLiPW.exe` | 86,016 | `6ff90c64e5ad9386071857fd6edf429a` | Crack / patcher |

### lamento change voice.rar — AV Voice Changer Diamond (cracked)
| File | Size | SHA-256 (first 32) | Role |
|---|---|---|---|
| `VCS_Diamond.7.0.29.exe` | 17,463,616 | `caf8652a1f1b1ec1a58b35a446271f92` | Installer |
| `Crack/vcscore.exe` | 1,005,733 | `1573c2646f63d27dba8686205ae3343a` | Crack |

### Receipt pack.rar — fake-receipt fraud kit (password-protected)
This RAR is **encrypted** (`Encrypted = +`, RAR 2.9): headers/filenames are
readable but file *data* is password-protected, so the executables cannot be
extracted or hashed without the password. The readable inventory shows a
template-driven fake-receipt fraud kit:
- `Amazon Reciept Generator/Amazon Receipt Generator.exe` (3,450,880 B) — hash N/A (encrypted)
- `PayPal Generator/PRG.exe` (399,872 B) — hash N/A (encrypted)
- Cloned PayPal page assets: `paypal.css`, `paypal_logo.gif`, `pp_main.js`,
  `regnet.htm` (a spoofed PayPal "registration/transaction" page)
- `Microsoft PID/pidback.psd` (Photoshop template), `Receipt Template.docx/.pdf`

Purpose: generate forged Amazon/PayPal/Microsoft receipts for refund / chargeback /
"item not received" fraud, using the bundled HTML/PSD/DOCX templates.

### MOff16ProP.rar — pirated Microsoft Office
- `Office_2016_..._by_Ratiborus.iso` (2.72 GB). No loose `.exe`; the ISO bundles the
  Office installer plus a **Ratiborus KMS** activator (a well-known piracy/activation
  toolkit).

### adobe photoshop.rar
- Pirated Adobe install; no `.exe`/`.msi`/`.iso` surfaced at the top level
  (installer likely nested). Treated as assumed-malicious pirated software.

---

## Typical / historical market value

Figures are approximate, reported retail or documented case values — included to
characterise the economics, not to facilitate acquisition.

| Tool | Type | Typical price | Notes / source context |
|---|---|---|---|
| **Blackshades NET** | Commercial RAT | **~$40** (tiers to ~$100) | Per the May 2014 FBI/Europol takedown: thousands of buyers, ~$350k total sales, ~500k claimed infections. Cheap, mass-market. |
| **DroidJack** *(APK/Java, not .exe — for context)* | Commercial Android RAT | **~$210** one-time/"lifetime" | Subject of June 2015 Europol-coordinated action across multiple countries. |
| **Advanced ID Creator Enterprise** | ID-card design software | **~$100–$300** (Enterprise) | Legitimate product; here cracked to $0. Repurposed for fake-ID fabrication. |
| **AV Voice Changer Software Diamond** (Audio4Fun) | Voice-changer software | **~$100** (~$99.95) | Legitimate product; cracked. Used for vishing/social-engineering. |
| **MS Office 2016 Pro Plus** | Office suite | **~$400–$540** | Pirated via Ratiborus KMS (free activator). |
| **Adobe Photoshop** | Image editor | **~$700 perpetual (CS-era)** / ~$10–21/mo CC | Pirated. |
| **Fake receipt generators** | Fraud tooling | **~$5–$50**, often free in packs | Commodity refund/chargeback-fraud tools; frequently bundled free, as here. |

## The economic story (and why it reinforces the "amateur/commodity" thesis)
- **The malware is the cheapest thing in the folder.** Blackshades at ~$40 is an
  impulse purchase; the "premium" items (Office ~$500, Photoshop ~$700) are the
  expensive ones — and every one of those is **pirated**, not bought.
- **Nothing here was paid for by the person who assembled the pack.** Even the
  $40 RAT is present as a *cracked* copy (the "Emulator" bypasses its license). The
  operator pirated the malware too.
- This is the financial signature of commodity cybercrime: low-cost, off-the-shelf
  RATs plus cracked legitimate software, aggregated and redistributed for free in a
  "bible." It is consumption, not capability — consistent with the code-quality and
  tradecraft findings (`CODE_REVIEW.md`, `AMATEUR_TRADECRAFT.md`): tools
  bought or stolen by operators who did not build them.

> All `.exe` hashes above are suitable for AV/EDR blocklists and VirusTotal
> correlation; they are also listed for the RAT in `intel/iocs.csv`.
