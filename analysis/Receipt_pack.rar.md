# Receipt pack.rar

## Identity
- **Filename:** `Receipt pack.rar`
- **Size:** 1,595,193 bytes
- **Detected type:** RAR archive data, v4, os: Win32
- **SHA-256:** `b10cfb2e34820c226266647695af47ce6853cb8ae19176e159bb52c52c524e92`

## Classification
- **Category:** Tool w/ executables — fake-receipt fraud
- **Safety verdict:** ACTIVE — archive contains executables

## Description / function
**Password-protected** RAR (`Encrypted = +`, RAR 2.9) — the only encrypted archive
in the pack, so the two generator exes cannot be extracted or hashed. Readable
headers reveal a template-driven **fake-receipt fraud kit**: `Amazon Receipt
Generator.exe` and `PayPal Generator/PRG.exe`, plus cloned PayPal page assets
(`paypal.css`, `paypal_logo.gif`, `pp_main.js`, a spoofed `regnet.htm`), a Microsoft
receipt PSD (`pidback.psd`), and `Receipt Template.docx/.pdf`. Purpose: forge
Amazon/PayPal/Microsoft receipts for refund / chargeback / "item not received"
fraud. That it is the *only* gated archive suggests it was the "paid" item.
See `EXECUTABLES.md` and `EXECUTABLES_ANALYSIS.md`.

## Handling guidance
- Treat as DANGEROUS. Keep inside the encrypted archive; only open in an isolated, offline sandbox VM. Never execute on a host you control.

