# Blackshades.5.5.1.zip

## Identity
- **Filename:** `Blackshades.5.5.1.zip`
- **Size:** 18,109,222 bytes
- **Detected type:** Zip archive data, at least v1.0 to extract, compression method=store
- **SHA-256:** `837d78e992cc53a6f125f486e3991975145d546c5f320e34df2af7c516f61e93`

## Classification
- **Category:** Live malware — Windows RAT
- **Safety verdict:** ACTIVE — archive contains executables

## Description / function
Controller/builder for the Blackshades NET remote-access trojan (VB6). Capabilities (from form names/strings): keylogging, webcam/mic/screen capture, credential/cookie/POS theft, remote shell, file/registry/process control, USB+IM spreading, click-fraud, DDoS, botkiller, crypter. C2 via no-ip/bshades.eu dynamic DNS. See MALWARE_ANALYSIS.md for full technical detail.

## Handling guidance
- Treat as DANGEROUS. Keep inside the encrypted archive; only open in an isolated, offline sandbox VM. Never execute on a host you control.

