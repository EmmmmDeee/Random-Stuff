# BLACKSHADES RAT.txt

## Identity
- **Filename:** `BLACKSHADES RAT.txt`
- **Size:** 102 bytes
- **Detected type:** ASCII text, with CRLF line terminators
- **SHA-256:** `7217d8a24cdcb49e5e37eec151ca70dfc399897b2b8fc5ded1a2b829dea23d16`

## Classification
- **Category:** Live malware — Windows RAT
- **Safety verdict:** inert — text/document (no execution path)

## Description / function
Controller/builder for the Blackshades NET remote-access trojan (VB6). Capabilities (from form names/strings): keylogging, webcam/mic/screen capture, credential/cookie/POS theft, remote shell, file/registry/process control, USB+IM spreading, click-fraud, DDoS, botkiller, crypter. C2 via no-ip/bshades.eu dynamic DNS. See MALWARE_ANALYSIS.md for full technical detail.

## Handling guidance
- No execution/infection risk from the file itself. Concern is the content (harmful/illegal instructions) and possession legality — store sealed, do not redistribute.

