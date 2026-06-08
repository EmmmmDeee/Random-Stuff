# MITRE ATT&CK Mapping

Techniques observed in the two RATs, from static analysis. Mobile techniques use
the ATT&CK for Mobile matrix; Windows techniques use Enterprise.

## DroidJack / SandroRat (ATT&CK Mobile)

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Persistence | Event Triggered Execution: Broadcast Receivers | T1624.001 | `Connector` on `BOOT_COMPLETED` + `CONNECTIVITY_CHANGE` |
| Collection | Audio Capture | T1429 | `MediaRecorder` `AudioSource.VOICE_CALL` in `CallListener` |
| Collection | Video Capture / Camera | T1512 | `CamSnapDJ`, `VideoCapDJ` silent capture activities |
| Collection | Location Tracking | T1430 | `GPSLocation` service, `LocationManager` |
| Collection | Protected User Data: SMS | T1636.004 | `READ_SMS`/`RECEIVE_SMS`, `SmsManager` |
| Collection | Protected User Data: Contacts | T1636.003 | `ContactsContract`, `PhoneContactsTable` |
| Collection | Protected User Data: Call Log | T1636.002 | `CallLog`, `RecordedCallLogsTable` |
| Collection | Stored Application Data (WhatsApp) | T1409 | `cp .../com.whatsapp/databases/msgstore.db` |
| C2 | Application Layer Protocol | T1437 | KryoNet over TCP/1337, `droidjack.net` HTTP report |
| Exfiltration | Exfil over C2 Channel | T1646 | `storeReport.php` upload of collected data |
| Defense Evasion | Indicator Removal on Host | T1630.002 | `CallListener` deletes call-log rows for control numbers |
| Impact | Call Control | T1616 | silent `endCall` via reflection on control-number calls |

## Blackshades NET (ATT&CK Enterprise)

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Persistence | Registry Run Keys / Startup Folder | T1547.001 | `...CurrentVersion\Run`, Active Setup, Winlogon |
| Collection | Input Capture: Keylogging | T1056.001 | `frmKeylogLive`, keylog manager |
| Collection | Video/Audio/Screen Capture | T1125/T1123/T1113 | `frmWebcam`, `frmAudioCap`, `frmScreenshot` |
| Credential Access | Credentials from Web Browsers/Stores | T1555 | `frmPasswords`, `frmCookies`, `frmFormGrabber` |
| Execution | Command and Scripting / remote shell | T1059 | `frmShell` remote command interface |
| C2 | Ingress Tool Transfer (download & execute) | T1105 | "Download and Execute (Hidden)", `DownloadExecute.bss` |
| Lateral Movement | Replication Through Removable Media | T1091 | `frmInfector` USB infection |
| Lateral Movement | Spreading via IM | T1570/T1534 | `frmSpread` MSN/AIM/IM |
| Impact | Network Denial of Service | T1498 | `frmDOS` |
| Defense Evasion | Obfuscation/Packing (crypter) | T1027 | ".NET Crypter settings", VB6 runtime-resolved APIs |
| Impact | Resource Hijacking (click fraud) | T1496 | `frmADClicker` |

## Usage
- Feed the IDs into your detection-coverage matrix to see which techniques your
  EDR/MDM already alerts on.
- Pair with `detection/*.yar`, `detection/droidjack_suricata.rules`, and
  `intel/iocs.csv` / `intel/iocs_stix.json` for host + network + intel coverage.
