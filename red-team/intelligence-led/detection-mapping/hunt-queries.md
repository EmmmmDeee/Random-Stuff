# Actionable Hunt & Detection Queries

The payoff of intelligence-led testing. Each query hunts for a **specific TTP**
used by an actor in [`../threat-actors.json`](../threat-actors.json). Run these
*before* an engagement to baseline coverage, and again during the purple-team
replay to confirm each emulated technique actually fires an alert.

> **Why these beat a red-team report:** a red team tells you that you were
> compromised. These queries tell you *whether you would have seen it* — and
> once tuned, they keep catching the technique long after the engagement ends.

**Query dialects:** primarily **KQL** (Microsoft Sentinel / Defender XDR). SPL
(Splunk) and Sigma equivalents are notal but the logic translates directly —
match on the same fields. Treat thresholds as starting points; tune to your
environment before enabling as alerts.

---

## Identity & Cloud (APT29, Scattered Spider)

### H-01 — Illicit OAuth app consent (T1528, APT29)
Catches OAuth token theft via malicious app consent — APT29's signature cloud move.
```kql
AuditLogs
| where OperationName in ("Consent to application", "Add app role assignment grant to user",
    "Add delegated permission grant", "Add OAuth2PermissionGrant")
| mv-expand mp = TargetResources[0].modifiedProperties
| extend perms = tostring(mp.newValue)
| where perms has_any ("Mail.Read", "Mail.ReadWrite", "Files.ReadWrite.All",
    "full_access_as_app", "Directory.ReadWrite.All")
| project TimeGenerated, InitiatedBy, app = tostring(TargetResources[0].displayName), perms
```
**Tune:** allow-list known internal apps; alert on high-privilege mail/file scopes.

### H-02 — Credential added to service principal (T1098.001, APT29)
Adversary adds a secret/cert to an app registration to persist in the cloud.
```kql
AuditLogs
| where OperationName in ("Add service principal credentials",
    "Update application - Certificates and secrets management")
| project TimeGenerated, actor = tostring(InitiatedBy.user.userPrincipalName),
    targetApp = tostring(TargetResources[0].displayName), OperationName
```
**Tune:** correlate with whether the actor normally manages app credentials.

### H-03 — MFA fatigue / push bombing (T1621, Scattered Spider)
Repeated MFA denials followed by a success = the user gave up and approved.
```kql
let denials = SigninLogs
  | where ResultType in ("500121", "50074")   // MFA denied / MFA required-not-satisfied
  | summarize denied = count() by UserPrincipalName, bin(TimeGenerated, 10m)
  | where denied >= 5;
let successes = SigninLogs | where ResultType == 0
  | project UserPrincipalName, SuccessTime = TimeGenerated;
denials | join kind=inner successes on UserPrincipalName
| where SuccessTime between (TimeGenerated .. (TimeGenerated + 15m))
| project UserPrincipalName, denied, TimeGenerated, SuccessTime
```
**Tune:** the deny-then-approve within 15m is the strong signal, not denials alone.

### H-04 — New MFA device / security-info registration (T1098.005, Scattered Spider)
After a help-desk-vished credential reset, the attacker registers their own MFA device.
```kql
AuditLogs
| where OperationName has_any ("User registered security info",
    "User registered all required security info", "Register device", "Add registered owner")
| project TimeGenerated, InitiatedBy, target = tostring(TargetResources[0].userPrincipalName), OperationName
```
**Tune:** alert when registration comes soon after a password reset or from a new IP.

### H-05 — Impossible travel / concurrent-country success (credential theft)
Same account, successful sign-ins from >1 country in a short window.
```kql
SigninLogs
| where ResultType == 0
| summarize countries = make_set(tostring(LocationDetails.countryOrRegion))
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(countries) > 1
```
**Tune:** exclude VPN egress ranges; pair with the built-in impossible-travel alert.

---

## Endpoint Execution (FIN7, LockBit)

### H-06 — Office app spawns a script interpreter (T1566.001 → T1204.002, FIN7)
Weaponized-document execution: Word/Excel/Outlook spawning a shell.
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```
**Tune:** near-zero false positives in most estates — good candidate for a hard alert.

### H-07 — Encoded / obfuscated PowerShell (T1059.001, FIN7 & LockBit)
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc","-EncodedCommand","FromBase64String",
    "-nop","-w hidden","-windowstyle hidden","IEX","Invoke-Expression","DownloadString","Net.WebClient")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
**Tune:** some admin tooling uses `-nop`; the base64/download combos are the sharp signals.

### H-08 — LSASS credential dumping (T1003.001, FIN7 & LockBit)
```kql
// comsvcs.dll MiniDump technique
DeviceProcessEvents
| where ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has_any ("MiniDump","#24")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
// plus: EDR "OpenProcess" against lsass.exe from a non-security process
```
**Tune:** allow-list legitimate crash/diagnostic tooling; alert on the rest.

### H-09 — Scheduled task persistence (T1053.005, FIN7)
```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd","http","\\appdata\\","\\temp\\","-enc")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
**Also:** Windows Security Event ID **4698** (scheduled task created).
**Tune:** name mimicry (e.g. "Windows Update Scheduler") + a temp/appdata payload = high confidence.

---

## Defense Evasion & Ransomware (LockBit, Lazarus, Scattered Spider)

### H-10 — Security tool tampering (T1562.001, LockBit & Scattered Spider)
Attackers disable EDR/AV right before detonation.
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("Set-MpPreference -DisableRealtimeMonitoring",
    "sc stop","net stop","taskkill")
| where ProcessCommandLine has_any ("Sense","WinDefend","MsMpEng","CrowdStrike","csagent",
    "cbdefense","Sophos","SentinelOne","cylance")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
**Also:** Defender tamper-protection events. **Tune:** any hit here is high severity.

### H-11 — Shadow-copy / backup deletion (T1490, LockBit) ⭐ highest-value ransomware precursor
Fires *seconds before* encryption — the best chance to stop impact.
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin delete shadows","vssadmin resize shadowstorage",
    "wmic shadowcopy delete","wbadmin delete catalog","bcdedit /set {default} recoveryenabled no",
    "Delete-VssShadow")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
**Tune:** legitimate backup software rarely uses these verbs interactively — alert hard.

### H-12 — Mass file modification = active encryption (T1486, LockBit/Lazarus)
```kql
DeviceFileEvents
| where ActionType == "FileModified"
| summarize touched = dcount(FileName) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where touched > 500
| order by touched desc
```
**Tune:** threshold varies by role (dev boxes churn files); baseline first. Pairs with a canary-file trap.

### H-13 — Exfil to cloud storage before encryption (T1567.002, LockBit double-extortion)
```kql
// rclone is the ransomware crews' favorite exfil tool
DeviceProcessEvents
| where FileName =~ "rclone.exe" or ProcessCommandLine has "rclone"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
// network side:
DeviceNetworkEvents
| where RemoteUrl has_any ("mega.nz","mega.io","anonfiles.com","transfer.sh","gofile.io","tmpfiles.org")
| summarize bytes = sum(tolong(coalesce(ResponseSize, 0))) by DeviceName, RemoteUrl
```
**Tune:** rclone on a workstation is almost always malicious — alert.

---

## Server / Web Exploitation (APT41)

### H-14 — Web server spawns a shell (T1190 → T1505.003, APT41)
IIS/Apache/Tomcat launching cmd/powershell = web-shell or exploit execution.
```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","tomcat.exe","java.exe","nginx.exe","php-cgi.exe")
| where FileName in~ ("cmd.exe","powershell.exe","whoami.exe","net.exe","net1.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```
**Tune:** very high fidelity — a web worker process should almost never spawn a shell.

### H-15 — Web-shell file dropped in a web root (T1505.003, APT41)
```kql
DeviceFileEvents
| where FolderPath has_any ("\\inetpub\\wwwroot","\\wwwroot","\\htdocs","\\webapps","\\www\\")
| where FileName endswith ".aspx" or FileName endswith ".asp" or FileName endswith ".jsp"
    or FileName endswith ".php" or FileName endswith ".ashx" or FileName endswith ".jspx"
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","tomcat.exe","java.exe","php-cgi.exe")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName
```
**Tune:** exclude legitimate deployment pipelines; a web process writing a new script file is suspect.

---

## Coverage Summary

| # | Hunt | TTP | Actor(s) | Fidelity |
|---|------|-----|----------|----------|
| H-01 | Illicit OAuth consent | T1528 | APT29 | High |
| H-02 | SP credential added | T1098.001 | APT29 | Medium |
| H-03 | MFA push bombing | T1621 | Scattered Spider | High |
| H-04 | New MFA device | T1098.005 | Scattered Spider | Medium-High |
| H-05 | Impossible travel | T1078 | APT29, Scattered Spider | Medium |
| H-06 | Office spawns shell | T1566.001/T1204 | FIN7 | Very High |
| H-07 | Encoded PowerShell | T1059.001 | FIN7, LockBit | Medium-High |
| H-08 | LSASS dumping | T1003.001 | FIN7, LockBit | High |
| H-09 | Scheduled task | T1053.005 | FIN7 | Medium-High |
| H-10 | Security-tool tampering | T1562.001 | LockBit, Scattered Spider | Very High |
| H-11 | Shadow-copy deletion | T1490 | LockBit | Very High |
| H-12 | Mass file modification | T1486 | LockBit, Lazarus | Medium |
| H-13 | Cloud exfil / rclone | T1567.002 | LockBit | High |
| H-14 | Web server spawns shell | T1190/T1505.003 | APT41 | Very High |
| H-15 | Web-shell dropped | T1505.003 | APT41 | High |

**Start here (highest fidelity, lowest tuning cost):** H-06, H-10, H-11, H-14.
These four alone cover the detonation-critical moments of most finance/healthcare
intrusions and produce very few false positives.

---

**Last Updated**: 2026-08-06
