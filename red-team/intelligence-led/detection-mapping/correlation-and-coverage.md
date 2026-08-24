# Correlation, Coverage & Baseline Queries — the tier above single-TTP hunts

The [`hunt-queries.md`](hunt-queries.md) set catches **individual** techniques.
This set is what a mature SOC runs *on top* of that — and it's the part a red
team fundamentally **cannot** hand you:

- A red team shows you **one path** they happened to find. **Coverage queries**
  tell you *systematically* where you're blind across every host and data source.
- A single-TTP hunt fires on one signal (and its false positives). **Correlation
  queries** fire only when the *attack narrative* lines up across stages — far
  fewer false positives, far higher confidence.
- Static hunts match known-bad. **Baseline queries** catch the novel — the thing
  no signature exists for yet.

Dialect: **KQL** (Microsoft Sentinel / Defender XDR). Table names assume Defender
XDR (`Device*`, `UrlClickEvents`) and Entra/Sentinel (`SigninLogs`, `AuditLogs`,
`OfficeActivity`, `Heartbeat`). Translate table/field names for your stack; the
*logic* is portable.

> ⚠️ **Join caveat used throughout:** identity joins between cloud logs
> (`UserPrincipalName`, UPN) and endpoint logs (`AccountName`, SAM) don't match
> cleanly — normalize (e.g. `tolower(split(UserPrincipalName,"@")[0])`) before
> joining, and expect to tune. These are hunt scaffolds, not turnkey alerts.

---

## Tier 1 — Kill-Chain Correlation (multi-signal, high confidence)

### C-01 — Risky sign-in → lateral movement within 1h  (Credential Access → Lateral Movement)
Fires only when a flagged sign-in is *followed by* that account moving laterally — the story, not just a login.
```kql
let window = 1h;
let risky = SigninLogs
  | where RiskLevelDuringSignIn in ("high","medium")
  | project riskyUser = tolower(tostring(split(UserPrincipalName,"@")[0])), riskTime = TimeGenerated;
DeviceLogonEvents
| where LogonType in ("RemoteInteractive","Network")
| project LogonTime = Timestamp, acct = tolower(AccountName), DeviceName, RemoteIP
| join kind=inner risky on $left.acct == $right.riskyUser
| where LogonTime between (riskTime .. riskTime + window)
| project riskTime, LogonTime, acct, DeviceName, RemoteIP
```

### C-02 — Phishing click → shell on the same user's device within 30m  (Initial Access → Execution)
Crosses email security and endpoint — the exact seam a red team walks through and single-table hunts miss.
```kql
UrlClickEvents
| where ActionType == "ClickAllowed"
| project ClickTime = Timestamp, user = tolower(tostring(split(AccountUpn,"@")[0])), Url
| join kind=inner (
    DeviceProcessEvents
    | where InitiatingProcessFileName in~ ("outlook.exe","chrome.exe","msedge.exe","firefox.exe")
        and FileName in~ ("powershell.exe","cmd.exe","mshta.exe","wscript.exe","rundll32.exe")
    | project ExecTime = Timestamp, DeviceName,
        user = tolower(InitiatingProcessAccountName), FileName, ProcessCommandLine
  ) on user
| where ExecTime between (ClickTime .. ClickTime + 30m)
| project ClickTime, ExecTime, user, DeviceName, Url, FileName, ProcessCommandLine
```

### C-03 — New MFA device → inbox rule created within 6h  (ATO → Persistence / BEC)
Scattered-Spider / BEC signature: attacker registers their own MFA, then hides replies with a mail rule.
```kql
let mfa = AuditLogs
  | where OperationName has_any ("registered security info","Register device")
  | project mfaTime = TimeGenerated, user = tolower(tostring(TargetResources[0].userPrincipalName));
mfa
| join kind=inner (
    OfficeActivity
    | where Operation in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
    | project ruleTime = TimeGenerated, user = tolower(UserId), Parameters=OfficeObjectId
  ) on user
| where ruleTime between (mfaTime .. mfaTime + 6h)
| project mfaTime, ruleTime, user
```

### C-04 — Shadow-copy deletion → mass file modification on same host  (Defense Evasion → Impact)
Two-signal ransomware confirmation. Either alone false-positives; together it's near-certain detonation.
```kql
let tamper = DeviceProcessEvents
  | where ProcessCommandLine has_any ("vssadmin delete shadows","wmic shadowcopy delete",
      "wbadmin delete catalog","bcdedit /set {default} recoveryenabled no")
  | project tamperTime = Timestamp, DeviceName;
tamper
| join kind=inner (
    DeviceFileEvents
    | where ActionType == "FileModified"
    | summarize touched = dcount(FileName) by DeviceName, bin(Timestamp, 5m)
    | where touched > 300
    | project encTime = Timestamp, DeviceName, touched
  ) on DeviceName
| where encTime between (tamperTime .. tamperTime + 30m)
| project tamperTime, encTime, DeviceName, touched
```

### C-05 — LSASS access → outbound to rare external IP within 15m  (Credential dump → Exfil/C2)
Credential theft immediately followed by the host phoning out = dumped creds leaving the building.
```kql
let dump = DeviceProcessEvents
  | where ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has_any ("MiniDump","#24")
  | project dumpTime = Timestamp, DeviceName;
dump
| join kind=inner (
    DeviceNetworkEvents
    | where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
    | project netTime = Timestamp, DeviceName, RemoteIP, RemoteUrl
  ) on DeviceName
| where netTime between (dumpTime .. dumpTime + 15m)
| project dumpTime, netTime, DeviceName, RemoteIP, RemoteUrl
```

---

## Tier 2 — Detection Health & Blind Spots (what red teams can't measure)

### B-01 — Endpoints that went dark (EDR telemetry stopped)
A host active for 30 days but silent for 24h is either off — or the agent was killed. This is your blind-spot map.
```kql
let recent = DeviceInfo | where Timestamp between (ago(30d) .. ago(24h)) | distinct DeviceName;
let reporting = DeviceInfo | where Timestamp > ago(24h) | distinct DeviceName;
recent | where DeviceName !in (reporting)
```

### B-02 — Log source silence (a data source stopped ingesting)
If a whole table stops flowing, every detection built on it is silently dead. Catch it before an attacker does.
```kql
Heartbeat
| summarize lastBeat = max(TimeGenerated) by Computer
| where lastBeat < ago(1h)
| order by lastBeat asc
// Sentinel-wide variant: Usage | summarize max(TimeGenerated) by DataType | where max_TimeGenerated < ago(3h)
```

### B-03 — MITRE tactic coverage inventory (find the zeros)
Which ATT&CK tactics have *never* fired an alert? Those are your uncovered flanks — the gaps to build next.
```kql
SecurityAlert
| where TimeGenerated > ago(30d)
| mv-expand tactic = todynamic(Tactics)
| summarize alerts = count(), rules = dcount(AlertName) by tostring(tactic)
| order by alerts asc
// Cross-reference against the full tactic list; a tactic absent here = zero coverage.
```

### B-04 — Noisy rules driving alert fatigue (tune these or go blind)
The rules burying analysts. Alert fatigue is why real detections get ignored — a coverage problem a red team never sees.
```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| summarize volume = count() by AlertName
| order by volume desc
| take 15
```

---

## Tier 3 — Behavioral Baseline / Anomaly (catch the novel)

### A-01 — First-ever execution of a binary on a host  (rare-process anomaly)
No signature needed — flags any executable never before seen on that device in the last 30 days.
```kql
let baseline = DeviceProcessEvents
  | where Timestamp between (ago(30d) .. ago(1d))
  | distinct DeviceName, FileName;
DeviceProcessEvents
| where Timestamp > ago(1d)
| join kind=leftanti baseline on DeviceName, FileName
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

### A-02 — User file access spikes above their own 30-day norm  (staging / insider / ransomware prep)
Deviation from each user's *own* baseline — catches data staging without a fixed threshold.
```kql
let perUser = DeviceFileEvents
  | where Timestamp between (ago(30d) .. ago(1d)) and ActionType in ("FileCreated","FileModified")
  | summarize dailyAvg = count() / 29.0 by acct = InitiatingProcessAccountName;
DeviceFileEvents
| where Timestamp > ago(1d) and ActionType in ("FileCreated","FileModified")
| summarize today = count() by acct = InitiatingProcessAccountName
| join kind=inner perUser on acct
| where today > 3 * dailyAvg and today > 500
| project acct, today, dailyAvg = round(dailyAvg,1), ratio = round(today / dailyAvg, 1)
```

### A-03 — Low-prevalence, regular-interval egress  (beaconing / C2)
Beacons hide in low volume but betray themselves through *regularity*. Rare destination + steady cadence = C2.
```kql
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| summarize hits = count(), hours = dcount(bin(Timestamp,1h)),
    span = max(Timestamp) - min(Timestamp) by RemoteUrl, DeviceName
| where hours >= 6 and hits < 200        // present across many hours, low total volume
| extend regularity = todouble(hours) / (hits + 1)
| where regularity > 0.5                  // roughly one connection per active hour = heartbeat
| order by regularity desc
```

---

## Why this set is "better than red team"

| A red team gives you… | These queries give you… |
|-----------------------|-------------------------|
| One attack path, once | A **systematic map** of every blind spot (B-01…B-04) |
| Proof a technique worked | **Correlated confirmation** across the whole chain (C-01…C-05) |
| Known-bad findings | **Baseline anomalies** for the novel/unknown (A-01…A-03) |
| A point-in-time report | **Durable, repeatable** detections that keep working |

**Run order:** wire up **B-01/B-02 first** — there's no point tuning detections
on hosts or log sources that have gone dark. Then the **C-** correlations (highest
signal-to-noise). Then the **A-** baselines once you have 30 days of clean history.

---

**Last Updated**: 2026-08-06
