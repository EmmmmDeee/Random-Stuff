# Amateur Tradecraft — Methods & Functionality Critique

A security assessment of *how the provided malware actually works* and why its
methods and functionality are amateurish. This is distinct from `CODE_REVIEW.md`
(which critiques code style); here the focus is design and tradecraft.

**Security framing:** the point of cataloguing these weaknesses is that they make
the malware easy to detect, attribute, and defeat — useful to a blue team. Where a
"why it's weak" could double as "how to do it better," the analysis stops at the
weakness and does not provide the upgrade.

---

## DroidJack / SandroRat — amateur methods

### 1. Brand and intent are in plaintext, everywhere
- Package name: `net.droidjack.server` — the malware **names itself** in the one
  field every install dialog and every scanner reads first.
- C2 host `droidjack.net`, report path `/storeReport.php`, access path `/Access/DJ`,
  and the command token `DJ_GooDbYe:(` are all bare literals.
- Internal tables: `SandroRat_Contacts_Database`, `RecordedCallLogsTable`.
**Why amateur:** zero indicator hygiene. The product's identity is its own
signature. A single string match identifies it forever.

### 2. Single hardcoded C2 — one IP/domain to rule it all
The bot reports to one host, `droidjack.net`, over plain HTTP. No domain rotation,
no fallback, no fronting, no encryption of the channel.
**Why amateur:** one sinkhole or takedown kills every bot at once; the traffic is
trivially recognised and blocked. Commercial-grade families assume their C2 will be
burned and plan for it. This one bets everything on a single name.

### 3. Plaintext exfiltration
Stolen data is uploaded via `storeReport.php` with no transport encryption and no
payload encryption.
**Why amateur:** anyone on the path (proxy, IDS, mobile carrier) sees exactly what
leaves the device. The IOC feed and Suricata rules in this repo work *because* of
this.

### 4. "Persistence" is a single boot receiver
`Connector` re-launches the service on `BOOT_COMPLETED`/`CONNECTIVITY_CHANGE`. That
is the entire persistence story.
**Why amateur:** it's the first place any MDM/AV checks, it's declared in the
manifest, and it survives nothing more sophisticated than an uninstall. No
redundancy, no watchdog, no stealth.

### 5. Over-broad, all-up-front permissions
The manifest requests SMS read/write/send, call log read/write, contacts, camera,
mic, fine location, phone state, call control — **all declared at install time**.
**Why amateur:** the permission screen alone is a giant red flag to the user, and a
trivial static-analysis verdict for any app-vetting pipeline. No staging, no
runtime minimization.

### 6. Crude anti-forensics that creates its own tell
`CallListener` deletes call-log rows whose number matches the operator's secret
"control numbers" (defaults `000000000000000` / `111111111111111`).
**Why amateur:** (a) hardcoded sentinel numbers are themselves a signature; (b)
selectively deleting call-log rows leaves gaps and other artifacts; (c) it only
hides *one* trace while audio files, SQLite DBs, and network logs remain. It's the
appearance of stealth without the substance.

### 7. Fragile reflection into private APIs
Toggling mobile data / ending calls is done by reflecting `getITelephony` /
`setMobileDataEnabled` — undocumented internals — inside swallow-all `catch`.
**Why amateur:** breaks silently on the next OS version; the program can't even
tell that its core capability stopped working.

### 8. Capability assumptions that often just fail
WhatsApp theft is attempted via a shell copy of
`data/data/com.whatsapp/databases/msgstore.db` — a path that is **not readable
without root** on a normal device.
**Why amateur:** a headline feature that silently no-ops on the majority of targets,
and (per #7's swallowed errors) the operator may not even know.

### 9. Obvious network fingerprint
KryoNet on the default port `1337`, plus the literal `DJ_GooDbYe:(` control token
on the wire.
**Why amateur:** `1337` ("leet") is self-parody, and a fixed plaintext token is a
free network signature.

---

## Blackshades NET — amateur methods

### 1. Dynamic-DNS C2 on free providers
C2 points at `bshades.eu` and `*.no-ip.*` dynamic-DNS subdomains.
**Why amateur:** free dynamic DNS is cheap, heavily abused, and widely
reputation-blocked; the whole category is a known-bad indicator.

### 2. Persistence in the most-watched locations
Run keys (`...CurrentVersion\Run`), Winlogon, Active Setup.
**Why amateur:** these are the *first* autostart locations every AV and analyst
inspects. No creativity, maximum visibility.

### 3. "Download and Execute" as a core feature
A menu item literally labelled "Download and Execute (Hidden)" pulling `*.bss`
payloads.
**Why amateur:** the marquee capability depends entirely on AV *not* catching the
second-stage download — there is no inherent evasion, just hope.

### 4. Noisy, dated propagation
USB infection and MSN/AIM/IM "spreading" modules.
**Why amateur:** loud, self-replicating behavior that lights up host and network
sensors, targeting platforms already dead by the time this was distributed.

### 5. Built on a dead runtime, then cracked
VB6 (`msvbvm60`) in 2013, and the distributed copy is a third-party **crack** of
itself (`.mackt` section, "cracked by MaxXor").
**Why amateur:** an obsolete, easily-fingerprinted runtime, shipped as a tampered
binary the operator doesn't even fully control.

### 6. Kitchen-sink UI = kitchen-sink signature
~70 feature forms (keylog, webcam, DDoS, click-fraud, botkiller, crypter…) all
bolted into one monolith.
**Why amateur:** every feature adds detectable strings and behaviors; breadth here
means a larger, louder fingerprint, not capability discipline.

---

## Overall verdict
Both samples share the same amateur signature: **everything important is hardcoded,
in plaintext, in the most obvious place, with no assumption that anyone is watching.**
Brand names, C2, commands, persistence, and exfiltration are all out in the open;
"stealth" features (call-log scrubbing, obfuscated class names) are superficial and
generate their own tells. The functionality is broad but shallow — long feature
lists whose individual methods are the simplest, loudest possible implementation.

This is *commodity* malware: bought or cracked, deployed by operators who didn't
write it, against targets assumed to have no defenses. The detection package in
this repo (`detection/`, `intel/`) is effective precisely because the tradecraft
is this weak.
