# Detection Playbook — Catching DroidJack & Blackshades

Every realistic security measure that catches the provided samples, organized by
control layer, with concrete rules/commands — and, where relevant, "the BurntSushi
way": how a world-class search/systems engineer builds the detection so it is
**correct, linear-time, tested, and fast at scale**.

Indicators referenced here live in `intel/iocs.csv` (+ `intel/iocs_stix.json`),
rules in `detection/`, technique mapping in `ATTACK_MAPPING.md`.

---

## Layer 0 — Triage & hunt at scale (the BurntSushi specialty)

The malware's cardinal weakness is that all its indicators are **plaintext
literals**. That makes multi-pattern literal search the highest-leverage detection,
and that is exactly the problem his tools solve.

### Immediate sweep with `ripgrep`
One command to sweep a filesystem, repo, or unpacked APK/disk image for every
literal indicator at once (`-uuu` = scan ignored + hidden + binary files):
```sh
rg -uuu -i --no-heading -e 'droidjack\.net' \
                        -e 'DJ_GooDbYe:\(' \
                        -e 'net[./]droidjack[./]server' \
                        -e 'storeReport\.php' -e '/Access/DJ' \
                        -e 'SandroRat_Contacts_Database' \
                        -e 'bshades\.eu' -e 'DownloadExecute\.bss' \
                        -e 'Blackshades Project' \
                        /path/to/scan
```
Why this and not `grep`: ripgrep walks directories in parallel, uses a
literal-optimized engine (`memchr`/Teddy SIMD), and handles the mixed/legacy
encodings present in real corpora. On the dead-simple plaintext IOCs here, it is
effectively a free, instant detector.

### Repeatable, high-volume scanning with `aho-corasick`
For a feed of many indicators scanned over many files repeatedly, build **one
automaton** and stream bytes through it — O(input), independent of indicator count.
That is `tools/ioc-scanner/` in this repo:
```sh
ioc-scanner intel/iocs.csv /mnt/share /quarantine/unpacked_apk
# file:offset \t malware \t kind=value ; exit 1 if any hit (pipeline-friendly)
```
The BurntSushi properties baked in: **bytes, not strings** (correct on legacy
encodings), `Result`-typed errors (no silent misses), unit+fuzz tests, a measured
benchmark, and a minimal dep tree.

### Scale-out notes
- **Huge indicator sets:** compile them into an `fst` (his crate) for a compact,
  memory-mapped, queryable index.
- **Linear-time regexes only:** if patterns are needed beyond literals, the `regex`
  crate guarantees linear time (no catastrophic backtracking / ReDoS) — important
  when the "input" is attacker-influenced.
- **Measure it:** detection that can't keep up with disk/network throughput is
  theater. Benchmark bytes/sec and report it honestly (see `RUST_PERSPECTIVE.md`).

---

## Layer 1 — Pre-execution / static (file at rest, email, proxy, EDR)

### Hash blocklisting
Push these to EDR/AV/email/proxy denylists:
- Blackshades `client.exe` SHA-256 `5b239d68…339f43`; ZIP `837d78e9…1e93`
- DroidJack `SandroRat.apk` `30aa2eee…b268`; `classes.dex` `fcac2275…7a1e`; ZIP `ba01b036…1bf5`
- Blackshades **imphash** `e22efc20…00c70` (catches recompiled VB6 variants)

### YARA at rest
```sh
yara -r detection/blackshades.yar detection/droidjack.yar /path/to/scan
```
- `Blackshades_NET_client` / `Blackshades_NET_imphash` — content + import hash
- `DroidJack_SandroRat_dex` — DEX-anchored (no doc false-positives)
Tested to match the real samples; see `detection/`.

### Android static analysis (APK vetting)
- **Package name** `net.droidjack.server` → instant verdict.
- **Permission red-flags in the manifest**: SMS read/write/send + call-log
  read/write + RECORD_AUDIO + CAMERA + FINE_LOCATION + CALL_PHONE + RECEIVE_SMS,
  all declared together — a textbook spyware permission set.
- **Components**: a `BroadcastReceiver` on `BOOT_COMPLETED` paired with SMS/audio
  permissions; translucent no-UI capture activities (`CamSnapDJ`, `VideoCapDJ`).
- Tooling: `apkanalyzer`, `aapt dump badging`, androguard, or the YARA dex rule.

### Windows static heuristics
- **Unsigned** PE + **imphash** match + VB6 (`msvbvm60.dll`-only imports).
- Abnormal section layout (`.mackt`, unnamed first section) = tampered/cracked.

---

## Layer 2 — Host behavioral (EDR / Sysmon / MDM)

### Windows (Blackshades)
- **Autostart writes** (Sysmon Event ID 13) to
  `...\CurrentVersion\Run`, `...\Winlogon`, `...\Active Setup\Installed Components`.
- **Process lineage**: a VB6 process (`msvbvm60`-linked) spawning children, or
  performing screen/keyboard capture API patterns.
- **"Download and Execute"**: correlate an outbound fetch immediately followed by
  execution of the fetched file (`*.bss`) — Sysmon EID 1 + 3 + 11 correlation.
- **Spreading**: writes of executables to removable drives (EID 11 on USB).

### Android (DroidJack)
- **Play Protect / MDM** signature + heuristic on the package/cert.
- A **non-system app** that: registers `BOOT_COMPLETED`, holds RECORD_AUDIO, and
  reads `CallLog`/`Contacts` — behavioral policy violation.
- **Sensitive path access**: attempts to read
  `data/data/com.whatsapp/databases/msgstore.db`.
- **Radio toggling via reflection** (`setMobileDataEnabled`) — anomalous for a
  user app.

---

## Layer 3 — Network (Suricata/Snort, Zeek, DNS, egress)

Rules in `detection/droidjack_suricata.rules` (tune SIDs/HOME_NET):
- **DNS**: lookups of `droidjack.net`, `*.no-ip.*`, `bshades.eu` → alert/sinkhole.
- **HTTP**: `POST …/storeReport.php` and URI `/Access/DJ` with host `droidjack.net`.
- **TCP**: KryoNet on `1337` carrying the literal token `DJ_GooDbYe:(`.
- **Plaintext-exfil heuristic**: cleartext HTTP bodies carrying contact/SMS/call-log
  field names leaving the network.
- **Egress filtering**: default-deny outbound; dynamic-DNS categories blocked at the
  proxy/firewall.
- **TLS**: not applicable here — the C2 is cleartext, which is itself the tell.

---

## Layer 4 — Intelligence & coverage (SIEM / MISP / ATT&CK)

- Import `intel/iocs.csv` and `intel/iocs_stix.json` (STIX 2.1) into MISP/TAXII;
  fan out to EDR/SIEM watchlists.
- Map alerts to `ATTACK_MAPPING.md` (T1430/T1429/T1512/T1636.* for DroidJack;
  T1547.001/T1056.001/T1105 for Blackshades) to find coverage gaps.
- Track detections by **hash + imphash** so recompiles/repacks are still caught.

---

## Per-sample quick reference

| Sample | Fastest catch | Backstop |
|---|---|---|
| DroidJack APK at rest | YARA `DroidJack_SandroRat_dex` on the dex | hash blocklist; package-name verdict |
| DroidJack live | DNS/HTTP rules (`droidjack.net`, `storeReport.php`) | behavioral: boot-receiver + RECORD_AUDIO |
| Blackshades binary | imphash `e22efc20…` + YARA | unsigned VB6 + abnormal sections |
| Blackshades live | Run-key write (Sysmon EID 13) | dynamic-DNS C2 DNS alert |
| Either, in a corpus | `rg -uuu` literal sweep | `ioc-scanner` automaton pass |

---

## The disparity, restated for defense
The amateur put every indicator in plaintext, in the open, assuming no one is
watching. The professional response is not subtle and does not need to be: a
literal multi-pattern sweep (`ripgrep`), a single automaton over a feed
(`aho-corasick`), and standard host/network telemetry catch all of it. The
malware's defining weakness — naive plaintext literals and naive literal matching —
is precisely what makes professional, *correct, linear-time* detection trivial.
