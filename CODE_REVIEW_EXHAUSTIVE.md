# Exhaustive Code Review — Decompiled DroidJack & Blackshades

A maximal, category-by-category teardown of the recovered code, citing the actual
decompiled constructs. The goal is to settle the question of whether this is
competently programmed. It is not. Evidence is in `SOURCE_LEVEL_ANALYSIS.md`.

This critiques *engineering quality*. It does not provide improvements that would
make the malware more effective or evasive.

Severity key: 🔴 critical · 🟠 major · 🟡 minor

---

## A. Correctness & error handling

**A1 🔴 Blanket exception swallowing.** The dominant idiom is
`try { … } catch (Exception e) { ae.a(e); e.printStackTrace(); }`. Catching the
root `Exception` and continuing means `NullPointerException`, `SecurityException`,
`IOException`, and success are *indistinguishable*. The program has no concept of
its own failure. Every other bug below is masked by this one.

**A2 🔴 Catch-and-continue as control flow.** In `Connector.onReceive`, when the
connect path throws, the `catch` calls `Controller.b()` (teardown). Failure is
silently repurposed as a state transition — the worst kind of "error handling,"
where the error path and the happy path converge with no record of which happened.

**A3 🟠 Exceptions used for normal branching.** `CallListener.a()` does
`getDeclaredMethod("getITelephony")` and, on `NoSuchMethodException`, falls back to
`getITelephonyMSim`. Control flow driven by thrown-and-caught reflection
exceptions — slow, opaque, and impossible to reason about statically.

**A4 🟠 No error values anywhere.** Not a single method returns a status/`Optional`/
result type for a fallible operation. Success is assumed; failure is printed.

---

## B. Concurrency & thread-safety

**B1 🔴 Mutable static shared state.** `CallListener` holds
`private static MediaRecorder c;` plus `static boolean f236a/f237b;`.
`Controller` holds `static byte[] v; static String y; static int z; static boolean
x/A;`. These are mutated from broadcast receivers, timers, and worker threads with
**no synchronization**. Textbook data races; behavior is undefined under any real
concurrency.

**B2 🔴 State machine guarded by a bare boolean.** Recording state is a single
non-volatile `static boolean f236a`. Two overlapping `PHONE_STATE` events corrupt
the recorder lifecycle (start-on-start, stop-on-null). Not even `volatile`, so the
flag isn't reliably visible across threads anyway.

**B3 🟠 Hand-rolled threads despite importing a pool.** `Controller` imports
`java.util.concurrent.Executors`/`ExecutorService` and then starts work via
`new u().start()`, `new x().start()`, `new z(a,b).start()` — unbounded, unnamed,
unmanaged `Thread` subclasses with no lifecycle, pool, or backpressure.

**B4 🔴 Executor-per-call, then blocked synchronously.** `CamSnapDJ.a(Bitmap)` does
`Executors.newSingleThreadExecutor().submit(new k(...)).get();` — it (a) allocates a
brand-new executor on every call, (b) **never shuts it down** (thread leak), and
(c) immediately `.get()`s, blocking the caller and defeating the entire point of
submitting to an executor. Three distinct mistakes in one line.

**B5 🟠 Listener leak.** `CallListener` registers `i.listen(j, 32)` (PhoneState
listener) and a `ContentObserver` but has no symmetric unregister path, so
callbacks accumulate.

---

## C. Memory & resource management

**C1 🔴 `static Context` retention.** `Connector` stores `private static Context
f240a;` and `CamSnapDJ`/others hold Contexts. A `static` reference to a
`Context`/`Activity` is the canonical Android memory leak — it pins the whole
Activity/Service for the process lifetime and risks use-after-destroy.

**C2 🟠 Non-deterministic cleanup.** `MediaRecorder` is released only on the happy
path of `CallListener.c()`; any earlier throw (swallowed per A1) leaks the
recorder and the mic handle. No `finally`, no RAII equivalent.

**C3 🟡 Bitmap handling.** `CamSnapDJ.a(byte[])` decodes bounds, computes a sample
size, then decodes again — reasonable — but never recycles intermediate bitmaps and
hands large bitmaps across threads with no size guard.

---

## D. Architecture & module design

**D1 🔴 No separation of concerns.** `CallListener.onReceive` simultaneously: reads
prefs, writes defaults, normalizes a phone number, branches on it, toggles wifi and
mobile data via reflection, ends calls, and registers a ContentObserver. One method,
~7 responsibilities.

**D2 🟠 God-objects.** Blackshades is ~70 `frm*` forms where the UI form *is* the
business logic. There is no model layer; presentation, networking, persistence, and
capability code are fused into event handlers.

**D3 🟠 Monolith with no boundaries.** Every capability (keylog, webcam, DDoS,
crypter, botkiller) is compiled into one artifact with shared global state — no
modules, no interfaces, no seams for testing or reuse.

---

## E. Naming & readability

**E1 🟠 Obfuscation masquerading as design.** 90 classes named `a`…`cg`, fields
`c`, `d`, `e`, `f236a`. This is shipped ProGuard output; combined with the *brand*
sitting in plaintext (`net.droidjack.server`), it provides neither secrecy nor
readability.

**E2 🟡 Single-letter helper classes with hidden responsibilities.** `g` (upload),
`e`/`d` (listeners), `by` (prefs), `ae` (logging) — meaning is entirely positional;
nothing self-documents.

---

## F. Control flow & complexity

**F1 🟠 Deeply nested, duplicated conditionals.** `CallListener.onReceive` nests
`PHONE_STATE` checks twice (the same `equals` re-tested inside its own branch), with
repeated default-setting blocks for `l`/`m`.

**F2 🟡 Dead/redundant checks.** `if (this.l.equals("") || this.l == null)` — the
null check is **after** the dereference, so it can never save a null `l`; it's both
dead and ordered backwards (NPE risk before the guard).

---

## G. Algorithms & performance

**G1 🟠 Linear string-equality command dispatch.** `Controller` matches commands via
chained `String.equals` (e.g. `y.equals("DJ_GooDbYe:(")`). O(commands) per message;
the correct construct is a `match`/jump table or an automaton.

**G2 🟡 String-based resource lookup in a hot path.** `CamSnapDJ` uses
`getResources().getIdentifier("cameraview","layout",pkg)` instead of compile-time
`R.layout.cameraview`. Reflection-style lookup by string — slower, typo-prone, and
defeats the resource compiler.

**G3 🟡 Polling timer.** `Controller.j()` schedules a 20s `Timer` keepalive — crude
fixed-interval polling rather than event-driven liveness.

---

## H. Platform & portability

**H1 🔴 Reflection into private framework internals.** `getITelephony`,
`setMobileDataEnabled` are undocumented, version-specific internals reached via
reflection. Guaranteed to break across OS versions, and (per A1) it breaks
*silently*.

**H2 🟠 Deprecated/identifier misuse.** `Controller` uses `Build.SERIAL` as the bot
identifier — deprecated, privacy-sensitive, and unreliable across Android versions.

**H3 🟠 Capability assumed, not checked.** WhatsApp theft shells out to copy
`data/data/com.whatsapp/databases/msgstore.db` — unreadable without root on a normal
device; the feature silently no-ops on most targets.

---

## I. Internationalization & encoding

**I1 🟡 Naive string normalization.** Phone numbers are cleaned with four chained
`.replace("-","")….replace(")","")` calls — locale-blind, fragile, and incapable of
handling formats it didn't anticipate.

---

## J. Logging & observability

**J1 🟠 Debug prints in production.** `System.out.println("Connecting!")`,
`println(5)`, `println(6)`, `println(3)`, `println(7)`, `println(8)`,
`"Clear n working - Cam"` — raw stdout scaffolding never removed. No levels, no
structure, no toggle.

**J2 🟡 Logging via swallow.** The only "telemetry" is `ae.a(e)` inside catch
blocks — i.e. errors go to a log helper and nowhere actionable.

---

## K. Configuration management

**K1 🟠 Everything hardcoded.** C2 host, port (`1337`), command tokens, sentinel
control numbers (`000000000000000`/`111111111111111`), table names — all baked in as
literals. No configuration layer; changing any of them means recompiling.

---

## L. Testing & verification

**L1 🔴 Zero tests.** No unit, integration, property, or smoke tests anywhere.
Verification was deployment. Nothing in the codebase is known to work except by
having run once on a target.

---

## M. Build, toolchain & language choice

**M1 🔴 Dead language.** Blackshades is VB6 (`msvbvm60.dll`) — in 2013, on a runtime
already obsolete, with all Win32 access funneled through the VB runtime.

**M2 🔴 Ships a crack of itself.** The distributed binary is third-party-patched
(`.mackt` section, unnamed first section, `"cracked by MaxXor"`). The operator runs
a tampered build they don't control or understand.

**M3 🟡 No reproducible build / dependency pinning.** No manifest of dependencies,
no lockfile, no integrity story.

---

## N. Documentation

**N1 🟡 None.** No comments of intent, no design notes, no API docs. The only prose
is end-user EULA boilerplate embedded as strings.

---

## O. Idiomatic violations (the "you had one job" pile)

- Imports a thread pool, uses raw threads (B3).
- Creates an executor only to block on it (B4).
- Null-checks after dereferencing (F2).
- String resource IDs instead of generated `R` constants (G2).
- `static` Context in Android (C1).
- Exceptions for control flow (A3).
- `Build.SERIAL` as an identity (H2).

Each is a well-known anti-pattern with a textbook correct alternative the author
ignored.

---

## Verdict

Across **15 categories** the code fails at the level of fundamentals: it cannot
detect its own errors (A), it data-races on global state (B), it leaks Contexts and
recorders (C), it has no architecture (D), no tests (L), runs on a dead language
shipped as a crack (M), and is littered with first-week anti-patterns (O). The few
competent choices (using KryoNet; the bitmap downsample math) are isolated islands —
and KryoNet is competent because *someone else wrote it*.

This is not "well-programmed software with security implications." It is
**commodity, copy-pasted, untested code**, whose breadth of features disguises the
fact that each one is implemented in the simplest, most fragile way available. The
notion that it is well programmed does not survive contact with the source.
