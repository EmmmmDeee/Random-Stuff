# Code Review — Decompiled DroidJack (Java) & Blackshades (VB6)

An engineering-quality critique of the recovered code, paired with
`SOURCE_LEVEL_ANALYSIS.md`. This reviews **craft** (correctness, safety, clarity,
maintainability, tooling). It deliberately does **not** describe how to make the
malware more effective, more reliable, or harder to detect — where a "fix" would
mean a better weapon, the entry says so and stops.

> Detectability note: this code is trivially detectable, and that is a *symptom*
> of poor engineering (magic literals, no abstraction), not a property to "fix."
> Improving detection evasion is out of scope here and everywhere in this repo.

## Findings

### 1. Swallowed exceptions (cardinal sin)
`try { ... } catch (Exception e) { ae.a(e); e.printStackTrace(); }` repeated
throughout. Catch-base-class, log, continue — every failure is indistinguishable
from success.
**Instead:** errors as values (`Result` + `?`); narrow, typed catches that branch
on the failure at the layer that can handle it; never catch the base class.

### 2. Debug output shipped to production
`System.out.println("Connecting!")`, `println(5)`, `println(6)`,
`"Clear n working - Cam"` — left in a remote-access trojan.
**Instead:** a logging facade with levels, off in release, diagnostics to stderr.

### 3. Mutable global state, no concurrency model
`static MediaRecorder c; static boolean f236a;` mutated from broadcast receivers;
strategy is "hope events never overlap."
**Instead:** own state in an instance with a clear lifecycle; make concurrency
explicit. Rust would reject this at compile time (`static mut` is unsafe; the
borrow checker forbids the data race).

### 4. Imported the right tool, used the wrong one
Imports `ExecutorService`, then spawns `new u().start()` / `new x().start()` —
unbounded hand-rolled threads, no pool, no backpressure.
**Instead:** one concurrency primitive (a bounded executor / structured
concurrency), used consistently.

### 5. God-methods
`CallListener.onReceive` reads prefs, writes defaults, parses a number via four
chained `.replace()`, branches, toggles radios, registers a `ContentObserver` —
all inline.
**Instead:** one function, one job; extract `parseNumber`/`loadConfig`/`onIncoming`;
the chained-`replace` normalization becomes one tested function.

### 6. Reflection without guards *(boundary)*
`getDeclaredMethod("getITelephony")` / `setMobileDataEnabled` via reflection
inside swallow-all `catch`; works only on tested API levels.
The defect is brittleness + silent failure. **Hardening this is making the RAT
work on more victims, so the hardened version is intentionally not given.** The
fix that matters here is the *detector* that flags the reflection pattern.

### 7. Naming & magic literals
90 classes named `a`…`cg` (shipped ProGuard output) while the brand leaks in
cleartext: `net.droidjack.server`, `droidjack.net`, `DJ_GooDbYe:(`.
**Instead:** meaningful names and no magic literals (constants/config, a clear
boundary on what enters the artifact). This is naming discipline — *not* "encrypt
strings so AV misses them."

### 8. Duplication & dead structure
Copy-pasted `try/catch` boilerplate; near-duplicate corpus files; `store`-method
ZIPs that don't compress.
**Instead:** factor the (error-handling) helper once; dedup by content hash; one
source of truth.

### 9. No tests
Verification was "it ran on the target."
**Instead:** unit + integration + property tests, fuzzing, benchmarks — as done
in `tools/ioc-scanner/` (tests green, clippy clean, benchmarked, fuzzed).

### 10. Blackshades, structurally
VB6 in 2013; ~70 `frm*` forms where presentation *is* logic; Win32 resolved
through the VB runtime; the binary is a third-party *crack* (`.mackt` section).
**Instead:** separation of concerns, a memory-safe language, an auditable build.

## Verdict
Fails on correctness, safety, clarity, maintainability, and tooling discipline.
Every "instead" above is ordinary good engineering — typed errors, owned state,
small tested functions, honest logging, minimal deps — and **none** of them is
"hide better." The two places where a fix would yield a stealthier/more reliable
RAT (#6, #7) are exactly where the review stops and points at the detector.
