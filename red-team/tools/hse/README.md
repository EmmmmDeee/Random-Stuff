# HSE — Huntsman Search Engine

A small Rust CLI that indexes and searches the red-team **detection catalog**
(`../../intelligence-led/detection-mapping/detections.json`) — the machine-readable
form of the hunt (`H-*`), correlation (`C-*`), blind-spot (`B-*`), and baseline
(`A-*`) detections.

It answers "which detection covers X?" fast, from the terminal — the queryable
counterpart to the prose in `hunt-queries.md` / `correlation-and-coverage.md`.

> Security tooling. HSE searches detection *content*; it executes nothing
> against any system.

## Build

```bash
cd red-team/tools/hse
cargo build --release
# binary at target/release/hse
```

The catalog is embedded at compile time, so the binary is self-contained. Editing
`detections.json` requires a rebuild (or pass `--catalog <path>` to read a file at
runtime).

### Cross-platform (Android/Termux/aarch64)

HSE uses only standard Rust (no platform-specific code or system calls). To build
for aarch64 (Termux on Android, etc.):

```bash
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
# binary at target/aarch64-unknown-linux-gnu/release/hse
```

No root required. The binary is portable and works in any userland environment
(Termux, chroot, etc.).

## Usage

```bash
hse list [--tier T] [--fidelity F]   # list detections (filter by tier/fidelity)
hse search <terms...>                # ranked full-text search across all fields
hse technique <ATT&CK-ID>            # detections covering a technique (parent/child aware)
hse tactic <name>                    # detections for an ATT&CK tactic
hse actor <ID>                       # detections mapped to a threat actor
hse show <detection-id>              # full detail incl. the query and tuning notes
hse stats                            # counts by tier and by actor
```

Global flag: `--catalog <path>` uses a catalog file instead of the embedded one.

### Examples

```bash
hse technique T1486        # → H-12 (mass file mod) and C-04 (shadow-copy→encrypt)
hse actor APT41            # → H-14, H-15 (web-shell chain)
hse search ransomware shadow
hse list --tier correlation
hse show C-04              # prints the full KQL + tuning
```

Technique matching is parent/child aware: `hse technique T1566` also returns
detections tagged `T1566.001`, and vice-versa.

## How it fits the framework

```
detections.json  ──►  HSE (search/filter)         ← this tool
      ▲                └─ "which detection covers technique X / actor Y?"
      │
hunt-queries.md, correlation-and-coverage.md  (full prose + rationale)
```

The catalog is the single machine-readable source; the markdown files remain the
authoritative, human-readable reference with full context and caveats.

## Design

- **Minimal deps**: only `serde` + `serde_json`.
- **Ranked search**: scores each detection by how many query terms appear across
  its id/name/techniques/tactics/actors/summary/query/tuning text.
- **Library + binary**: `lib.rs` holds the model and search logic (unit-tested);
  `main.rs` is the CLI. Run `cargo test` for the library tests.

---

**Status**: security detection-catalog search • **License**: MIT
