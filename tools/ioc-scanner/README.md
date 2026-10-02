# ioc-scanner

A small, fast, multi-pattern IOC scanner for malware triage — the defensive
counterpart to the string-token command loop found in the analysed RATs.

It loads literal indicators from a CSV feed (e.g. `intel/iocs.csv`), compiles a
single **Aho-Corasick** automaton, and streams files through it. Scan cost is
`O(total_bytes)` and **independent of the number of indicators**.

## Build & test
```sh
cargo test            # unit + integration tests
cargo clippy          # lints (kept warning-free)
cargo build --release
```

## Usage
```sh
ioc-scanner [--json] [--min-confidence low|medium|high] [--summary] [--hashes] \
            intel/iocs.csv path/to/dir [more paths ...]
# prints:  file:offset \t <malware> \t <kind>=<value>   (--json: JSON Lines)
# exit 1 if any hit, 0 if clean, 2 on error  (pipeline-friendly)
```

## Design (the standards this demonstrates)
- **One automaton, many patterns** — adding IOCs never slows the hot loop.
- **Bytes, not strings** — never assumes UTF-8; correct on mixed/legacy encodings.
- **Errors are values** — every fallible path returns `Result`; nothing swallowed.
- **Minimal deps** — `aho-corasick`, `walkdir`, `memchr`; auditable tree.
- **Tested** — match/no-match, case-insensitivity, offsets, error cases.

Content-scannable indicator types (domain/url/string/package/section/filemarker)
are compiled into the automaton. `sha256` rows are matched by file digest when
`--hashes` is given; md5/imphash/port/regkey rows are matched by other tooling
(YARA `pe.imphash()`, network rules), not by this scanner.
