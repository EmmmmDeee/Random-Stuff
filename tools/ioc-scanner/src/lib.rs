/*!
A small, fast, multi-pattern IOC scanner for malware triage.

Given a set of literal indicators (loaded from a CSV feed such as
`intel/iocs.csv`), this builds a single [Aho-Corasick] automaton and streams
file contents through it, so the cost of scanning is `O(total_bytes)` and is
*independent of the number of patterns*. This is the linear-time alternative to
the chain-of-`String.equals` dispatch found in the malware it detects.

# Design notes
- **One automaton, many patterns.** Adding indicators does not slow the hot loop.
- **Bytes, not strings.** Inputs are scanned as raw bytes; we never assume UTF-8,
  because real-world samples (and the corpus this targets) are full of mixed and
  legacy encodings. Correctness over convenience.
- **Errors are values.** Every fallible operation returns [`Result`]; nothing is
  swallowed. Contrast the analysed RAT, whose every failure path is an empty
  `catch`.
- **Memory-mapped I/O.** The CLI memory-maps each file (`memmap2`) and scans the
  mapping as a `&[u8]`, avoiding the multi-gigabyte heap copy that a plain read
  incurs; the pages are file-backed and reclaimable under pressure. (Measured: a
  full scan still faults every page in, so peak RSS during a single scan is
  comparable to a read — the gain is the avoided copy and reclaimable pages, not a
  lower peak.) The library stays I/O-agnostic: [`Scanner::scan`] takes any `&[u8]`.

[Aho-Corasick]: https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm
*/

use std::fmt;
use std::io::Read;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

/// A single indicator of compromise: the literal to match and its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indicator {
    pub value: String,
    pub kind: String,
    pub malware: String,
}

/// One detection: which indicator matched, and at what byte offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub indicator: usize,
    pub offset: usize,
}

/// Error type for scanner construction and CSV parsing.
#[derive(Debug)]
pub enum Error {
    /// The IOC feed contained no usable string-literal indicators.
    NoIndicators,
    /// The Aho-Corasick automaton failed to build.
    Build(aho_corasick::BuildError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoIndicators => write!(f, "no scannable indicators were provided"),
            Error::Build(e) => write!(f, "failed to build automaton: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// Scan thoroughness vs. speed — a *measured* tradeoff, not a guess.
///
/// - [`Mode::Complete`]: overlapping + ASCII case-insensitive. Reports every
///   indicator, including nested ones and case variants. Slower hot loop.
/// - [`Mode::Fast`]: leftmost-longest, case-sensitive, non-overlapping. Fewer
///   reports, faster scan. Use when indicators are case-exact and disjoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Complete,
    Fast,
}

/// A compiled scanner: an Aho-Corasick automaton plus the indicator table.
pub struct Scanner {
    ac: AhoCorasick,
    indicators: Vec<Indicator>,
    mode: Mode,
}

impl Scanner {
    /// Build a scanner with the default [`Mode::Complete`].
    ///
    /// Only string-literal-scannable indicators should be passed here (hashes,
    /// imphashes, ports, etc. are matched elsewhere, not by content scanning).
    ///
    /// # Errors
    /// Returns [`Error::NoIndicators`] if `indicators` is empty, or
    /// [`Error::Build`] if the automaton cannot be constructed.
    pub fn new(indicators: Vec<Indicator>) -> Result<Self, Error> {
        Self::with_mode(indicators, Mode::default())
    }

    /// Build a scanner with an explicit [`Mode`].
    ///
    /// # Errors
    /// Same as [`Scanner::new`].
    pub fn with_mode(indicators: Vec<Indicator>, mode: Mode) -> Result<Self, Error> {
        if indicators.is_empty() {
            return Err(Error::NoIndicators);
        }
        let match_kind = match mode {
            // Standard semantics are required for overlapping search.
            Mode::Complete => MatchKind::Standard,
            Mode::Fast => MatchKind::LeftmostLongest,
        };
        let ac = AhoCorasickBuilder::new()
            .match_kind(match_kind)
            .ascii_case_insensitive(mode == Mode::Complete)
            .build(indicators.iter().map(|i| i.value.as_bytes()))
            .map_err(Error::Build)?;
        Ok(Scanner { ac, indicators, mode })
    }

    /// Parse indicators from an `intel/iocs.csv`-style reader.
    ///
    /// Expected header: `type,value,malware,...`. Only rows whose `type` is a
    /// content-scannable literal (domain/url/string/package/filemarker) are
    /// kept; hash/port/regkey rows are skipped (they aren't byte-substring IOCs).
    ///
    /// This is a deliberately tiny, allocation-light CSV reader: the feed is
    /// trusted, simple, and unquoted. It is *not* a general CSV parser.
    pub fn from_csv(text: &str) -> Result<Self, Error> {
        const SCANNABLE: &[&str] =
            &["domain", "url", "string", "package", "filemarker"];
        let mut out = Vec::new();
        for (n, line) in text.lines().enumerate() {
            if n == 0 || line.trim().is_empty() {
                continue; // header / blank
            }
            let mut f = line.splitn(4, ',');
            let (kind, value, malware) = match (f.next(), f.next(), f.next()) {
                (Some(k), Some(v), Some(m)) => (k.trim(), v.trim(), m.trim()),
                _ => continue,
            };
            if SCANNABLE.contains(&kind) && !value.is_empty() {
                out.push(Indicator {
                    value: value.to_string(),
                    kind: kind.to_string(),
                    malware: malware.to_string(),
                });
            }
        }
        Scanner::new(out)
    }

    /// Scan a byte haystack, returning (indicator, offset) hits.
    ///
    /// In [`Mode::Complete`] this reports overlapping matches; in [`Mode::Fast`]
    /// it reports non-overlapping leftmost-longest matches.
    pub fn scan(&self, haystack: &[u8]) -> Vec<Hit> {
        let to_hit = |m: aho_corasick::Match| Hit {
            indicator: m.pattern().as_usize(),
            offset: m.start(),
        };
        match self.mode {
            Mode::Complete => {
                self.ac.find_overlapping_iter(haystack).map(to_hit).collect()
            }
            Mode::Fast => self.ac.find_iter(haystack).map(to_hit).collect(),
        }
    }

    /// Scan from a streaming reader without holding the whole input in memory.
    ///
    /// Uses Aho-Corasick streaming search, so peak memory is `O(internal buffer +
    /// longest pattern)` — *independent of input length*. This is the right tool
    /// for multi-gigabyte files: unlike scanning an mmap (which faults every page
    /// in), a stream scan keeps resident size bounded by the buffer.
    ///
    /// Streaming search reports **non-overlapping** matches regardless of
    /// [`Mode`]; case-insensitivity (a build-time property of [`Mode::Complete`])
    /// is preserved. For IOC literals, which do not nest, non-overlapping is
    /// equivalent in practice.
    ///
    /// # Errors
    /// Propagates any I/O error from the reader.
    pub fn scan_reader<R: Read>(&self, reader: R) -> std::io::Result<Vec<Hit>> {
        let mut hits = Vec::new();
        for m in self.ac.stream_find_iter(reader) {
            let m = m?;
            hits.push(Hit { indicator: m.pattern().as_usize(), offset: m.start() });
        }
        Ok(hits)
    }

    /// Look up the [`Indicator`] behind a [`Hit`].
    pub fn indicator(&self, hit: &Hit) -> &Indicator {
        &self.indicators[hit.indicator]
    }

    /// Number of compiled indicators.
    pub fn len(&self) -> usize {
        self.indicators.len()
    }

    /// Whether the scanner has any indicators (always true once built).
    pub fn is_empty(&self) -> bool {
        self.indicators.is_empty()
    }
}
