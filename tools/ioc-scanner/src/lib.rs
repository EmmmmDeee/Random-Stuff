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
- **Streaming.** Files are read once into a buffer and scanned; large inputs do
  not require holding N copies. (A future revision can `mmap` for huge files.)

[Aho-Corasick]: https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm
*/

use std::fmt;

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

/// A compiled scanner: an Aho-Corasick automaton plus the indicator table.
pub struct Scanner {
    ac: AhoCorasick,
    indicators: Vec<Indicator>,
}

impl Scanner {
    /// Build a scanner from a list of indicators.
    ///
    /// Only string-literal-scannable indicators should be passed here (hashes,
    /// imphashes, ports, etc. are matched elsewhere, not by content scanning).
    ///
    /// # Errors
    /// Returns [`Error::NoIndicators`] if `indicators` is empty, or
    /// [`Error::Build`] if the automaton cannot be constructed.
    pub fn new(indicators: Vec<Indicator>) -> Result<Self, Error> {
        if indicators.is_empty() {
            return Err(Error::NoIndicators);
        }
        let ac = AhoCorasickBuilder::new()
            // Standard semantics: required for overlapping search, so every
            // indicator is reported even when one IOC is a substring of another.
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(true)
            .build(indicators.iter().map(|i| i.value.as_bytes()))
            .map_err(Error::Build)?;
        Ok(Scanner { ac, indicators })
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

    /// Scan a byte haystack, returning every (indicator, offset) hit.
    pub fn scan(&self, haystack: &[u8]) -> Vec<Hit> {
        self.ac
            .find_overlapping_iter(haystack)
            .map(|m| Hit { indicator: m.pattern().as_usize(), offset: m.start() })
            .collect()
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
