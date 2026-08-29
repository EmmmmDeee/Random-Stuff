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

use std::collections::HashMap;
use std::fmt;
use std::io::Read;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

/// Confidence grade of an indicator (from the feed's `confidence` column).
///
/// Ordered `Low < Medium < High`; unknown/missing grades parse as `Low`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    /// Parse a grade string; anything unrecognised (incl. empty) is `Low`.
    pub fn parse(s: &str) -> Confidence {
        let s = s.trim();
        if s.eq_ignore_ascii_case("high") {
            Confidence::High
        } else if s.eq_ignore_ascii_case("medium") {
            Confidence::Medium
        } else {
            Confidence::Low
        }
    }
}

/// A single indicator of compromise: the literal to match and its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indicator {
    pub value: String,
    pub kind: String,
    pub malware: String,
    pub confidence: Confidence,
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

/// A compiled scanner: an Aho-Corasick automaton plus the indicator table,
/// and a side table of SHA-256 hash indicators for hash-based matching.
pub struct Scanner {
    ac: AhoCorasick,
    indicators: Vec<Indicator>,
    mode: Mode,
    hashes: HashMap<String, Indicator>,
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
        Ok(Scanner { ac, indicators, mode, hashes: HashMap::new() })
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
        Self::from_csv_min(text, Confidence::Low)
    }

    /// Like [`Scanner::from_csv`], but keeps only indicators whose confidence is
    /// at least `min` (the feed's 5th column, `confidence`).
    ///
    /// # Errors
    /// Same as [`Scanner::new`] (including [`Error::NoIndicators`] if the filter
    /// leaves nothing).
    pub fn from_csv_min(text: &str, min: Confidence) -> Result<Self, Error> {
        const SCANNABLE: &[&str] =
            &["domain", "url", "string", "package", "section", "filemarker"];
        // Cap indicator length. Real content IOCs (domains, URLs, byte strings)
        // are short — comfortably under a few hundred bytes. Automaton
        // construction cost is superlinear in the *longest* pattern (aho-corasick
        // auto-selects a DFA, whose build is ~O(n^2) in pattern length: a 20 KiB
        // pattern takes ~30 s, a 1 MiB pattern effectively never finishes), so a
        // single pathologically long row would hang startup. A malformed row that
        // long is not a usable indicator anyway; skip it, as we already skip empty
        // values and unknown kinds. Keeps the DFA's fast scan for real feeds while
        // bounding worst-case build time.
        const MAX_INDICATOR_LEN: usize = 4096;
        let mut out = Vec::new();
        let mut hashes: HashMap<String, Indicator> = HashMap::new();
        for (n, line) in text.lines().enumerate() {
            if n == 0 || line.trim().is_empty() {
                continue; // header / blank
            }
            // type,value,malware,context,confidence
            let parts: Vec<&str> = line.splitn(5, ',').collect();
            if parts.len() < 3 {
                continue;
            }
            let (kind, value, malware) = (parts[0].trim(), parts[1].trim(), parts[2].trim());
            let confidence = Confidence::parse(parts.get(4).copied().unwrap_or(""));
            if value.is_empty() || value.len() > MAX_INDICATOR_LEN || confidence < min {
                continue;
            }
            let ind = Indicator {
                value: value.to_string(),
                kind: kind.to_string(),
                malware: malware.to_string(),
                confidence,
            };
            if SCANNABLE.contains(&kind) {
                out.push(ind);
            } else if kind == "sha256" {
                // Hash IOCs are matched by file digest, not content scanning.
                hashes.insert(value.to_ascii_lowercase(), ind);
            }
        }
        let mut scanner = Scanner::new(out)?;
        scanner.hashes = hashes;
        Ok(scanner)
    }

    /// Look up a SHA-256 hex digest (case-insensitive) among the feed's hash IOCs.
    pub fn hash_lookup(&self, sha256_hex: &str) -> Option<&Indicator> {
        self.hashes.get(&sha256_hex.to_ascii_lowercase())
    }

    /// Number of SHA-256 hash indicators loaded.
    pub fn hash_count(&self) -> usize {
        self.hashes.len()
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

/// Escape a string for embedding in a JSON string literal (RFC 8259 §7).
///
/// Handles the required escapes (`"`, `\`, the C0 control characters) so callers
/// can build JSON output without pulling in a serializer. Note: input is already
/// valid UTF-8 (`&str`); this does not perform any encoding conversion.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                const HEX: &[u8] = b"0123456789abcdef";
                let n = c as u32;
                out.push_str("\\u00");
                out.push(HEX[(n >> 4) as usize] as char);
                out.push(HEX[(n & 0xf) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod csv_tests {
    use super::{Confidence, Scanner};

    #[test]
    fn skips_overlong_indicator_values() {
        // A pathologically long row must not reach the automaton builder (its
        // build is superlinear in the longest pattern). Here the only content row
        // is over-length, so it is skipped and the feed yields no indicators.
        let feed = format!("type,value,malware\ndomain,{},m\n", "a".repeat(10_000));
        assert!(matches!(
            Scanner::from_csv(&feed),
            Err(super::Error::NoIndicators)
        ));

        // A normal-length row alongside an over-length one keeps the good one.
        let feed = format!(
            "type,value,malware\ndomain,evil.example,M\nstring,{},N\n",
            "b".repeat(10_000)
        );
        let s = Scanner::from_csv(&feed).unwrap();
        assert_eq!(s.len(), 1);
        assert!(!s.scan(b"go to evil.example now").is_empty());
    }

    #[test]
    fn confidence_filter_still_applies() {
        let feed = "type,value,malware,context,confidence\n\
                    domain,low.example,M,,low\n\
                    domain,high.example,M,,high\n";
        let s = Scanner::from_csv_min(feed, Confidence::High).unwrap();
        assert_eq!(s.len(), 1);
    }
}

#[cfg(test)]
mod json_tests {
    use super::json_escape;

    #[test]
    fn escapes_quote_and_backslash() {
        assert_eq!(json_escape(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn escapes_control_chars() {
        assert_eq!(json_escape("x\ny\tz"), "x\\ny\\tz");
        assert_eq!(json_escape("\u{01}"), "\\u0001");
    }

    #[test]
    fn passes_through_plain_and_unicode() {
        assert_eq!(json_escape("droidjack.net"), "droidjack.net");
        assert_eq!(json_escape("café"), "café");
    }
}
