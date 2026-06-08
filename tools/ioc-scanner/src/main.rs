//! CLI front-end for the IOC scanner.
//!
//! Usage:
//!   ioc-scanner [--json] [--min-confidence low|medium|high] [--summary] <iocs.csv> <path> [path ...]
//!
//! Walks each path, scans every regular file against the IOC feed, and prints
//! `file:offset  <malware>  <kind>=<value>` for each hit (tab-separated). With
//! `--json`, emits one JSON object per hit (JSON Lines) for SIEM/pipeline intake.
//! `--min-confidence` drops indicators below the given grade; `--summary` prints a
//! files/hits/by-malware tally to stderr at the end. Exit code is 1 if any hit was
//! found (useful in CI/pipelines), 0 if clean, 2 on error.
//!
//! Scanning strategy is chosen by file size (measured, not assumed). Large files
//! (>= 16 MiB) are streamed in fixed-size chunks, so peak resident memory stays
//! bounded by the buffer regardless of file size; small files are memory-mapped
//! and scanned whole, preserving full overlapping-match fidelity without per-file
//! heap copies. Empty files yield no hits; an mmap failure falls back to a read.
//!
//! Why streaming and not mmap-only: a full scan of an mmap faults every page in,
//! so a 2.5 GB mapping ends up ~2.5 GB resident (verified by measurement). Only
//! streaming keeps a multi-gigabyte input from sitting fully resident.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

use ioc_scanner::{json_escape, Confidence, Hit, Scanner};
use memmap2::Mmap;
use walkdir::WalkDir;

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    // Optional `--json` flag (anywhere before the positional args) selects JSON
    // Lines output instead of the default tab-separated format.
    let json = if let Some(i) = args.iter().position(|a| a == "--json") {
        args.remove(i);
        true
    } else {
        false
    };

    // Optional `--summary`: print a tally to stderr at the end (keeps stdout clean).
    let summary = if let Some(i) = args.iter().position(|a| a == "--summary") {
        args.remove(i);
        true
    } else {
        false
    };

    // Optional `--min-confidence <low|medium|high>` filters the indicator set.
    let mut min_conf = Confidence::Low;
    if let Some(i) = args.iter().position(|a| a == "--min-confidence") {
        match args.get(i + 1).map(|s| s.to_ascii_lowercase()) {
            Some(ref v) if v == "low" => min_conf = Confidence::Low,
            Some(ref v) if v == "medium" => min_conf = Confidence::Medium,
            Some(ref v) if v == "high" => min_conf = Confidence::High,
            other => {
                eprintln!("error: --min-confidence expects low|medium|high, got {other:?}");
                return ExitCode::from(2);
            }
        }
        args.drain(i..=i + 1);
    }

    if args.len() < 2 {
        eprintln!("usage: ioc-scanner [--json] [--min-confidence low|medium|high] [--summary] <iocs.csv> <path> [path ...]");
        return ExitCode::from(2);
    }
    let (feed, paths) = (&args[0], &args[1..]);

    let csv = match std::fs::read_to_string(feed) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: reading feed {feed}: {e}");
            return ExitCode::from(2);
        }
    };
    let scanner = match Scanner::from_csv_min(&csv, min_conf) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    eprintln!("loaded {} scannable indicators", scanner.len());

    // Lock stdout once and buffer; per-hit `println!` would lock on every write.
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut any = false;

    // Summary counters (cheap; only reported when `--summary` is set).
    let mut files_scanned = 0usize;
    let mut files_flagged = 0usize;
    let mut total_hits = 0usize;
    let mut by_malware: BTreeMap<String, usize> = BTreeMap::new();

    for root in paths {
        for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            files_scanned += 1;
            let path = entry.path();
            match scan_file(&scanner, path) {
                Ok(hits) => {
                    if !hits.is_empty() {
                        files_flagged += 1;
                    }
                    for hit in hits {
                        any = true;
                        total_hits += 1;
                        let ind = scanner.indicator(&hit);
                        *by_malware.entry(ind.malware.clone()).or_insert(0) += 1;
                        // Write errors here mean stdout is gone; bail cleanly.
                        let res = if json {
                            writeln!(
                                out,
                                r#"{{"file":"{}","offset":{},"malware":"{}","kind":"{}","value":"{}"}}"#,
                                json_escape(&path.display().to_string()),
                                hit.offset,
                                json_escape(&ind.malware),
                                json_escape(&ind.kind),
                                json_escape(&ind.value)
                            )
                        } else {
                            writeln!(
                                out,
                                "{}:{}\t{}\t{}={}",
                                path.display(),
                                hit.offset,
                                ind.malware,
                                ind.kind,
                                ind.value
                            )
                        };
                        if res.is_err() {
                            return ExitCode::from(2);
                        }
                    }
                }
                Err(e) => eprintln!("warn: skipping {}: {e}", path.display()),
            }
        }
    }

    if out.flush().is_err() {
        return ExitCode::from(2);
    }

    if summary {
        eprintln!(
            "summary: scanned {files_scanned} files, {files_flagged} flagged, {total_hits} hits"
        );
        for (malware, count) in &by_malware {
            eprintln!("  {malware}: {count}");
        }
    }

    if any {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Files at or above this size are streamed (bounded memory) instead of mapped.
const STREAM_THRESHOLD: u64 = 16 * 1024 * 1024;

/// Scan a single file, choosing the right strategy for its size.
///
/// - **Large files (>= 16 MiB):** streamed via [`Scanner::scan_reader`], so peak
///   memory stays bounded by the stream buffer rather than the file size. This is
///   what keeps a multi-GB input from sitting fully resident.
/// - **Small files:** memory-mapped and scanned whole, preserving full
///   (overlapping) match fidelity.
///
/// Empty files yield no hits; an mmap failure falls back to a plain read.
fn scan_file(scanner: &Scanner, path: &std::path::Path) -> io::Result<Vec<Hit>> {
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(Vec::new());
    }
    if len >= STREAM_THRESHOLD {
        return scanner.scan_reader(io::BufReader::new(file));
    }
    // SAFETY: read-only mapping. As with ripgrep, we accept that a file mutated
    // by another process mid-scan is undefined behavior; for triage scanning of
    // at-rest samples this is an acceptable, documented risk.
    match unsafe { Mmap::map(&file) } {
        Ok(mmap) => Ok(scanner.scan(&mmap)),
        Err(_) => Ok(scanner.scan(&std::fs::read(path)?)),
    }
}
