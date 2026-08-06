//! CLI front-end for the IOC scanner.
//!
//! Usage:
//!   ioc-scanner [--json] [--min-confidence low|medium|high] [--summary] [--hashes] <iocs.csv> <path> [path ...]
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
use std::io::{self, BufWriter, Read, Write};
use std::path::Path;
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

    // Optional `--hashes`: also SHA-256 each file and match the feed's hash IOCs.
    // This catches samples whose indicators are not present as plaintext (e.g.
    // compressed archives), which content scanning alone cannot detect.
    let do_hashes = if let Some(i) = args.iter().position(|a| a == "--hashes") {
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
        eprintln!("usage: ioc-scanner [--json] [--min-confidence low|medium|high] [--summary] [--hashes] <iocs.csv> <path> [path ...]");
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
    eprintln!(
        "loaded {} scannable indicators{}",
        scanner.len(),
        if do_hashes {
            format!(" + {} hash IOCs", scanner.hash_count())
        } else {
            String::new()
        }
    );

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
            let mut flagged = false;

            // 1) Content (substring) matching.
            match scan_file(&scanner, path) {
                Ok(hits) => {
                    for hit in hits {
                        let ind = scanner.indicator(&hit);
                        if emit(&mut out, json, path, hit.offset, &ind.malware, &ind.kind, &ind.value)
                            .is_err()
                        {
                            return ExitCode::from(2);
                        }
                        any = true;
                        flagged = true;
                        total_hits += 1;
                        *by_malware.entry(ind.malware.clone()).or_insert(0) += 1;
                    }
                }
                Err(e) => eprintln!("warn: skipping {}: {e}", path.display()),
            }

            // 2) SHA-256 hash matching (opt-in) — catches compressed/opaque samples.
            if do_hashes && scanner.hash_count() > 0 {
                match file_sha256(path) {
                    Ok(digest) => {
                        if let Some(ind) = scanner.hash_lookup(&digest) {
                            if emit(&mut out, json, path, 0, &ind.malware, "sha256", &ind.value)
                                .is_err()
                            {
                                return ExitCode::from(2);
                            }
                            any = true;
                            flagged = true;
                            total_hits += 1;
                            *by_malware.entry(ind.malware.clone()).or_insert(0) += 1;
                        }
                    }
                    Err(e) => eprintln!("warn: hashing {}: {e}", path.display()),
                }
            }

            if flagged {
                files_flagged += 1;
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

/// Write one hit in the selected format (tab-separated or JSON Lines).
fn emit(
    out: &mut impl Write,
    json: bool,
    path: &Path,
    offset: usize,
    malware: &str,
    kind: &str,
    value: &str,
) -> io::Result<()> {
    if json {
        writeln!(
            out,
            r#"{{"file":"{}","offset":{},"malware":"{}","kind":"{}","value":"{}"}}"#,
            json_escape(&path.display().to_string()),
            offset,
            json_escape(malware),
            json_escape(kind),
            json_escape(value)
        )
    } else {
        writeln!(out, "{}:{}\t{}\t{}={}", path.display(), offset, malware, kind, value)
    }
}

/// Stream a file and return its lowercase SHA-256 hex digest.
fn file_sha256(path: &Path) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1 << 18];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
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
