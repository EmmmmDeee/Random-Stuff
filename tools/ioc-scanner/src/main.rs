//! CLI front-end for the IOC scanner.
//!
//! Usage:
//!   ioc-scanner <iocs.csv> <path> [path ...]
//!
//! Walks each path, scans every regular file against the IOC feed, and prints
//! `file:offset  <malware>  <kind>=<value>` for each hit. Exit code is 1 if any
//! hit was found (useful in CI/pipelines), 0 if clean, 2 on error.
//!
//! Files are **memory-mapped** rather than read into the heap. Measured benefit
//! (not assumed): this avoids a multi-gigabyte `malloc`+copy that `fs::read`
//! incurs, and the pages are clean and file-backed, so the kernel can reclaim
//! them under memory pressure. Note a *full* scan still faults every page in, so
//! peak resident size during one scan is comparable to reading the file — the win
//! is the avoided copy and reclaimable (not heap-pinned) pages, not lower peak RSS.
//! Empty files and map failures fall back to a plain read.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

use ioc_scanner::{Hit, Scanner};
use memmap2::Mmap;
use walkdir::WalkDir;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: ioc-scanner <iocs.csv> <path> [path ...]");
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
    let scanner = match Scanner::from_csv(&csv) {
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

    for root in paths {
        for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            match scan_file(&scanner, path) {
                Ok(hits) => {
                    for hit in hits {
                        any = true;
                        let ind = scanner.indicator(&hit);
                        // Write errors here mean stdout is gone; bail cleanly.
                        if writeln!(
                            out,
                            "{}:{}\t{}\t{}={}",
                            path.display(),
                            hit.offset,
                            ind.malware,
                            ind.kind,
                            ind.value
                        )
                        .is_err()
                        {
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
    if any {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Scan a single file, memory-mapping it when possible.
///
/// Empty files yield no hits. If mmap is unavailable (e.g. some virtual
/// filesystems), fall back to reading the file into memory.
fn scan_file(scanner: &Scanner, path: &std::path::Path) -> io::Result<Vec<Hit>> {
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: read-only mapping. As with ripgrep, we accept that a file mutated
    // by another process mid-scan is undefined behavior; for triage scanning of
    // at-rest samples this is an acceptable, documented risk.
    match unsafe { Mmap::map(&file) } {
        Ok(mmap) => Ok(scanner.scan(&mmap)),
        Err(_) => Ok(scanner.scan(&std::fs::read(path)?)),
    }
}
