//! CLI front-end for the IOC scanner.
//!
//! Usage:
//!   ioc-scanner <iocs.csv> <path> [path ...]
//!
//! Walks each path, scans every regular file against the IOC feed, and prints
//! `file:offset  <malware>  <kind>=<value>` for each hit. Exit code is 1 if any
//! hit was found (useful in CI/pipelines), 0 if clean, 2 on error.

use std::process::ExitCode;

use ioc_scanner::Scanner;
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

    let mut any = false;
    for root in paths {
        for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let data = match std::fs::read(path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("warn: skipping {}: {e}", path.display());
                    continue;
                }
            };
            for hit in scanner.scan(&data) {
                any = true;
                let ind = scanner.indicator(&hit);
                println!(
                    "{}:{}\t{}\t{}={}",
                    path.display(),
                    hit.offset,
                    ind.malware,
                    ind.kind,
                    ind.value
                );
            }
        }
    }
    if any { ExitCode::from(1) } else { ExitCode::SUCCESS }
}
