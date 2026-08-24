//! `hse` — Huntsman Search Engine CLI.
//!
//! Searches the red-team detection catalog. The catalog is embedded at build
//! time; override it at runtime with `--catalog <path>`.
//!
//!   hse list [--tier T] [--fidelity F]
//!   hse search <terms...>
//!   hse technique <ID>
//!   hse tactic <name>
//!   hse actor <ID>
//!   hse show <id>
//!   hse stats

use std::collections::BTreeMap;
use std::process::ExitCode;

use hse::{parse_catalog, search, Detection};

/// Catalog baked in at compile time (path relative to this crate's Cargo.toml).
const EMBEDDED: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../intelligence-led/detection-mapping/detections.json"
));

fn usage() {
    eprintln!(
        "hse — Huntsman Search Engine (search the detection catalog)\n\n\
         USAGE:\n  \
         hse list [--tier T] [--fidelity F]\n  \
         hse search <terms...>\n  \
         hse technique <ATT&CK-ID>\n  \
         hse tactic <name>\n  \
         hse actor <ID>\n  \
         hse show <detection-id>\n  \
         hse stats\n\n\
         Global: --catalog <path>   use a catalog file instead of the embedded one"
    );
}

fn brief(d: &Detection) {
    let extra = if d.techniques.is_empty() {
        String::new()
    } else {
        format!("  {}", d.techniques.join(","))
    };
    println!(
        "  {:<5} [{:<11}] {:<11} {}{}",
        d.id, d.tier, d.fidelity, d.name, extra
    );
}

fn show(d: &Detection) {
    println!("{} — {}", d.id, d.name);
    println!("  tier:        {}", d.tier);
    println!("  fidelity:    {}", d.fidelity);
    if !d.techniques.is_empty() {
        println!("  techniques:  {}", d.techniques.join(", "));
    }
    if !d.tactics.is_empty() {
        println!("  tactics:     {}", d.tactics.join(", "));
    }
    if !d.actors.is_empty() {
        println!("  actors:      {}", d.actors.join(", "));
    }
    println!("  data source: {}", d.data_source);
    println!("  dialect:     {}", d.dialect);
    println!("  summary:     {}", d.summary);
    println!("  tuning:      {}", d.tuning);
    println!("\n  {}\n", d.query);
}

/// Pull `--catalog <path>` (and its value) out of args; return the JSON to use.
fn resolve_catalog(args: &mut Vec<String>) -> Result<String, String> {
    if let Some(i) = args.iter().position(|a| a == "--catalog") {
        let path = args
            .get(i + 1)
            .cloned()
            .ok_or_else(|| "--catalog needs a path".to_string())?;
        args.drain(i..=i + 1);
        std::fs::read_to_string(&path).map_err(|e| format!("cannot read {path}: {e}"))
    } else {
        Ok(EMBEDDED.to_string())
    }
}

/// Pull `--flag <value>` out of args, returning the value if present.
fn take_opt(args: &mut Vec<String>, flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| {
        let v = args.get(i + 1).cloned();
        if v.is_some() {
            args.drain(i..=i + 1);
        }
        v
    })
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        return Err(String::new());
    }

    let json = resolve_catalog(&mut args)?;
    let catalog = parse_catalog(&json).map_err(|e| format!("bad catalog JSON: {e}"))?;

    let command = args.remove(0);
    match command.as_str() {
        "list" => {
            let tier = take_opt(&mut args, "--tier");
            let fidelity = take_opt(&mut args, "--fidelity");
            let mut shown = 0;
            for d in &catalog {
                if let Some(t) = &tier {
                    if !d.tier.eq_ignore_ascii_case(t) {
                        continue;
                    }
                }
                if let Some(f) = &fidelity {
                    if !d.fidelity.eq_ignore_ascii_case(f) {
                        continue;
                    }
                }
                brief(d);
                shown += 1;
            }
            println!("\n  {shown} detection(s)");
        }
        "search" => {
            if args.is_empty() {
                return Err("search needs terms".into());
            }
            let q = args.join(" ");
            let hits = search(&catalog, &q);
            if hits.is_empty() {
                println!("  no matches for: {q}");
            }
            for (score, d) in &hits {
                println!("  [{score}] {:<5} {} — {}", d.id, d.name, d.summary);
            }
        }
        "technique" => {
            let id = args.first().ok_or("technique needs an ATT&CK ID")?;
            let hits: Vec<_> = catalog.iter().filter(|d| d.covers_technique(id)).collect();
            if hits.is_empty() {
                println!("  no detection covers {id}");
            }
            for d in hits {
                brief(d);
            }
        }
        "tactic" => {
            let name = args.join(" ");
            if name.is_empty() {
                return Err("tactic needs a name".into());
            }
            for d in catalog.iter().filter(|d| d.has_tactic(&name)) {
                brief(d);
            }
        }
        "actor" => {
            let id = args.first().ok_or("actor needs an ID")?;
            for d in catalog.iter().filter(|d| d.has_actor(id)) {
                brief(d);
            }
        }
        "show" => {
            let id = args.first().ok_or("show needs a detection id")?;
            match catalog.iter().find(|d| d.id.eq_ignore_ascii_case(id)) {
                Some(d) => show(d),
                None => return Err(format!("no detection with id {id}")),
            }
        }
        "stats" => {
            let mut by_tier: BTreeMap<&str, usize> = BTreeMap::new();
            let mut by_actor: BTreeMap<&str, usize> = BTreeMap::new();
            for d in &catalog {
                *by_tier.entry(d.tier.as_str()).or_default() += 1;
                for a in &d.actors {
                    *by_actor.entry(a.as_str()).or_default() += 1;
                }
            }
            println!("  {} detections total\n", catalog.len());
            println!("  by tier:");
            for (t, n) in &by_tier {
                println!("    {t:<12} {n}");
            }
            println!("\n  by actor:");
            for (a, n) in &by_actor {
                println!("    {a:<18} {n}");
            }
        }
        "-h" | "--help" | "help" => usage(),
        other => return Err(format!("unknown command: {other}")),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("error: {msg}");
            }
            ExitCode::FAILURE
        }
    }
}
