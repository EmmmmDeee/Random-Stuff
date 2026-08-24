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
//!   hse llm-analyze <event>

use std::collections::BTreeMap;
use std::process::ExitCode;

use hse::{parse_attack_surface, parse_catalog, parse_catalogs, search, Detection, llm::OllamaClient};

const EMBEDDED_DETECTIONS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../intelligence-led/detection-mapping/detections.json"
));
const EMBEDDED_SELF_AUDIT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../intelligence-led/reconnaissance/self-audit.json"
));
const EMBEDDED_RECON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../intelligence-led/reconnaissance/attack-surface.json"
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
         hse stats\n  \
         hse llm-analyze <event>\n\n\
         Global: --catalog <path>   use a catalog file instead of the embedded one\n  \
         Global: --ollama <url>     Ollama endpoint (default: http://127.0.0.1:11434)"
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
        d.id, d.tier, d.label(), d.name, extra
    );
}

fn show(d: &Detection) {
    let (ds_label, fix_label, q_label) = match d.tier.as_str() {
        "self-audit" => ("tool", "fix", "how to check"),
        "recon" => ("open sources", "counter-measure", "detail"),
        _ => ("data source", "tuning", "query"),
    };
    println!("{} — {}", d.id, d.name);
    println!("  tier:        {}", d.tier);
    if !d.fidelity.is_empty() {
        println!("  fidelity:    {}", d.fidelity);
    }
    if !d.priority.is_empty() {
        println!("  priority:    {}", d.priority);
    }
    if !d.techniques.is_empty() {
        println!("  techniques:  {}", d.techniques.join(", "));
    }
    if !d.tactics.is_empty() {
        println!("  tactics:     {}", d.tactics.join(", "));
    }
    if !d.actors.is_empty() {
        println!("  actors:      {}", d.actors.join(", "));
    }
    if !d.data_source.is_empty() {
        println!("  {ds_label:<12} {}", d.data_source);
    }
    if !d.summary.is_empty() {
        println!("  summary:     {}", d.summary);
    }
    if !d.tuning.is_empty() {
        println!("  {fix_label:<12} {}", d.tuning);
    }
    if !d.query.is_empty() {
        println!("\n  [{q_label}]\n  {}\n", d.query);
    }
}

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

    let ollama_endpoint = take_opt(&mut args, "--ollama").unwrap_or_else(|| "http://127.0.0.1:11434".to_string());

    let catalog = if let Some(path) = take_opt(&mut args, "--catalog") {
        let j = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
        parse_catalog(&j).map_err(|e| format!("bad catalog JSON: {e}"))?
    } else {
        let mut c = parse_catalogs(&[EMBEDDED_DETECTIONS, EMBEDDED_SELF_AUDIT])
            .map_err(|e| format!("bad embedded catalog: {e}"))?;
        c.extend(
            parse_attack_surface(EMBEDDED_RECON)
                .map_err(|e| format!("bad recon catalog: {e}"))?,
        );
        c
    };

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
        "llm-analyze" => {
            if args.is_empty() {
                return Err("llm-analyze needs an event description".into());
            }
            let event = args.join(" ");
            println!("  [LLM Analysis] Connecting to Ollama at {}...", ollama_endpoint);

            let client = OllamaClient::with_endpoint(
                ollama_endpoint,
                "qwen2.5-coder:1.5b".to_string(),
            );

            tokio::runtime::Runtime::new()
                .map_err(|e| format!("Failed to create async runtime: {}", e))?
                .block_on(async {
                    match client.analyze_security_event(&event, "Threat detection context").await {
                        Ok(analysis) => {
                            println!("  threat_type:    {}", analysis.threat_type);
                            println!("  confidence:     {:.1}%", analysis.confidence * 100.0);
                            println!("  reasoning:      {}", analysis.reasoning);
                            println!("  recommended:");
                            for action in analysis.recommended_actions {
                                println!("    - {}", action);
                            }
                        }
                        Err(e) => {
                            return Err::<(), String>(format!("LLM analysis failed: {}", e));
                        }
                    }
                    Ok(())
                })?;
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
