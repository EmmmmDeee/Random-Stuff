//! Throughput benchmark for the IOC scanner.
//!
//! Measures bytes/sec through the Aho-Corasick automaton so the "independent of
//! pattern count, linear in input" claim is measured, not asserted.
//!
//! Run with: `cargo bench`

use std::time::Instant;

use ioc_scanner::{Indicator, Mode, Scanner};

const FEED: &str = "\
type,value,malware,context,confidence
domain,droidjack.net,DroidJack,C2,high
string,DJ_GooDbYe:(,DroidJack,kill token,high
package,net.droidjack.server,DroidJack,pkg,high
domain,bshades.eu,Blackshades,C2,medium
string,DownloadExecute.bss,Blackshades,stub,medium
";

fn indicators() -> Vec<Indicator> {
    // Parse directly into raw indicators so we can build both modes from the same set.
    FEED.lines()
        .skip(1)
        .filter_map(|l| {
            let mut f = l.splitn(4, ',');
            match (f.next(), f.next(), f.next()) {
                (Some(k), Some(v), Some(m))
                    if matches!(k, "domain" | "url" | "string" | "package" | "filemarker") =>
                {
                    Some(Indicator {
                        value: v.into(),
                        kind: k.into(),
                        malware: m.into(),
                        confidence: ioc_scanner::Confidence::High,
                    })
                }
                _ => None,
            }
        })
        .collect()
}

fn bench(label: &str, scanner: &Scanner, hay: &[u8], runs: usize) {
    let _ = scanner.scan(hay); // warmup
    let start = Instant::now();
    let mut hits = 0usize;
    for _ in 0..runs {
        hits += scanner.scan(hay).len();
    }
    let secs = start.elapsed().as_secs_f64();
    let gibps = (hay.len() * runs) as f64 / secs / (1u64 << 30) as f64;
    eprintln!(
        "{label:9} {:.1} MiB x {runs} in {secs:.3}s => {gibps:.2} GiB/s ({hits} hits)",
        hay.len() as f64 / (1u64 << 20) as f64,
    );
}

fn main() {
    let inds = indicators();
    let complete = Scanner::with_mode(inds.clone(), Mode::Complete).unwrap();
    let fast = Scanner::with_mode(inds, Mode::Fast).unwrap();

    let mut hay = Vec::with_capacity(16 << 20);
    let filler = b"the quick brown fox jumps over the lazy dog 0123456789 ";
    while hay.len() < (16 << 20) {
        hay.extend_from_slice(filler);
        if hay.len() % (1 << 20) < filler.len() {
            hay.extend_from_slice(b" connect droidjack.net then DJ_GooDbYe:( ");
        }
    }

    let runs = 20;
    bench("Complete", &complete, &hay, runs);
    bench("Fast", &fast, &hay, runs);
}
