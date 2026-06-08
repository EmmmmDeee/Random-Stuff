//! Throughput benchmark for the IOC scanner.
//!
//! Measures bytes/sec through the Aho-Corasick automaton so the "independent of
//! pattern count, linear in input" claim is measured, not asserted.
//!
//! Run with: `cargo bench`

use std::time::Instant;

use ioc_scanner::Scanner;

const FEED: &str = "\
type,value,malware,context,confidence
domain,droidjack.net,DroidJack,C2,high
string,DJ_GooDbYe:(,DroidJack,kill token,high
package,net.droidjack.server,DroidJack,pkg,high
domain,bshades.eu,Blackshades,C2,medium
string,DownloadExecute.bss,Blackshades,stub,medium
";

fn main() {
    let scanner = Scanner::from_csv(FEED).expect("feed builds");

    // Build a representative haystack: mostly benign bytes with sparse hits,
    // ~16 MiB, which is far larger than any single file in the target corpus.
    let mut hay = Vec::with_capacity(16 << 20);
    let filler = b"the quick brown fox jumps over the lazy dog 0123456789 ";
    while hay.len() < (16 << 20) {
        hay.extend_from_slice(filler);
        if hay.len() % (1 << 20) < filler.len() {
            hay.extend_from_slice(b" connect droidjack.net then DJ_GooDbYe:( ");
        }
    }

    // Warmup.
    let _ = scanner.scan(&hay);

    let runs = 20;
    let start = Instant::now();
    let mut total_hits = 0usize;
    for _ in 0..runs {
        total_hits += scanner.scan(&hay).len();
    }
    let elapsed = start.elapsed();

    let bytes = (hay.len() * runs) as f64;
    let secs = elapsed.as_secs_f64();
    let gibps = bytes / secs / (1u64 << 30) as f64;
    eprintln!(
        "scanned {:.1} MiB x {} runs in {:.3}s  =>  {:.2} GiB/s  ({} hits)",
        hay.len() as f64 / (1u64 << 20) as f64,
        runs,
        secs,
        gibps,
        total_hits
    );
}
