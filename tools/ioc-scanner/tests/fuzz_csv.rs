//! Robustness ("fuzz-lite") tests for the CSV feed parser.
//!
//! The feed is trusted, but a parser that panics on malformed input is a bug.
//! These throw deliberately broken, truncated, and adversarial inputs at
//! `Scanner::from_csv` and assert it never panics — it either builds or returns
//! an `Err`. A full `cargo-fuzz` target can wrap the same entry point on nightly.

use ioc_scanner::Scanner;

/// Drive the parser; success is "did not panic" (Ok or Err both fine).
fn drive(input: &str) {
    let _ = Scanner::from_csv(input);
}

#[test]
fn does_not_panic_on_adversarial_inputs() {
    let cases = [
        "",                                  // empty
        "\n\n\n",                            // only newlines
        "type,value,malware",               // header only
        "type,value,malware\n",             // header + trailing newline
        "domain",                           // one bare field, no header semantics
        "x,y",                              // too few fields after header
        "header\n,,,",                      // empty fields
        "header\ndomain,,DroidJack",        // empty value -> skipped
        "header\ndomain,a,b,c,d,e,f",       // too many commas (splitn caps it)
        "header\nstring,DJ_GooDbYe:(,DroidJack", // a real one
        "header\n\u{0}\u{1}\u{2},x,y",       // control bytes
        "header\nstring,a\u{FFFF}b,m",       // non-ASCII in value
    ];
    for c in cases {
        drive(c);
    }
}

#[test]
fn does_not_panic_on_pathological_sizes() {
    // One enormous line.
    let big = format!("header\ndomain,{},m", "a".repeat(1_000_000));
    drive(&big);
    // Many tiny lines (kept modest so the test stays fast in debug builds).
    let mut many = String::from("header\n");
    for i in 0..5_000 {
        many.push_str(&format!("string,v{i},m\n"));
    }
    drive(&many);
}

#[test]
fn built_scanner_never_panics_on_arbitrary_haystacks() {
    let s = Scanner::from_csv("header\ndomain,droidjack.net,DroidJack\n").unwrap();
    for bytes in [vec![], vec![0u8; 4096], (0u8..=255).cycle().take(100_000).collect()] {
        let _ = s.scan(&bytes);
    }
}
