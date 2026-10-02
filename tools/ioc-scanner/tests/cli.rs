//! End-to-end exit-code contract of the CLI: 1 = hit, 0 = clean, 2 = error.
//! An incomplete scan (unreadable path) must never be reported as clean.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ioc-scanner-cli-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("feed.csv"),
        "type,value,malware\ndomain,evil.example,M\n",
    )
    .unwrap();
    dir
}

fn run(args: &[&std::ffi::OsStr]) -> i32 {
    Command::new(env!("CARGO_BIN_EXE_ioc-scanner"))
        .args(args)
        .output()
        .unwrap()
        .status
        .code()
        .unwrap()
}

#[test]
fn exit_codes() {
    let dir = scratch("codes");
    let feed = dir.join("feed.csv");
    let clean = dir.join("clean");
    let hit = dir.join("hit");
    fs::create_dir_all(&clean).unwrap();
    fs::create_dir_all(&hit).unwrap();
    fs::write(clean.join("a"), "nothing here").unwrap();
    fs::write(hit.join("b"), "beacon to evil.example").unwrap();
    let missing = dir.join("does-not-exist");

    assert_eq!(run(&[feed.as_os_str(), clean.as_os_str()]), 0, "clean");
    assert_eq!(run(&[feed.as_os_str(), hit.as_os_str()]), 1, "hit");
    assert_eq!(
        run(&[feed.as_os_str(), missing.as_os_str()]),
        2,
        "missing path is an error, not clean"
    );
    assert_eq!(
        run(&[feed.as_os_str(), clean.as_os_str(), missing.as_os_str()]),
        2,
        "partial scan is not clean"
    );
    assert_eq!(
        run(&[feed.as_os_str(), hit.as_os_str(), missing.as_os_str()]),
        1,
        "a definite hit still wins"
    );
    assert_eq!(
        run(&[missing.as_os_str(), clean.as_os_str()]),
        2,
        "unreadable feed"
    );
    let _ = fs::remove_dir_all(&dir);
}
