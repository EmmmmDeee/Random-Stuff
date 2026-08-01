use ioc_scanner::{Confidence, Scanner};

const FEED: &str = "\
type,value,malware,context,confidence
domain,droidjack.net,DroidJack,C2,high
string,DJ_GooDbYe:(,DroidJack,kill token,high
sha256,deadbeef,DroidJack,should be skipped,high
domain,bshades.eu,Blackshades,C2,medium
";

#[test]
fn loads_only_scannable_indicators() {
    let s = Scanner::from_csv(FEED).unwrap();
    // 3 scannable (two domains + one string); the sha256 row is skipped.
    assert_eq!(s.len(), 3);
}

#[test]
fn finds_hits_with_offsets() {
    let s = Scanner::from_csv(FEED).unwrap();
    let hay = b"GET http://droidjack.net/Access/DJ then DJ_GooDbYe:(";
    let hits = s.scan(hay);
    let values: Vec<&str> =
        hits.iter().map(|h| s.indicator(h).value.as_str()).collect();
    assert!(values.contains(&"droidjack.net"));
    assert!(values.contains(&"DJ_GooDbYe:("));
}

#[test]
fn case_insensitive_match() {
    let s = Scanner::from_csv(FEED).unwrap();
    let hits = s.scan(b"connect to DROIDJACK.NET now");
    assert_eq!(hits.len(), 1);
    assert_eq!(s.indicator(&hits[0]).value, "droidjack.net");
}

#[test]
fn empty_feed_is_an_error() {
    assert!(Scanner::from_csv("type,value,malware\n").is_err());
}

#[test]
fn clean_input_has_no_hits() {
    let s = Scanner::from_csv(FEED).unwrap();
    assert!(s.scan(b"a perfectly innocent file about cats").is_empty());
}

#[test]
fn min_confidence_filters_below_threshold() {
    // `from_csv_min(High)` should drop the medium-confidence bshades row.
    let s = Scanner::from_csv_min(FEED, Confidence::High).unwrap();
    // Only 2 high-confidence scannable rows (domain + string); bshades.eu gone.
    assert_eq!(s.len(), 2);
    assert!(s.scan(b"bshades.eu").is_empty());
    assert!(!s.scan(b"droidjack.net").is_empty());
}

#[test]
fn hash_lookup_finds_and_misses() {
    let feed = "\
type,value,malware,context,confidence
sha256,abc123def456,DroidJack,sample,high
string,keepme,DroidJack,marker,high
";
    let s = Scanner::from_csv(feed).unwrap();
    // Hit — case-insensitive.
    let hit = s.hash_lookup("ABC123DEF456");
    assert!(hit.is_some());
    assert_eq!(hit.unwrap().malware, "DroidJack");
    // Miss.
    assert!(s.hash_lookup("000000").is_none());
}
