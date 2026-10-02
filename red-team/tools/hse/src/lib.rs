//! Huntsman Search Engine (HSE) — a small searchable index over the red-team
//! detection catalog (`detection-mapping/detections.json`).
//!
//! Defensive tooling: it searches detection *content* (hunt/correlation/blind-spot/
//! baseline queries). It does not execute anything against any system.

use serde::Deserialize;

/// One detection in the catalog.
#[derive(Debug, Clone, Deserialize)]
pub struct Detection {
    pub id: String,
    pub name: String,
    /// One of: hunt | correlation | blind-spot | baseline
    pub tier: String,
    #[serde(default)]
    pub techniques: Vec<String>,
    #[serde(default)]
    pub tactics: Vec<String>,
    #[serde(default)]
    pub actors: Vec<String>,
    pub fidelity: String,
    pub data_source: String,
    pub dialect: String,
    pub summary: String,
    pub query: String,
    pub tuning: String,
}

#[derive(Debug, Deserialize)]
struct Catalog {
    detections: Vec<Detection>,
}

/// Parse the catalog JSON into a list of detections.
pub fn parse_catalog(json: &str) -> Result<Vec<Detection>, serde_json::Error> {
    Ok(serde_json::from_str::<Catalog>(json)?.detections)
}

impl Detection {
    /// Lowercased concatenation of every searchable field.
    pub fn haystack(&self) -> String {
        [
            self.id.as_str(),
            &self.name,
            &self.tier,
            &self.techniques.join(" "),
            &self.tactics.join(" "),
            &self.actors.join(" "),
            &self.fidelity,
            &self.data_source,
            &self.summary,
            &self.query,
            &self.tuning,
        ]
        .join(" ")
        .to_lowercase()
    }

    /// True if this detection covers `tid` (exact, or parent/child sub-technique).
    pub fn covers_technique(&self, tid: &str) -> bool {
        let want = tid.to_uppercase();
        self.techniques.iter().any(|t| {
            let t = t.to_uppercase();
            t == want
                || t.starts_with(&format!("{want}."))
                || want.starts_with(&format!("{t}."))
        })
    }

    pub fn has_actor(&self, actor: &str) -> bool {
        let a = actor.to_lowercase();
        self.actors.iter().any(|x| x.to_lowercase().contains(&a))
    }

    pub fn has_tactic(&self, tactic: &str) -> bool {
        let t = tactic.to_lowercase();
        self.tactics.iter().any(|x| x.to_lowercase().contains(&t))
    }
}

/// Rank detections by how many query terms appear in their searchable text.
/// Returns `(score, detection)` pairs, highest score first, ties broken by id.
pub fn search<'a>(catalog: &'a [Detection], query: &str) -> Vec<(usize, &'a Detection)> {
    let terms: Vec<String> = query.split_whitespace().map(|t| t.to_lowercase()).collect();
    let mut scored: Vec<(usize, &Detection)> = catalog
        .iter()
        .filter_map(|d| {
            let hay = d.haystack();
            let score = terms.iter().filter(|t| hay.contains(t.as_str())).count();
            (score > 0).then_some((score, d))
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.id.cmp(&b.1.id)));
    scored
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "detections": [
            {"id":"H-06","name":"Office app spawns a shell","tier":"hunt",
             "techniques":["T1566.001","T1204.002"],"tactics":["Execution"],
             "actors":["FIN7"],"fidelity":"very-high","data_source":"DeviceProcessEvents",
             "dialect":"KQL","summary":"macro spawns powershell","query":"DeviceProcessEvents ...","tuning":"low FP"},
            {"id":"B-01","name":"Endpoints went dark","tier":"blind-spot",
             "fidelity":"high","data_source":"DeviceInfo","dialect":"KQL",
             "summary":"EDR telemetry stopped","query":"DeviceInfo ...","tuning":"exclude decom"}
        ]
    }"#;

    #[test]
    fn parses_and_defaults_empty_vecs() {
        let cat = parse_catalog(SAMPLE).unwrap();
        assert_eq!(cat.len(), 2);
        // B-01 omits techniques/tactics/actors — must default to empty, not error.
        let b01 = cat.iter().find(|d| d.id == "B-01").unwrap();
        assert!(b01.techniques.is_empty());
        assert!(b01.actors.is_empty());
    }

    #[test]
    fn technique_matches_parent_and_child() {
        let cat = parse_catalog(SAMPLE).unwrap();
        let h06 = &cat[0];
        assert!(h06.covers_technique("T1566.001")); // exact
        assert!(h06.covers_technique("T1566")); // parent -> child
        assert!(!h06.covers_technique("T1059"));
    }

    #[test]
    fn search_ranks_by_term_matches() {
        let cat = parse_catalog(SAMPLE).unwrap();
        let hits = search(&cat, "powershell edr");
        // H-06 matches "powershell"; B-01 matches "edr". Both score 1 here,
        // but a query hitting both terms on one doc should rank it first.
        assert!(!hits.is_empty());
        let hits2 = search(&cat, "office powershell fin7");
        assert_eq!(hits2[0].1.id, "H-06");
        assert!(hits2[0].0 >= 2);
    }

    #[test]
    fn actor_filter_is_case_insensitive() {
        let cat = parse_catalog(SAMPLE).unwrap();
        assert!(cat[0].has_actor("fin7"));
        assert!(!cat[1].has_actor("fin7"));
    }
}
