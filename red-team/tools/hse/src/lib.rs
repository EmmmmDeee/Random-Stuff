//! Huntsman Search Engine (HSE) — a small searchable index over the red-team
//! detection catalog (`detection-mapping/detections.json`).
//!
//! Defensive tooling: it searches detection *content* (hunt/correlation/blind-spot/
//! baseline queries). It does not execute anything against any system.

pub mod llm;

use serde::Deserialize;

/// One entry in a catalog — either a detection (tier hunt/correlation/blind-spot/
/// baseline) or a self-audit control (tier self-audit). Detection-specific fields
/// default to empty so both content types share one schema.
#[derive(Debug, Clone, Deserialize)]
pub struct Detection {
    pub id: String,
    pub name: String,
    /// hunt | correlation | blind-spot | baseline | self-audit | recon
    pub tier: String,
    #[serde(default)]
    pub techniques: Vec<String>,
    #[serde(default)]
    pub tactics: Vec<String>,
    #[serde(default)]
    pub actors: Vec<String>,
    /// Detection confidence (detections). Empty for self-audit controls.
    #[serde(default)]
    pub fidelity: String,
    /// Priority (self-audit controls, e.g. P1). Empty for detections.
    #[serde(default)]
    pub priority: String,
    #[serde(default)]
    pub data_source: String,
    #[serde(default)]
    pub dialect: String,
    #[serde(default)]
    pub summary: String,
    /// The detection query, or (self-audit) how to run the check.
    #[serde(default)]
    pub query: String,
    /// Tuning notes, or (self-audit) the fix.
    #[serde(default)]
    pub tuning: String,
}

#[derive(Debug, Deserialize)]
struct Catalog {
    // detections.json uses "detections"; self-audit.json uses "entries".
    #[serde(alias = "entries")]
    detections: Vec<Detection>,
}

/// Parse one catalog file into a list of entries.
pub fn parse_catalog(json: &str) -> Result<Vec<Detection>, serde_json::Error> {
    Ok(serde_json::from_str::<Catalog>(json)?.detections)
}

/// Parse and concatenate several catalog files into one searchable set.
pub fn parse_catalogs(jsons: &[&str]) -> Result<Vec<Detection>, serde_json::Error> {
    let mut all = Vec::new();
    for j in jsons {
        all.extend(parse_catalog(j)?);
    }
    Ok(all)
}

/// Parse attack-surface.json (recon techniques) into Detection entries with tier='recon'.
pub fn parse_attack_surface(json: &str) -> Result<Vec<Detection>, serde_json::Error> {
    #[derive(Debug, Deserialize)]
    struct ReconSurface {
        recon_techniques: Vec<ReconTechnique>,
    }
    #[derive(Debug, Deserialize)]
    struct ReconTechnique {
        id: String,
        name: String,
        mitre_id: String,
        #[serde(default)]
        activity: String,
        #[serde(default)]
        what_it_reveals: String,
        #[serde(default)]
        open_sources: Vec<String>,
        #[serde(default)]
        defensive_counter: String,
        #[serde(default)]
        detection_signal: String,
    }

    let surface: ReconSurface = serde_json::from_str(json)?;
    let detections = surface.recon_techniques.into_iter().map(|rt| {
        Detection {
            id: rt.id,
            name: rt.name,
            tier: "recon".to_string(),
            techniques: vec![rt.mitre_id],
            tactics: vec!["Reconnaissance".to_string()],
            actors: vec![],
            fidelity: String::new(),
            priority: String::new(),
            data_source: rt.open_sources.join("; "),
            dialect: rt.activity,
            summary: rt.what_it_reveals,
            query: rt.detection_signal,
            tuning: rt.defensive_counter,
        }
    }).collect();
    Ok(detections)
}

impl Detection {
    /// Display label: detection fidelity, or the self-audit priority.
    pub fn label(&self) -> &str {
        if !self.fidelity.is_empty() {
            &self.fidelity
        } else {
            &self.priority
        }
    }

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
            &self.priority,
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
        let b01 = cat.iter().find(|d| d.id == "B-01").unwrap();
        assert!(b01.techniques.is_empty());
        assert!(b01.actors.is_empty());
    }

    #[test]
    fn technique_matches_parent_and_child() {
        let cat = parse_catalog(SAMPLE).unwrap();
        let h06 = &cat[0];
        assert!(h06.covers_technique("T1566.001"));
        assert!(h06.covers_technique("T1566"));
        assert!(!h06.covers_technique("T1059"));
    }

    #[test]
    fn search_ranks_by_term_matches() {
        let cat = parse_catalog(SAMPLE).unwrap();
        let hits = search(&cat, "powershell edr");
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
