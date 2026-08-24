use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackScenario {
    pub id: String,
    pub metadata: Metadata,
    pub stages: Vec<ScenarioStage>,
    #[serde(default)]
    pub cross_kill_chain_analysis: Option<CrossKillChainAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub name: String,
    pub difficulty: String,
    #[serde(default)]
    pub realistic_success_rate: serde_json::Value,
    #[serde(default)]
    pub estimated_duration_hours: Option<f32>,
    #[serde(default)]
    pub estimated_duration_days: Option<f32>,
    #[serde(default)]
    pub scenario_id: Option<String>,
    #[serde(default)]
    pub industry_targets: Vec<String>,
    #[serde(default)]
    pub last_observed_in_wild: Option<String>,
    #[serde(default)]
    pub average_attacker_dwell_time_days: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioStage {
    pub stage_id: String,
    pub tactic: String,
    pub technique: String,
    pub action_description: String,
    pub success_rate_percent: f32,
    #[serde(default)]
    pub detection_points: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossKillChainAnalysis {
    #[serde(default)]
    pub time_to_detection_hours: Option<f32>,
    #[serde(default)]
    pub time_to_detection_days: Option<f32>,
    #[serde(default)]
    pub time_to_response_hours: Option<f32>,
    #[serde(default)]
    pub time_to_response_days: Option<f32>,
    #[serde(default)]
    pub dwell_time_advantage_hours: Option<f32>,
    #[serde(default)]
    pub dwell_time_advantage_days: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub id: String,
    pub tier: String,
    pub technique: String,
    pub tactic: String,
    pub detection_name: String,
    pub data_source: String,
    pub query: String,
    #[serde(default)]
    pub tuning: Option<String>,
    #[serde(default)]
    pub associated_campaigns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub characteristic_ttps: Vec<TTP>,
    #[serde(default)]
    pub target_sectors: Vec<String>,
    pub sophistication: String,
    pub emulation_difficulty: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TTP {
    pub tactic: String,
    pub technique: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentResponseDrill {
    pub drill_id: String,
    pub name: String,
    pub scenario_source: String,
    #[serde(default)]
    pub objectives: Vec<String>,
    #[serde(default)]
    pub success_criteria: HashMap<String, f32>,
    #[serde(default)]
    pub current_performance: HashMap<String, f32>,
    pub score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconTechnique {
    pub id: String,
    pub technique_name: String,
    pub category: String,
    pub footprint_risk: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfAudit {
    pub id: String,
    pub technique_name: String,
    pub detection_id: String,
    #[serde(default)]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub associated_actors: Vec<String>,
    #[serde(default)]
    pub techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkIndex {
    pub metadata: IndexMetadata,
    pub technique_index: HashMap<String, TechniqueEntry>,
    #[serde(default)]
    pub coverage_matrix: Vec<CoverageRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexMetadata {
    pub generated: String,
    pub framework_version: String,
    pub total_techniques: usize,
    pub total_actors: usize,
    pub total_scenarios: usize,
    pub total_detections: usize,
    pub total_drills: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueEntry {
    pub id: String,
    #[serde(default)]
    pub actors: Vec<String>,
    #[serde(default)]
    pub scenarios: Vec<String>,
    #[serde(default)]
    pub campaigns: Vec<String>,
    #[serde(default)]
    pub detections: Vec<String>,
    #[serde(default)]
    pub recon_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageRow {
    pub scenario_id: String,
    pub stage_id: String,
    pub technique: String,
    pub detection_coverage: Vec<String>,
    pub coverage_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreFramework {
    pub tactics: Vec<Tactic>,
    pub techniques: Vec<Technique>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tactic {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub tactic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioReport {
    pub metadata: ReportMetadata,
    pub execution_metrics: ExecutionMetrics,
    pub timing_metrics: TimingMetrics,
    #[serde(default)]
    pub technique_coverage: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub generated: String,
    pub scenario_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionMetrics {
    pub total_stages: usize,
    pub unique_techniques: usize,
    pub techniques_covered_by_detections: usize,
    pub detection_coverage_percent: f32,
    pub detection_gaps: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingMetrics {
    #[serde(default)]
    pub time_to_detection_hours: Option<f32>,
    #[serde(default)]
    pub time_to_response_hours: Option<f32>,
    #[serde(default)]
    pub attacker_dwell_time_advantage_hours: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawAttackScenario {
    pub metadata: serde_json::Value,
    pub attack_chain: HashMap<String, serde_json::Value>,
}

impl RawAttackScenario {
    pub fn to_normalized(&self, scenario_id: String) -> AttackScenario {
        let metadata_obj = &self.metadata;
        let scenario_id_from_meta = metadata_obj
            .get("scenario_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let final_id = if scenario_id_from_meta.is_empty() {
            scenario_id
        } else {
            scenario_id_from_meta
        };

        let name = metadata_obj
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();
        let difficulty = metadata_obj
            .get("difficulty")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();

        let estimated_duration_hours = metadata_obj
            .get("estimated_duration_hours")
            .and_then(|v| v.as_f64())
            .map(|v| v as f32);
        let estimated_duration_days = metadata_obj
            .get("estimated_duration_days")
            .and_then(|v| v.as_f64())
            .map(|v| v as f32);

        let mut stages = Vec::new();
        for (stage_key, stage_value) in &self.attack_chain {
            if let Some(technique) = stage_value.get("technique").and_then(|v| v.as_str()) {
                let tactic = stage_value
                    .get("tactics")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string();

                let description = stage_value
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let success_rate_percent = stage_value
                    .get("implementation")
                    .and_then(|impl_obj| impl_obj.get("success_rate_percent"))
                    .and_then(|v| v.as_f64())
                    .map(|v| v as f32)
                    .unwrap_or(0.0);

                let detection_points = stage_value
                    .get("detection_points")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|item| item.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                stages.push(ScenarioStage {
                    stage_id: stage_key.clone(),
                    tactic,
                    technique: technique.to_string(),
                    action_description: description,
                    success_rate_percent,
                    detection_points,
                });
            }
        }

        AttackScenario {
            id: final_id,
            metadata: Metadata {
                name,
                difficulty,
                realistic_success_rate: metadata_obj
                    .get("realistic_success_rate")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                estimated_duration_hours,
                estimated_duration_days,
                scenario_id: metadata_obj
                    .get("scenario_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                industry_targets: metadata_obj
                    .get("industry_targets")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|item| item.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                last_observed_in_wild: metadata_obj
                    .get("last_observed_in_wild")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                average_attacker_dwell_time_days: metadata_obj
                    .get("average_attacker_dwell_time_days")
                    .and_then(|v| v.as_i64())
                    .map(|v| v as i32),
            },
            stages,
            cross_kill_chain_analysis: None,
        }
    }
}
