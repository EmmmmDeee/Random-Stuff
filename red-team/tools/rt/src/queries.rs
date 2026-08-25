use crate::loaders::EntityLoader;
use crate::models::*;
use crate::llm::{LocalLLMConfig, AnalysisEngine, LLMResult};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

pub struct Framework {
    loader: EntityLoader,
    llm_engine: Option<Arc<AnalysisEngine>>,
}

impl Framework {
    pub fn new() -> Self {
        Framework {
            loader: EntityLoader::new(),
            llm_engine: None,
        }
    }

    pub fn with_llm(mut self, config: LocalLLMConfig) -> Result<Self> {
        let engine = AnalysisEngine::from_config(&config)?;
        self.llm_engine = Some(Arc::new(engine));
        Ok(self)
    }

    pub fn get_llm_engine(&self) -> Option<Arc<AnalysisEngine>> {
        self.llm_engine.clone()
    }

    pub async fn analyze_scenario_with_llm(&self, scenario: &AttackScenario) -> Result<Option<String>> {
        if let Some(engine) = &self.llm_engine {
            let scenario_json = serde_json::to_string(scenario)?;
            let analysis = engine.analyze_entity(&scenario_json).await;
            match analysis {
                Ok(result) => Ok(Some(result.entity_summary)),
                Err(_) => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    pub async fn analyze_actor_with_llm(&self, actor: &ThreatActor) -> Result<Option<String>> {
        if let Some(engine) = &self.llm_engine {
            let actor_json = serde_json::to_string(actor)?;
            let analysis = engine.analyze_entity(&actor_json).await;
            match analysis {
                Ok(result) => Ok(Some(result.entity_summary)),
                Err(_) => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    pub async fn assess_scenario_threat_with_llm(&self, scenario: &AttackScenario) -> Result<Option<String>> {
        if let Some(engine) = &self.llm_engine {
            let scenario_json = serde_json::to_string(scenario)?;
            let assessment = engine.assess_threat(&scenario_json).await;
            match assessment {
                Ok(result) => Ok(Some(format!("Threat Level: {}", result.threat_level))),
                Err(_) => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    pub async fn correlate_scenario_actor_with_llm(&self, scenario: &AttackScenario, actor: &ThreatActor) -> Result<Option<String>> {
        if let Some(engine) = &self.llm_engine {
            let scenario_json = serde_json::to_string(scenario)?;
            let actor_json = serde_json::to_string(actor)?;
            let correlation = engine.correlate_entities(&scenario_json, &actor_json).await;
            match correlation {
                Ok(result) => Ok(Some(format!("Relationship: {} (strength: {:.2})", result.relationship_type, result.relationship_strength))),
                Err(_) => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    pub fn detections_for_technique(&self, technique: &str) -> Result<Vec<Detection>> {
        let detections = self.loader.load_detections()?;
        Ok(detections
            .into_iter()
            .filter(|d| d.technique == technique)
            .collect())
    }

    pub fn scenarios_for_technique(&self, technique: &str) -> Result<Vec<AttackScenario>> {
        let scenarios = self.loader.load_scenarios()?;
        let mut result = Vec::new();
        for scenario in scenarios.values() {
            for stage in &scenario.stages {
                if stage.technique == technique {
                    result.push(scenario.clone());
                    break;
                }
            }
        }
        Ok(result)
    }

    pub fn campaigns_for_technique(&self, technique: &str) -> Result<Vec<Campaign>> {
        let campaigns = self.loader.load_campaigns()?;
        Ok(campaigns
            .into_iter()
            .filter(|c| c.techniques.contains(&technique.to_string()))
            .collect())
    }

    pub fn actors_for_sector(&self, sector: &str) -> Result<Vec<ThreatActor>> {
        let actors = self.loader.load_threat_actors()?;
        Ok(actors
            .into_iter()
            .filter(|a| a.target_sectors.iter().any(|s| s == sector))
            .collect())
    }

    pub fn techniques_by_tactic(&self, tactic: &str) -> Result<Vec<Technique>> {
        let framework = self.loader.load_mitre_framework()?;
        Ok(framework
            .techniques
            .into_iter()
            .filter(|t| t.tactic == tactic)
            .collect())
    }

    pub fn technique_by_id(&self, technique_id: &str) -> Result<Option<Technique>> {
        let framework = self.loader.load_mitre_framework()?;
        Ok(framework
            .techniques
            .into_iter()
            .find(|t| t.id == technique_id))
    }

    pub fn get_scenario(&self, scenario_id: &str) -> Result<Option<AttackScenario>> {
        let scenarios = self.loader.load_scenarios()?;
        Ok(scenarios.get(scenario_id).cloned())
    }

    pub fn list_scenarios(&self) -> Result<Vec<AttackScenario>> {
        let scenarios = self.loader.load_scenarios()?;
        let mut result: Vec<_> = scenarios.values().cloned().collect();
        result.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(result)
    }

    pub fn list_threat_actors(&self) -> Result<Vec<ThreatActor>> {
        self.loader.load_threat_actors()
    }

    pub fn list_detections(&self) -> Result<Vec<Detection>> {
        self.loader.load_detections()
    }

    pub fn list_drills(&self) -> Result<Vec<IncidentResponseDrill>> {
        self.loader.load_drills()
    }

    pub fn list_campaigns(&self) -> Result<Vec<Campaign>> {
        self.loader.load_campaigns()
    }

    pub fn list_recon_techniques(&self) -> Result<Vec<ReconTechnique>> {
        self.loader.load_recon_techniques()
    }

    pub fn get_actor(&self, actor_id: &str) -> Result<Option<ThreatActor>> {
        let actors = self.loader.load_threat_actors()?;
        Ok(actors.into_iter().find(|a| a.id == actor_id))
    }

    pub fn build_technique_index(&self) -> Result<HashMap<String, TechniqueEntry>> {
        let mut index: HashMap<String, TechniqueEntry> = HashMap::new();

        let scenarios = self.loader.load_scenarios()?;
        let detections = self.loader.load_detections()?;
        let campaigns = self.loader.load_campaigns()?;
        let actors = self.loader.load_threat_actors()?;
        let recon = self.loader.load_recon_techniques()?;

        for scenario in scenarios.values() {
            for stage in &scenario.stages {
                let technique_id = &stage.technique;
                let entry = index
                    .entry(technique_id.clone())
                    .or_insert_with(|| TechniqueEntry {
                        id: technique_id.clone(),
                        actors: Vec::new(),
                        scenarios: Vec::new(),
                        campaigns: Vec::new(),
                        detections: Vec::new(),
                        recon_techniques: Vec::new(),
                    });

                if !entry.scenarios.contains(&scenario.id) {
                    entry.scenarios.push(scenario.id.clone());
                }
            }
        }

        for detection in detections {
            let technique_id = &detection.technique;
            let entry = index
                .entry(technique_id.clone())
                .or_insert_with(|| TechniqueEntry {
                    id: technique_id.clone(),
                    actors: Vec::new(),
                    scenarios: Vec::new(),
                    campaigns: Vec::new(),
                    detections: Vec::new(),
                    recon_techniques: Vec::new(),
                });

            if !entry.detections.contains(&detection.id) {
                entry.detections.push(detection.id);
            }
        }

        for campaign in campaigns {
            for technique in &campaign.techniques {
                let entry = index
                    .entry(technique.clone())
                    .or_insert_with(|| TechniqueEntry {
                        id: technique.clone(),
                        actors: Vec::new(),
                        scenarios: Vec::new(),
                        campaigns: Vec::new(),
                        detections: Vec::new(),
                        recon_techniques: Vec::new(),
                    });

                if !entry.campaigns.contains(&campaign.id) {
                    entry.campaigns.push(campaign.id.clone());
                }
            }
        }

        for actor in actors {
            for ttp in &actor.characteristic_ttps {
                let technique_id = &ttp.technique;
                let entry = index
                    .entry(technique_id.clone())
                    .or_insert_with(|| TechniqueEntry {
                        id: technique_id.clone(),
                        actors: Vec::new(),
                        scenarios: Vec::new(),
                        campaigns: Vec::new(),
                        detections: Vec::new(),
                        recon_techniques: Vec::new(),
                    });

                if !entry.actors.contains(&actor.id) {
                    entry.actors.push(actor.id.clone());
                }
            }
        }

        for technique in recon {
            // Map recon techniques to related detection techniques if needed
            if let Ok(Some(_)) = self.technique_by_id(&technique.id) {
                let entry = index
                    .entry(technique.id.clone())
                    .or_insert_with(|| TechniqueEntry {
                        id: technique.id.clone(),
                        actors: Vec::new(),
                        scenarios: Vec::new(),
                        campaigns: Vec::new(),
                        detections: Vec::new(),
                        recon_techniques: Vec::new(),
                    });

                if !entry.recon_techniques.contains(&technique.id) {
                    entry.recon_techniques.push(technique.id);
                }
            }
        }

        Ok(index)
    }

    pub fn build_coverage_matrix(&self) -> Result<Vec<CoverageRow>> {
        let mut matrix = Vec::new();
        let scenarios = self.loader.load_scenarios()?;

        for scenario in scenarios.values() {
            for stage in &scenario.stages {
                let detections = self.detections_for_technique(&stage.technique)?;
                let detection_ids: Vec<String> = detections.iter().map(|d| d.id.clone()).collect();
                let coverage_percent = if !detection_ids.is_empty() {
                    100.0
                } else {
                    0.0
                };

                matrix.push(CoverageRow {
                    scenario_id: scenario.id.clone(),
                    stage_id: stage.stage_id.clone(),
                    technique: stage.technique.clone(),
                    detection_coverage: detection_ids,
                    coverage_percent,
                });
            }
        }

        Ok(matrix)
    }

    pub fn get_tactics(&self) -> Result<Vec<Tactic>> {
        let framework = self.loader.load_mitre_framework()?;
        Ok(framework.tactics)
    }

    pub fn get_framework_index(&self) -> Result<FrameworkIndex> {
        self.loader.load_framework_index()
    }

    pub fn clear_cache(&self) {
        self.loader.clear_cache();
    }
}

impl Clone for Framework {
    fn clone(&self) -> Self {
        Framework {
            loader: self.loader.clone(),
            llm_engine: self.llm_engine.clone(),
        }
    }
}
