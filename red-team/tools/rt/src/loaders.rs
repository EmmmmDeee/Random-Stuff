use crate::models::*;
use crate::paths::FrameworkPaths;
use anyhow::{Context, Result};
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

pub struct EntityCache {
    scenarios: Mutex<Option<HashMap<String, AttackScenario>>>,
    detections: Mutex<Option<Vec<Detection>>>,
    threat_actors: Mutex<Option<Vec<ThreatActor>>>,
    drills: Mutex<Option<Vec<IncidentResponseDrill>>>,
    recon_techniques: Mutex<Option<Vec<ReconTechnique>>>,
    self_audits: Mutex<Option<Vec<SelfAudit>>>,
    campaigns: Mutex<Option<Vec<Campaign>>>,
    mitre_framework: Mutex<Option<MitreFramework>>,
    framework_index: Mutex<Option<FrameworkIndex>>,
}

impl EntityCache {
    pub fn new() -> Self {
        EntityCache {
            scenarios: Mutex::new(None),
            detections: Mutex::new(None),
            threat_actors: Mutex::new(None),
            drills: Mutex::new(None),
            recon_techniques: Mutex::new(None),
            self_audits: Mutex::new(None),
            campaigns: Mutex::new(None),
            mitre_framework: Mutex::new(None),
            framework_index: Mutex::new(None),
        }
    }

    pub fn clear(&self) {
        *self.scenarios.lock().unwrap() = None;
        *self.detections.lock().unwrap() = None;
        *self.threat_actors.lock().unwrap() = None;
        *self.drills.lock().unwrap() = None;
        *self.recon_techniques.lock().unwrap() = None;
        *self.self_audits.lock().unwrap() = None;
        *self.campaigns.lock().unwrap() = None;
        *self.mitre_framework.lock().unwrap() = None;
        *self.framework_index.lock().unwrap() = None;
    }
}

pub struct EntityLoader {
    cache: Arc<EntityCache>,
}

impl EntityLoader {
    pub fn new() -> Self {
        EntityLoader {
            cache: Arc::new(EntityCache::new()),
        }
    }

    pub fn load_scenarios(&self) -> Result<HashMap<String, AttackScenario>> {
        let mut cache = self.cache.scenarios.lock().unwrap();
        if let Some(scenarios) = &*cache {
            return Ok(scenarios.clone());
        }

        let paths = FrameworkPaths::get();
        let scenarios_dir = &paths.scenarios_dir;

        let mut scenarios = HashMap::new();
        if scenarios_dir.exists() {
            for entry in fs::read_dir(scenarios_dir).context("Failed to read scenarios directory")? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().map_or(false, |ext| ext == "json") {
                    let filename = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let scenario_id = filename.replace(".json", "");

                    let content = fs::read_to_string(&path)
                        .context(format!("Failed to read scenario file: {:?}", path))?;

                    let raw_scenario: RawAttackScenario = serde_json::from_str(&content)
                        .context(format!("Failed to parse scenario JSON: {:?}", path))?;

                    let normalized = raw_scenario.to_normalized(scenario_id.clone());
                    scenarios.insert(normalized.id.clone(), normalized);
                }
            }
        }

        *cache = Some(scenarios.clone());
        Ok(scenarios)
    }

    pub fn load_detections(&self) -> Result<Vec<Detection>> {
        let mut cache = self.cache.detections.lock().unwrap();
        if let Some(detections) = &*cache {
            return Ok(detections.clone());
        }

        let paths = FrameworkPaths::get();
        let detections_path = &paths.detections_file;

        let mut detections = Vec::new();
        if detections_path.exists() {
            let content = fs::read_to_string(detections_path)
                .context("Failed to read detections file")?;
            let data: serde_json::Value = serde_json::from_str(&content)
                .context("Failed to parse detections JSON")?;

            if let Some(arr) = data.as_array() {
                for item in arr {
                    if let Ok(detection) = serde_json::from_value(item.clone()) {
                        detections.push(detection);
                    }
                }
            }
        }

        *cache = Some(detections.clone());
        Ok(detections)
    }

    pub fn load_threat_actors(&self) -> Result<Vec<ThreatActor>> {
        let mut cache = self.cache.threat_actors.lock().unwrap();
        if let Some(actors) = &*cache {
            return Ok(actors.clone());
        }

        let paths = FrameworkPaths::get();
        let threat_actors_path = &paths.threat_actors_file;

        let mut actors = Vec::new();
        if threat_actors_path.exists() {
            let content = fs::read_to_string(threat_actors_path)
                .context("Failed to read threat actors file")?;
            let data: serde_json::Value = serde_json::from_str(&content)
                .context("Failed to parse threat actors JSON")?;

            if let Some(arr) = data.as_array() {
                for item in arr {
                    if let Ok(actor) = serde_json::from_value(item.clone()) {
                        actors.push(actor);
                    }
                }
            }
        }

        *cache = Some(actors.clone());
        Ok(actors)
    }

    pub fn load_drills(&self) -> Result<Vec<IncidentResponseDrill>> {
        let mut cache = self.cache.drills.lock().unwrap();
        if let Some(drills) = &*cache {
            return Ok(drills.clone());
        }

        let paths = FrameworkPaths::get();
        let drills_dir = &paths.drills_dir;

        let mut drills = Vec::new();
        if drills_dir.exists() {
            for entry in fs::read_dir(drills_dir).context("Failed to read drills directory")? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().map_or(false, |ext| ext == "json") {
                    let content = fs::read_to_string(&path)
                        .context(format!("Failed to read drill file: {:?}", path))?;
                    if let Ok(drill) = serde_json::from_str::<IncidentResponseDrill>(&content) {
                        drills.push(drill);
                    }
                }
            }
        }

        *cache = Some(drills.clone());
        Ok(drills)
    }

    pub fn load_recon_techniques(&self) -> Result<Vec<ReconTechnique>> {
        let mut cache = self.cache.recon_techniques.lock().unwrap();
        if let Some(techniques) = &*cache {
            return Ok(techniques.clone());
        }

        let paths = FrameworkPaths::get();
        let attack_surface_path = &paths.attack_surface_file;

        let mut techniques = Vec::new();
        if attack_surface_path.exists() {
            let content = fs::read_to_string(attack_surface_path)
                .context("Failed to read attack surface file")?;
            let data: serde_json::Value = serde_json::from_str(&content)
                .context("Failed to parse attack surface JSON")?;

            if let Some(arr) = data.as_array() {
                for item in arr {
                    if let Ok(technique) = serde_json::from_value(item.clone()) {
                        techniques.push(technique);
                    }
                }
            }
        }

        *cache = Some(techniques.clone());
        Ok(techniques)
    }

    pub fn load_self_audits(&self) -> Result<Vec<SelfAudit>> {
        let mut cache = self.cache.self_audits.lock().unwrap();
        if let Some(audits) = &*cache {
            return Ok(audits.clone());
        }

        let paths = FrameworkPaths::get();
        let detection_dir = &paths.detection_dir;

        let mut audits = Vec::new();
        let self_audit_file = detection_dir.join("self-audit.json");
        if self_audit_file.exists() {
            let content = fs::read_to_string(&self_audit_file)
                .context("Failed to read self-audit file")?;
            let data: serde_json::Value = serde_json::from_str(&content)
                .context("Failed to parse self-audit JSON")?;

            if let Some(arr) = data.as_array() {
                for item in arr {
                    if let Ok(audit) = serde_json::from_value(item.clone()) {
                        audits.push(audit);
                    }
                }
            }
        }

        *cache = Some(audits.clone());
        Ok(audits)
    }

    pub fn load_campaigns(&self) -> Result<Vec<Campaign>> {
        let mut cache = self.cache.campaigns.lock().unwrap();
        if let Some(campaigns) = &*cache {
            return Ok(campaigns.clone());
        }

        let paths = FrameworkPaths::get();
        let campaigns_dir = &paths.campaigns_dir;

        let mut campaigns = Vec::new();
        if campaigns_dir.exists() {
            for entry in fs::read_dir(campaigns_dir).context("Failed to read campaigns directory")? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().map_or(false, |ext| ext == "json") {
                    let content = fs::read_to_string(&path)
                        .context(format!("Failed to read campaign file: {:?}", path))?;
                    if let Ok(campaign) = serde_json::from_str::<Campaign>(&content) {
                        campaigns.push(campaign);
                    }
                }
            }
        }

        *cache = Some(campaigns.clone());
        Ok(campaigns)
    }

    pub fn load_mitre_framework(&self) -> Result<MitreFramework> {
        let mut cache = self.cache.mitre_framework.lock().unwrap();
        if let Some(framework) = &*cache {
            return Ok(framework.clone());
        }

        let paths = FrameworkPaths::get();
        let framework_path = &paths.framework_file;

        let mut framework = MitreFramework {
            tactics: Vec::new(),
            techniques: Vec::new(),
        };

        if framework_path.exists() {
            let content = fs::read_to_string(framework_path)
                .context("Failed to read MITRE framework file")?;
            framework = serde_json::from_str(&content)
                .context("Failed to parse MITRE framework JSON")?;
        }

        *cache = Some(framework.clone());
        Ok(framework)
    }

    pub fn load_framework_index(&self) -> Result<FrameworkIndex> {
        let mut cache = self.cache.framework_index.lock().unwrap();
        if let Some(index) = &*cache {
            return Ok(index.clone());
        }

        let paths = FrameworkPaths::get();
        let index_path = &paths.index_file;

        let index = if index_path.exists() {
            let content = fs::read_to_string(index_path)
                .context("Failed to read framework index file")?;
            serde_json::from_str(&content)
                .context("Failed to parse framework index JSON")?
        } else {
            FrameworkIndex {
                metadata: IndexMetadata {
                    generated: chrono::Local::now().to_rfc3339(),
                    framework_version: "1.0.0".to_string(),
                    total_techniques: 0,
                    total_actors: 0,
                    total_scenarios: 0,
                    total_detections: 0,
                    total_drills: 0,
                },
                technique_index: HashMap::new(),
                coverage_matrix: Vec::new(),
            }
        };

        *cache = Some(index.clone());
        Ok(index)
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

impl Clone for EntityLoader {
    fn clone(&self) -> Self {
        EntityLoader {
            cache: Arc::clone(&self.cache),
        }
    }
}
