use crate::queries::Framework;
use crate::models::FrameworkIndex;
use anyhow::Result;

pub struct IndexCommand {
    framework: Framework,
}

impl IndexCommand {
    pub fn new() -> Self {
        IndexCommand {
            framework: Framework::new(),
        }
    }

    pub fn generate(&self) -> Result<()> {
        println!("\n📊 Generating Unified Framework Index");

        let scenarios = self.framework.list_scenarios()?;
        let detections = self.framework.list_detections()?;
        let actors = self.framework.list_threat_actors()?;
        let drills = self.framework.list_drills()?;
        let technique_index = self.framework.build_technique_index()?;
        let coverage_matrix = self.framework.build_coverage_matrix()?;

        let index = FrameworkIndex {
            metadata: crate::models::IndexMetadata {
                generated: chrono::Local::now().to_rfc3339(),
                framework_version: "1.0.0".to_string(),
                total_techniques: technique_index.len(),
                total_actors: actors.len(),
                total_scenarios: scenarios.len(),
                total_detections: detections.len(),
                total_drills: drills.len(),
            },
            technique_index: technique_index.clone(),
            coverage_matrix,
        };

        let paths = crate::FrameworkPaths::get();
        std::fs::create_dir_all(&paths.mitre_dir)?;

        let index_path = &paths.index_file;
        let json = serde_json::to_string_pretty(&index)?;
        std::fs::write(index_path, json)?;

        println!("✅ Index generated: {}", index_path.display());
        println!("   Techniques: {}", technique_index.len());
        println!("   Actors: {}", actors.len());
        println!("   Scenarios: {}", scenarios.len());
        println!("   Detections: {}", detections.len());
        println!("   Drills: {}\n", drills.len());

        Ok(())
    }
}
