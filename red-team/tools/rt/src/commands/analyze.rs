use crate::{Framework, LocalLLMConfig};
use anyhow::Result;

pub struct AnalyzeCommand {
    framework: Framework,
}

impl AnalyzeCommand {
    pub fn new() -> Result<Self> {
        let framework = Framework::new();
        Ok(AnalyzeCommand { framework })
    }

    pub async fn analyze_scenario_with_intelligence(&self, scenario_id: &str) -> Result<()> {
        println!("\n=== Scenario Intelligence Analysis ===\n");

        match self.framework.get_scenario(scenario_id)? {
            Some(scenario) => {
                println!("Scenario: {} ({})", scenario.id, scenario.metadata.name);

                let framework_with_llm = Framework::new()
                    .with_llm(LocalLLMConfig::ollama_lightweight())?;

                println!("Running LLM analysis...");
                if let Some(analysis) = framework_with_llm.analyze_scenario_with_llm(&scenario).await? {
                    println!("Analysis Summary: {}\n", analysis);
                }

                if let Some(threat) = framework_with_llm.assess_scenario_threat_with_llm(&scenario).await? {
                    println!("Threat Assessment: {}\n", threat);
                }

                println!("Scenario stages:");
                for stage in &scenario.stages {
                    println!("  [{}] {}: {}", stage.stage_id, stage.technique, stage.action_description);
                }
            }
            None => {
                println!("Scenario {} not found", scenario_id);
            }
        }

        println!("\n======================================\n");
        Ok(())
    }

    pub async fn correlate_scenario_and_actor(&self, scenario_id: &str, actor_id: &str) -> Result<()> {
        println!("\n=== Scenario-Actor Correlation Analysis ===\n");

        let scenario = self.framework.get_scenario(scenario_id)?;
        let actor = self.framework.get_actor(actor_id)?;

        if scenario.is_none() {
            println!("Scenario {} not found", scenario_id);
            return Ok(());
        }

        if actor.is_none() {
            println!("Actor {} not found", actor_id);
            return Ok(());
        }

        let scenario = scenario.unwrap();
        let actor = actor.unwrap();

        println!("Scenario: {} ({})", scenario.id, scenario.metadata.name);
        println!("Actor: {}", actor.id);
        println!();

        let framework_with_llm = Framework::new()
            .with_llm(LocalLLMConfig::ollama_lightweight())?;

        println!("Running LLM correlation analysis...");
        if let Some(correlation) = framework_with_llm.correlate_scenario_actor_with_llm(&scenario, &actor).await? {
            println!("Correlation: {}\n", correlation);
        }

        println!("Scenario techniques:");
        for stage in &scenario.stages {
            println!("  - {}: {}", stage.technique, stage.action_description);
        }

        println!("\nActor TTPs:");
        for ttp in &actor.characteristic_ttps {
            println!("  - {}: {}", ttp.technique, ttp.name);
        }

        println!("\n===========================================\n");
        Ok(())
    }

    pub async fn threat_intelligence_report(&self, scenario_id: &str) -> Result<()> {
        println!("\n=== Threat Intelligence Report ===\n");

        match self.framework.get_scenario(scenario_id)? {
            Some(scenario) => {
                println!("Report for: {} ({})\n", scenario.id, scenario.metadata.name);

                let framework_with_llm = Framework::new()
                    .with_llm(LocalLLMConfig::ollama_detailed())?;

                println!("Threat Assessment:");
                if let Some(threat) = framework_with_llm.assess_scenario_threat_with_llm(&scenario).await? {
                    println!("  {}\n", threat);
                }

                println!("Scenario Execution Flow:");
                for stage in &scenario.stages {
                    println!("  Stage {}: {} ({})", stage.stage_id, stage.technique, stage.action_description);
                }

                let detections = self.framework.detections_for_technique(&scenario.stages.get(0).map(|s| s.technique.as_str()).unwrap_or(""))?;
                if !detections.is_empty() {
                    println!("\nDetection Capabilities:");
                    for detection in detections.iter().take(3) {
                        println!("  - {} (Data Source: {})", detection.id, detection.data_source);
                    }
                }
            }
            None => {
                println!("Scenario {} not found", scenario_id);
            }
        }

        println!("\n==================================\n");
        Ok(())
    }

    pub async fn bulk_scenario_analysis(&self) -> Result<()> {
        println!("\n=== Bulk Scenario Intelligence Analysis ===\n");

        let scenarios = self.framework.list_scenarios()?;
        let framework_with_llm = Framework::new()
            .with_llm(LocalLLMConfig::ollama_lightweight())?;

        println!("Analyzing {} scenarios...\n", scenarios.len());

        for scenario in scenarios.iter().take(5) {
            println!("Scenario: {}", scenario.metadata.name);
            if let Some(analysis) = framework_with_llm.analyze_scenario_with_llm(scenario).await? {
                println!("  Summary: {}", analysis.chars().take(100).collect::<String>());
            }
            println!();
        }

        if scenarios.len() > 5 {
            println!("... and {} more scenarios", scenarios.len() - 5);
        }

        println!("\n=========================================\n");
        Ok(())
    }
}
