use crate::queries::Framework;
use crate::models::*;
use anyhow::Result;
use std::collections::HashMap;

pub struct ScenarioCommand {
    framework: Framework,
}

impl ScenarioCommand {
    pub fn new() -> Self {
        ScenarioCommand {
            framework: Framework::new(),
        }
    }

    pub fn list(&self) -> Result<()> {
        let scenarios = self.framework.list_scenarios()?;

        if scenarios.is_empty() {
            println!("❌ No scenarios found");
            return Ok(());
        }

        println!("\n📋 Available Red Team Scenarios\n");
        for scenario in scenarios {
            println!("  📌 {}", scenario.id);
            println!("     Name: {}", scenario.metadata.name);
            println!("     Difficulty: {}", scenario.metadata.difficulty);

            let duration = if let Some(hours) = scenario.metadata.estimated_duration_hours {
                format!("{} hours", hours)
            } else if let Some(days) = scenario.metadata.estimated_duration_days {
                format!("{} days", days)
            } else {
                "Unknown".to_string()
            };
            println!("     Duration: {}", duration);
            println!(
                "     Success Rate: {}%",
                scenario.metadata.realistic_success_rate
            );

            let stages = &scenario.stages;
            let techniques: Vec<String> = stages.iter().map(|s| s.technique.clone()).collect();
            println!("     Stages: {} | Techniques: {}", stages.len(), techniques.join(", "));

            let covered = techniques
                .iter()
                .filter(|t| {
                    self.framework
                        .detections_for_technique(t)
                        .map(|d| !d.is_empty())
                        .unwrap_or(false)
                })
                .count();

            println!("     Detection Coverage: {}/{}\n", covered, techniques.len());
        }

        Ok(())
    }

    pub fn run(
        &self,
        scenario_id: &str,
        record_traffic: bool,
        capture_logs: bool,
    ) -> Result<()> {
        let scenario = match self.framework.get_scenario(scenario_id)? {
            Some(s) => s,
            None => {
                println!("❌ Scenario not found: {}", scenario_id);
                return Ok(());
            }
        };

        if record_traffic {
            println!(
                "ℹ️  --record-traffic requested (not implemented; capture "
            );
            println!("    externally, e.g. tcpdump/Wireshark)");
        }
        if capture_logs {
            println!("ℹ️  --capture-logs requested (not implemented; collect logs");
            println!("    externally during the run)");
        }

        println!("\n🎯 Running Scenario: {}", scenario.metadata.name);
        println!("   ID: {}", scenario.id);

        let duration = if let Some(hours) = scenario.metadata.estimated_duration_hours {
            format!("{} hours", hours)
        } else if let Some(days) = scenario.metadata.estimated_duration_days {
            format!("{} days", days)
        } else {
            "Unknown".to_string()
        };
        println!("   Duration: {}", duration);
        println!(
            "   Expected Success Rate: {}%\n",
            scenario.metadata.realistic_success_rate
        );

        let stages = &scenario.stages;
        println!("📊 Execution Plan: {} stages\n", stages.len());

        let mut coverage_map: HashMap<String, Vec<String>> = HashMap::new();

        for (i, stage) in stages.iter().enumerate() {
            let technique = &stage.technique;
            let detections = self.framework.detections_for_technique(technique)?;
            let detection_ids: Vec<String> = detections.iter().map(|d| d.id.clone()).collect();
            coverage_map.insert(technique.clone(), detection_ids.clone());

            println!("[{}/{}] {}: {}", i + 1, stages.len(), stage.tactic, technique);
            println!("  Action: {}", stage.action_description);
            println!("  Success Rate: {}%", stage.success_rate_percent);
            println!("  Detection Points: {}", stage.detection_points.len());

            for det in &stage.detection_points {
                println!("    - {}", det);
            }

            if !detection_ids.is_empty() {
                println!("  Detections Available: {}", detection_ids.join(", "));
            } else {
                println!("  ⚠️  No detections found for {}", technique);
            }
            println!();
        }

        self.write_scenario_report(&scenario, &coverage_map)?;
        Ok(())
    }

    fn write_scenario_report(
        &self,
        scenario: &AttackScenario,
        coverage_map: &HashMap<String, Vec<String>>,
    ) -> Result<()> {
        let paths = crate::FrameworkPaths::get();
        std::fs::create_dir_all(&paths.reports_dir)?;

        let total_techniques = coverage_map.len();
        let covered_techniques = coverage_map.values().filter(|v| !v.is_empty()).count();
        let coverage_percent = if total_techniques > 0 {
            (covered_techniques as f32 / total_techniques as f32) * 100.0
        } else {
            0.0
        };

        let analysis = &scenario.cross_kill_chain_analysis;

        let report = ScenarioReport {
            metadata: ReportMetadata {
                generated: chrono::Local::now().to_rfc3339(),
                scenario_id: scenario.id.clone(),
                status: "SIMULATED".to_string(),
            },
            execution_metrics: ExecutionMetrics {
                total_stages: scenario.stages.len(),
                unique_techniques: total_techniques,
                techniques_covered_by_detections: covered_techniques,
                detection_coverage_percent: coverage_percent,
                detection_gaps: total_techniques - covered_techniques,
            },
            timing_metrics: TimingMetrics {
                time_to_detection_hours: analysis
                    .as_ref()
                    .and_then(|a| {
                        a.time_to_detection_hours
                            .or_else(|| a.time_to_detection_days.map(|d| d * 24.0))
                    }),
                time_to_response_hours: analysis
                    .as_ref()
                    .and_then(|a| {
                        a.time_to_response_hours
                            .or_else(|| a.time_to_response_days.map(|d| d * 24.0))
                    }),
                attacker_dwell_time_advantage_hours: analysis
                    .as_ref()
                    .and_then(|a| {
                        a.dwell_time_advantage_hours
                            .or_else(|| a.dwell_time_advantage_days.map(|d| d * 24.0))
                    }),
            },
            technique_coverage: coverage_map.clone(),
        };

        let filename = format!(
            "scenario-report-{}.json",
            chrono::Local::now().format("%Y%m%d-%H%M%S")
        );
        let report_path = paths.reports_dir.join(&filename);
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(&report_path, json)?;

        println!("✅ Report saved: {}", report_path.display());
        Ok(())
    }

    pub fn generate_ir_drill(&self, scenario_id: &str) -> Result<()> {
        let scenario = match self.framework.get_scenario(scenario_id)? {
            Some(s) => s,
            None => {
                println!("❌ Scenario not found: {}", scenario_id);
                return Ok(());
            }
        };

        let drills = self.framework.list_drills()?;
        if drills.is_empty() {
            println!("❌ No drills found");
            return Ok(());
        }

        println!("\n🔴 Generating IR Drill from Scenario: {}\n", scenario_id);

        let objectives: Vec<String> = scenario
            .stages
            .iter()
            .map(|s| format!("Detect and respond to {}: {}", s.tactic, s.technique))
            .collect();

        println!("📋 Drill Objectives:");
        for obj in &objectives {
            println!("  ☐ {}", obj);
        }

        let paths = crate::FrameworkPaths::get();
        std::fs::create_dir_all(&paths.reports_dir)?;

        let drill_id = format!(
            "ir-drill-{}-{}",
            scenario_id.split('-').next().unwrap_or("unknown"),
            chrono::Local::now().format("%Y%m%d")
        );

        let mapped_drills: Vec<String> = drills
            .iter()
            .filter(|d| {
                d.scenario_source
                    .starts_with(scenario_id.split('-').next().unwrap_or(""))
            })
            .map(|d| d.drill_id.clone())
            .collect();

        let drill_plan = serde_json::json!({
            "metadata": {
                "generated": chrono::Local::now().to_rfc3339(),
                "drill_id": drill_id,
                "scenario_source": scenario_id,
                "mapped_drills": mapped_drills.clone(),
            },
            "objectives": objectives,
            "execution_steps": [
                "1. Notify IR team of drill start",
                "2. Activate SIEM/EDR monitoring for scenario",
                "3. Inject scenario stages into test environment",
                "4. Record detection times for each stage",
                "5. Measure IR response time and effectiveness",
                "6. Document any detection gaps",
                "7. Generate post-drill report with improvement recommendations",
            ],
        });

        let filename = format!("{}.json", drill_id);
        let drill_path = paths.reports_dir.join(&filename);
        let json = serde_json::to_string_pretty(&drill_plan)?;
        std::fs::write(&drill_path, json)?;

        println!("\n✅ Drill plan saved: {}", drill_path.display());
        println!("   Mapped to {} existing drills\n", mapped_drills.len());

        Ok(())
    }

    pub fn mitre_report(&self) -> Result<()> {
        let scenarios = self.framework.list_scenarios()?;
        let tactics = self.framework.get_tactics()?;

        if scenarios.is_empty() {
            println!("❌ Scenarios not found");
            return Ok(());
        }

        let mut technique_usage: HashMap<String, Vec<String>> = HashMap::new();
        for scenario in &scenarios {
            for stage in &scenario.stages {
                technique_usage
                    .entry(stage.technique.clone())
                    .or_insert_with(Vec::new)
                    .push(scenario.id.clone());
            }
        }

        println!("\n📊 MITRE ATT&CK Framework Coverage Report\n");

        let mut total_coverage = 0.0;
        for tactic in &tactics {
            let techniques = self.framework.techniques_by_tactic(&tactic.name)?;
            let implemented = techniques
                .iter()
                .filter(|t| technique_usage.contains_key(&t.id))
                .count();
            let total = techniques.len();
            let coverage_pct = if total > 0 {
                (implemented as f32 / total as f32) * 100.0
            } else {
                0.0
            };

            println!("  {}", tactic.name);
            println!(
                "    Implementation: {}/{} ({:.1}%)",
                implemented, total, coverage_pct
            );
            total_coverage += coverage_pct;
        }

        let avg_coverage = if !tactics.is_empty() {
            total_coverage / tactics.len() as f32
        } else {
            0.0
        };

        println!("\n  Overall Coverage: {:.1}%", avg_coverage);
        println!("  Techniques Implemented: {}\n", technique_usage.len());

        Ok(())
    }
}
