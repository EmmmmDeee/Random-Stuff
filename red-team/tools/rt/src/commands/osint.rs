use crate::{Framework, osint::{OsintAggregator, OsintCache}};
use anyhow::Result;

pub struct OsintCommand {
    framework: Framework,
    aggregator: OsintAggregator,
    cache: OsintCache,
}

impl OsintCommand {
    pub fn new() -> Result<Self> {
        let framework = Framework::new();
        let aggregator = OsintAggregator::with_mock();
        let cache = OsintCache::new(3600);

        Ok(OsintCommand {
            framework,
            aggregator,
            cache,
        })
    }

    pub async fn analyze_entity(&self, entity: &str) -> Result<()> {
        println!("\n=== OSINT Entity Analysis ===\n");

        if let Some(cached) = self.cache.get_email(entity).await {
            println!("📦 Result from cache\n");
            self.print_osint_result(&cached);
            return Ok(());
        }

        match self.aggregator.analyze_email(entity).await? {
            Some(result) => {
                self.cache.set_email(entity.to_string(), result.clone()).await;
                self.print_osint_result(&result);
            }
            None => {
                println!("No data found for: {}", entity);
            }
        }

        println!("\n=============================\n");
        Ok(())
    }

    pub async fn correlate_with_scenario(&self, entity: &str, scenario_id: &str) -> Result<()> {
        println!("\n=== Entity-Scenario Correlation ===\n");

        match self.aggregator.analyze_email(entity).await? {
            Some(osint_result) => {
                if let Ok(Some(scenario)) = self.framework.get_scenario(scenario_id) {
                    println!("Entity: {}", entity);
                    println!("Scenario: {} ({})\n", scenario.id, scenario.metadata.name);

                    let breach_score = osint_result.breaches.len() as f64 / 6.0;
                    let threat_score = osint_result.threats.len() as f64 / 6.0;
                    let correlation_strength = (breach_score + threat_score) / 2.0;

                    println!("Correlation Strength: {:.2}", correlation_strength);
                    println!("Risk Level: {}\n", osint_result.risk_level);

                    println!("Matching Indicators:");
                    if !osint_result.breaches.is_empty() {
                        println!("  ✓ Credential Exposure (Credential Theft stage match)");
                    }
                    if !osint_result.threats.is_empty() {
                        println!("  ✓ Threat Indicators (Attack pattern match)");
                    }

                    println!("\nRecommendations:");
                    for (i, rec) in osint_result.recommendations.iter().enumerate() {
                        println!("  {}. {}", i + 1, rec);
                    }
                } else {
                    println!("Scenario {} not found", scenario_id);
                }
            }
            None => {
                println!("No OSINT data for: {}", entity);
            }
        }

        println!("\n=====================================\n");
        Ok(())
    }

    pub async fn bulk_analyze(&self, entities: Vec<String>) -> Result<()> {
        println!("\n=== Bulk OSINT Analysis ===\n");

        let results = self.aggregator.batch_analyze(entities.clone()).await?;

        println!("Analyzing {} entities...\n", entities.len());

        for result in &results {
            println!("Entity: {}", result.entity.entity);
            println!("  Risk: {}", result.risk_level);
            println!("  Breaches: {}", result.breaches.len());
            println!("  Threats: {}", result.threats.len());
            println!();
        }

        let critical = results.iter().filter(|r| r.risk_level == "critical").count();
        let high = results.iter().filter(|r| r.risk_level == "high").count();
        let medium = results.iter().filter(|r| r.risk_level == "medium").count();
        let low = results.iter().filter(|r| r.risk_level == "low").count();

        println!("Summary:");
        println!("  Critical: {}", critical);
        println!("  High: {}", high);
        println!("  Medium: {}", medium);
        println!("  Low: {}", low);

        println!("\n=============================\n");
        Ok(())
    }

    fn print_osint_result(&self, result: &crate::osint::models::OsintResult) {
        println!("Entity: {}", result.entity.entity);
        println!("Risk Level: {}", result.risk_level);
        println!();

        if !result.breaches.is_empty() {
            println!("Breach History:");
            for breach in &result.breaches {
                println!("  • {} ({})", breach.name, breach.date);
                println!("    Exposed: {}", breach.exposed_data.join(", "));
            }
            println!();
        }

        if let Some(profile) = &result.email_profile {
            println!("Email Profile:");
            println!("  Domain: {}", profile.domain);
            println!("  Usage: {}", profile.usage_context);
            if !profile.associated_names.is_empty() {
                println!("  Names: {}", profile.associated_names.join(", "));
            }
            println!();
        }

        if !result.threats.is_empty() {
            println!("Threat Indicators:");
            for threat in &result.threats {
                println!("  • {} ({})", threat.indicator_type, threat.threat_level);
                println!("    Source: {}", threat.source);
            }
            println!();
        }

        if !result.recommendations.is_empty() {
            println!("Recommendations:");
            for (i, rec) in result.recommendations.iter().enumerate() {
                println!("  {}. {}", i + 1, rec);
            }
        }
    }
}
