use crate::{Framework, osint::{OsintAggregator, OsintCache, ThreatIntelligenceFeed, OsintApiConfig, MultiSourceAggregator, CorrelationEngine, GeolocationEngine}};
use anyhow::Result;

pub struct OsintCommand {
    framework: Framework,
    aggregator: OsintAggregator,
    multi_source: Option<MultiSourceAggregator>,
    cache: OsintCache,
    threat_feed: ThreatIntelligenceFeed,
    config: OsintApiConfig,
}

impl OsintCommand {
    pub fn new() -> Result<Self> {
        Self::with_config(OsintApiConfig::from_env())
    }

    pub fn with_config(config: OsintApiConfig) -> Result<Self> {
        let framework = Framework::new();

        let aggregator = if config.use_mock_data {
            OsintAggregator::with_mock()
        } else if config.haveibeenpwned_enabled {
            OsintAggregator::with_haveibeenpwned()
        } else {
            OsintAggregator::with_mock()
        };

        let multi_source = if !config.use_mock_data
            && (config.virustotal_key.is_some() || config.abuseipdb_key.is_some()) {
            Some(MultiSourceAggregator::new(
                config.virustotal_key.clone(),
                config.abuseipdb_key.clone(),
            ))
        } else {
            None
        };

        let cache = OsintCache::new(3600);
        let threat_feed = ThreatIntelligenceFeed::new();

        Ok(OsintCommand {
            framework,
            aggregator,
            multi_source,
            cache,
            threat_feed,
            config,
        })
    }

    pub async fn analyze_entity(&self, entity: &str) -> Result<()> {
        println!("\n=== OSINT Entity Analysis ===\n");

        if let Some(cached) = self.cache.get_email(entity).await {
            println!("📦 Result from cache\n");
            self.print_osint_result(&cached);
            return Ok(());
        }

        let result = if let Some(multi) = &self.multi_source {
            let email_result = multi.analyze_email_comprehensive(entity).await.ok().flatten();
            email_result
        } else {
            self.aggregator.analyze_email(entity).await?
        };

        match result {
            Some(osint_result) => {
                self.cache.set_email(entity.to_string(), osint_result.clone()).await;
                self.print_osint_result(&osint_result);

                if !self.config.use_mock_data {
                    println!("\n✓ Data sourced from external APIs");
                    if self.config.haveibeenpwned_enabled {
                        print!(" (HaveIBeenPwned)");
                    }
                    if self.config.virustotal_key.is_some() {
                        print!(" (VirusTotal)");
                    }
                    println!();
                }
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

    pub async fn threat_actor_analysis(&self, actor_id: &str) -> Result<()> {
        println!("\n=== Threat Actor Intelligence ===\n");

        if let Some(actor) = self.threat_feed.get_actor(actor_id) {
            println!("Actor ID: {}", actor.actor_id);
            println!("Name: {}", actor.name);
            println!("Aliases: {}", actor.aliases.join(", "));
            println!("Country: {}", actor.country);
            println!("Motivation: {}\n", actor.motivation);

            println!("Known Techniques:");
            for technique in &actor.techniques {
                println!("  • {}", technique);
            }
            println!();

            println!("Known Targets:");
            for target in &actor.known_targets {
                println!("  • {}", target);
            }
            println!();

            println!("Recent Activity:");
            for activity in &actor.recent_activity {
                println!("  • {}", activity);
            }
            println!();

            println!("Known Infrastructure:");
            if !actor.infrastructure.c2_ips.is_empty() {
                println!("  C2 IPs: {}", actor.infrastructure.c2_ips.join(", "));
            }
            if !actor.infrastructure.phishing_domains.is_empty() {
                println!(
                    "  Phishing Domains: {}",
                    actor.infrastructure.phishing_domains.join(", ")
                );
            }
            if !actor.infrastructure.recent_campaigns.is_empty() {
                println!(
                    "  Active Campaigns: {}",
                    actor.infrastructure.recent_campaigns.join(", ")
                );
            }

            println!("\nIndicator Monitoring:");
            for campaign in &actor.infrastructure.recent_campaigns {
                println!("  ✓ Monitor for {}", campaign);
            }
        } else {
            println!("Threat actor {} not found in threat intelligence feed", actor_id);
        }

        println!("\n==============================\n");
        Ok(())
    }

    pub async fn threat_feed_search(&self, query: &str) -> Result<()> {
        println!("\n=== Threat Feed Search ===\n");

        let query_lower = query.to_lowercase();

        if query_lower.starts_with("country:") {
            let country = query.strip_prefix("country:").unwrap_or("");
            let actors = self.threat_feed.find_actors_by_country(country);
            println!("Actors from {}:", country);
            for actor in actors {
                println!("  • {} ({})", actor.actor_id, actor.name);
            }
        } else if query_lower.starts_with("technique:") {
            let technique = query.strip_prefix("technique:").unwrap_or("");
            let actors = self.threat_feed.find_actors_by_technique(technique);
            println!("Actors using technique {}:", technique);
            for actor in actors {
                println!("  • {} ({})", actor.actor_id, actor.name);
            }
        } else if query_lower.starts_with("sector:") {
            let sector = query.strip_prefix("sector:").unwrap_or("");
            let actors = self.threat_feed.find_actors_targeting_sector(sector);
            println!("Actors targeting {}:", sector);
            for actor in actors {
                println!("  • {} ({})", actor.actor_id, actor.name);
            }
        } else if query_lower.starts_with("indicator:") {
            let indicator = query.strip_prefix("indicator:").unwrap_or("");
            let matches = self.threat_feed.check_indicator_presence(indicator);
            if matches.is_empty() {
                println!("No actors found for indicator: {}", indicator);
            } else {
                println!("Indicator {} attributed to:", indicator);
                for actor_match in matches {
                    println!("  • {}", actor_match);
                }
            }
        } else {
            println!("Supported queries:");
            println!("  country:<country>");
            println!("  technique:<technique>");
            println!("  sector:<sector>");
            println!("  indicator:<ip/domain/hash>");
        }

        println!("\n=======================\n");
        Ok(())
    }

    pub async fn analyze_actor_correlations(&self) -> Result<()> {
        println!("\n=== Multi-Actor Threat Correlation ===\n");

        let engine = CorrelationEngine::new(self.threat_feed.clone());
        let correlations = engine.correlate_all_actors();

        if correlations.is_empty() {
            println!("No technique overlaps found between threat actors.");
            println!("\n=====================================\n");
            return Ok(());
        }

        println!("Discovered {} correlation links:\n", correlations.len());

        for (i, link) in correlations.iter().enumerate().take(10) {
            println!(
                "{}. {} ↔ {} (Shared Techniques: {})",
                i + 1,
                link.actor1_id,
                link.actor2_id,
                link.shared_techniques.len()
            );
            println!(
                "   Techniques: {}",
                link.shared_techniques.join(", ")
            );
            println!();
        }

        println!("\n=====================================\n");
        Ok(())
    }

    pub async fn analyze_ttp_prevalence(&self) -> Result<()> {
        println!("\n=== MITRE ATT&CK Technique Prevalence ===\n");

        let engine = CorrelationEngine::new(self.threat_feed.clone());
        let patterns = engine.get_most_common_techniques(15);

        let total_actors = self.threat_feed.list_actors().len();
        println!("Technique prevalence across {} actors:\n", total_actors);

        for (i, pattern) in patterns.iter().enumerate() {
            println!(
                "{}. {} (Used by {} actors, {:.1}%)",
                i + 1,
                pattern.technique,
                pattern.count,
                pattern.prevalence * 100.0
            );
            println!("   Actors: {}", pattern.actors.join(", "));
            println!();
        }

        println!("\n========================================\n");
        Ok(())
    }

    pub async fn analyze_targeting_overlap(&self) -> Result<()> {
        println!("\n=== Shared Target Sectors ===\n");

        let engine = CorrelationEngine::new(self.threat_feed.clone());
        let targets = engine.find_common_targets();

        if targets.is_empty() {
            println!("No overlapping target sectors found.");
            println!("\n=============================\n");
            return Ok(());
        }

        let mut target_list: Vec<_> = targets.iter().collect();
        target_list.sort_by_key(|&(_, actors)| std::cmp::Reverse(actors.len()));

        println!("Sectors targeted by multiple threat actors:\n");

        for (i, (target, actors)) in target_list.iter().take(10).enumerate() {
            println!(
                "{}. {} (Targeted by {} actors)",
                i + 1,
                target,
                actors.len()
            );
            println!("   Actors: {}", actors.join(", "));
            println!();
        }

        println!("\n=============================\n");
        Ok(())
    }

    pub async fn analyze_actor_network(&self, actor_id: &str) -> Result<()> {
        println!("\n=== {} Threat Network ===\n", actor_id);

        if self.threat_feed.get_actor(actor_id).is_none() {
            println!("Threat actor {} not found", actor_id);
            println!("\n==========================\n");
            return Ok(());
        }

        let engine = CorrelationEngine::new(self.threat_feed.clone());

        if let Some(network) = engine.get_actor_network(actor_id) {
            println!(
                "Connected to {} other actors via {} shared techniques\n",
                network.connected_actors.len(),
                network.shared_technique_count
            );

            for link in &network.connected_actors {
                let other = if link.actor1_id == actor_id {
                    &link.actor2_id
                } else {
                    &link.actor1_id
                };

                println!("↔ {} (Shared techniques: {})", other, link.shared_techniques.len());
                println!("  {}\n", link.shared_techniques.join(", "));
            }
        } else {
            println!("No technique overlaps with other actors");
            println!("\n==========================\n");
        }

        println!("\n==========================\n");
        Ok(())
    }

    pub async fn analyze_geolocation(&self, ip: &str) -> Result<()> {
        println!("\n=== IP Geolocation Analysis ===\n");

        let engine = GeolocationEngine::new();
        if let Some(location) = engine.resolve_ip_location(ip) {
            println!("IP Address: {}", location.ip_address);
            println!("Country: {} ({})", location.country, location.country_code);
            println!("Region/City: {}, {}", location.region, location.city);
            println!("Coordinates: {}, {}", location.latitude, location.longitude);
            println!("ISP: {}", location.isp);
            println!("Organization: {}", location.organization);
            println!("Threat Level: {}\n", location.threat_level);
        } else {
            println!("Geolocation data not available for IP: {}", ip);
        }

        println!("\n==============================\n");
        Ok(())
    }

    pub async fn analyze_breach_stealer_data(&self, email: &str) -> Result<()> {
        println!("\n=== Breach Stealer Intelligence ===\n");

        let engine = GeolocationEngine::new();
        let enrichment = engine.find_related_compromises(email);

        println!("Email: {}", email);
        println!("Geographic Risk Score: {:.2}\n", enrichment.geographic_risk_score);

        if let Some(location) = enrichment.primary_location {
            println!("Primary Location: {} ({}, {})",
                     location.country, location.city, location.country_code);
            println!("Coordinates: {}, {}", location.latitude, location.longitude);
        }

        if !enrichment.breach_history.is_empty() {
            println!("\nVictim in {} Breaches:\n", enrichment.breach_history.len());

            for (i, breach) in enrichment.breach_history.iter().enumerate() {
                println!("{}. {} ({})", i + 1, breach.breach_name, breach.breach_date);
                println!("   Forum: {}", breach.stealer_forum);
                println!("   Exposed: {}", breach.exposed_fields.join(", "));
                println!("   Recoverable: {}", if breach.recovery_possible { "Yes" } else { "No" });
                println!();
            }
        } else {
            println!("No breach stealer data found for this email");
        }

        if !enrichment.related_locations.is_empty() {
            println!("\nRelated Locations:");
            for location in &enrichment.related_locations {
                println!("  • {} - {} ({})", location.city, location.country, location.threat_level);
            }
            println!();
        }

        println!("\n==================================\n");
        Ok(())
    }

    pub async fn analyze_geographic_patterns(&self, email: &str) -> Result<()> {
        println!("\n=== Geographic Breach Patterns ===\n");

        let engine = GeolocationEngine::new();
        let breaches = engine.get_breach_victim_data(email);
        let patterns = engine.identify_geographic_patterns(&breaches);

        println!("Email: {}\n", email);
        println!("Breach Geographic Distribution:\n");

        let mut sorted_patterns: Vec<_> = patterns.iter().collect();
        sorted_patterns.sort_by_key(|&(_, count)| std::cmp::Reverse(*count));

        for (location, count) in sorted_patterns {
            println!("  • {}: {} breach(es)", location, count);
        }

        println!("\nGeographic Risk Assessment:");
        if breaches.len() > 1 {
            println!("  ⚠️  Multiple breaches across different geographies - HIGH RISK");
        } else if breaches.len() == 1 {
            println!("  ⚠️  Single breach - MEDIUM RISK");
        } else {
            println!("  ✓ No detected breaches - LOW RISK");
        }

        println!("\n==================================\n");
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
