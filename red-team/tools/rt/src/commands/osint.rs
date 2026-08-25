use crate::{Framework, osint::{OsintAggregator, OsintCache, ThreatIntelligenceFeed, OsintApiConfig, MultiSourceAggregator, CorrelationEngine, GeolocationEngine, AttributionEngine, DetectionRuleGenerator, RuleFormat, TimelineAnalyzer, ThreatEmulator, IncidentMapper, CampaignPlanner, SupplyChainPlanner}};
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

    pub async fn analyze_campaign_attribution(&self, email: &str) -> Result<()> {
        println!("\n=== Campaign Attribution Analysis ===\n");

        let engine = AttributionEngine::new(self.threat_feed.clone());
        let attribution = engine.attribute_campaign(email);

        println!("Email: {}", email);
        println!("Geographic Fingerprint: {}", attribution.geographic_fingerprint);
        println!("Attack Stage: {}\n", attribution.timeline_stage);

        if let Some(primary) = &attribution.primary_attribution {
            println!("PRIMARY ATTRIBUTION");
            println!("  Actor: {} ({}% confidence)", primary, (attribution.attribution_confidence * 100.0) as u32);

            if let Some(actor) = self.threat_feed.get_actor(primary) {
                println!("  Profile: {} ({})", actor.name, actor.motivation);
                println!("  Country: {}", actor.country);
            }
        } else {
            println!("PRIMARY ATTRIBUTION: Unable to determine");
        }

        if !attribution.secondary_attributions.is_empty() {
            println!("\nSECONDARY ATTRIBUTIONS");
            for (i, (actor, confidence)) in attribution.secondary_attributions.iter().enumerate() {
                println!("  {}. {} ({}% confidence)", i + 1, actor, (confidence * 100.0) as u32);
            }
        }

        println!("\nATTRIBUTION INDICATORS");
        for indicator in &attribution.indicators {
            println!("  • {}: {} ({:.0}% confidence)",
                     indicator.indicator_type,
                     indicator.value,
                     indicator.confidence * 100.0);
            if !indicator.matched_actors.is_empty() {
                println!("    Matched: {}", indicator.matched_actors.join(", "));
            }
        }

        println!("\nRECOMMENDED RESPONSE");
        for (i, rec) in attribution.recommended_response.iter().enumerate() {
            println!("  {}. {}", i + 1, rec);
        }

        println!("\nDETECTION OPPORTUNITIES");
        for (i, opp) in attribution.detection_opportunities.iter().enumerate() {
            println!("  {}. {}", i + 1, opp);
        }

        println!("\n=====================================\n");
        Ok(())
    }

    pub async fn analyze_incident_profile(&self, email: &str) -> Result<()> {
        println!("\n=== Incident Profile ===\n");

        let engine = AttributionEngine::new(self.threat_feed.clone());
        let profile = engine.profile_incident(email);

        println!("Email: {}", email);
        println!("Breach Count: {}", profile.breach_count);
        println!("Geographic Spread: {} unique location(s)", profile.geographic_spread);
        println!("Exposure Severity: {}", profile.exposure_severity.to_uppercase());
        println!("Recovery Difficulty: {}", profile.recovery_difficulty);
        println!("Temporal Clustering: {:.0}%\n", profile.temporal_clustering * 100.0);

        if let Some(highest_risk) = &profile.highest_risk_breach {
            println!("HIGHEST RISK EXPOSURE: {}", highest_risk);
        }

        if !profile.actor_profiles.is_empty() {
            println!("\nKNOWN THREAT ACTORS PROFILE");
            println!("  Total actors monitored: {}", profile.actor_profiles.len());
            for (i, actor) in profile.actor_profiles.iter().take(3).enumerate() {
                println!("  {}. {}", i + 1, actor);
            }
        }

        println!("\n==================\n");
        Ok(())
    }

    pub async fn generate_detection_rules(&self, actor_id: &str, format: &str) -> Result<()> {
        println!("\n=== Detection Rule Generation ===\n");

        let rule_format = match format.to_lowercase().as_str() {
            "sigma" => RuleFormat::Sigma,
            "yara" => RuleFormat::Yara,
            "siem" | "siemquery" => RuleFormat::SiemQuery,
            "snort" => RuleFormat::Snort,
            _ => RuleFormat::Sigma,
        };

        let generator = DetectionRuleGenerator::new(self.threat_feed.clone());

        if let Some(ruleset) = generator.generate_rules_for_actor(actor_id, rule_format.clone()) {
            println!("Actor: {} ({})", actor_id, ruleset.actor_name);
            println!("Format: {:?}", rule_format);
            println!("Coverage: {}/{} techniques ({:.1}%)\n",
                     ruleset.covered_techniques,
                     ruleset.total_techniques,
                     ruleset.overall_coverage * 100.0);

            println!("Generated Rules:\n");
            for rule in ruleset.rules.iter().take(5) {
                println!("Rule: {}", rule.rule_id);
                println!("Title: {}", rule.title);
                println!("Description: {}", rule.description);
                println!("Severity: {} | Confidence: {:.0}% | FP Risk: {}",
                         rule.severity,
                         rule.confidence * 100.0,
                         rule.false_positive_risk);
                println!("Technique: {}\n", rule.techniques.join(", "));
            }

            if ruleset.rules.len() > 5 {
                println!("... and {} more rules\n", ruleset.rules.len() - 5);
            }
        } else {
            println!("Actor {} not found", actor_id);
        }

        println!("\n======================================\n");
        Ok(())
    }

    pub async fn show_tuning_guidance(&self, rule_id: &str) -> Result<()> {
        println!("\n=== Detection Rule Tuning Guidance ===\n");

        let generator = DetectionRuleGenerator::new(self.threat_feed.clone());
        let guidance = generator.get_tuning_guidance(rule_id);

        println!("Rule ID: {}", guidance.rule_id);
        println!("Baseline Period: {} days", guidance.baseline_period_days);
        println!("Alert Threshold: {}\n", guidance.alert_threshold);

        println!("Common False Positive Causes:");
        for (i, cause) in guidance.false_positive_causes.iter().enumerate() {
            println!("  {}. {}", i + 1, cause);
        }

        println!("\nTuning Recommendations:");
        for (i, rec) in guidance.tuning_recommendations.iter().enumerate() {
            println!("  {}. {}", i + 1, rec);
        }

        println!("\n=========================================\n");
        Ok(())
    }

    pub async fn analyze_breach_timeline(&self, email: &str) -> Result<()> {
        println!("\n=== Attack Timeline Analysis ===\n");

        let analyzer = TimelineAnalyzer::new(self.threat_feed.clone());
        let engine = crate::osint::GeolocationEngine::new();
        let breaches = engine.get_breach_victim_data(email);

        let timeline = analyzer.analyze_attack_timeline(email, &breaches);

        println!("Email: {}", email);
        println!("Total Events: {}", timeline.total_events);
        println!("Attack Duration: {} days\n", timeline.attack_duration_days);

        if let Some(earliest) = &timeline.earliest_event {
            println!("Timeline: {} to {}", earliest, timeline.latest_event.as_deref().unwrap_or("Present"));
        }

        println!("Likely Attack Vector: {}\n", timeline.likely_attack_vector);

        if let Some(country) = &timeline.estimated_attacker_country {
            println!("Estimated Attacker Country: {}", country);
        }

        if !timeline.events.is_empty() {
            println!("\nAttack Progression:");
            for event in &timeline.events {
                println!("  {} - {} ({:.0}% confidence)",
                         event.date,
                         event.stage.as_str(),
                         event.confidence * 100.0);
                println!("    Description: {}", event.description);
            }
        }

        println!("\nInferred Attack Stages:");
        for stage in &timeline.stage_progression {
            println!("  • {}: {}", stage.as_str(), stage.description());
        }

        println!("\n==================================\n");
        Ok(())
    }

    pub async fn emulate_actor_campaign(&self, actor_id: &str, target_domain: &str) -> Result<()> {
        println!("\n=== Threat Actor Campaign Emulation ===\n");

        let emulator = ThreatEmulator::new(self.threat_feed.clone());

        if let Some(scenario) = emulator.emulate_actor_campaign(actor_id, target_domain) {
            println!("Scenario ID: {}", scenario.scenario_id);
            println!("Actor: {} ({})", scenario.actor_name, scenario.actor_id);
            println!("Target: {}", scenario.target_profile);
            println!("Estimated Duration: {} days", scenario.estimated_duration_days);
            println!("Success Probability: {:.0}%\n", scenario.success_probability * 100.0);

            println!("Attack Phases:");
            for phase in &scenario.attack_phases {
                println!("  Phase {}: {}", phase.phase_number, phase.name);
                println!("    Description: {}", phase.description);
                println!("    Duration: {} days", phase.duration_days);
                println!("    Primary Techniques: {}", phase.primary_techniques.join(", "));
                println!("    Recommended Tools: {}", phase.recommended_tools.join(", "));
                println!("    Evasion: {}", phase.evasion_techniques.join(", "));
                println!();
            }

            println!("Required Capabilities:");
            for cap in &scenario.required_capabilities {
                println!("  • {}", cap);
            }

            println!("\nRecommended Infrastructure:");
            for infra in &scenario.recommended_infrastructure {
                println!("  • {}", infra);
            }
        } else {
            println!("Actor {} not found", actor_id);
        }

        println!("\n========================================\n");
        Ok(())
    }

    pub async fn plan_reconnaissance(&self, actor_id: &str, target_domain: &str) -> Result<()> {
        println!("\n=== Reconnaissance Plan ===\n");

        let emulator = ThreatEmulator::new(self.threat_feed.clone());

        if let Some(plan) = emulator.plan_reconnaissance(actor_id, target_domain) {
            println!("Target: {}", plan.target_domain);
            println!("Actor: {}", plan.actor_id);
            println!("Estimated Duration: {} days\n", plan.estimated_recon_duration_days);

            println!("Passive Reconnaissance Tasks:");
            for task in &plan.passive_recon_tasks {
                println!("  {} - {}", task.task_id, task.description);
                println!("    Technique: {}", task.technique_id);
                println!("    Tools: {}", task.tools.join(", "));
                println!("    Expected Output: {}", task.expected_output);
                println!("    Detection Likelihood: {:.0}%", task.detection_likelihood * 100.0);
                println!();
            }

            println!("Active Reconnaissance Tasks:");
            for task in &plan.active_recon_tasks {
                println!("  {} - {}", task.task_id, task.description);
                println!("    Risk Level: {}", task.risk_level);
                println!("    Detection Likelihood: {:.0}%\n", task.detection_likelihood * 100.0);
            }

            println!("Social Engineering Targets:");
            for target in &plan.social_engineering_targets {
                println!("  • {}", target);
            }

            println!("\nOperational Security Requirements:");
            for req in &plan.opsec_requirements {
                println!("  • {}", req);
            }
        } else {
            println!("Actor {} not found", actor_id);
        }

        println!("\n===========================\n");
        Ok(())
    }

    pub async fn recommend_delivery_vectors(&self, actor_id: &str, target_domain: &str) -> Result<()> {
        println!("\n=== Delivery Vector Recommendations ===\n");

        let emulator = ThreatEmulator::new(self.threat_feed.clone());

        if let Some(actor) = self.threat_feed.get_actor(actor_id) {
            let target_profile = crate::osint::TargetProfile {
                target_domain: target_domain.to_string(),
                estimated_size: "medium".to_string(),
                industry: actor.known_targets.first().cloned().unwrap_or_else(|| "Unknown".to_string()),
                security_posture: "moderate".to_string(),
                attack_surface_score: 0.5,
                vulnerability_likelihood: 0.5,
                employee_count_estimate: 250,
                recommended_vectors: vec![],
                likely_defenders: vec![],
            };

            let vectors = emulator.recommend_delivery_vectors(actor_id, &target_profile);

            println!("Target: {}", target_domain);
            println!("Industry: {}\n", target_profile.industry);

            for vector in vectors {
                println!("Vector: {} ({})", vector.vector_type, vector.technique_id);
                println!("  Description: {}", vector.description);
                println!("  Payload Type: {}", vector.payload_type);
                println!("  Success Rate: {:.0}%", vector.success_rate * 100.0);
                println!("  Detection Risk: {:.0}%", vector.detection_risk * 100.0);
                println!("  Setup Complexity: {}", vector.setup_complexity);
                println!("  Infrastructure Needed: {}", vector.required_infrastructure.join(", "));
                println!();
            }
        } else {
            println!("Actor {} not found", actor_id);
        }

        println!("========================================\n");
        Ok(())
    }

    pub fn show_scenario_incidents(&self, actor_id: &str) -> Result<()> {
        let mapper = IncidentMapper::new();
        let result = mapper.map_scenarios_to_actor(actor_id);

        match result {
            Ok(output) => println!("{}", output),
            Err(err) => println!("Error: {}", err),
        }

        println!("========================================\n");
        Ok(())
    }

    pub fn show_attack_chain(&self, actor_id: &str, target_sector: &str) -> Result<()> {
        let mapper = IncidentMapper::new();
        let result = mapper.build_attack_chain(actor_id, target_sector);

        match result {
            Ok(output) => println!("{}", output),
            Err(err) => println!("Error: {}", err),
        }

        println!("========================================\n");
        Ok(())
    }

    pub fn show_technique_analysis(&self, actor_id: &str) -> Result<()> {
        let mapper = IncidentMapper::new();
        let result = mapper.analyze_technique_usage(actor_id);

        match result {
            Ok(output) => println!("{}", output),
            Err(err) => println!("Error: {}", err),
        }

        println!("========================================\n");
        Ok(())
    }

    pub fn show_infrastructure_patterns(&self, actor_id: &str) -> Result<()> {
        let mapper = IncidentMapper::new();
        let result = mapper.get_infrastructure_patterns(actor_id);

        match result {
            Ok(output) => println!("{}", output),
            Err(err) => println!("Error: {}", err),
        }

        println!("========================================\n");
        Ok(())
    }

    pub fn plan_campaign(&self, actor_id: &str, target_org: &str, target_sector: &str) -> Result<()> {
        let planner = CampaignPlanner;
        let campaign = planner.plan_multi_actor_campaign(actor_id, target_org, target_sector)?;

        println!("\n=== Multi-Actor Campaign Plan ===\n");
        println!("Campaign ID: {}", campaign.campaign_id);
        println!("Target: {} ({})", campaign.target_organization, campaign.target_sector);
        println!("Duration: {} days", campaign.total_duration_days);
        println!(
            "Estimated Success Rate: {:.0}%",
            campaign.estimated_success_rate * 100.0
        );
        println!(
            "Evasion Score: {:.0}%\n",
            campaign.detection_evasion_score * 100.0
        );

        println!("Actors Involved:");
        for actor in &campaign.actors_involved {
            println!("  • {}", actor);
        }

        println!("\nCampaign Phases:");
        for phase in &campaign.phases {
            println!("\n{}. {} ({} days)", phase.phase_number, phase.phase_name, phase.duration_days);
            println!("   Primary Actor: {}", phase.primary_actor);
            println!("   Success Probability: {:.0}%", phase.success_probability * 100.0);
            println!("   Detection Risk: {:.0}%", phase.detection_risk_score * 100.0);
            println!("   Techniques:");
            for tech in &phase.techniques {
                println!("     - {}", tech);
            }
            println!("   Objectives:");
            for obj in &phase.objectives {
                println!("     • {}", obj);
            }
            println!("   Evasion Tactics:");
            for tactic in &phase.evasion_tactics {
                println!("     - {}", tactic);
            }
        }

        println!("\nRequired Infrastructure ({} items):", campaign.total_infrastructure_required.len());
        for (i, infra) in campaign.total_infrastructure_required.iter().take(10).enumerate() {
            println!("  {}. {}", i + 1, infra);
        }

        println!("\nCritical Success Factors:");
        for factor in &campaign.critical_success_factors {
            println!("  • {}", factor);
        }

        println!("\n========================================\n");
        Ok(())
    }

    pub fn show_timing_windows(&self) -> Result<()> {
        let planner = CampaignPlanner;
        let windows = planner.identify_optimal_timing()?;

        println!("\n=== Optimal Attack Timing Windows ===\n");
        for window in windows {
            println!("{}:", window.window_type);
            println!("  Description: {}", window.description);
            println!("  Timing: {}", window.timing);
            println!("  Guidance: {}", window.operational_guidance);
            println!("  Risk Level: {}\n", window.risk_level);
        }

        println!("========================================\n");
        Ok(())
    }

    pub fn estimate_detection_timeline(&self, actor_id: &str, target_org: &str, sector: &str) -> Result<()> {
        let planner = CampaignPlanner;
        let campaign = planner.plan_multi_actor_campaign(actor_id, target_org, sector)?;
        let timeline = planner.estimate_detection_timeline(&campaign)?;

        println!("\n{}", timeline);
        println!("========================================\n");
        Ok(())
    }

    pub fn list_vendor_targets(&self) -> Result<()> {
        let planner = SupplyChainPlanner;
        let targets = planner.identify_vendor_targets()?;

        println!("\n=== High-Value Supply Chain Targets ===\n");
        for target in targets {
            println!("{}:", target.vendor_name);
            println!("  Software: {}", target.software_name);
            println!("  Market Penetration: {:.0}%", target.market_penetration * 100.0);
            println!("  Affected Customers: ~{:?}", target.customer_count_estimate);
            println!("  Security Maturity: {}", target.security_maturity);
            println!("  Exploitation Difficulty: {}", target.exploitation_difficulty);
            println!("  Impact Score: {:.2}/1.0", target.potential_impact_score);
            println!("  Target Sectors:");
            for sector in &target.target_sectors {
                println!("    • {}", sector);
            }
            println!();
        }

        println!("========================================\n");
        Ok(())
    }

    pub fn plan_vendor_compromise(&self, vendor: &str, software: &str) -> Result<()> {
        let planner = SupplyChainPlanner;
        let strategy = planner.plan_vendor_compromise(vendor, software)?;

        println!("\n=== Vendor Compromise Strategy ===\n");
        println!("Target: {} ({})", strategy.vendor_target, strategy.software_target);
        println!("Attack Vector: {}", strategy.attack_vector);
        println!("Difficulty: {}\n", strategy.compromise_difficulty);

        println!("Attack Techniques:");
        for technique in &strategy.techniques {
            println!("  • {}", technique);
        }

        println!("\nCompromise Steps:");
        for (i, step) in strategy.steps.iter().enumerate() {
            println!("  {}. {}", i + 1, step);
        }

        println!("\nRequired Capabilities:");
        for cap in &strategy.required_capabilities {
            println!("  • {}", cap);
        }

        println!("\nPersistence Methods:");
        for method in &strategy.persistence_methods {
            println!("  • {}", method);
        }

        println!("\nEvasion Tactics:");
        for tactic in &strategy.evasion_tactics {
            println!("  • {}", tactic);
        }

        println!("\nSuccess Probability: {:.0}%", strategy.success_probability * 100.0);
        println!("Detection Risk: {:.0}%", strategy.detection_risk * 100.0);
        println!("Estimated Affected Targets: {:?}\n", strategy.affected_targets_estimate);

        println!("========================================\n");
        Ok(())
    }

    pub fn show_compromise_impact(&self, vendor: &str) -> Result<()> {
        let planner = SupplyChainPlanner;
        let impact = planner.estimate_compromise_impact(vendor)?;

        println!("\n{}", impact);
        println!("========================================\n");
        Ok(())
    }

    pub fn show_attack_surface(&self) -> Result<()> {
        let planner = SupplyChainPlanner;
        let surface = planner.identify_attack_surface()?;

        println!("\n=== Supply Chain Attack Surface ===\n");
        for (i, vector) in surface.iter().enumerate() {
            println!("{}. {}", i + 1, vector);
        }
        println!("\n========================================\n");
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
