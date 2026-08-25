use clap::{Parser, Subcommand};
use rt::*;

#[derive(Parser)]
#[command(
    name = "rt",
    version = "1.0.0",
    about = "Unified Rust CLI for intelligence-led red-team framework",
    author = "Red Team Framework"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List, run, and drill attack scenarios; report ATT&CK coverage
    Scenario {
        #[command(subcommand)]
        subcommand: ScenarioSubcommand,
    },
    /// Derive attack scenarios from threat actors and sectors
    Derive {
        #[command(subcommand)]
        subcommand: DeriveSubcommand,
    },
    /// Reconnaissance planning and footprint reduction
    Recon {
        #[command(subcommand)]
        subcommand: ReconSubcommand,
    },
    /// Generate unified framework index
    Index,
    /// Generate ATT&CK Navigator layer
    Navigator,
    /// Validate scenarios, detections, and cross-references
    Validate {
        #[command(subcommand)]
        subcommand: ValidateSubcommand,
    },
    /// Local LLM integration for OSINT analysis
    Llm {
        #[command(subcommand)]
        subcommand: LlmSubcommand,
    },
    /// Framework intelligence analysis with LLM integration
    Analyze {
        #[command(subcommand)]
        subcommand: AnalyzeSubcommand,
    },
    /// OSINT entity reconnaissance and analysis
    Osint {
        #[command(subcommand)]
        subcommand: OsintSubcommand,
    },
}

#[derive(Subcommand)]
enum AnalyzeSubcommand {
    /// Analyze a scenario with LLM intelligence
    Scenario {
        /// Scenario ID to analyze
        id: String,
    },
    /// Correlate scenario with threat actor
    Correlate {
        /// Scenario ID
        scenario_id: String,
        /// Actor ID
        actor_id: String,
    },
    /// Generate threat intelligence report
    Report {
        /// Scenario ID
        id: String,
    },
    /// Bulk analyze multiple scenarios
    Bulk,
}

#[derive(Subcommand)]
enum OsintSubcommand {
    /// Analyze an entity (email, domain, IP)
    Analyze {
        /// Entity to analyze
        entity: String,
    },
    /// Correlate entity with attack scenario
    Correlate {
        /// Entity to analyze
        entity: String,
        /// Scenario ID to correlate with
        scenario_id: String,
    },
    /// Bulk analyze multiple entities
    Bulk {
        /// Entities as JSON array string
        entities: String,
    },
    /// Analyze threat actor from intelligence feed
    Actor {
        /// Actor ID (APT28, APT41, Lazarus, etc.)
        actor_id: String,
    },
    /// Search threat feed
    Search {
        /// Query (country:Russia, technique:T1566, sector:Finance, indicator:1.2.3.4)
        query: String,
    },
    /// Analyze multi-actor threat correlations
    Correlations,
    /// Show MITRE ATT&CK technique prevalence
    Techniques,
    /// Analyze shared targeting across actors
    Targets,
    /// Show actor's threat network
    Network {
        /// Actor ID to analyze
        actor_id: String,
    },
    /// IP geolocation and threat analysis
    Geolocation {
        /// IP address to analyze
        ip: String,
    },
    /// Breach stealer victim data analysis
    Breach {
        /// Email address to analyze
        email: String,
    },
    /// Geographic breach patterns
    Patterns {
        /// Email address to analyze
        email: String,
    },
    /// Campaign attribution analysis
    Attribution {
        /// Email address to attribute
        email: String,
    },
    /// Incident profile and risk assessment
    Profile {
        /// Email address to profile
        email: String,
    },
    /// Generate detection rules for threat actor
    Rules {
        /// Actor ID to generate rules for
        actor_id: String,
        /// Output format (sigma, yara, siem, snort)
        #[arg(default_value = "sigma")]
        format: String,
    },
    /// Show tuning guidance for detection rule
    Tuning {
        /// Rule ID to get guidance for
        rule_id: String,
    },
    /// Analyze attack timeline from breach data
    Timeline {
        /// Email address to analyze timeline for
        email: String,
    },
    /// Emulate threat actor campaign
    Campaign {
        /// Actor ID to emulate
        actor_id: String,
        /// Target domain
        target_domain: String,
    },
    /// Plan reconnaissance for target
    Recon {
        /// Actor ID to emulate
        actor_id: String,
        /// Target domain
        target_domain: String,
    },
    /// Recommend delivery vectors for target
    Vectors {
        /// Actor ID to emulate
        actor_id: String,
        /// Target domain
        target_domain: String,
    },
    /// Map scenarios to actor incidents
    Incidents {
        /// Actor ID to map scenarios for
        actor_id: String,
    },
    /// Build attack chain from known scenarios
    Chain {
        /// Actor ID for attack chain
        actor_id: String,
        /// Target sector (Government, Finance, etc.)
        #[arg(default_value = "Government")]
        sector: String,
    },
    /// Analyze threat actor technique usage patterns
    ActorTechniques {
        /// Actor ID to analyze techniques for
        actor_id: String,
    },
    /// Show actor infrastructure patterns
    Infrastructure {
        /// Actor ID to analyze infrastructure for
        actor_id: String,
    },
}

#[derive(Subcommand)]
enum ScenarioSubcommand {
    /// List available scenarios
    List,
    /// Run a scenario by ID
    Run {
        /// Scenario ID to run
        id: String,
        /// Record traffic capture (external tool required)
        #[arg(long)]
        record_traffic: bool,
        /// Capture logs (external tool required)
        #[arg(long)]
        capture_logs: bool,
        /// Generate incident response drill from scenario
        #[arg(long)]
        ir_drill: bool,
    },
    /// Generate MITRE ATT&CK coverage report
    MitreReport,
}

#[derive(Subcommand)]
enum DeriveSubcommand {
    /// Derive scenario from sector and threat actor
    Scenario {
        /// Target sector
        sector: String,
        /// Threat actor
        actor: String,
    },
    /// Build executable scenario
    Build,
}

#[derive(Subcommand)]
enum ReconSubcommand {
    /// Generate reconnaissance plan
    Plan {
        /// Organization name
        org: String,
        /// Domain
        domain: String,
        /// Authorize active reconnaissance
        #[arg(long)]
        authorize_active: bool,
    },
    /// Generate footprint reduction report
    FootprintReduction {
        /// Organization name
        org: String,
        /// Domain
        domain: String,
    },
}

#[derive(Subcommand)]
enum ValidateSubcommand {
    /// Validate scenarios
    Scenarios,
    /// Validate detections
    Detections,
    /// Validate cross-references
    CrossReferences,
}

#[derive(Subcommand)]
enum LlmSubcommand {
    /// Check Ollama connectivity and model availability
    Health,
    /// Analyze an OSINT entity
    Analyze {
        /// Entity data as JSON string
        entity: String,
        /// Use lightweight model (default: detailed)
        #[arg(long)]
        lightweight: bool,
    },
    /// Correlate two entities
    Correlate {
        /// First entity as JSON string
        entity1: String,
        /// Second entity as JSON string
        entity2: String,
        /// Use lightweight model (default: detailed)
        #[arg(long)]
        lightweight: bool,
    },
    /// Assess threat level from OSINT data
    Threat {
        /// Entities data as JSON string
        data: String,
        /// Use lightweight model (default: detailed)
        #[arg(long)]
        lightweight: bool,
    },
    /// Get collection strategy recommendations
    Strategy {
        /// Target profile as JSON string
        target: String,
        /// Use lightweight model (default: detailed)
        #[arg(long)]
        lightweight: bool,
    },
    /// Validate OSINT data accuracy
    Validate {
        /// Data to validate as JSON string
        data: String,
        /// Data type classification
        data_type: String,
        /// Use lightweight model (default: detailed)
        #[arg(long)]
        lightweight: bool,
    },
    /// Deployment profile management
    Profiles {
        #[command(subcommand)]
        subcommand: ProfileSubcommand,
    },
    /// Batch processing operations
    Batch {
        #[command(subcommand)]
        subcommand: BatchSubcommand,
    },
    /// Metrics and monitoring
    Metrics {
        #[command(subcommand)]
        subcommand: MetricsSubcommand,
    },
    /// Connection pool management
    Pool {
        #[command(subcommand)]
        subcommand: PoolSubcommand,
    },
}

#[derive(Subcommand)]
enum ProfileSubcommand {
    /// List all available deployment profiles
    List,
    /// Select a deployment profile
    Select {
        /// Profile name (edge, standard, enterprise, realtime, batch)
        name: String,
    },
}

#[derive(Subcommand)]
enum BatchSubcommand {
    /// Batch analyze multiple entities
    Analyze {
        /// Entities as JSON array string
        entities: String,
        /// Maximum concurrent operations
        #[arg(long, default_value = "5")]
        max_concurrent: usize,
    },
    /// Batch correlate entity pairs
    Correlate {
        /// Entity pairs as JSON array string
        pairs: String,
        /// Maximum concurrent operations
        #[arg(long, default_value = "5")]
        max_concurrent: usize,
    },
    /// Batch assess threats
    Threats {
        /// Datasets as JSON array string
        datasets: String,
        /// Maximum concurrent operations
        #[arg(long, default_value = "5")]
        max_concurrent: usize,
    },
    /// Batch validate data items
    Validate {
        /// Items as JSON array string
        items: String,
        /// Maximum concurrent operations
        #[arg(long, default_value = "5")]
        max_concurrent: usize,
    },
}

#[derive(Subcommand)]
enum MetricsSubcommand {
    /// Display current metrics
    Show,
    /// Reset metrics to zero
    Reset,
}

#[derive(Subcommand)]
enum PoolSubcommand {
    /// Display connection pool status
    Status {
        /// Pool size
        #[arg(long, default_value = "5")]
        size: usize,
    },
}

fn main() -> anyhow::Result<()> {
    FrameworkPaths::init()?;

    let cli = Cli::parse();

    match cli.command {
        Commands::Scenario { subcommand } => handle_scenario(subcommand)?,
        Commands::Derive { subcommand } => handle_derive(subcommand)?,
        Commands::Recon { subcommand } => handle_recon(subcommand)?,
        Commands::Index => handle_index()?,
        Commands::Navigator => handle_navigator()?,
        Commands::Validate { subcommand } => handle_validate(subcommand)?,
        Commands::Llm { subcommand } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(handle_llm(subcommand))?;
        }
        Commands::Analyze { subcommand } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(handle_analyze(subcommand))?;
        }
        Commands::Osint { subcommand } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(handle_osint(subcommand))?;
        }
    }

    Ok(())
}

fn handle_scenario(subcommand: ScenarioSubcommand) -> anyhow::Result<()> {
    let cmd = commands::ScenarioCommand::new();
    match subcommand {
        ScenarioSubcommand::List => cmd.list()?,
        ScenarioSubcommand::Run {
            id,
            record_traffic,
            capture_logs,
            ir_drill,
        } => {
            if ir_drill {
                cmd.generate_ir_drill(&id)?;
            } else {
                cmd.run(&id, record_traffic, capture_logs)?;
            }
        }
        ScenarioSubcommand::MitreReport => cmd.mitre_report()?,
    }
    Ok(())
}

fn handle_derive(subcommand: DeriveSubcommand) -> anyhow::Result<()> {
    let cmd = commands::DeriveCommand::new();
    match subcommand {
        DeriveSubcommand::Scenario { sector, actor } => {
            cmd.derive_scenario(&sector, &actor)?;
        }
        DeriveSubcommand::Build => {
            cmd.build_scenario()?;
        }
    }
    Ok(())
}

fn handle_recon(subcommand: ReconSubcommand) -> anyhow::Result<()> {
    let cmd = commands::ReconCommand::new();
    match subcommand {
        ReconSubcommand::Plan {
            org,
            domain,
            authorize_active,
        } => {
            cmd.generate_plan(&org, &domain, authorize_active)?;
        }
        ReconSubcommand::FootprintReduction { org, domain } => {
            cmd.generate_footprint_reduction(&org, &domain)?;
        }
    }
    Ok(())
}

fn handle_index() -> anyhow::Result<()> {
    let cmd = commands::IndexCommand::new();
    cmd.generate()?;
    Ok(())
}

fn handle_navigator() -> anyhow::Result<()> {
    let cmd = commands::NavigatorCommand::new();
    cmd.generate_layer()?;
    Ok(())
}

fn handle_validate(subcommand: ValidateSubcommand) -> anyhow::Result<()> {
    let cmd = commands::ValidateCommand::new();
    match subcommand {
        ValidateSubcommand::Scenarios => cmd.validate_scenarios()?,
        ValidateSubcommand::Detections => cmd.validate_detections()?,
        ValidateSubcommand::CrossReferences => cmd.validate_cross_references()?,
    }
    Ok(())
}

async fn handle_llm(subcommand: LlmSubcommand) -> anyhow::Result<()> {
    match &subcommand {
        LlmSubcommand::Profiles { subcommand } => {
            handle_profiles(subcommand)?;
            return Ok(());
        }
        LlmSubcommand::Metrics { subcommand } => {
            handle_metrics(subcommand)?;
            return Ok(());
        }
        LlmSubcommand::Pool { subcommand } => {
            handle_pool(subcommand)?;
            return Ok(());
        }
        _ => {}
    }

    let config = if matches!(&subcommand, LlmSubcommand::Health |
                            LlmSubcommand::Analyze { lightweight: true, .. } |
                            LlmSubcommand::Correlate { lightweight: true, .. } |
                            LlmSubcommand::Threat { lightweight: true, .. } |
                            LlmSubcommand::Strategy { lightweight: true, .. } |
                            LlmSubcommand::Validate { lightweight: true, .. }) {
        LocalLLMConfig::ollama_lightweight()
    } else {
        LocalLLMConfig::ollama_detailed()
    };

    let cmd = commands::LLMCommand::new(config);

    match subcommand {
        LlmSubcommand::Health => {
            cmd.health_check().await?;
        }
        LlmSubcommand::Analyze { entity, .. } => {
            cmd.analyze_entity(&entity).await?;
        }
        LlmSubcommand::Correlate { entity1, entity2, .. } => {
            cmd.correlate_entities(&entity1, &entity2).await?;
        }
        LlmSubcommand::Threat { data, .. } => {
            cmd.assess_threat(&data).await?;
        }
        LlmSubcommand::Strategy { target, .. } => {
            cmd.collection_strategy(&target).await?;
        }
        LlmSubcommand::Validate { data, data_type, .. } => {
            cmd.validate_data(&data, &data_type).await?;
        }
        LlmSubcommand::Batch { subcommand } => {
            handle_batch(&subcommand, &cmd).await?;
        }
        LlmSubcommand::Profiles { .. } | LlmSubcommand::Metrics { .. } | LlmSubcommand::Pool { .. } => {
            unreachable!()
        }
    }

    Ok(())
}

fn handle_profiles(subcommand: &ProfileSubcommand) -> anyhow::Result<()> {
    match subcommand {
        ProfileSubcommand::List => {
            commands::LLMCommand::show_deployment_profiles();
        }
        ProfileSubcommand::Select { name } => {
            let _cmd = commands::LLMCommand::with_deployment_profile(name)?;
            println!("✓ Selected deployment profile: {}", name);
            if let Some(profile) = crate::llm::DeploymentProfile::get_profile(name) {
                profile.print_info();
            }
        }
    }
    Ok(())
}

fn handle_metrics(subcommand: &MetricsSubcommand) -> anyhow::Result<()> {
    match subcommand {
        MetricsSubcommand::Show => {
            println!("Note: Initialize metrics with --enable-metrics flag to track requests");
        }
        MetricsSubcommand::Reset => {
            println!("Metrics can only be reset after operations complete");
        }
    }
    Ok(())
}

fn handle_pool(subcommand: &PoolSubcommand) -> anyhow::Result<()> {
    match subcommand {
        PoolSubcommand::Status { size } => {
            println!("\n=== Connection Pool Configuration ===");
            println!("Pool Size: {}", size);
            println!("Available Permits: {}", size);
            println!("Active Connections: 0");
            println!("=====================================\n");
        }
    }
    Ok(())
}

async fn handle_batch(subcommand: &BatchSubcommand, cmd: &commands::LLMCommand) -> anyhow::Result<()> {
    match subcommand {
        BatchSubcommand::Analyze { entities, max_concurrent } => {
            let entity_list: Vec<String> = serde_json::from_str(entities)?;
            cmd.batch_analyze_entities(entity_list, *max_concurrent).await?;
        }
        BatchSubcommand::Correlate { pairs, max_concurrent } => {
            let pair_list: Vec<(String, String)> = serde_json::from_str(pairs)?;
            cmd.batch_correlate_entities(pair_list, *max_concurrent).await?;
        }
        BatchSubcommand::Threats { datasets, max_concurrent } => {
            let dataset_list: Vec<String> = serde_json::from_str(datasets)?;
            cmd.batch_assess_threats(dataset_list, *max_concurrent).await?;
        }
        BatchSubcommand::Validate { items, max_concurrent } => {
            let item_list: Vec<(String, String)> = serde_json::from_str(items)?;
            cmd.batch_validate_data(item_list, *max_concurrent).await?;
        }
    }
    Ok(())
}

async fn handle_analyze(subcommand: AnalyzeSubcommand) -> anyhow::Result<()> {
    let cmd = commands::AnalyzeCommand::new()?;

    match subcommand {
        AnalyzeSubcommand::Scenario { id } => {
            cmd.analyze_scenario_with_intelligence(&id).await?;
        }
        AnalyzeSubcommand::Correlate { scenario_id, actor_id } => {
            cmd.correlate_scenario_and_actor(&scenario_id, &actor_id).await?;
        }
        AnalyzeSubcommand::Report { id } => {
            cmd.threat_intelligence_report(&id).await?;
        }
        AnalyzeSubcommand::Bulk => {
            cmd.bulk_scenario_analysis().await?;
        }
    }

    Ok(())
}

async fn handle_osint(subcommand: OsintSubcommand) -> anyhow::Result<()> {
    let cmd = commands::OsintCommand::new()?;

    match subcommand {
        OsintSubcommand::Analyze { entity } => {
            cmd.analyze_entity(&entity).await?;
        }
        OsintSubcommand::Correlate { entity, scenario_id } => {
            cmd.correlate_with_scenario(&entity, &scenario_id).await?;
        }
        OsintSubcommand::Bulk { entities } => {
            let entity_list: Vec<String> = serde_json::from_str(&entities)?;
            cmd.bulk_analyze(entity_list).await?;
        }
        OsintSubcommand::Actor { actor_id } => {
            cmd.threat_actor_analysis(&actor_id).await?;
        }
        OsintSubcommand::Search { query } => {
            cmd.threat_feed_search(&query).await?;
        }
        OsintSubcommand::Correlations => {
            cmd.analyze_actor_correlations().await?;
        }
        OsintSubcommand::Techniques => {
            cmd.analyze_ttp_prevalence().await?;
        }
        OsintSubcommand::Targets => {
            cmd.analyze_targeting_overlap().await?;
        }
        OsintSubcommand::Network { actor_id } => {
            cmd.analyze_actor_network(&actor_id).await?;
        }
        OsintSubcommand::Geolocation { ip } => {
            cmd.analyze_geolocation(&ip).await?;
        }
        OsintSubcommand::Breach { email } => {
            cmd.analyze_breach_stealer_data(&email).await?;
        }
        OsintSubcommand::Patterns { email } => {
            cmd.analyze_geographic_patterns(&email).await?;
        }
        OsintSubcommand::Attribution { email } => {
            cmd.analyze_campaign_attribution(&email).await?;
        }
        OsintSubcommand::Profile { email } => {
            cmd.analyze_incident_profile(&email).await?;
        }
        OsintSubcommand::Rules { actor_id, format } => {
            cmd.generate_detection_rules(&actor_id, &format).await?;
        }
        OsintSubcommand::Tuning { rule_id } => {
            cmd.show_tuning_guidance(&rule_id).await?;
        }
        OsintSubcommand::Timeline { email } => {
            cmd.analyze_breach_timeline(&email).await?;
        }
        OsintSubcommand::Campaign { actor_id, target_domain } => {
            cmd.emulate_actor_campaign(&actor_id, &target_domain).await?;
        }
        OsintSubcommand::Recon { actor_id, target_domain } => {
            cmd.plan_reconnaissance(&actor_id, &target_domain).await?;
        }
        OsintSubcommand::Vectors { actor_id, target_domain } => {
            cmd.recommend_delivery_vectors(&actor_id, &target_domain).await?;
        }
        OsintSubcommand::Incidents { actor_id } => {
            cmd.show_scenario_incidents(&actor_id)?;
        }
        OsintSubcommand::Chain { actor_id, sector } => {
            cmd.show_attack_chain(&actor_id, &sector)?;
        }
        OsintSubcommand::ActorTechniques { actor_id } => {
            cmd.show_technique_analysis(&actor_id)?;
        }
        OsintSubcommand::Infrastructure { actor_id } => {
            cmd.show_infrastructure_patterns(&actor_id)?;
        }
    }

    Ok(())
}
