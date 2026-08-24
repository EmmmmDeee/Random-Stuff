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
