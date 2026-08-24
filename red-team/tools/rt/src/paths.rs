use std::path::PathBuf;
use std::sync::OnceLock;

static PATHS: OnceLock<FrameworkPaths> = OnceLock::new();

pub struct FrameworkPaths {
    pub red_team_dir: PathBuf,
    pub scenarios_dir: PathBuf,
    pub intel_dir: PathBuf,
    pub recon_dir: PathBuf,
    pub detection_dir: PathBuf,
    pub campaigns_dir: PathBuf,
    pub drills_dir: PathBuf,
    pub mitre_dir: PathBuf,
    pub reports_dir: PathBuf,

    pub threat_actors_file: PathBuf,
    pub targeting_model_file: PathBuf,
    pub attack_surface_file: PathBuf,
    pub detections_file: PathBuf,
    pub drill_framework_file: PathBuf,
    pub framework_file: PathBuf,
    pub navigator_layer_file: PathBuf,
    pub index_file: PathBuf,
}

impl FrameworkPaths {
    pub fn init() -> anyhow::Result<()> {
        let red_team_dir = std::env::current_dir()?
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Cannot find parent directory"))?
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Cannot find red-team directory"))?
            .to_path_buf();

        let intel_dir = red_team_dir.join("intelligence-led");
        let recon_dir = intel_dir.join("reconnaissance");
        let detection_dir = intel_dir.join("detection-mapping");
        let campaigns_dir = intel_dir.join("campaigns");
        let drills_dir = red_team_dir.join("incident-response");
        let mitre_dir = red_team_dir.join("mitre-attack");

        let paths = FrameworkPaths {
            scenarios_dir: red_team_dir.join("scenarios"),
            drills_dir: drills_dir.clone(),
            mitre_dir: mitre_dir.clone(),
            reports_dir: red_team_dir.join("reports"),

            threat_actors_file: intel_dir.join("threat-actors.json"),
            targeting_model_file: intel_dir.join("targeting-model.json"),
            attack_surface_file: recon_dir.join("attack-surface.json"),
            detections_file: detection_dir.join("detections.json"),
            drill_framework_file: drills_dir.join("drill-framework.json"),
            framework_file: mitre_dir.join("framework.json"),
            navigator_layer_file: mitre_dir.join("navigator-layer.json"),
            index_file: mitre_dir.join("index.json"),

            intel_dir,
            recon_dir,
            detection_dir,
            campaigns_dir,
            red_team_dir,
        };

        PATHS.get_or_init(|| paths);
        Ok(())
    }

    pub fn get() -> &'static FrameworkPaths {
        PATHS.get_or_init(|| {
            let red_team_dir = std::env::current_dir()
                .ok()
                .and_then(|p| p.parent().and_then(|x| x.parent().map(|y| y.to_path_buf())))
                .unwrap_or_else(|| PathBuf::from("."));

            let intel_dir = red_team_dir.join("intelligence-led");
            let recon_dir = intel_dir.join("reconnaissance");
            let detection_dir = intel_dir.join("detection-mapping");
            let campaigns_dir = intel_dir.join("campaigns");
            let drills_dir = red_team_dir.join("incident-response");
            let mitre_dir = red_team_dir.join("mitre-attack");

            FrameworkPaths {
                scenarios_dir: red_team_dir.join("scenarios"),
                drills_dir: drills_dir.clone(),
                mitre_dir: mitre_dir.clone(),
                reports_dir: red_team_dir.join("reports"),

                threat_actors_file: intel_dir.join("threat-actors.json"),
                targeting_model_file: intel_dir.join("targeting-model.json"),
                attack_surface_file: recon_dir.join("attack-surface.json"),
                detections_file: detection_dir.join("detections.json"),
                drill_framework_file: drills_dir.join("drill-framework.json"),
                framework_file: mitre_dir.join("framework.json"),
                navigator_layer_file: mitre_dir.join("navigator-layer.json"),
                index_file: mitre_dir.join("index.json"),

                intel_dir,
                recon_dir,
                detection_dir,
                campaigns_dir,
                red_team_dir,
            }
        })
    }
}
