# End-to-End Rust Refactoring Plan

## Objective
Consolidate the entire red-team framework from Python CLI tools into a unified, high-performance Rust binary with feature parity and enhanced architecture.

## Current State (Python)
- `rt.py` — unified CLI routing
- `attack.py` — shared library (paths, JSON I/O, ATT&CK helpers)
- `scenario.py` — scenario listing, execution, drill generation
- `derive.py` — scenario derivation from actor+sector
- `recon.py` — reconnaissance planning + footprint reduction
- `index.py` — unified framework index generation
- `navigator.py` — ATT&CK Navigator layer generation

Total: ~800 lines of Python, 5 command modules + 1 shared library

## Target State (Rust)
Single unified binary (`rt`) with integrated commands and enhanced performance.

```
rt (binary)
├── rt scenario      (list, run, drill, mitre-report)
├── rt derive        (sector, actor, build-scenario)
├── rt recon         (org, domain, plan, footprint-reduction)
├── rt index         (generate unified framework index)
├── rt navigator     (generate ATT&CK Navigator layer)
└── rt validate      (NEW: scenario coverage validation)
```

## Architecture

### Core Modules (Rust)

**1. `lib/mod.rs` — Unified Library**
```rust
pub mod paths;          // Repository layout (single source of truth)
pub mod loaders;        // Entity loaders (with caching)
pub mod models;         // Data structures (Scenario, Drill, Detection, etc.)
pub mod attack;         // MITRE ATT&CK utilities
pub mod queries;        // Cross-reference queries
pub mod reports;        // Report generation
```

**2. `bin/rt.rs` — CLI Dispatcher**
```rust
mod commands {
    pub mod scenario;   // scenario.rs — scenario operations
    pub mod derive;     // derive.rs — scenario derivation
    pub mod recon;      // recon.rs — reconnaissance
    pub mod index;      // index.rs — index generation
    pub mod navigator;  // navigator.rs — navigator layer
    pub mod validate;   // validate.rs — NEW coverage validation
}
```

### Data Models

```rust
// scenarios
pub struct AttackScenario {
    pub id: String,
    pub metadata: Metadata,
    pub stages: Vec<ScenarioStage>,
    pub cross_kill_chain_analysis: Option<Analysis>,
}

pub struct ScenarioStage {
    pub stage_id: String,
    pub tactic: String,
    pub technique: String,
    pub action_description: String,
    pub success_rate_percent: f32,
    pub detection_points: Vec<String>,
}

// detections
pub struct Detection {
    pub id: String,
    pub tier: String,  // "detection", "self-audit", "recon"
    pub technique: String,
    pub tactic: String,
    pub detection_name: String,
    pub data_source: String,
    pub query: String,
    pub tuning: Option<String>,
    pub associated_campaigns: Vec<String>,
}

// actors & targeting
pub struct ThreatActor {
    pub id: String,
    pub aliases: Vec<String>,
    pub characteristic_ttps: Vec<TTP>,
    pub target_sectors: Vec<String>,
    pub sophistication: String,
    pub emulation_difficulty: String,
}

pub struct TTP {
    pub tactic: String,
    pub technique: String,
    pub name: String,
}

// drills
pub struct IncidentResponseDrill {
    pub drill_id: String,
    pub name: String,
    pub scenario_source: String,
    pub objectives: Vec<String>,
    pub success_criteria: Map<String, f32>,
    pub current_performance: Map<String, f32>,
    pub score: f32,
}
```

### Entity Loaders (with Caching)

```rust
pub trait EntityLoader {
    type Item;
    fn load(&self) -> Result<Self::Item, LoadError>;
    fn cached(&mut self) -> Result<Self::Item, LoadError>;
}

pub struct ThreatActorLoader { /* cached */ }
pub struct ScenarioLoader { /* cached */ }
pub struct DetectionLoader { /* cached */ }
pub struct DrillLoader { /* cached */ }
pub struct ReconLoader { /* cached */ }
// ... etc
```

### Cross-Reference Queries

```rust
pub struct FrameworkIndex {
    pub technique_index: Map<String, TechniqueEntry>,
    pub coverage_matrix: Vec<CoverageRow>,
}

pub struct TechniqueEntry {
    pub id: String,
    pub actors: Vec<String>,
    pub scenarios: Vec<String>,
    pub campaigns: Vec<String>,
    pub detections: Vec<String>,
    pub recon_techniques: Vec<String>,
}

// Unified query interface
pub trait Queryable {
    fn detections_for_technique(&self, technique: &str) -> Vec<Detection>;
    fn scenarios_for_technique(&self, technique: &str) -> Vec<AttackScenario>;
    fn campaigns_for_technique(&self, technique: &str) -> Vec<Campaign>;
    fn actors_for_sector(&self, sector: &str) -> Vec<ThreatActor>;
    fn techniques_by_tactic(&self, tactic: &str) -> Vec<Technique>;
}
```

### Commands (Rust Implementation)

**commands/scenario.rs**
- `list_scenarios()` — list all scenarios with cross-references
- `run_scenario(id)` — execute scenario + detection coverage report
- `generate_ir_drill(id)` — IR drill from scenario
- `mitre_report()` — MITRE coverage report

**commands/derive.rs**
- `derive_scenario(sector, actor)` — derive attack chain from actor TTPs + sector recon
- `build_scenario()` — build executable scenario JSON

**commands/recon.rs**
- `generate_plan(org, domain, authorize_active)` — passive recon checklist
- `generate_footprint_reduction(org, domain)` — security fixes report

**commands/index.rs**
- `generate_index()` — unified framework index with statistics

**commands/navigator.rs**
- `generate_navigator_layer()` — ATT&CK Navigator coverage heatmap

**commands/validate.rs** (NEW)
- `validate_scenarios()` — coverage gaps analysis
- `validate_detections()` — cross-reference validation
- `validate_cross_references()` — end-to-end consistency

## Implementation Phases

### Phase 1: Foundation (Core Library)
- [ ] Define all data models in `models.rs`
- [ ] Implement entity loaders in `loaders.rs`
- [ ] Implement MITRE ATT&CK utilities in `attack.rs`
- [ ] Implement queries in `queries.rs`
- [ ] Add comprehensive tests for data loading + queries

### Phase 2: Commands (Feature Parity)
- [ ] Implement `scenario` command (feature parity with Python)
- [ ] Implement `derive` command
- [ ] Implement `recon` command
- [ ] Implement `index` command
- [ ] Implement `navigator` command

### Phase 3: CLI & Integration
- [ ] Build unified CLI dispatcher (rt binary)
- [ ] Integrate all commands with clap (arg parsing)
- [ ] Add progress indicators + output formatting
- [ ] Performance optimization

### Phase 4: Enhancement
- [ ] Implement `validate` command (NEW)
- [ ] Add parallel processing (scenario runs, index generation)
- [ ] Add caching layer for massive frameworks
- [ ] Comprehensive error handling + diagnostics

## Performance Gains

| Operation | Python | Rust | Speedup |
|-----------|--------|------|---------|
| Load all entities | ~500ms | ~50ms | 10x |
| Generate index | ~1s | ~100ms | 10x |
| Scenario execution | ~500ms | ~100ms | 5x |
| Generate navigator layer | ~2s | ~200ms | 10x |

## File Structure

```
red-team/
├── tools/
│   ├── rt/              (NEW: Rust project)
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── main.rs  (CLI dispatcher)
│   │   │   ├── lib.rs   (library root)
│   │   │   ├── paths.rs
│   │   │   ├── models.rs
│   │   │   ├── loaders.rs
│   │   │   ├── attack.rs
│   │   │   ├── queries.rs
│   │   │   ├── reports.rs
│   │   │   └── commands/
│   │   │       ├── mod.rs
│   │   │       ├── scenario.rs
│   │   │       ├── derive.rs
│   │   │       ├── recon.rs
│   │   │       ├── index.rs
│   │   │       ├── navigator.rs
│   │   │       └── validate.rs
│   │   └── tests/
│   ├── rt.py            (DEPRECATED, kept for reference)
│   ├── scenario.py      (DEPRECATED)
│   ├── derive.py        (DEPRECATED)
│   └── ... (other .py files)
└── consolidate.sh       (updated to use rt binary instead of rt.py)
```

## Dependencies

```toml
[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
clap = { version = "4.0", features = ["derive"] }
tokio = { version = "1", features = ["full"] }  # for async I/O, parallel processing
anyhow = "1.0"
thiserror = "1.0"
chrono = "0.4"
walkdir = "2"
colored = "2"  # for colorized output
```

## Testing Strategy

```rust
#[cfg(test)]
mod tests {
    // Entity loading tests
    #[test]
    fn test_load_scenarios() { }
    #[test]
    fn test_load_detections() { }
    #[test]
    fn test_cache_effectiveness() { }

    // Cross-reference tests
    #[test]
    fn test_detections_for_technique() { }
    #[test]
    fn test_scenarios_for_technique() { }
    #[test]
    fn test_technique_coverage() { }

    // Command tests
    #[test]
    fn test_scenario_listing() { }
    #[test]
    fn test_scenario_execution() { }
    #[test]
    fn test_index_generation() { }

    // Integration tests
    #[test]
    fn test_end_to_end_workflow() { }
}
```

## Migration Path

1. **Phase 1-2**: Rust refactoring runs parallel to Python tools
   - `rt.py` still works for backward compatibility
   - `rt` (Rust binary) available as alternative
   
2. **Phase 3**: Cutover
   - `consolidate.sh` updated to use `rt` binary
   - Python tools marked as deprecated
   - Python tools kept in repo for reference (archived)

3. **Phase 4**: Optimization
   - Remove Python tools once Rust is battle-tested
   - Integrate with HSE binary (may merge if beneficial)

## Success Criteria

- [ ] All Python command functionality replicated in Rust
- [ ] 10x performance improvement on index generation + data loading
- [ ] Zero-copy JSON parsing where possible
- [ ] Comprehensive error handling (no panics)
- [ ] Full test coverage (>85%)
- [ ] Consolidated binary <5MB (release build)
- [ ] Framework consolidation still passes all validations

## Time Estimate

- Phase 1 (Foundation): 4-6 hours
- Phase 2 (Commands): 4-6 hours  
- Phase 3 (CLI + Integration): 2-3 hours
- Phase 4 (Enhancement + Optimization): 3-4 hours

**Total: ~15 hours end-to-end**

---

**Status**: Ready for implementation  
**Priority**: High — foundational refactoring for framework maturity  
**Next Step**: Initialize Rust project structure and begin Phase 1
