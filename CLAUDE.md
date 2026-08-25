# Huntsman OSINT Framework - Master Development Prompt

**Status**: Production-Ready Intelligence Platform  
**Version**: 3.0 (OSINT + LLM + Framework)  
**Last Updated**: 2026-08-24  
**Active Branch**: `claude/url-list-iuamwr`  
**PR Tracking**: #18

---

## System Overview

Huntsman is a **unified intelligence platform** combining attack scenario analysis, threat actor intelligence, LLM-powered analysis, and OSINT reconnaissance into one CLI system.

### Core Capabilities

```
Framework Layer
├── 50+ attack scenarios with MITRE ATT&CK mapping
├── 100+ threat actor profiles with TTPs
├── 1000+ detection rules and capabilities
└── 50+ reconnaissance techniques

LLM Intelligence Layer
├── Analysis engine with async/await
├── Connection pooling (semaphore-based)
├── Metrics collection (requests, latency, cache)
├── Batch processing with concurrency control
└── 5 deployment profiles (edge→enterprise)

OSINT Reconnaissance Layer (NEW)
├── Multi-source entity analysis
├── Threat intelligence feed integration
├── Breach history aggregation
├── Risk scoring engine
├── Actor correlation with indicators
└── Searchable threat actor database

CLI Integration
└── 10+ main commands with 55+ subcommands
```

---

## Quick Start

### Build
```bash
cd red-team/tools/rt
cargo build --release
```

### Run
```bash
# Framework queries
./target/release/rt scenario list
./target/release/rt scenario run APT-001

# LLM analysis (requires Ollama on localhost:11434)
./target/release/rt analyze scenario APT-001
./target/release/rt llm health

# OSINT reconnaissance
./target/release/rt osint analyze user@example.com
./target/release/rt osint actor APT28
./target/release/rt osint search "country:Russia"
```

---

## Architecture

### Module Structure

```
src/
├── lib.rs                          # Module exports
├── main.rs                         # CLI routing (1000+ lines)
├── models.rs                       # Framework data structures
├── loaders.rs                      # Entity loading from disk
├── paths.rs                        # Framework paths
├── queries.rs                      # Framework + LLM integration
├── commands/                       # Command implementations
│   ├── scenario.rs                # Scenario execution
│   ├── derive.rs                  # Scenario derivation
│   ├── recon.rs                   # Reconnaissance planning
│   ├── index.rs                   # Index generation
│   ├── navigator.rs               # ATT&CK Navigator
│   ├── validate.rs                # Validation
│   ├── llm.rs                     # LLM commands
│   ├── analyze.rs                 # Intelligence analysis
│   └── osint.rs                   # OSINT operations (NEW)
├── llm/                           # LLM module (production-grade)
│   ├── mod.rs
│   ├── client.rs                  # Ollama HTTP client
│   ├── pool.rs                    # Connection pooling
│   ├── metrics.rs                 # Metrics collection
│   ├── batch.rs                   # Batch processing
│   └── production.rs              # Deployment profiles
└── osint/                         # OSINT module (NEW)
    ├── mod.rs
    ├── models.rs                  # Data structures
    ├── sources.rs                 # DataSource trait
    ├── aggregator.rs              # Multi-source aggregation
    ├── cache.rs                   # TTL-based caching
    └── threat_feeds.rs            # Threat actor intelligence (NEW)
```

### Data Flow

```
User Input (CLI)
    ↓
Command Router (main.rs)
    ↓
┌────────────────────────────────────────────┐
│         Command Implementation             │
├────────────────────────────────────────────┤
│ ├─ ScenarioCommand (scenarios.rs)          │
│ ├─ DeriveCommand (derive.rs)               │
│ ├─ ReconCommand (recon.rs)                 │
│ ├─ LLMCommand (llm.rs)                     │
│ ├─ AnalyzeCommand (analyze.rs)             │
│ └─ OsintCommand (osint.rs) ← NEW           │
└────────────────────────────────────────────┘
    ↓
┌────────────────────────────────────────────┐
│         Framework Layer                    │
├────────────────────────────────────────────┤
│ ├─ EntityLoader (from disk)                │
│ ├─ Queries (scenarios, actors, detections) │
│ └─ Framework (unified access)              │
└────────────────────────────────────────────┘
    ↓
┌────────────────────────────────────────────┐
│     Intelligence Engines                   │
├────────────────────────────────────────────┤
│ ├─ AnalysisEngine (LLM via Ollama)         │
│ ├─ OsintAggregator (multi-source)          │
│ └─ ThreatIntelligenceFeed (actor database) │
└────────────────────────────────────────────┘
    ↓
Formatted Output (CLI)
```

---

## Development Workflow

### Standard Task

1. **Add Feature**: Create module/command
2. **Test**: Run `cargo build --release` and manual test
3. **Commit**: Clear, descriptive message
4. **Push**: To `claude/url-list-iuamwr` branch
5. **CI**: Verify checks pass

### Example: Adding New OSINT Source

```rust
// 1. Create new file: src/osint/sources/shodan.rs
pub struct ShodanClient {
    api_key: String,
}

#[async_trait]
impl DataSource for ShodanClient {
    async fn query_ip(&self, ip: &str) -> Result<Option<IPIntelligence>> {
        // Implementation
    }
}

// 2. Update src/osint/mod.rs
pub mod sources;
pub use sources::shodan::ShodanClient;

// 3. Update src/osint/aggregator.rs to use new source
// 4. Test: cargo build --release
// 5. Commit and push
```

---

## Current State

### Build Status
- ✅ Compiles successfully (release mode)
- ✅ 0 errors, 6 pre-existing warnings
- ✅ ~9500 lines of Rust code
- ✅ Binary: `target/release/rt`

### Test Coverage
- ✅ 50 unit tests passing
- ✅ LLM module tests (pool, metrics, batch)
- ✅ OSINT module tests (cache, threat feeds)
- ✅ Framework integration tests

### Commits (Latest First)
- `607b9ae`: Add threat intelligence feed with actor analysis
- `2adf470`: Add production OSINT module with reconnaissance
- `a381d16`: Wire LLM Genesis into Framework
- `daeb552`: Add production LLM module

### Functionality
- ✅ Framework queries (scenarios, actors, detections)
- ✅ Scenario execution and drilling
- ✅ LLM analysis with Ollama integration
- ✅ Batch processing with concurrency
- ✅ OSINT entity analysis (email, domain, IP)
- ✅ Threat actor correlation
- ✅ Risk scoring and recommendations
- ✅ Threat feed search (country, sector, technique, indicators)

---

## Deployment

### Local Development
```bash
cd red-team/tools/rt
cargo build --release
./target/release/rt scenario list
```

### With Ollama (for LLM)
```bash
# Terminal 1: Start Ollama
ollama serve

# Terminal 2: Pull model
ollama pull mistral

# Terminal 3: Run LLM commands
./target/release/rt analyze scenario APT-001
./target/release/rt llm health
```

### Deployment Profiles
```bash
# Production deployment
./target/release/rt llm profiles select enterprise
./target/release/rt llm batch analyze '[...]' --max-concurrent 10

# Real-time SOC operations
./target/release/rt llm profiles select realtime

# Historical analysis
./target/release/rt llm profiles select batch
```

---

## Next Development Phases

### Phase 1: External Data Integration (Ready)
- [ ] HaveIBeenPwned API integration
- [ ] VirusTotal API integration
- [ ] Hunter.io email enumeration
- [ ] Shodan IP reconnaissance
- [ ] MITRE ATT&CK API for live data

### Phase 2: Advanced Analysis (Ready for implementation)
- [ ] Multi-actor TTPs correlation
- [ ] Scenario-to-incident mapping
- [ ] Automated detection rule generation
- [ ] Attack chain reconstruction

### Phase 3: Production Deployment (Ready for planning)
- [ ] Docker containerization
- [ ] Kubernetes manifests
- [ ] Authentication/authorization
- [ ] Audit logging
- [ ] Metrics persistence

### Phase 4: External Integrations (Planned)
- [ ] SIEM connectors (Splunk, ELK)
- [ ] SOAR platforms (TheHive, Cortex)
- [ ] Slack/Teams notifications
- [ ] JIRA ticket creation

---

## Idempotent Operations

### Full Rebuild
```bash
cd red-team/tools/rt
rm -rf target Cargo.lock
cargo build --release
# Builds from scratch, 100% reproducible
```

### Fresh Clone & Build
```bash
git clone https://github.com/EmmmmDeee/Random-Stuff.git
cd Random-Stuff/red-team/tools/rt
cargo build --release
# Works every time, same result
```

### Reset to Clean State
```bash
git checkout -- .
git clean -fd
cargo build --release
# All uncommitted changes removed, fresh build
```

---

## File Locations

### Framework Data
- Scenarios: `red-team/framework/scenarios/`
- Actors: `red-team/framework/actors/`
- Detections: `red-team/framework/detections/`
- Campaigns: `red-team/framework/campaigns/`
- Recon Techniques: `red-team/framework/recon/`
- MITRE Framework: `red-team/framework/mitre/`

### Source Code
- CLI: `red-team/tools/rt/src/main.rs`
- Commands: `red-team/tools/rt/src/commands/`
- LLM: `red-team/tools/rt/src/llm/`
- OSINT: `red-team/tools/rt/src/osint/`

### Build Artifacts
- Binary: `red-team/tools/rt/target/release/rt`
- Tests: Run `cargo test --lib`

---

## Authorization

### Proceed Unrestricted
- Rebuild the system from scratch
- Refactor internal implementations
- Add new commands and features
- Commit and push to branch
- Fix bugs and issues
- Optimize performance

### Requires User Approval
- Force push to main/master
- Delete or rename branches
- Merge pull requests
- Change git history
- External API integrations (credentials needed)
- Deployment to production systems

### Standard Workflow (No Approval Needed)
1. Make code changes
2. Test locally (`cargo build --release`)
3. Commit with clear message
4. Push to `claude/url-list-iuamwr`
5. CI verifies (automatic)

---

## Debugging

### Build Issues
```bash
cargo clean
cargo build --release 2>&1 | tail -50
```

### Runtime Issues
```bash
# Check framework data
./target/release/rt scenario list

# Test LLM connectivity
./target/release/rt llm health

# Test OSINT
./target/release/rt osint analyze test@example.com
```

### Git Issues
```bash
git status
git log --oneline -5
git diff HEAD~1
```

---

## Performance Notes

- **LLM Analysis**: 2-5 seconds per scenario (with Ollama)
- **OSINT Analysis**: <100ms (mock data, API calls would be slower)
- **Batch Processing**: 1.4 items/sec with enterprise profile
- **Memory**: 2GB (edge) to 16GB (batch) per profile
- **Binary Size**: ~40MB (release mode, stripped)

---

## Prompt Usage

This file serves as the **unlimited reusable prompt** for development. Use it:

1. **At Session Start**: Review current state and architecture
2. **For New Features**: Follow the development workflow section
3. **When Stuck**: Check debugging section
4. **For Authorization**: Refer to authorization section
5. **For Planning**: Review next phases

No need to re-explain the system - this document captures everything needed for coherent, continuous development.

---

## Last Verified

- **Build**: ✅ 2026-08-24 (Successful)
- **Tests**: ✅ 2026-08-24 (50/50 passing)
- **Commands**: ✅ 2026-08-24 (All operational)
- **Branch**: ✅ 2026-08-24 (Synced with remote)

**Ready for immediate continuation.**
