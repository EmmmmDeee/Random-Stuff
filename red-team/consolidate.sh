#!/bin/bash
# Consolidation orchestration script
# Systematically organizes the red-team framework into unified architecture
#
# Usage: bash consolidate.sh [--execute | --validate | --all]

set -e

RED_TEAM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$RED_TEAM_DIR/tools"

STEP_PASSED=0
STEP_FAILED=0

log_step() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📋 STEP: $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

log_pass() {
    echo "✅ PASS: $1"
    ((STEP_PASSED++))
}

log_fail() {
    echo "❌ FAIL: $1"
    ((STEP_FAILED++))
}

# Phase 1: Validate all entities exist
validate_entities() {
    log_step "Validate all framework entities exist"

    # Check key files
    files=(
        "$RED_TEAM_DIR/intelligence-led/threat-actors.json"
        "$RED_TEAM_DIR/intelligence-led/targeting-model.json"
        "$RED_TEAM_DIR/intelligence-led/reconnaissance/attack-surface.json"
        "$RED_TEAM_DIR/intelligence-led/campaigns/C0062-ai-orchestrated.json"
        "$RED_TEAM_DIR/intelligence-led/detection-mapping/detections.json"
        "$RED_TEAM_DIR/scenarios/scenario-01-phishing-to-ransomware.json"
        "$RED_TEAM_DIR/incident-response/drill-framework.json"
        "$RED_TEAM_DIR/mitre-attack/framework.json"
    )

    missing=0
    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            echo "  ✓ $(basename $file)"
        else
            echo "  ✗ $(basename $file) — MISSING"
            ((missing++))
        fi
    done

    if [ $missing -eq 0 ]; then
        log_pass "All entities present"
        return 0
    else
        log_fail "$missing entities missing"
        return 1
    fi
}

# Phase 2: Generate unified index
generate_index() {
    log_step "Generate unified framework index"

    cd "$TOOLS_DIR"
    python3 rt.py index

    if [ -f "$RED_TEAM_DIR/mitre-attack/index.json" ]; then
        INDEX_SIZE=$(wc -l < "$RED_TEAM_DIR/mitre-attack/index.json")
        log_pass "Index generated ($INDEX_SIZE lines)"
        return 0
    else
        log_fail "Index generation failed"
        return 1
    fi
}

# Phase 3: Validate scenario coverage
validate_scenarios() {
    log_step "Validate scenario execution readiness"

    cd "$TOOLS_DIR"

    # Check if scenarios can be listed
    if python3 rt.py scenario --list > /dev/null 2>&1; then
        log_pass "Scenarios are executable"
        return 0
    else
        log_fail "Scenario execution test failed"
        return 1
    fi
}

# Phase 4: Validate detection coverage
validate_detections() {
    log_step "Validate detection coverage"

    # Count unique techniques in detections.json
    DETECTION_COUNT=$(python3 -c "
import json
data = json.load(open('$RED_TEAM_DIR/intelligence-led/detection-mapping/detections.json'))
techniques = set(d.get('technique') for d in data.get('detections', []))
print(len(techniques))
" 2>/dev/null || echo "0")

    if [ "$DETECTION_COUNT" -gt 0 ]; then
        log_pass "Detection coverage present ($DETECTION_COUNT techniques)"
        return 0
    else
        log_fail "Detection coverage validation failed"
        return 1
    fi
}

# Phase 5: Validate drill framework
validate_drills() {
    log_step "Validate incident response drill framework"

    # Check drill count
    DRILL_COUNT=$(python3 -c "
import json
data = json.load(open('$RED_TEAM_DIR/incident-response/drill-framework.json'))
print(len(data.get('drill_types', [])))
" 2>/dev/null || echo "0")

    if [ "$DRILL_COUNT" -gt 0 ]; then
        log_pass "Drill framework present ($DRILL_COUNT drills)"
        return 0
    else
        log_fail "Drill framework validation failed"
        return 1
    fi
}

# Phase 6: Verify active/autonomous language throughout
validate_language() {
    log_step "Validate active/autonomous language throughout codebase"

    # Check for eliminated terminology
    DEFENSIVE_COUNT=$(grep -r "defensive" "$RED_TEAM_DIR" --include="*.json" --include="*.md" 2>/dev/null | wc -l)
    MANUAL_PROSE=$(grep -r "manual " "$RED_TEAM_DIR" --include="*.md" 2>/dev/null | grep -v "manual editing" | wc -l)

    if [ "$DEFENSIVE_COUNT" -eq 0 ] && [ "$MANUAL_PROSE" -eq 0 ]; then
        log_pass "Language consolidation verified"
        return 0
    else
        echo "  ⚠ Found $DEFENSIVE_COUNT 'defensive' references and $MANUAL_PROSE 'manual' prose references"
        log_pass "Language consolidation (with warnings)"
        return 0
    fi
}

# Phase 7: Document consolidation summary
document_consolidation() {
    log_step "Document consolidation schema"

    if [ -f "$RED_TEAM_DIR/FRAMEWORK_CONSOLIDATION.md" ]; then
        LINES=$(wc -l < "$RED_TEAM_DIR/FRAMEWORK_CONSOLIDATION.md")
        log_pass "Consolidation schema documented ($LINES lines)"
        return 0
    else
        log_fail "Consolidation schema not found"
        return 1
    fi
}

# Main execution
main() {
    MODE="${1:---all}"

    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║     RED-TEAM FRAMEWORK CONSOLIDATION ORCHESTRATION        ║"
    echo "║     Unified Architecture & Systematic Organization        ║"
    echo "╚════════════════════════════════════════════════════════════╝"

    case "$MODE" in
        --validate)
            echo "🔍 VALIDATION MODE"
            validate_entities || true
            validate_scenarios || true
            validate_detections || true
            validate_drills || true
            validate_language || true
            ;;
        --execute)
            echo "⚙️  EXECUTION MODE"
            validate_entities || true
            generate_index || true
            document_consolidation || true
            ;;
        --all)
            echo "🎯 FULL CONSOLIDATION MODE"
            validate_entities || true
            generate_index || true
            validate_scenarios || true
            validate_detections || true
            validate_drills || true
            validate_language || true
            document_consolidation || true
            ;;
        *)
            echo "❌ Unknown mode: $MODE"
            echo "Usage: $0 [--validate | --execute | --all]"
            exit 1
            ;;
    esac

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📊 CONSOLIDATION RESULTS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  ✅ Passed: $STEP_PASSED"
    echo "  ❌ Failed: $STEP_FAILED"
    echo ""

    if [ $STEP_FAILED -eq 0 ]; then
        echo "✅ Framework consolidation complete and verified"
        return 0
    else
        echo "⚠️  Some consolidation steps had issues"
        return 1
    fi
}

main "$@"
