// ============================================================================
// ANALYSIS PROMPTS (Optimized for Local Models)
// ============================================================================

pub struct AnalysisPrompts;

impl AnalysisPrompts {
    pub fn entity_analysis() -> &'static str {
        r#"You are an OSINT analyst. Analyze this entity and return ONLY valid JSON.

Return JSON with these exact fields:
{
  "entity_summary": "brief description",
  "key_attributes": ["attribute1", "attribute2"],
  "confidence_assessment": 0.0-1.0,
  "intelligence_value": 0.0-1.0,
  "recommendations": ["next step1", "next step2"],
  "potential_connections": ["connection1"]
}"#
    }

    pub fn correlation_analysis() -> &'static str {
        r#"Analyze the relationship between these two entities. Return ONLY valid JSON.

Return JSON with these exact fields:
{
  "relationship_type": "owns|associated_with|connected_to",
  "relationship_strength": 0.0-1.0,
  "supporting_evidence": ["evidence1", "evidence2"],
  "confidence_score": 0.0-1.0,
  "intelligence_implications": ["implication1"]
}"#
    }

    pub fn threat_assessment() -> &'static str {
        r#"Assess threats from this OSINT data. Return ONLY valid JSON.

Return JSON with these exact fields:
{
  "threat_level": "low|medium|high|critical",
  "threat_vectors": ["vector1", "vector2"],
  "vulnerability_assessment": ["vuln1", "vuln2"],
  "mitigation_recommendations": ["fix1", "fix2"],
  "monitoring_priorities": ["priority1"]
}"#
    }

    pub fn collection_strategy() -> &'static str {
        r#"Recommend OSINT collection strategy for this target. Return ONLY valid JSON.

Return JSON with these exact fields:
{
  "priority_sources": ["source1", "source2"],
  "collection_methods": {"source1": ["method1", "method2"]},
  "scheduling_recommendations": {"source1": "daily|weekly|monthly"},
  "resource_requirements": ["requirement1"],
  "success_probability": 0.0-1.0
}"#
    }

    pub fn data_validation() -> &'static str {
        r#"Validate this OSINT data for accuracy. Return ONLY valid JSON.

Return JSON with these exact fields:
{
  "accuracy_assessment": 0.0-1.0,
  "reliability_score": 0.0-1.0,
  "inconsistencies": ["inconsistency1"],
  "verification_recommendations": ["check1", "check2"],
  "confidence_level": 0.0-1.0
}"#
    }
}
