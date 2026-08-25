use crate::osint::threat_feeds::ThreatIntelligenceFeed;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct CorrelationLink {
    pub actor1_id: String,
    pub actor2_id: String,
    pub shared_techniques: Vec<String>,
    pub correlation_score: f64,
}

#[derive(Debug, Clone)]
pub struct TTPPattern {
    pub technique: String,
    pub actors: Vec<String>,
    pub count: usize,
    pub prevalence: f64,
}

#[derive(Debug, Clone)]
pub struct ActorNetwork {
    pub actor_id: String,
    pub connected_actors: Vec<CorrelationLink>,
    pub shared_technique_count: usize,
}

pub struct CorrelationEngine {
    feed: ThreatIntelligenceFeed,
}

impl CorrelationEngine {
    pub fn new(feed: ThreatIntelligenceFeed) -> Self {
        CorrelationEngine { feed }
    }

    pub fn correlate_all_actors(&self) -> Vec<CorrelationLink> {
        let actors = self.feed.list_actors();
        let mut links = Vec::new();

        for i in 0..actors.len() {
            for j in (i + 1)..actors.len() {
                let link = self.correlate_pair(&actors[i].actor_id, &actors[j].actor_id);
                if !link.shared_techniques.is_empty() {
                    links.push(link);
                }
            }
        }

        links.sort_by(|a, b| {
            b.correlation_score
                .partial_cmp(&a.correlation_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        links
    }

    pub fn correlate_pair(&self, actor1_id: &str, actor2_id: &str) -> CorrelationLink {
        let actor1 = self.feed.get_actor(actor1_id).unwrap();
        let actor2 = self.feed.get_actor(actor2_id).unwrap();

        let techniques1: HashSet<_> = actor1.techniques.iter().cloned().collect();
        let techniques2: HashSet<_> = actor2.techniques.iter().cloned().collect();
        let shared_techniques: Vec<_> = techniques1
            .intersection(&techniques2)
            .cloned()
            .collect();

        let correlation_score = shared_techniques.len() as f64;

        CorrelationLink {
            actor1_id: actor1_id.to_string(),
            actor2_id: actor2_id.to_string(),
            shared_techniques,
            correlation_score,
        }
    }

    pub fn get_ttp_patterns(&self) -> Vec<TTPPattern> {
        let mut technique_map: HashMap<String, HashSet<String>> = HashMap::new();
        let actors = self.feed.list_actors();
        let total_actors = actors.len() as f64;

        for actor in actors {
            for technique in &actor.techniques {
                technique_map
                    .entry(technique.clone())
                    .or_insert_with(HashSet::new)
                    .insert(actor.actor_id.clone());
            }
        }

        let mut patterns: Vec<TTPPattern> = technique_map
            .into_iter()
            .map(|(technique, actor_set)| {
                let count = actor_set.len();
                let prevalence = count as f64 / total_actors;
                TTPPattern {
                    technique,
                    actors: actor_set.into_iter().collect(),
                    count,
                    prevalence,
                }
            })
            .collect();

        patterns.sort_by(|a, b| b.count.cmp(&a.count));
        patterns
    }

    pub fn get_actor_network(&self, actor_id: &str) -> Option<ActorNetwork> {
        let all_correlations = self.correlate_all_actors();
        let connected: Vec<_> = all_correlations
            .into_iter()
            .filter(|link| link.actor1_id == actor_id || link.actor2_id == actor_id)
            .collect();

        if connected.is_empty() {
            return None;
        }

        let total_shared = connected.iter().map(|l| l.shared_techniques.len()).sum();

        Some(ActorNetwork {
            actor_id: actor_id.to_string(),
            connected_actors: connected,
            shared_technique_count: total_shared,
        })
    }

    pub fn get_most_common_techniques(&self, limit: usize) -> Vec<TTPPattern> {
        let mut patterns = self.get_ttp_patterns();
        patterns.sort_by(|a, b| b.count.cmp(&a.count));
        patterns.into_iter().take(limit).collect()
    }

    pub fn find_common_targets(&self) -> HashMap<String, Vec<String>> {
        let actors = self.feed.list_actors();
        let mut target_map: HashMap<String, Vec<String>> = HashMap::new();

        for actor in actors {
            for target in &actor.known_targets {
                target_map
                    .entry(target.clone())
                    .or_insert_with(Vec::new)
                    .push(actor.actor_id.clone());
            }
        }

        target_map.retain(|_, actors| actors.len() > 1);
        target_map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlate_all_actors() {
        let feed = ThreatIntelligenceFeed::new();
        let engine = CorrelationEngine::new(feed);
        let correlations = engine.correlate_all_actors();
        assert!(!correlations.is_empty());
    }

    #[test]
    fn test_ttp_patterns() {
        let feed = ThreatIntelligenceFeed::new();
        let engine = CorrelationEngine::new(feed);
        let patterns = engine.get_ttp_patterns();
        assert!(!patterns.is_empty());
        for pattern in &patterns {
            assert!(!pattern.actors.is_empty());
        }
    }

    #[test]
    fn test_most_common_techniques() {
        let feed = ThreatIntelligenceFeed::new();
        let engine = CorrelationEngine::new(feed);
        let techniques = engine.get_most_common_techniques(3);
        assert!(techniques.len() <= 3);
    }

    #[test]
    fn test_common_targets() {
        let feed = ThreatIntelligenceFeed::new();
        let engine = CorrelationEngine::new(feed);
        let targets = engine.find_common_targets();
        assert!(!targets.is_empty());
        for (target, actors) in &targets {
            assert!(actors.len() > 1, "Target {} should be shared by multiple actors", target);
        }
    }
}
