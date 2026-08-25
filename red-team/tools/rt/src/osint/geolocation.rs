use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub ip_address: String,
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub isp: String,
    pub organization: String,
    pub threat_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachVictimData {
    pub breach_name: String,
    pub breach_date: String,
    pub victim_email: String,
    pub victim_location: Option<String>,
    pub username: Option<String>,
    pub password_hash: Option<String>,
    pub exposed_fields: Vec<String>,
    pub stealer_forum: String,
    pub recovery_possible: bool,
}

#[derive(Debug, Clone)]
pub struct GeolocationEnrichment {
    pub primary_location: Option<GeoLocation>,
    pub related_locations: Vec<GeoLocation>,
    pub breach_history: Vec<BreachVictimData>,
    pub geographic_risk_score: f64,
}

pub struct GeolocationEngine;

impl GeolocationEngine {
    pub fn new() -> Self {
        GeolocationEngine
    }

    pub fn resolve_ip_location(&self, ip: &str) -> Option<GeoLocation> {
        self.mock_ip_geolocation(ip)
    }

    pub fn resolve_domain_location(&self, domain: &str) -> Vec<GeoLocation> {
        self.mock_domain_geolocation(domain)
    }

    fn mock_ip_geolocation(&self, ip: &str) -> Option<GeoLocation> {
        let geolocation_db = self.get_mock_geolocation_db();
        geolocation_db.get(ip).cloned()
    }

    fn mock_domain_geolocation(&self, domain: &str) -> Vec<GeoLocation> {
        match domain {
            d if d.contains("ru") => vec![self.location("194.67.0.0", "Russia", "RU", "Moscow", "Moscow", 55.7558, 37.6173, "Rostelecom", "Russian Federation", "high")],
            d if d.contains("cn") => vec![self.location("210.0.0.0", "China", "CN", "Beijing", "Beijing", 39.9042, 116.4074, "CHINANET", "China", "high")],
            d if d.contains("kp") => vec![self.location("175.45.0.0", "North Korea", "KP", "Pyongyang", "Pyongyang", 39.0191, 125.7453, "STAR-JV", "North Korea", "critical")],
            _ => vec![self.location("1.1.1.1", "United States", "US", "California", "Los Angeles", 34.0522, -118.2437, "Cloudflare", "USA", "low")],
        }
    }

    fn location(&self, ip: &str, country: &str, cc: &str, region: &str, city: &str, lat: f64, lon: f64, isp: &str, org: &str, threat: &str) -> GeoLocation {
        GeoLocation {
            ip_address: ip.to_string(),
            country: country.to_string(),
            country_code: cc.to_string(),
            region: region.to_string(),
            city: city.to_string(),
            latitude: lat,
            longitude: lon,
            isp: isp.to_string(),
            organization: org.to_string(),
            threat_level: threat.to_string(),
        }
    }

    fn get_mock_geolocation_db(&self) -> HashMap<String, GeoLocation> {
        let mut db = HashMap::new();

        db.insert("203.0.113.45".to_string(), self.location("203.0.113.45", "Russia", "RU", "Moscow", "Moscow", 55.7558, 37.6173, "Rostelecom", "Russian Federation", "high"));
        db.insert("198.51.100.89".to_string(), self.location("198.51.100.89", "Russia", "RU", "Saint Petersburg", "Saint Petersburg", 59.9311, 30.3609, "Megafon", "Russian Federation", "high"));
        db.insert("192.0.2.50".to_string(), self.location("192.0.2.50", "China", "CN", "Shanghai", "Shanghai", 31.2304, 121.4737, "CHINATELECOM", "China", "high"));
        db.insert("198.51.100.10".to_string(), self.location("198.51.100.10", "North Korea", "KP", "Pyongyang", "Pyongyang", 39.0191, 125.7453, "STAR-JV", "North Korea", "critical"));
        db.insert("192.0.2.120".to_string(), self.location("192.0.2.120", "Russia", "RU", "Moscow", "Moscow", 55.7558, 37.6173, "Rostelecom", "Russian Federation", "high"));
        db.insert("203.0.113.99".to_string(), self.location("203.0.113.99", "Russia", "RU", "Moscow", "Moscow", 55.7558, 37.6173, "MTS", "Russian Federation", "high"));
        db.insert("192.0.2.88".to_string(), self.location("192.0.2.88", "Russia", "RU", "Vladivostok", "Vladivostok", 43.1056, 131.8735, "Rostelecom", "Russian Federation", "high"));
        db.insert("198.51.100.77".to_string(), self.location("198.51.100.77", "Ukraine", "UA", "Kyiv", "Kyiv", 50.4501, 30.5234, "Ukrtelecom", "Ukraine", "medium"));

        db
    }

    pub fn get_breach_victim_data(&self, email: &str) -> Vec<BreachVictimData> {
        self.mock_breach_stealer_data(email)
    }

    fn mock_breach_stealer_data(&self, email: &str) -> Vec<BreachVictimData> {
        let base_domain = email.split('@').nth(1).unwrap_or("example.com");

        match base_domain {
            "gmail.com" => vec![
                BreachVictimData {
                    breach_name: "LinkedIn 2021".to_string(),
                    breach_date: "2021-06-21".to_string(),
                    victim_email: email.to_string(),
                    victim_location: Some("United States".to_string()),
                    username: Some("user_".to_string() + email.split('@').next().unwrap_or("unknown")),
                    password_hash: None,
                    exposed_fields: vec!["email".to_string(), "profile_name".to_string()],
                    stealer_forum: "BreachForums".to_string(),
                    recovery_possible: true,
                },
                BreachVictimData {
                    breach_name: "Twitter 2021".to_string(),
                    breach_date: "2021-06-01".to_string(),
                    victim_email: email.to_string(),
                    victim_location: Some("United States".to_string()),
                    username: Some("twitter_".to_string() + email.split('@').next().unwrap_or("unknown")),
                    password_hash: None,
                    exposed_fields: vec!["email".to_string(), "phone".to_string()],
                    stealer_forum: "BreachForums".to_string(),
                    recovery_possible: true,
                },
            ],
            "yahoo.com" => vec![
                BreachVictimData {
                    breach_name: "Yahoo 2013".to_string(),
                    breach_date: "2013-08-24".to_string(),
                    victim_email: email.to_string(),
                    victim_location: Some("USA".to_string()),
                    username: Some("yahoo_".to_string() + email.split('@').next().unwrap_or("unknown")),
                    password_hash: Some("sha256_hash".to_string()),
                    exposed_fields: vec!["email".to_string(), "password_hash".to_string(), "security_q&a".to_string()],
                    stealer_forum: "BreachForums".to_string(),
                    recovery_possible: false,
                },
            ],
            _ => vec![],
        }
    }

    pub fn calculate_geographic_risk(&self, locations: &[GeoLocation], breaches: &[BreachVictimData]) -> f64 {
        let location_risk: f64 = locations.iter().map(|l| {
            match l.threat_level.as_str() {
                "critical" => 1.0,
                "high" => 0.7,
                "medium" => 0.4,
                "low" => 0.1,
                _ => 0.0,
            }
        }).sum::<f64>() / locations.len().max(1) as f64;

        let breach_risk = (breaches.len() as f64 / 10.0).min(1.0);

        (location_risk + breach_risk) / 2.0
    }

    pub fn identify_geographic_patterns(&self, breaches: &[BreachVictimData]) -> HashMap<String, usize> {
        let mut location_counts: HashMap<String, usize> = HashMap::new();

        for breach in breaches {
            if let Some(location) = &breach.victim_location {
                *location_counts.entry(location.clone()).or_insert(0) += 1;
            }
        }

        location_counts
    }

    pub fn find_related_compromises(&self, email: &str) -> GeolocationEnrichment {
        let breach_data = self.get_breach_victim_data(email);
        let domain = email.split('@').nth(1).unwrap_or("example.com");
        let locations = self.resolve_domain_location(domain);

        let geographic_risk = self.calculate_geographic_risk(&locations, &breach_data);

        GeolocationEnrichment {
            primary_location: locations.first().cloned(),
            related_locations: locations,
            breach_history: breach_data,
            geographic_risk_score: geographic_risk,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_geolocation() {
        let engine = GeolocationEngine::new();
        let location = engine.resolve_ip_location("203.0.113.45");
        assert!(location.is_some());
        assert_eq!(location.unwrap().country, "Russia");
    }

    #[test]
    fn test_domain_geolocation() {
        let engine = GeolocationEngine::new();
        let locations = engine.resolve_domain_location("phishing.ru");
        assert!(!locations.is_empty());
        assert_eq!(locations[0].country, "Russia");
    }

    #[test]
    fn test_breach_victim_data() {
        let engine = GeolocationEngine::new();
        let breaches = engine.get_breach_victim_data("test@gmail.com");
        assert!(!breaches.is_empty());
    }

    #[test]
    fn test_geographic_patterns() {
        let engine = GeolocationEngine::new();
        let breaches = engine.get_breach_victim_data("test@gmail.com");
        let patterns = engine.identify_geographic_patterns(&breaches);
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_enrichment() {
        let engine = GeolocationEngine::new();
        let enrichment = engine.find_related_compromises("test@gmail.com");
        assert!(enrichment.primary_location.is_some());
        assert!(enrichment.geographic_risk_score >= 0.0);
    }
}
