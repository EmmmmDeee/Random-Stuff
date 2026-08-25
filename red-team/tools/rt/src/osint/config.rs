use std::env;

#[derive(Debug, Clone)]
pub struct OsintApiConfig {
    pub virustotal_key: Option<String>,
    pub abuseipdb_key: Option<String>,
    pub haveibeenpwned_enabled: bool,
    pub use_mock_data: bool,
}

impl OsintApiConfig {
    pub fn from_env() -> Self {
        OsintApiConfig {
            virustotal_key: env::var("VIRUSTOTAL_API_KEY").ok(),
            abuseipdb_key: env::var("ABUSEIPDB_API_KEY").ok(),
            haveibeenpwned_enabled: env::var("HIBP_ENABLED")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true),
            use_mock_data: env::var("USE_MOCK_DATA")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(false),
        }
    }

    pub fn with_virustotal_key(mut self, key: String) -> Self {
        self.virustotal_key = Some(key);
        self
    }

    pub fn with_abuseipdb_key(mut self, key: String) -> Self {
        self.abuseipdb_key = Some(key);
        self
    }

    pub fn with_mock_data(mut self, use_mock: bool) -> Self {
        self.use_mock_data = use_mock;
        self
    }

    pub fn with_hibp_enabled(mut self, enabled: bool) -> Self {
        self.haveibeenpwned_enabled = enabled;
        self
    }

    pub fn get_summary(&self) -> String {
        let mut summary = String::new();
        summary.push_str("=== OSINT API Configuration ===\n");
        summary.push_str(&format!("VirusTotal: {}\n",
            if self.virustotal_key.is_some() { "✓ Configured" } else { "✗ Not configured" }));
        summary.push_str(&format!("AbuseIPDB: {}\n",
            if self.abuseipdb_key.is_some() { "✓ Configured" } else { "✗ Not configured" }));
        summary.push_str(&format!("HaveIBeenPwned: {}\n",
            if self.haveibeenpwned_enabled { "✓ Enabled" } else { "✗ Disabled" }));
        summary.push_str(&format!("Mock Data: {}\n",
            if self.use_mock_data { "✓ Enabled" } else { "✗ Disabled" }));
        summary.push_str("===============================\n");
        summary
    }
}

impl Default for OsintApiConfig {
    fn default() -> Self {
        OsintApiConfig {
            virustotal_key: None,
            abuseipdb_key: None,
            haveibeenpwned_enabled: true,
            use_mock_data: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = OsintApiConfig::default();
        assert!(config.haveibeenpwned_enabled);
        assert!(!config.use_mock_data);
    }

    #[test]
    fn test_config_builder() {
        let config = OsintApiConfig::default()
            .with_virustotal_key("test_key".to_string())
            .with_mock_data(true);

        assert!(config.virustotal_key.is_some());
        assert!(config.use_mock_data);
    }

    #[test]
    fn test_config_summary() {
        let config = OsintApiConfig::default();
        let summary = config.get_summary();
        assert!(summary.contains("OSINT API Configuration"));
        assert!(summary.contains("VirusTotal"));
    }
}
