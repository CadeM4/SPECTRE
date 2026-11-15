use crate::detection::Indicator;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub profile: String,
    pub theme: String,
    pub refresh_ms: u64,
    pub retention_events: usize,
    pub autonomous: bool,
    /// Makes the discovered local IPv4 survey available as an explicit session.
    /// It does not start network traffic when SPECTRE launches.
    pub lan_assessment_enabled: bool,
    pub allowed_targets: Vec<String>,
    pub enabled_modules: Vec<String>,
    pub prepared_workflow: Vec<String>,
    pub indicators: Vec<Indicator>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile: "local-research".into(),
            theme: "intelligence".into(),
            refresh_ms: 500,
            retention_events: 2_000,
            autonomous: true,
            lan_assessment_enabled: true,
            allowed_targets: Vec::new(),
            enabled_modules: vec![
                "host".into(),
                "process".into(),
                "binary".into(),
                "traffic".into(),
                "correlation".into(),
            ],
            prepared_workflow: Vec::new(),
            indicators: Vec::new(),
        }
    }
}

impl Config {
    pub const PROFILES: [&'static str; 5] = [
        "local-research",
        "binary-monitor",
        "focused",
        "offline",
        "custom",
    ];

    pub fn path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("spectre")
            .join("config.toml")
    }

    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("cannot read configuration {}", path.display()))?;
        let mut config: Self = toml::from_str(&content)
            .with_context(|| format!("invalid configuration {}", path.display()))?;
        config.upgrade_default_modules();
        config.validate()?;
        Ok(config)
    }

    pub fn load_or_default(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self::recommended())
        }
    }

    pub fn recommended() -> Self {
        let mut config = Self::default();
        if let Ok(mut system) = sysinfo::System::new() {
            system.refresh_memory();
            if system.total_memory() >= 8 * 1024 * 1024 * 1024 {
                let _ = config.apply_profile("binary-monitor");
            }
        }
        config
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        let content = toml::to_string_pretty(self)?;
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let temporary = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("cannot write {}", temporary.display()))?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        drop(file);
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error).with_context(|| format!("cannot replace {}", path.display()));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if !Self::PROFILES.contains(&self.profile.as_str()) {
            bail!(
                "unknown profile {}; available: {}",
                self.profile,
                Self::PROFILES.join(", ")
            );
        }
        if !(100..=10_000).contains(&self.refresh_ms) {
            bail!("refresh_ms must be between 100 and 10000");
        }
        if !(100..=100_000).contains(&self.retention_events) {
            bail!("retention_events must be between 100 and 100000");
        }
        if !["intelligence", "arctic", "amber", "monochrome"].contains(&self.theme.as_str()) {
            bail!("theme must be intelligence, arctic, amber, or monochrome");
        }
        if self.allowed_targets.len() > 256 {
            bail!("allowed_targets exceeds 256 entries");
        }
        for target in &self.allowed_targets {
            normalize_target(target)?;
        }
        for module in &self.enabled_modules {
            if !["host", "process", "binary", "traffic", "correlation"].contains(&module.as_str()) {
                bail!("unknown autonomous module: {module}");
            }
        }
        if self.enabled_modules.iter().any(|module| module == "binary")
            && !self
                .enabled_modules
                .iter()
                .any(|module| module == "process")
        {
            bail!("autonomous binary inspection requires the process module");
        }
        if self.prepared_workflow.len() > 256
            || self.prepared_workflow.iter().any(|v| v.len() > 4096)
        {
            bail!("prepared_workflow exceeds supported limits");
        }
        if self.indicators.len() > 1024 {
            bail!("indicators exceeds 1024 entries");
        }
        for indicator in &self.indicators {
            indicator.validate()?;
        }
        Ok(())
    }

    pub fn target_allowed(&self, target: &str) -> bool {
        let Ok(target) = normalize_target(target) else {
            return false;
        };
        self.allowed_targets
            .iter()
            .any(|entry| normalize_target(entry).is_ok_and(|entry| entry == target))
    }

    pub fn apply_profile(&mut self, profile: &str) -> Result<()> {
        match profile {
            "local-research" => {
                self.autonomous = true;
                self.enabled_modules = vec![
                    "host".into(),
                    "process".into(),
                    "binary".into(),
                    "traffic".into(),
                    "correlation".into(),
                ];
            }
            "binary-monitor" => {
                self.autonomous = true;
                self.enabled_modules = vec![
                    "host".into(),
                    "process".into(),
                    "binary".into(),
                    "traffic".into(),
                    "correlation".into(),
                ];
            }
            "focused" => {
                self.autonomous = true;
                self.enabled_modules = vec!["process".into(), "correlation".into()];
            }
            "offline" => {
                self.autonomous = false;
                self.enabled_modules = vec!["correlation".into()];
            }
            "custom" => {}
            _ => bail!("unknown profile; available: {}", Self::PROFILES.join(", ")),
        }
        self.profile = profile.into();
        self.validate()
    }

    /// Existing installations with an untouched bundled profile get the new
    /// passive traffic module. Custom selections remain exactly as saved.
    fn upgrade_default_modules(&mut self) {
        if !matches!(self.profile.as_str(), "local-research" | "binary-monitor") {
            return;
        }
        let mut modules = self
            .enabled_modules
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        modules.sort_unstable();
        if modules == ["binary", "correlation", "host", "process"] {
            self.enabled_modules.push("traffic".into());
        }
    }
}

pub fn normalize_target(target: &str) -> Result<String> {
    let unbracketed = target
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(target);
    if let Ok(address) = unbracketed.parse::<std::net::IpAddr>() {
        return Ok(address.to_string());
    }
    if target.is_empty()
        || target.len() > 253
        || target.starts_with('.')
        || target.ends_with('.')
        || target.contains(':')
    {
        bail!("scope target must be a single IP address or DNS hostname without a scheme or port");
    }
    if !target.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    }) {
        bail!("scope target must be a single IP address or DNS hostname without a scheme or port");
    }
    Ok(target.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_bounds() {
        let config = Config {
            refresh_ms: 0,
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn target_scope_is_exact() {
        let config = Config {
            allowed_targets: vec!["example.com".into()],
            ..Config::default()
        };
        assert!(config.target_allowed("example.com"));
        assert!(config.target_allowed("EXAMPLE.COM"));
        assert!(!config.target_allowed("sub.example.com"));
        assert!(!config.target_allowed("example.com.evil"));
        assert_eq!(normalize_target("[::1]").unwrap(), "::1");
        assert!(normalize_target("example.com:443").is_err());
    }

    #[test]
    fn configuration_round_trip_and_profile_switch() {
        let path = std::env::temp_dir().join(format!(
            "spectre-config-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut config = Config::default();
        config.apply_profile("binary-monitor").unwrap();
        config.allowed_targets.push("EXAMPLE.COM".into());
        config.save(&path).unwrap();
        config.theme = "amber".into();
        config.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.profile, "binary-monitor");
        assert_eq!(loaded.theme, "amber");
        assert!(loaded.enabled_modules.contains(&"binary".into()));
        assert!(loaded.target_allowed("example.com"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn existing_configuration_defaults_lan_session_to_available() {
        let mut value = toml::Value::try_from(Config::default()).unwrap();
        value
            .as_table_mut()
            .unwrap()
            .remove("lan_assessment_enabled");
        let config: Config = value.try_into().unwrap();
        assert!(config.lan_assessment_enabled);
        assert!(config.allowed_targets.is_empty());
    }

    #[test]
    fn unchanged_bundled_profile_gains_passive_traffic_on_load() {
        let path = std::env::temp_dir().join(format!(
            "spectre-traffic-upgrade-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut config = Config {
            profile: "binary-monitor".into(),
            ..Config::default()
        };
        config.enabled_modules.retain(|module| module != "traffic");
        config.save(&path).unwrap();
        let migrated = Config::load(&path).unwrap();
        assert!(migrated.enabled_modules.contains(&"traffic".into()));

        config.profile = "custom".into();
        config.save(&path).unwrap();
        let custom = Config::load(&path).unwrap();
        assert!(!custom.enabled_modules.contains(&"traffic".into()));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn local_research_enables_a_binary_baseline_without_changing_other_profiles() {
        let mut config = Config::default();
        assert!(
            config
                .enabled_modules
                .iter()
                .any(|module| module == "binary")
        );
        config.apply_profile("focused").unwrap();
        assert!(
            !config
                .enabled_modules
                .iter()
                .any(|module| module == "binary")
        );
        config.apply_profile("local-research").unwrap();
        assert!(
            config
                .enabled_modules
                .iter()
                .any(|module| module == "binary")
        );
        assert!(
            config
                .enabled_modules
                .iter()
                .any(|module| module == "process")
        );
        config.apply_profile("offline").unwrap();
        assert!(!config.autonomous);
        assert!(
            !config
                .enabled_modules
                .iter()
                .any(|module| module == "binary")
        );
    }
}
