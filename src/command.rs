use crate::{
    analysis, capability,
    config::{Config, normalize_target},
    detection::Indicator,
    engine::EventHub,
    model::{Event, Severity, SourceKind},
    network,
};
use anyhow::{Context, Result, bail};
use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkspaceRequest {
    Command(String),
    AssistedCompletion { index: usize, text: String },
}

pub async fn execute_workspace_request(
    request: WorkspaceRequest,
    hub: &EventHub,
    config_path: &Path,
) -> Result<Vec<Event>> {
    match request {
        WorkspaceRequest::Command(line) => execute_line(&line, hub, config_path).await,
        WorkspaceRequest::AssistedCompletion { index, text } => {
            let config = Config::load_or_default(config_path)?;
            if index == 0 || config.prepared_workflow.get(index - 1) != Some(&text) {
                bail!("completed assisted step does not match the configured workflow");
            }
            let event = Event::new(
                "presentation",
                "prepared.input",
                format!("Prepared step {index} revealed"),
                None,
                Severity::Info,
                SourceKind::Prepared,
            )
            .with_evidence("step_index", index.to_string(), "prepared_workflow")
            .with_evidence("input", text, "prepared_workflow");
            hub.publish(event.clone());
            Ok(vec![event])
        }
    }
}

pub async fn execute_line(line: &str, hub: &EventHub, config_path: &Path) -> Result<Vec<Event>> {
    let words = tokenize(line)?;
    if words.is_empty() {
        return Ok(Vec::new());
    }
    let config = Config::load_or_default(config_path)?;
    let canonical_indicators = canonicalize_indicators(&config.indicators)?;
    hub.set_indicators(canonical_indicators.clone());
    let output = match words[0].as_str() {
        "help" => vec![Event::new("command", "command.help", "Command reference (F1 for keyboard controls)", None, Severity::Info, SourceKind::Live)
            .with_evidence("commands", "binary <file>\npcap <file>\nscan <target> [ports]\ninvestigate <target> [ports]\nhttp <url>\nscope add|remove|list\nindicator add|remove|list\nprofile <name>|list\ntheme <name>|list\nmodule enable|disable|list\nautonomous on|off\nworkflow list|add|remove|clear\nretention [set COUNT]\nexport <file>\ndoctor", "built_in")],
        "doctor" => {
            let report = capability::inspect();
            let found = report.tools.iter().filter(|tool| tool.path.is_some()).count();
            vec![Event::new("command", "command.doctor", format!("{} {}; {found} optional tools found", report.os, report.arch), None, Severity::Info, SourceKind::Live)
                .with_evidence("report", serde_json::to_string_pretty(&report)?, "capability_inspection")]
        },
        "binary" if words.len() == 2 => {
            let path = PathBuf::from(&words[1]);
            tokio::task::spawn_blocking(move || analysis::analyze_binary(&path)).await??
        }
        "pcap" if words.len() == 2 => {
            let path = PathBuf::from(&words[1]);
            tokio::task::spawn_blocking(move || analysis::analyze_pcap(&path)).await??
        }
        "scan" if (2..=3).contains(&words.len()) => {
            let target = normalize_target(&words[1])?;
            if !config.target_allowed(&target) {
                bail!(
                    "target {} is outside configured scope; use `spectre scope add {}`",
                    words[1],
                    words[1]
                );
            }
            let ports = parse_ports(
                words
                    .get(2)
                    .map(String::as_str)
                    .unwrap_or("21,22,25,53,80,110,143,443,445,3389,5432,6379,8080,8443"),
            )?;
            network::scan_tcp(&target, &ports, Duration::from_secs(2)).await?
        }
        "investigate" if (2..=3).contains(&words.len()) => {
            let target = normalize_target(&words[1])?;
            if !config.target_allowed(&target) {
                bail!(
                    "target {target} is outside configured scope; use `spectre scope add {target}`"
                );
            }
            let ports = parse_ports(
                words
                    .get(2)
                    .map(String::as_str)
                    .unwrap_or("22,80,443,8080,8443"),
            )?;
            let mut events = network::scan_tcp(&target, &ports, Duration::from_secs(2)).await?;
            let mut followed = 0usize;
            let mut web_events = 0usize;
            let open_endpoints = events
                .iter()
                .filter(|event| event.kind == "tcp_open")
                .filter_map(|event| event.evidence.iter().find(|item| item.label == "endpoint"))
                .filter_map(|item| item.value.parse::<std::net::SocketAddr>().ok())
                .filter(|endpoint| [80, 443, 8080, 8443].contains(&endpoint.port()))
                .collect::<std::collections::BTreeSet<_>>();
            for endpoint in open_endpoints.into_iter().take(4) {
                followed += 1;
                let url = follow_up_url(&target, endpoint)?;
                match network::inspect_http_at(&url, Duration::from_secs(8), Some(endpoint)).await {
                    Ok(result) => {
                        web_events += result.len();
                        events.extend(result);
                    }
                    Err(error) => events.push(follow_up_error(&target, &url, endpoint, &error)),
                }
            }
            events.push(
                Event::new(
                    "investigation",
                    "investigation.complete",
                    format!(
                        "Investigation of {target} completed; {followed} web endpoint(s) checked"
                    ),
                    None,
                    Severity::Info,
                    SourceKind::Derived,
                )
                .with_evidence("target", target, "configured_scope")
                .with_evidence(
                    "web_events",
                    web_events.to_string(),
                    "observed_results",
                ),
            );
            events
        }
        "http" if words.len() == 2 => {
            let url =
                reqwest::Url::parse(&words[1]).context("expected a valid HTTP or HTTPS URL")?;
            if !matches!(url.scheme(), "http" | "https") {
                bail!("only HTTP and HTTPS URLs are supported");
            }
            let host = url.host_str().context("URL has no host")?;
            if !config.target_allowed(host) {
                bail!("host {host} is outside configured scope; use `spectre scope add {host}`");
            }
            network::inspect_http(&words[1], Duration::from_secs(8)).await?
        }
        "scope" if words.len() >= 2 => match words[1].as_str() {
            "list" if words.len() == 2 => vec![status(if config.allowed_targets.is_empty() {
                "No targets configured".into()
            } else {
                config.allowed_targets.join(", ")
            })],
            "add" if words.len() == 3 => {
                let target = normalize_target(&words[2])?;
                let mut next = config;
                if !next.target_allowed(&target) {
                    next.allowed_targets.push(target.clone());
                }
                next.save(config_path)?;
                vec![status(format!("Target added to scope: {target}"))]
            }
            "remove" if words.len() == 3 => {
                let target = normalize_target(&words[2])?;
                let mut next = config;
                next.allowed_targets
                    .retain(|value| normalize_target(value).is_ok_and(|value| value != target));
                next.save(config_path)?;
                vec![status(format!("Target removed from scope: {target}"))]
            }
            _ => bail!("usage: scope add|remove <host>, or scope list"),
        },
        "profile" if words.len() == 2 => {
            if words[1] == "list" {
                vec![status(format!("Profiles: {}", Config::PROFILES.join(", ")))]
            } else {
                let mut next = config;
                next.apply_profile(&words[1])?;
                next.save(config_path)?;
                vec![
                    Event::new(
                        "config",
                        "config.profile",
                        format!("Profile: {}", words[1]),
                        None,
                        Severity::Info,
                        SourceKind::Live,
                    )
                    .with_evidence("name", &words[1], "config.toml"),
                ]
            }
        }
        "theme" if words.len() == 2 => {
            if words[1] == "list" {
                vec![status("Themes: intelligence, arctic, amber, monochrome")]
            } else {
                let mut next = config;
                next.theme = words[1].clone();
                next.save(config_path)?;
                vec![
                    Event::new(
                        "config",
                        "config.theme",
                        format!("Theme: {}", words[1]),
                        None,
                        Severity::Info,
                        SourceKind::Live,
                    )
                    .with_evidence("name", &words[1], "config.toml"),
                ]
            }
        }
        "module" if words.len() >= 2 => {
            let available = ["host", "process", "binary", "correlation"];
            match words[1].as_str() {
                "list" if words.len() == 2 => vec![status(format!(
                    "Autonomous modules: {}; enabled: {}",
                    available.join(", "),
                    config.enabled_modules.join(", ")
                ))],
                "enable" | "disable" if words.len() == 3 => {
                    if !available.contains(&words[2].as_str()) {
                        bail!("unknown autonomous module: {}", words[2]);
                    }
                    let mut next = config;
                    if words[1] == "enable" && !next.enabled_modules.contains(&words[2]) {
                        next.enabled_modules.push(words[2].clone());
                    }
                    if words[1] == "disable" {
                        next.enabled_modules.retain(|name| name != &words[2]);
                    }
                    next.profile = "custom".into();
                    next.save(config_path)?;
                    vec![status(format!(
                        "Module {}: {}",
                        words[2],
                        if words[1] == "enable" {
                            "enabled"
                        } else {
                            "disabled"
                        }
                    ))]
                }
                _ => bail!("usage: module enable|disable <name>, or module list"),
            }
        }
        "indicator" if words.len() >= 2 => match words[1].as_str() {
            "list" if words.len() == 2 => {
                let listing = canonical_indicators.iter()
                    .map(|indicator| format!("{} {}  {}", indicator.kind.as_str(), indicator.value, indicator.label))
                    .collect::<Vec<_>>().join("\n");
                vec![Event::new("config", "indicator.list", format!("{} indicators configured", canonical_indicators.len()), None, Severity::Info, SourceKind::Live)
                    .with_evidence("indicators", listing, "config.toml")]
            }
            "add" if (4..=5).contains(&words.len()) => {
                let label = words.get(4).map(String::as_str).unwrap_or("configured indicator");
                let indicator = Indicator::parse(&words[2], &words[3], label)?;
                let mut next = config;
                next.indicators = canonical_indicators;
                next.indicators.retain(|existing| existing.kind != indicator.kind || existing.value != indicator.value);
                next.indicators.push(indicator.clone());
                next.save(config_path)?;
                hub.set_indicators(next.indicators);
                vec![status(format!("Indicator added: {} {}", indicator.kind.as_str(), indicator.value))]
            }
            "remove" if words.len() == 4 => {
                let indicator = Indicator::parse(&words[2], &words[3], "configured indicator")?;
                let mut next = config;
                next.indicators = canonical_indicators;
                next.indicators.retain(|existing| existing.kind != indicator.kind || existing.value != indicator.value);
                next.save(config_path)?;
                hub.set_indicators(next.indicators);
                vec![status(format!("Indicator removed: {} {}", indicator.kind.as_str(), indicator.value))]
            }
            _ => bail!("usage: indicator add <sha256|domain|ip> <value> [label], indicator remove <kind> <value>, or indicator list"),
        },
        "autonomous" if words.len() == 2 => {
            let mut next = config;
            next.autonomous = match words[1].as_str() {
                "on" => true,
                "off" => false,
                _ => bail!("usage: autonomous on|off"),
            };
            next.save(config_path)?;
            vec![status(format!("Autonomous collection: {}", words[1]))]
        }
        "workflow" if words.len() >= 2 => match words[1].as_str() {
            "list" if words.len() == 2 => {
                let steps = config.prepared_workflow.iter().enumerate()
                    .map(|(index, step)| format!("{}. {}", index + 1, step))
                    .collect::<Vec<_>>().join("\n");
                vec![Event::new(
                    "config", "workflow.list",
                    format!("{} prepared step(s) configured", config.prepared_workflow.len()),
                    None, Severity::Info, SourceKind::Live,
                ).with_evidence("steps", steps, "config.toml")]
            }
            "add" if words.len() >= 3 => {
                let step = words[2..].join(" ");
                if step.trim().is_empty() {
                    bail!("prepared step cannot be empty");
                }
                let mut next = config;
                next.prepared_workflow.push(step);
                next.save(config_path)?;
                vec![status(format!("Prepared step {} added", next.prepared_workflow.len()))]
            }
            "remove" if words.len() == 3 => {
                let index: usize = words[2].parse().context("prepared step index must be a number")?;
                let mut next = config;
                if index == 0 || index > next.prepared_workflow.len() {
                    bail!("prepared step index is outside the configured workflow");
                }
                next.prepared_workflow.remove(index - 1);
                next.save(config_path)?;
                vec![status(format!("Prepared step {index} removed"))]
            }
            "clear" if words.len() == 2 => {
                let mut next = config;
                let count = next.prepared_workflow.len();
                next.prepared_workflow.clear();
                next.save(config_path)?;
                vec![status(format!("{count} prepared step(s) removed"))]
            }
            _ => bail!("usage: workflow list, workflow add <text>, workflow remove <index>, or workflow clear"),
        },
        "retention" if words.len() == 1 => {
            vec![status(format!("Retention limit: {} events", config.retention_events))]
        }
        "retention" if words.len() == 3 && words[1] == "set" => {
            let count: usize = words[2].parse().context("retention count must be a number")?;
            let mut next = config;
            next.retention_events = count;
            next.save(config_path)?;
            vec![status(format!("Retention saved: {count} events; hub capacity changes on next launch"))]
        }
        "retention" => bail!("usage: retention, or retention set <100..100000>"),
        "config" if words.len() == 2 && words[1] == "reload" => {
            vec![status("Configuration reloaded")]
        }
        "export" if words.len() == 2 => {
            let count = hub.export_jsonl(Path::new(&words[1]))?;
            vec![status(format!("Exported {count} events to {}", words[1]))]
        }
        _ => bail!("unknown command or arguments; enter `help` for commands"),
    };
    for event in &output {
        hub.publish(event.clone());
    }
    Ok(output)
}

pub fn status(summary: impl Into<String>) -> Event {
    Event::new(
        "command",
        "command.result",
        summary,
        None,
        Severity::Info,
        SourceKind::Live,
    )
}

fn follow_up_error(target: &str, url: &str, endpoint: SocketAddr, error: &anyhow::Error) -> Event {
    Event::new(
        "investigation",
        "follow_up.error",
        format!("HTTP follow-up on {url} via {endpoint}: {error}"),
        Some(target.to_string()),
        Severity::Low,
        SourceKind::Live,
    )
    .with_evidence("url", url, "configured_scope")
    .with_evidence("resolved_endpoint", endpoint.to_string(), "tcp_scan")
}

fn follow_up_url(target: &str, endpoint: SocketAddr) -> Result<String> {
    let target = normalize_target(target)?;
    let host = match target.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{target}]"),
        _ => target,
    };
    let scheme = if matches!(endpoint.port(), 443 | 8443) {
        "https"
    } else {
        "http"
    };
    Ok(format!("{scheme}://{host}:{}/", endpoint.port()))
}

fn canonicalize_indicators(indicators: &[Indicator]) -> Result<Vec<Indicator>> {
    let mut normalized = Vec::<Indicator>::with_capacity(indicators.len());
    for raw in indicators {
        let indicator = Indicator::parse(raw.kind.as_str(), &raw.value, &raw.label)?;
        if let Some(existing) = normalized
            .iter_mut()
            .find(|existing| existing.kind == indicator.kind && existing.value == indicator.value)
        {
            *existing = indicator;
        } else {
            normalized.push(indicator);
        }
    }
    Ok(normalized)
}

pub fn parse_ports(input: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in input.split(',') {
        if let Some((first, last)) = part.split_once('-') {
            let first: u16 = first.parse().context("invalid first port")?;
            let last: u16 = last.parse().context("invalid last port")?;
            if first == 0 || last < first || last - first > 127 {
                bail!("port range must contain 1 to 128 valid ports");
            }
            ports.extend(first..=last);
        } else {
            let port: u16 = part.parse().context("invalid port")?;
            if port == 0 {
                bail!("port zero is not supported");
            }
            ports.push(port);
        }
        if ports.len() > 128 {
            bail!("at most 128 ports can be scanned per command");
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

pub fn tokenize(input: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;
    for ch in input.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            started = true;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            escaped = true;
            started = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                started = true;
            }
            ch if ch.is_whitespace() => {
                if started {
                    out.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            _ => {
                current.push(ch);
                started = true;
            }
        }
    }
    if escaped || quote.is_some() {
        bail!("unfinished escape or quote in command");
    }
    if started {
        out.push(current);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::IndicatorKind;
    use tokio::net::TcpListener;

    #[test]
    fn quotes_paths_without_running_a_shell() {
        assert_eq!(
            tokenize("binary '/tmp/a b' --x").unwrap(),
            vec!["binary", "/tmp/a b", "--x"]
        );
        assert!(tokenize("binary 'bad").is_err());
    }

    #[test]
    fn ports_are_bounded_and_deduplicated() {
        assert_eq!(
            parse_ports("443,80,80,81-82").unwrap(),
            vec![80, 81, 82, 443]
        );
        assert!(parse_ports("1-200").is_err());
        assert!(parse_ports("0").is_err());
    }

    #[test]
    fn follow_up_url_brackets_ipv6_exactly_once() {
        let endpoint = "[::1]:8080".parse().unwrap();
        assert_eq!(
            follow_up_url("[::1]", endpoint).unwrap(),
            "http://[::1]:8080/"
        );
        assert_eq!(
            follow_up_url("::1", endpoint).unwrap(),
            "http://[::1]:8080/"
        );
        let tls_endpoint = "[::1]:8443".parse().unwrap();
        assert_eq!(
            follow_up_url("[::1]", tls_endpoint).unwrap(),
            "https://[::1]:8443/"
        );
    }

    #[tokio::test]
    async fn bracketed_ipv6_scope_allows_loopback_scan_when_available() {
        let Ok(listener) = TcpListener::bind("[::1]:0").await else {
            return;
        };
        let port = listener.local_addr().unwrap().port();
        let path = std::env::temp_dir().join(format!(
            "spectre-ipv6-command-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let hub = EventHub::new(100);
        execute_line("scope add [::1]", &hub, &path).await.unwrap();
        let events = execute_line(&format!("scan [::1] {port}"), &hub, &path)
            .await
            .unwrap();
        assert!(
            events
                .iter()
                .any(|event| event.kind == "tcp_open" && event.subject.as_deref() == Some("::1"))
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn indicator_commands_canonicalize_raw_toml_entries() {
        let path = std::env::temp_dir().join(format!(
            "spectre-indicator-command-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let raw = Indicator {
            kind: IndicatorKind::Domain,
            value: "EXAMPLE.ORG.".into(),
            label: "old label".into(),
        };
        let mut config = Config {
            indicators: vec![raw.clone()],
            ..Config::default()
        };
        config.save(&path).unwrap();
        let hub = EventHub::new(100);
        let listed = execute_line("indicator list", &hub, &path).await.unwrap();
        assert!(listed[0].evidence.iter().any(
            |item| item.label == "indicators" && item.value == "domain example.org  old label"
        ));

        execute_line("indicator add domain example.org replacement", &hub, &path)
            .await
            .unwrap();
        let saved = Config::load(&path).unwrap();
        assert_eq!(saved.indicators.len(), 1);
        assert_eq!(saved.indicators[0].value, "example.org");
        assert_eq!(saved.indicators[0].label, "replacement");

        config.indicators = vec![raw];
        config.save(&path).unwrap();
        execute_line("indicator remove domain example.org", &hub, &path)
            .await
            .unwrap();
        assert!(Config::load(&path).unwrap().indicators.is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn command_scope_and_prepared_provenance() {
        let path = std::env::temp_dir().join(format!(
            "spectre-command-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let hub = EventHub::new(100);
        let denied = execute_line("scan 127.0.0.1 9", &hub, &path)
            .await
            .unwrap_err();
        assert!(denied.to_string().contains("outside configured scope"));
        execute_line("scope add 127.0.0.1", &hub, &path)
            .await
            .unwrap();
        let mut config = Config::load(&path).unwrap();
        assert!(config.target_allowed("127.0.0.1"));
        config.prepared_workflow = vec!["binary /tmp/example".into()];
        config.save(&path).unwrap();
        assert!(
            execute_workspace_request(
                WorkspaceRequest::Command("present 1 \"binary /tmp/example\"".into()),
                &hub,
                &path,
            )
            .await
            .is_err()
        );
        assert!(
            !hub.snapshot()
                .iter()
                .any(|event| event.kind == "prepared.input")
        );
        let event = execute_workspace_request(
            WorkspaceRequest::AssistedCompletion {
                index: 1,
                text: "binary /tmp/example".into(),
            },
            &hub,
            &path,
        )
        .await
        .unwrap()
        .remove(0);
        assert_eq!(event.source, SourceKind::Prepared);
        assert_eq!(
            event
                .evidence
                .iter()
                .find(|e| e.label == "input")
                .unwrap()
                .value,
            "binary /tmp/example"
        );
        assert!(
            execute_workspace_request(
                WorkspaceRequest::AssistedCompletion {
                    index: 1,
                    text: "scan 127.0.0.1".into(),
                },
                &hub,
                &path,
            )
            .await
            .is_err()
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn workflow_and_retention_commands_validate_and_save() {
        let path = std::env::temp_dir().join(format!(
            "spectre-workflow-command-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let hub = EventHub::new(100);
        execute_line("workflow add 'binary /bin/ls'", &hub, &path)
            .await
            .unwrap();
        execute_line("workflow add 'pcap /tmp/capture.pcap'", &hub, &path)
            .await
            .unwrap();
        let listed = execute_line("workflow list", &hub, &path).await.unwrap();
        assert_eq!(listed[0].kind, "workflow.list");
        assert!(
            listed[0]
                .evidence
                .iter()
                .any(|item| item.value.contains("1. binary /bin/ls"))
        );
        assert!(
            execute_line("workflow remove 0", &hub, &path)
                .await
                .is_err()
        );
        execute_line("workflow remove 1", &hub, &path)
            .await
            .unwrap();
        assert_eq!(
            Config::load(&path).unwrap().prepared_workflow,
            vec!["pcap /tmp/capture.pcap"]
        );
        assert!(execute_line("retention set 99", &hub, &path).await.is_err());
        execute_line("retention set 500", &hub, &path)
            .await
            .unwrap();
        assert_eq!(Config::load(&path).unwrap().retention_events, 500);
        execute_line("workflow clear", &hub, &path).await.unwrap();
        assert!(Config::load(&path).unwrap().prepared_workflow.is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_http_follow_up_retains_attempted_endpoint() {
        let endpoint: SocketAddr = "192.0.2.10:443".parse().unwrap();
        let event = follow_up_error(
            "example.org",
            "https://example.org:443/",
            endpoint,
            &anyhow::anyhow!("TLS handshake failed"),
        );
        assert_eq!(event.subject.as_deref(), Some("example.org"));
        assert_eq!(event.kind, "follow_up.error");
        assert!(event.evidence.iter().any(|item| {
            item.label == "resolved_endpoint" && item.value == endpoint.to_string()
        }));
    }
}
