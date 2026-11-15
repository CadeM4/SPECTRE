use std::{collections::BTreeSet, net::IpAddr};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::model::{Event, Severity, SourceKind};

const MAX_INDICATORS_PER_EVENT: usize = 4096;
const MAX_MATCHES_PER_EVENT: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorKind {
    Sha256,
    Domain,
    Ip,
}

impl IndicatorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Domain => "domain",
            Self::Ip => "ip",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Indicator {
    pub kind: IndicatorKind,
    pub value: String,
    pub label: String,
}

impl Indicator {
    pub fn parse(kind: &str, value: &str, label: &str) -> Result<Self> {
        let kind = match kind.to_ascii_lowercase().as_str() {
            "sha256" => IndicatorKind::Sha256,
            "domain" => IndicatorKind::Domain,
            "ip" => IndicatorKind::Ip,
            _ => bail!("indicator kind must be sha256, domain, or ip"),
        };
        if label.trim().is_empty() || label.len() > 256 || label.chars().any(char::is_control) {
            bail!("indicator label must contain 1 to 256 printable characters");
        }
        let value = canonical_value(kind, value)?;
        Ok(Self {
            kind,
            value,
            label: label.trim().to_owned(),
        })
    }

    pub fn validate(&self) -> Result<()> {
        Self::parse(self.kind.as_str(), &self.value, &self.label).map(|_| ())
    }
}

/// Match exact indicators against supported observations only. Derived matches are never fed back
/// into the matcher. The caller owns the indicator set and may persist the returned events.
pub fn evaluate(event: &Event, indicators: &[Indicator]) -> Vec<Event> {
    if matches!(event.source, SourceKind::Prepared | SourceKind::Derived)
        || matches!(
            event.module.as_str(),
            "command" | "config" | "presentation" | "correlation" | "detection"
        )
    {
        return Vec::new();
    }

    let observations = observation_fields(event);
    if observations.is_empty() {
        return Vec::new();
    }
    let mut matches = Vec::new();
    let mut emitted = BTreeSet::new();
    for indicator in indicators.iter().take(MAX_INDICATORS_PER_EVENT) {
        let Ok(canonical) =
            Indicator::parse(indicator.kind.as_str(), &indicator.value, &indicator.label)
        else {
            continue;
        };
        for (kind, value, field) in &observations {
            if *kind != canonical.kind || *value != canonical.value {
                continue;
            }
            let key = (
                canonical.kind,
                canonical.value.clone(),
                canonical.label.clone(),
                *field,
            );
            if !emitted.insert(key) {
                continue;
            }
            matches.push(
                Event::new(
                    "detection",
                    "indicator.match",
                    format!(
                        "Indicator match: {} {} ({})",
                        canonical.kind.as_str(),
                        canonical.value,
                        canonical.label
                    ),
                    event.subject.clone(),
                    Severity::Medium,
                    SourceKind::Derived,
                )
                .with_evidence("source_event_id", &event.id, &event.id)
                .with_evidence(
                    "source_timestamp_utc",
                    event.timestamp.to_rfc3339(),
                    &event.id,
                )
                .with_evidence("matched_field", *field, &event.id)
                .with_evidence(
                    "indicator_kind",
                    canonical.kind.as_str(),
                    "configured_indicator",
                )
                .with_evidence("indicator_value", &canonical.value, "configured_indicator")
                .with_evidence(
                    "indicator_label",
                    &canonical.label,
                    "configured_indicator",
                ),
            );
            if matches.len() >= MAX_MATCHES_PER_EVENT {
                return matches;
            }
        }
    }
    matches
}

fn observation_fields(event: &Event) -> Vec<(IndicatorKind, String, &'static str)> {
    let mut fields = Vec::new();
    match (event.module.as_str(), event.kind.as_str()) {
        ("binary", "binary.identity" | "binary.container") => {
            for evidence in event
                .evidence
                .iter()
                .filter(|item| item.label == "sha256")
                .take(2)
            {
                push_canonical(
                    &mut fields,
                    IndicatorKind::Sha256,
                    &evidence.value,
                    "evidence.sha256",
                );
            }
        }
        ("pcap", "pcap.dns_question") => {
            if let Some(subject) = &event.subject {
                let name = subject
                    .strip_suffix(']')
                    .and_then(|value| value.rsplit_once(" ["))
                    .map(|(name, _)| name)
                    .unwrap_or(subject);
                push_canonical(
                    &mut fields,
                    IndicatorKind::Domain,
                    name,
                    "subject.question_name",
                );
            }
        }
        ("pcap", "pcap.tls_sni") => {
            if let Some(subject) = &event.subject {
                push_canonical(&mut fields, IndicatorKind::Domain, subject, "subject");
            }
        }
        ("pcap", "pcap.http_host") => {
            if let Some(subject) = &event.subject {
                let host = subject
                    .rsplit_once(':')
                    .filter(|(host, port)| !host.contains(':') && port.parse::<u16>().is_ok())
                    .map(|(host, _)| host)
                    .unwrap_or(subject);
                push_canonical(&mut fields, IndicatorKind::Domain, host, "subject.host");
            }
        }
        ("web", "http_response") => {
            if let Some(subject) = &event.subject {
                let kind = if subject.parse::<IpAddr>().is_ok() {
                    IndicatorKind::Ip
                } else {
                    IndicatorKind::Domain
                };
                push_canonical(&mut fields, kind, subject, "subject");
            }
        }
        ("network", "tcp_open") | ("lan", "lan.host" | "lan.tcp_open") => {
            for evidence in event
                .evidence
                .iter()
                .filter(|item| item.label == "address")
                .take(2)
            {
                push_canonical(
                    &mut fields,
                    IndicatorKind::Ip,
                    &evidence.value,
                    "evidence.address",
                );
            }
        }
        ("pcap", "pcap.flow") => {
            for evidence in event.evidence.iter().take(16) {
                match evidence.label.as_str() {
                    "src_ip" => push_canonical(
                        &mut fields,
                        IndicatorKind::Ip,
                        &evidence.value,
                        "evidence.src_ip",
                    ),
                    "dst_ip" => push_canonical(
                        &mut fields,
                        IndicatorKind::Ip,
                        &evidence.value,
                        "evidence.dst_ip",
                    ),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    fields
}

fn push_canonical(
    fields: &mut Vec<(IndicatorKind, String, &'static str)>,
    kind: IndicatorKind,
    value: &str,
    field: &'static str,
) {
    if let Ok(value) = canonical_value(kind, value) {
        fields.push((kind, value, field));
    }
}

fn canonical_value(kind: IndicatorKind, value: &str) -> Result<String> {
    match kind {
        IndicatorKind::Sha256 => {
            if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                bail!("SHA-256 indicator must contain exactly 64 hexadecimal characters");
            }
            Ok(value.to_ascii_lowercase())
        }
        IndicatorKind::Domain => {
            let domain = value.strip_suffix('.').unwrap_or(value);
            if domain.is_empty()
                || domain.len() > 253
                || domain.parse::<IpAddr>().is_ok()
                || !domain.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
            {
                bail!("domain indicator must be an ASCII DNS hostname without a scheme or port");
            }
            Ok(domain.to_ascii_lowercase())
        }
        IndicatorKind::Ip => {
            let ip: IpAddr = value
                .parse()
                .map_err(|_| anyhow::anyhow!("IP indicator must be one IPv4 or IPv6 address"))?;
            Ok(ip.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(module: &str, kind: &str, subject: Option<&str>) -> Event {
        Event::new(
            module,
            kind,
            "observed",
            subject.map(str::to_owned),
            Severity::Info,
            SourceKind::File,
        )
    }

    #[test]
    fn validates_and_canonicalizes_indicators() {
        let hash = "A".repeat(64);
        assert_eq!(
            Indicator::parse("SHA256", &hash, " sample ").unwrap().value,
            "a".repeat(64)
        );
        assert_eq!(
            Indicator::parse("domain", "EXAMPLE.ORG.", "sample")
                .unwrap()
                .value,
            "example.org"
        );
        assert_eq!(
            Indicator::parse("ip", "2001:0db8::0001", "sample")
                .unwrap()
                .value,
            "2001:db8::1"
        );
        assert!(Indicator::parse("sha256", "a".repeat(63).as_str(), "sample").is_err());
        assert!(Indicator::parse("domain", "example..org", "sample").is_err());
        assert!(Indicator::parse("domain", "-example.org", "sample").is_err());
        assert!(Indicator::parse("ip", "192.0.2.999", "sample").is_err());
        assert!(Indicator::parse("domain", "example.org", "\n").is_err());
    }

    #[test]
    fn matches_binary_hash_with_source_provenance() {
        let hash = "b".repeat(64);
        let event = source("binary", "binary.identity", Some("/tmp/program")).with_evidence(
            "sha256",
            &hash,
            "/tmp/program",
        );
        let indicator = Indicator::parse("sha256", &hash, "research set").unwrap();
        let matches = evaluate(&event, &[indicator]);
        assert_eq!(matches.len(), 1);
        let detection = &matches[0];
        assert_eq!(detection.source, SourceKind::Derived);
        assert_eq!(detection.kind, "indicator.match");
        assert_eq!(detection.severity, Severity::Medium);
        assert_eq!(detection.subject, event.subject);
        assert!(
            detection
                .evidence
                .iter()
                .any(|item| item.label == "source_event_id" && item.value == event.id)
        );
        assert!(
            detection
                .evidence
                .iter()
                .any(|item| item.label == "matched_field" && item.value == "evidence.sha256")
        );
        assert!(
            detection
                .evidence
                .iter()
                .any(|item| item.label == "indicator_label" && item.value == "research set")
        );
    }

    #[test]
    fn matches_exact_observed_domains_and_ips() {
        let domain = Indicator::parse("domain", "example.org", "domain set").unwrap();
        let ip = Indicator::parse("ip", "192.0.2.7", "ip set").unwrap();
        let dns = source("pcap", "pcap.dns_question", Some("Example.Org [A]"));
        assert_eq!(evaluate(&dns, &[domain.clone(), ip.clone()]).len(), 1);
        let sni = source("pcap", "pcap.tls_sni", Some("example.org"));
        assert_eq!(evaluate(&sni, std::slice::from_ref(&domain)).len(), 1);
        let http_host = source("pcap", "pcap.http_host", Some("example.org:8080"));
        assert_eq!(evaluate(&http_host, std::slice::from_ref(&domain)).len(), 1);
        let web = source("web", "http_response", Some("example.org"));
        assert_eq!(evaluate(&web, std::slice::from_ref(&domain)).len(), 1);
        let tcp = source("network", "tcp_open", Some("target.example")).with_evidence(
            "address",
            "192.0.2.7",
            "dns_resolution",
        );
        assert_eq!(evaluate(&tcp, std::slice::from_ref(&ip)).len(), 1);
        let flow = source(
            "pcap",
            "pcap.flow",
            Some("192.0.2.7:1 → 198.51.100.4:2 (TCP)"),
        )
        .with_evidence("src_ip", "192.0.2.7", "capture")
        .with_evidence("dst_ip", "198.51.100.4", "capture");
        assert_eq!(evaluate(&flow, &[ip]).len(), 1);
    }

    #[test]
    fn lan_ip_matches_preserve_the_observed_event_link() {
        let indicator = Indicator::parse("ip", "192.168.1.42", "local watch").unwrap();
        for kind in ["lan.host", "lan.tcp_open"] {
            let mut observed = source("lan", kind, Some("192.168.1.42")).with_evidence(
                "address",
                "192.168.1.42",
                "tcp_connect",
            );
            observed.source = SourceKind::Live;
            let matches = evaluate(&observed, std::slice::from_ref(&indicator));
            assert_eq!(matches.len(), 1, "{kind}");
            let detection = &matches[0];
            assert_eq!(detection.subject, observed.subject);
            assert_eq!(detection.source, SourceKind::Derived);
            assert!(
                detection
                    .evidence
                    .iter()
                    .any(|item| { item.label == "source_event_id" && item.value == observed.id })
            );
            assert!(
                detection.evidence.iter().any(|item| {
                    item.label == "matched_field" && item.value == "evidence.address"
                })
            );
            assert!(evaluate(detection, std::slice::from_ref(&indicator)).is_empty());
        }

        let summary = source("lan", "lan.survey_complete", Some("192.168.1.0/24")).with_evidence(
            "address",
            "192.168.1.42",
            "unrelated_metadata",
        );
        assert!(evaluate(&summary, &[indicator]).is_empty());
    }

    #[test]
    fn rejects_derived_prepared_and_non_observation_events() {
        let hash = "c".repeat(64);
        let indicator = Indicator::parse("sha256", &hash, "sample").unwrap();
        for (module, kind, source_kind) in [
            ("binary", "binary.section", SourceKind::File),
            ("command", "binary.identity", SourceKind::Live),
            ("binary", "binary.identity", SourceKind::Prepared),
            ("binary", "binary.identity", SourceKind::Derived),
        ] {
            let mut event = source(module, kind, Some("/tmp/program")).with_evidence(
                "sha256",
                &hash,
                "/tmp/program",
            );
            event.source = source_kind;
            assert!(evaluate(&event, std::slice::from_ref(&indicator)).is_empty());
        }
        let other = source("pcap", "pcap.tls_sni", Some("other.example.org"));
        let domain = Indicator::parse("domain", "example.org", "sample").unwrap();
        assert!(evaluate(&other, &[domain]).is_empty());
    }
}
