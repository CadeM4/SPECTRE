//! Explicit, bounded enrichment against external threat-intelligence sources.
//! No file contents are uploaded. A hash, public IP, domain, or CVE is sent only
//! when the caller requests a lookup.

use std::{
    collections::HashMap,
    env,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::OnceLock,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use chrono::{TimeZone, Utc};
use reqwest::{Client, StatusCode, Url, header};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::model::{Event, Severity, SourceKind};

const HTTP_TIMEOUT: Duration = Duration::from_secs(8);
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);
const CISA_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const MAX_REPORT_BYTES: usize = 128 * 1024;
const MAX_CISA_BYTES: usize = 4 * 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 64;
const CISA_CATALOG: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const CISA_MIRROR: &str = "https://raw.githubusercontent.com/cisagov/kev-data/refs/heads/develop/known_exploited_vulnerabilities.json";
const CIRCL_BASE: &str = "https://hashlookup.circl.lu/lookup";
const VT_BASE: &str = "https://www.virustotal.com/api/v3";
const ABUSEIPDB_CHECK: &str = "https://api.abuseipdb.com/api/v2/check";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    Auto,
    CisaKev,
    Circl,
    VirusTotal,
    AbuseIpDb,
}

impl Provider {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" | "all" => Ok(Self::Auto),
            "cisa" | "kev" | "cisa-kev" => Ok(Self::CisaKev),
            "circl" | "hashlookup" => Ok(Self::Circl),
            "vt" | "virustotal" => Ok(Self::VirusTotal),
            "abuseipdb" | "abuse" => Ok(Self::AbuseIpDb),
            _ => bail!("provider must be auto, cisa, circl, virustotal, or abuseipdb"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::CisaKev => "CISA KEV",
            Self::Circl => "CIRCL hashlookup",
            Self::VirusTotal => "VirusTotal",
            Self::AbuseIpDb => "AbuseIPDB",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntelKind {
    Ip,
    Domain,
    Hash,
    Cve,
}

impl IntelKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "ip" | "ipv4" | "ipv6" => Ok(Self::Ip),
            "domain" | "host" => Ok(Self::Domain),
            "hash" | "sha256" | "sha1" | "md5" => Ok(Self::Hash),
            "cve" => Ok(Self::Cve),
            _ => bail!("indicator kind must be ip, domain, hash, or cve"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::Hash => "hash",
            Self::Cve => "cve",
        }
    }
}

#[derive(Clone, Debug)]
struct Query {
    kind: IntelKind,
    value: String,
}

impl Query {
    fn new(kind: IntelKind, raw: &str) -> Result<Self> {
        let value = match kind {
            IntelKind::Ip => {
                let ip: IpAddr = raw.parse().context("expected a valid IP address")?;
                if !is_public_ip(ip) {
                    bail!("external IP reputation lookup requires a public IP address");
                }
                ip.to_string()
            }
            IntelKind::Domain => canonical_domain(raw)?,
            IntelKind::Hash => {
                let value = raw.trim();
                if !matches!(value.len(), 32 | 40 | 64)
                    || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    bail!("hash must be a 32, 40, or 64 character hexadecimal digest");
                }
                value.to_ascii_lowercase()
            }
            IntelKind::Cve => canonical_cve(raw)?,
        };
        Ok(Self { kind, value })
    }
}

#[derive(Clone)]
struct CachedResponse {
    at: Instant,
    status: StatusCode,
    body: Vec<u8>,
    source_url: String,
}

static CACHE: OnceLock<Mutex<HashMap<String, CachedResponse>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<String, CachedResponse>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Look up one explicitly supplied indicator. `Auto` uses all configured
/// providers that support that indicator, including keyless CISA and CIRCL.
pub async fn lookup(provider: Provider, kind: IntelKind, value: &str) -> Result<Vec<Event>> {
    let query = Query::new(kind, value)?;
    let providers = selected_providers(provider, kind)?;
    let mut events = Vec::new();
    let mut failures = Vec::new();
    for source in providers {
        match lookup_one(source, &query).await {
            Ok(mut source_events) => events.append(&mut source_events),
            Err(error) => {
                if provider != Provider::Auto {
                    return Err(error);
                }
                failures.push(format!("{}: {error}", source.as_str()));
            }
        }
    }
    if events.is_empty() {
        bail!("external lookup failed: {}", failures.join("; "));
    }
    if !failures.is_empty() {
        events.push(
            Event::new(
                "intel",
                "intel.partial_error",
                format!(
                    "Some intelligence sources could not answer: {}",
                    failures.join("; ")
                ),
                Some(query.value),
                Severity::Low,
                SourceKind::Live,
            )
            .with_evidence("lookup_kind", kind.as_str(), "explicit_query"),
        );
    }
    Ok(events)
}

fn selected_providers(provider: Provider, kind: IntelKind) -> Result<Vec<Provider>> {
    if provider != Provider::Auto {
        if !supports(provider, kind) {
            bail!(
                "{} does not support {} lookups",
                provider.as_str(),
                kind.as_str()
            );
        }
        return Ok(vec![provider]);
    }
    let sources = match kind {
        IntelKind::Cve => vec![Provider::CisaKev],
        IntelKind::Hash => {
            let mut sources = vec![Provider::Circl];
            if env_key("SPECTRE_VT_API_KEY").is_some() {
                sources.push(Provider::VirusTotal);
            }
            sources
        }
        IntelKind::Domain => {
            if env_key("SPECTRE_VT_API_KEY").is_some() {
                vec![Provider::VirusTotal]
            } else {
                bail!("domain enrichment needs SPECTRE_VT_API_KEY");
            }
        }
        IntelKind::Ip => {
            let mut sources = Vec::new();
            if env_key("SPECTRE_VT_API_KEY").is_some() {
                sources.push(Provider::VirusTotal);
            }
            if env_key("SPECTRE_ABUSEIPDB_API_KEY").is_some() {
                sources.push(Provider::AbuseIpDb);
            }
            if sources.is_empty() {
                bail!("IP enrichment needs SPECTRE_VT_API_KEY or SPECTRE_ABUSEIPDB_API_KEY");
            }
            sources
        }
    };
    Ok(sources)
}

fn supports(provider: Provider, kind: IntelKind) -> bool {
    match provider {
        Provider::Auto => true,
        Provider::CisaKev => kind == IntelKind::Cve,
        Provider::Circl => kind == IntelKind::Hash,
        Provider::VirusTotal => kind != IntelKind::Cve,
        Provider::AbuseIpDb => kind == IntelKind::Ip,
    }
}

async fn lookup_one(provider: Provider, query: &Query) -> Result<Vec<Event>> {
    match provider {
        Provider::CisaKev => lookup_cisa(query).await,
        Provider::Circl => lookup_circl(query).await,
        Provider::VirusTotal => lookup_vt(query).await,
        Provider::AbuseIpDb => lookup_abuseipdb(query).await,
        Provider::Auto => bail!("auto is not an individual intelligence source"),
    }
}

async fn lookup_cisa(query: &Query) -> Result<Vec<Event>> {
    let response = match fetch(
        CISA_CATALOG,
        "cisa-kev:canonical",
        None,
        MAX_CISA_BYTES,
        CISA_CACHE_TTL,
    )
    .await
    {
        Ok(response) if response.status.is_success() => response,
        _ => {
            let mirror = fetch(
                CISA_MIRROR,
                "cisa-kev:mirror",
                None,
                MAX_CISA_BYTES,
                CISA_CACHE_TTL,
            )
            .await
            .context("CISA catalog and official mirror were unavailable")?;
            if !mirror.status.is_success() {
                bail!("CISA catalog and official mirror returned no catalog");
            }
            mirror
        }
    };
    let json: Value =
        serde_json::from_slice(&response.body).context("invalid CISA catalog JSON")?;
    Ok(vec![parse_cisa(
        &json,
        query,
        &response.source_url,
        response.at,
    )?])
}

async fn lookup_circl(query: &Query) -> Result<Vec<Event>> {
    let algorithm = match query.value.len() {
        32 => "md5",
        40 => "sha1",
        64 => "sha256",
        _ => unreachable!("hash validation already checked the length"),
    };
    let url = format!("{CIRCL_BASE}/{algorithm}/{}", query.value);
    let response = fetch(
        &url,
        &format!("circl:{algorithm}:{}", query.value),
        None,
        MAX_REPORT_BYTES,
        CACHE_TTL,
    )
    .await?;
    if response.status == StatusCode::NOT_FOUND {
        return Ok(vec![no_record(
            "CIRCL hashlookup",
            query,
            &url,
            response.at,
        )]);
    }
    let json: Value = serde_json::from_slice(&response.body).context("invalid CIRCL response")?;
    Ok(vec![parse_circl(&json, query, &url, response.at)])
}

async fn lookup_vt(query: &Query) -> Result<Vec<Event>> {
    let key = env_key("SPECTRE_VT_API_KEY").context("set SPECTRE_VT_API_KEY to use VirusTotal")?;
    let path = match query.kind {
        IntelKind::Ip => "ip_addresses",
        IntelKind::Domain => "domains",
        IntelKind::Hash => "files",
        IntelKind::Cve => bail!("VirusTotal does not support CVE report lookups"),
    };
    let mut url = Url::parse(VT_BASE).expect("fixed VirusTotal URL is valid");
    url.path_segments_mut()
        .expect("VirusTotal URL supports path segments")
        .push(path)
        .push(&query.value);
    let source_url = url.to_string();
    let response = fetch(
        &source_url,
        &format!("vt:{}:{}", query.kind.as_str(), query.value),
        Some(("x-apikey", key.as_str())),
        MAX_REPORT_BYTES,
        CACHE_TTL,
    )
    .await?;
    if response.status == StatusCode::NOT_FOUND {
        return Ok(vec![no_record(
            "VirusTotal",
            query,
            &source_url,
            response.at,
        )]);
    }
    let json: Value =
        serde_json::from_slice(&response.body).context("invalid VirusTotal response")?;
    Ok(vec![parse_vt(&json, query, &source_url, response.at)?])
}

async fn lookup_abuseipdb(query: &Query) -> Result<Vec<Event>> {
    let key = env_key("SPECTRE_ABUSEIPDB_API_KEY")
        .context("set SPECTRE_ABUSEIPDB_API_KEY to use AbuseIPDB")?;
    let mut url = Url::parse(ABUSEIPDB_CHECK).expect("fixed AbuseIPDB URL is valid");
    url.query_pairs_mut()
        .append_pair("ipAddress", &query.value)
        .append_pair("maxAgeInDays", "90");
    let source_url = url.to_string();
    let response = fetch(
        &source_url,
        &format!("abuseipdb:{}", query.value),
        Some(("Key", key.as_str())),
        MAX_REPORT_BYTES,
        CACHE_TTL,
    )
    .await?;
    let json: Value =
        serde_json::from_slice(&response.body).context("invalid AbuseIPDB response")?;
    Ok(vec![parse_abuseipdb(
        &json,
        query,
        &source_url,
        response.at,
    )?])
}

async fn fetch(
    url: &str,
    cache_key: &str,
    auth_header: Option<(&'static str, &str)>,
    max_bytes: usize,
    ttl: Duration,
) -> Result<CachedResponse> {
    if let Some(cached) = cache().lock().await.get(cache_key).cloned()
        && cached.at.elapsed() < ttl
    {
        return Ok(cached);
    }
    let client = Client::builder()
        .timeout(HTTP_TIMEOUT)
        .connect_timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("SPECTRE/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("could not create HTTPS client")?;
    let mut request = client.get(url).header(header::ACCEPT, "application/json");
    if let Some((name, secret)) = auth_header {
        let secret = header::HeaderValue::from_str(secret)
            .context("API key has characters that cannot be sent in a header")?;
        request = request.header(name, secret);
    }
    let mut response = request
        .send()
        .await
        .context("intelligence source did not respond")?;
    let status = response.status();
    if !status.is_success() && status != StatusCode::NOT_FOUND {
        if status == StatusCode::TOO_MANY_REQUESTS {
            bail!("intelligence source rate limit reached (HTTP 429)");
        }
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            if auth_header.is_some() {
                bail!("intelligence source rejected its API key (HTTP {status})");
            }
            bail!("intelligence source denied access (HTTP {status})");
        }
        bail!("intelligence source returned HTTP {status}");
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        bail!(
            "intelligence response exceeded the {} byte limit",
            max_bytes
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("could not read intelligence response")?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            bail!(
                "intelligence response exceeded the {} byte limit",
                max_bytes
            );
        }
        body.extend_from_slice(&chunk);
    }
    let payload = CachedResponse {
        at: Instant::now(),
        status,
        body,
        source_url: url.to_owned(),
    };
    if status.is_success() || status == StatusCode::NOT_FOUND {
        let mut cached = cache().lock().await;
        if cached.len() >= MAX_CACHE_ENTRIES
            && let Some(oldest) = cached
                .iter()
                .min_by_key(|(_, response)| response.at)
                .map(|(key, _)| key.clone())
        {
            cached.remove(&oldest);
        }
        cached.insert(cache_key.to_owned(), payload.clone());
    }
    Ok(payload)
}

fn parse_cisa(json: &Value, query: &Query, url: &str, at: Instant) -> Result<Event> {
    let entries = json["vulnerabilities"]
        .as_array()
        .context("CISA catalog has no vulnerabilities array")?;
    let release = json["dateReleased"].as_str().unwrap_or("unknown");
    let mut event = if let Some(item) = entries
        .iter()
        .find(|item| item["cveID"].as_str() == Some(query.value.as_str()))
    {
        let vendor = short_field(&item["vendorProject"], 80);
        let product = short_field(&item["product"], 80);
        Event::new(
            "intel",
            "intel.cisa.known_exploited",
            format!("CISA KEV lists {}: {vendor} / {product}", query.value),
            Some(query.value.clone()),
            Severity::High,
            SourceKind::Live,
        )
        .with_evidence(
            "vulnerability_name",
            short_field(&item["vulnerabilityName"], 200),
            url,
        )
        .with_evidence("date_added", short_field(&item["dateAdded"], 32), url)
        .with_evidence(
            "ransomware_campaign_use",
            short_field(&item["knownRansomwareCampaignUse"], 32),
            url,
        )
        .with_evidence(
            "required_action",
            short_field(&item["requiredAction"], 300),
            url,
        )
        .with_evidence("due_date", short_field(&item["dueDate"], 32), url)
    } else {
        Event::new(
            "intel",
            "intel.cisa.not_listed",
            format!(
                "{} is not listed in this CISA KEV catalog release",
                query.value
            ),
            Some(query.value.clone()),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence(
            "interpretation",
            "Not listed does not mean not exploited",
            "source_scope",
        )
    };
    event = source_evidence(event, "CISA KEV", url, at)
        .with_evidence("catalog_release_utc", release, url)
        .with_evidence("catalog_entries", entries.len().to_string(), url);
    Ok(event)
}

fn parse_circl(json: &Value, query: &Query, url: &str, at: Instant) -> Event {
    let name = short_field(&json["FileName"], 180);
    let product = short_field(&json["ProductCode"]["ProductName"], 180);
    let mut event = Event::new(
        "intel",
        "intel.circl.known_file",
        format!(
            "CIRCL known-file corpus match: {}",
            if name.is_empty() { &query.value } else { &name }
        ),
        Some(query.value.clone()),
        Severity::Info,
        SourceKind::Live,
    )
    .with_evidence(
        "interpretation",
        "Known-file context is not a malware or safety verdict",
        "source_scope",
    )
    .with_evidence("file_name", name, url)
    .with_evidence("product", product, url);
    for (field, label) in [
        ("FileSize", "file_size_bytes"),
        ("MD5", "md5"),
        ("SHA-1", "sha1"),
    ] {
        if let Some(value) = json[field]
            .as_str()
            .map(str::to_owned)
            .or_else(|| json[field].as_u64().map(|number| number.to_string()))
        {
            event = event.with_evidence(label, value, url);
        }
    }
    source_evidence(event, "CIRCL hashlookup", url, at)
}

fn parse_vt(json: &Value, query: &Query, url: &str, at: Instant) -> Result<Event> {
    let attributes = json["data"]["attributes"]
        .as_object()
        .context("VirusTotal report has no attributes")?;
    let stats = attributes
        .get("last_analysis_stats")
        .and_then(Value::as_object)
        .context("VirusTotal report has no analysis statistics")?;
    let count = |name: &str| stats.get(name).and_then(Value::as_u64).unwrap_or(0);
    let malicious = count("malicious");
    let suspicious = count("suspicious");
    let harmless = count("harmless");
    let undetected = count("undetected");
    let total = malicious
        .saturating_add(suspicious)
        .saturating_add(harmless)
        .saturating_add(undetected);
    let severity = if malicious >= 10 {
        Severity::High
    } else if malicious > 0 {
        Severity::Medium
    } else if suspicious > 0 {
        Severity::Low
    } else {
        Severity::Info
    };
    let event = Event::new(
        "intel",
        "intel.vt.report",
        format!("VirusTotal report: {malicious} malicious and {suspicious} suspicious of {total} classified results"),
        Some(query.value.clone()),
        severity,
        SourceKind::Live,
    )
    .with_evidence("malicious", malicious.to_string(), url)
    .with_evidence("suspicious", suspicious.to_string(), url)
    .with_evidence("harmless", harmless.to_string(), url)
    .with_evidence("undetected", undetected.to_string(), url)
    .with_evidence("interpretation", "Provider classifications can disagree and are not proof by themselves", "source_scope");
    let mut event = source_evidence(event, "VirusTotal", url, at);
    if let Some(timestamp) = stats_timestamp(json) {
        event = event.with_evidence("last_analysis_utc", timestamp, url);
    }
    if let Some(value) = attributes.get("reputation").and_then(Value::as_i64) {
        event = event.with_evidence("community_reputation", value.to_string(), url);
    }
    Ok(event)
}

fn parse_abuseipdb(json: &Value, query: &Query, url: &str, at: Instant) -> Result<Event> {
    let data = json["data"]
        .as_object()
        .context("AbuseIPDB report has no data")?;
    let confidence = data
        .get("abuseConfidenceScore")
        .and_then(Value::as_u64)
        .context("AbuseIPDB report has no confidence score")?;
    let reports = data
        .get("totalReports")
        .and_then(Value::as_u64)
        .context("AbuseIPDB report has no report count")?;
    let severity = if confidence >= 75 && reports > 0 {
        Severity::High
    } else if confidence >= 25 && reports > 0 {
        Severity::Medium
    } else {
        Severity::Info
    };
    let event = Event::new(
        "intel",
        "intel.abuseipdb.report",
        format!("AbuseIPDB: confidence {confidence}/100, {reports} reports in the last 90 days"),
        Some(query.value.clone()),
        severity,
        SourceKind::Live,
    )
    .with_evidence("abuse_confidence_score", confidence.to_string(), url)
    .with_evidence("total_reports_90d", reports.to_string(), url)
    .with_evidence(
        "interpretation",
        "Community reports and score are context, not proof",
        "source_scope",
    );
    let mut event = source_evidence(event, "AbuseIPDB", url, at);
    for (key, label) in [
        ("lastReportedAt", "last_reported_utc"),
        ("countryCode", "country_code"),
        ("usageType", "usage_type"),
        ("isp", "isp"),
    ] {
        if let Some(value) = data.get(key).and_then(Value::as_str) {
            event = event.with_evidence(label, value.chars().take(160).collect::<String>(), url);
        }
    }
    Ok(event)
}

fn no_record(provider: &str, query: &Query, url: &str, at: Instant) -> Event {
    source_evidence(
        Event::new(
            "intel",
            "intel.no_record",
            format!("{provider} has no report for this {}", query.kind.as_str()),
            Some(query.value.clone()),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence(
            "interpretation",
            "No report is not evidence of safety",
            "source_scope",
        ),
        provider,
        url,
        at,
    )
}

fn source_evidence(event: Event, provider: &str, url: &str, at: Instant) -> Event {
    event
        .with_evidence("provider", provider, "external_source")
        .with_evidence("source_url", url, "external_source")
        .with_evidence("lookup_utc", Utc::now().to_rfc3339(), "local_clock")
        .with_evidence(
            "response_age_seconds",
            at.elapsed().as_secs().to_string(),
            "local_cache",
        )
}

fn stats_timestamp(json: &Value) -> Option<String> {
    let seconds = json["data"]["attributes"]["last_analysis_date"].as_i64()?;
    Some(Utc.timestamp_opt(seconds, 0).single()?.to_rfc3339())
}

fn short_field(value: &Value, limit: usize) -> String {
    value
        .as_str()
        .unwrap_or("")
        .chars()
        .filter(|ch| !ch.is_control())
        .take(limit)
        .collect()
}

fn env_key(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn canonical_domain(raw: &str) -> Result<String> {
    let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.len() > 253
        || !domain.is_ascii()
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                || !label
                    .bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        bail!("expected a valid public ASCII domain");
    }
    if [
        ".local",
        ".lan",
        ".internal",
        ".home.arpa",
        ".localhost",
        ".test",
        ".invalid",
        ".example",
        ".onion",
    ]
    .iter()
    .any(|suffix| domain.ends_with(suffix))
    {
        bail!("private or test domain names are not sent to external providers");
    }
    Ok(domain)
}

fn canonical_cve(raw: &str) -> Result<String> {
    let cve = raw.trim().to_ascii_uppercase();
    let mut parts = cve.split('-');
    if parts.next() != Some("CVE")
        || !parts
            .next()
            .is_some_and(|year| year.len() == 4 && year.bytes().all(|byte| byte.is_ascii_digit()))
        || !parts.next().is_some_and(|number| {
            (4..=19).contains(&number.len()) && number.bytes().all(|byte| byte.is_ascii_digit())
        })
        || parts.next().is_some()
    {
        bail!("CVE must look like CVE-2024-12345");
    }
    Ok(cve)
}

/// Report whether an observed peer is suitable for an external IP lookup.
/// Local, reserved, and documentation addresses are excluded.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_ipv4(ip),
        IpAddr::V6(ip) => public_ipv6(ip),
    }
}

fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
    {
        return false;
    }
    !matches!(
        (a, b, c),
        (0, _, _)
            | (100, 64..=127, _)
            | (192, 0, 0)
            | (192, 0, 2)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
            | (224..=255, _, _)
    )
}

fn public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_ipv4(v4);
    }
    let segments = ip.segments();
    // Global unicast is 2000::/3, excluding documentation 2001:db8::/32.
    segments[0] & 0xe000 == 0x2000 && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(kind: IntelKind, value: &str) -> Query {
        Query::new(kind, value).unwrap()
    }

    #[test]
    fn validates_external_indicator_types_before_network_use() {
        assert_eq!(
            query(IntelKind::Domain, "Example.ORG.").value,
            "example.org"
        );
        assert_eq!(
            query(IntelKind::Cve, "cve-2024-12345").value,
            "CVE-2024-12345"
        );
        assert!(Query::new(IntelKind::Domain, "host.local").is_err());
        assert!(Query::new(IntelKind::Domain, "a/b.example.org").is_err());
        assert!(Query::new(IntelKind::Ip, "192.168.1.1").is_err());
        assert!(Query::new(IntelKind::Ip, "2001:db8::1").is_err());
        assert_eq!(query(IntelKind::Ip, "8.8.8.8").value, "8.8.8.8");
        assert!(Query::new(IntelKind::Hash, "xyz").is_err());
        assert!(Query::new(IntelKind::Cve, "CVE-2024-X").is_err());
    }

    #[test]
    fn provider_matrix_rejects_unsupported_combinations() {
        assert!(selected_providers(Provider::CisaKev, IntelKind::Ip).is_err());
        assert!(selected_providers(Provider::Circl, IntelKind::Cve).is_err());
        assert_eq!(
            selected_providers(Provider::Auto, IntelKind::Cve).unwrap(),
            vec![Provider::CisaKev]
        );
        assert_eq!(
            selected_providers(Provider::Auto, IntelKind::Hash).unwrap()[0],
            Provider::Circl
        );
    }

    #[test]
    fn parses_cisa_kev_hit_and_absence_without_overclaiming() {
        let fixture = serde_json::json!({
            "dateReleased": "2026-11-01T00:00:00Z",
            "vulnerabilities": [{
                "cveID": "CVE-2024-12345",
                "vendorProject": "Vendor",
                "product": "Product",
                "vulnerabilityName": "Example vulnerability",
                "dateAdded": "2026-10-01",
                "knownRansomwareCampaignUse": "Unknown",
                "requiredAction": "Apply updates",
                "dueDate": "2026-12-01"
            }]
        });
        let hit = parse_cisa(
            &fixture,
            &query(IntelKind::Cve, "CVE-2024-12345"),
            CISA_CATALOG,
            Instant::now(),
        )
        .unwrap();
        assert_eq!(hit.kind, "intel.cisa.known_exploited");
        assert_eq!(hit.severity, Severity::High);
        assert!(
            hit.evidence
                .iter()
                .any(|item| item.label == "catalog_release_utc")
        );
        let miss = parse_cisa(
            &fixture,
            &query(IntelKind::Cve, "CVE-2024-99999"),
            CISA_CATALOG,
            Instant::now(),
        )
        .unwrap();
        assert_eq!(miss.kind, "intel.cisa.not_listed");
        assert!(
            miss.evidence
                .iter()
                .any(|item| item.value.contains("does not mean"))
        );
    }

    #[test]
    fn circl_known_file_is_context_not_safety_verdict() {
        let fixture = serde_json::json!({"FileName":"sample.bin","FileSize":"42","ProductCode":{"ProductName":"Example"}});
        let event = parse_circl(
            &fixture,
            &query(IntelKind::Hash, &"a".repeat(64)),
            "https://hashlookup.circl.lu/example",
            Instant::now(),
        );
        assert_eq!(event.kind, "intel.circl.known_file");
        assert_eq!(event.severity, Severity::Info);
        assert!(
            event
                .evidence
                .iter()
                .any(|item| item.value.contains("not a malware"))
        );
    }

    #[test]
    fn parses_vt_and_abuseipdb_provider_counts() {
        let vt = serde_json::json!({"data":{"attributes":{"last_analysis_stats":{"malicious":3,"suspicious":2,"harmless":10,"undetected":5},"last_analysis_date":1760000000}}});
        let event = parse_vt(
            &vt,
            &query(IntelKind::Domain, "example.org"),
            "https://www.virustotal.com/example",
            Instant::now(),
        )
        .unwrap();
        assert_eq!(event.severity, Severity::Medium);
        assert!(event.summary.contains("3 malicious"));
        let abuse = serde_json::json!({"data":{"abuseConfidenceScore":80,"totalReports":4,"lastReportedAt":"2026-11-01T00:00:00Z"}});
        let event = parse_abuseipdb(
            &abuse,
            &query(IntelKind::Ip, "8.8.8.8"),
            "https://api.abuseipdb.com/example",
            Instant::now(),
        )
        .unwrap();
        assert_eq!(event.severity, Severity::High);
        assert!(event.summary.contains("4 reports"));
        assert!(
            parse_vt(
                &serde_json::json!({"data":{"attributes":{}}}),
                &query(IntelKind::Domain, "example.org"),
                "https://www.virustotal.com/example",
                Instant::now(),
            )
            .is_err()
        );
        assert!(
            parse_abuseipdb(
                &serde_json::json!({"data":{}}),
                &query(IntelKind::Ip, "8.8.8.8"),
                "https://api.abuseipdb.com/example",
                Instant::now(),
            )
            .is_err()
        );
    }
}
