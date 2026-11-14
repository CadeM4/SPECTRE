//! Bounded, explicitly targeted network observations.

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use reqwest::header::{HeaderMap, HeaderName, SET_COOKIE};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, lookup_host};
use tokio::task::JoinSet;
use tokio::time::timeout as within;

use crate::model::{Event, Severity, SourceKind};

const MAX_PORTS: usize = 1024;
const MAX_ADDRESSES: usize = 8;
const MAX_CONCURRENT_CONNECTS: usize = 64;
const MAX_HEADER_CHARS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectOutcome {
    Open,
    Refused,
    TimedOut,
    OtherError,
}

/// Connect to an explicit hostname or IP and return observed open endpoints and a
/// complete accounting of the attempted connections. No port is probed unless it
/// appears in `ports`.
pub async fn scan_tcp(target: &str, ports: &[u16], timeout: Duration) -> Result<Vec<Event>> {
    let target = target.trim();
    let (lookup_target, subject) = scan_target(target)?;
    if timeout.is_zero() {
        bail!("TCP timeout must be greater than zero");
    }
    if ports.is_empty() || ports.len() > MAX_PORTS || ports.contains(&0) {
        bail!("TCP scan requires 1 to {MAX_PORTS} nonzero ports");
    }

    let selected_ports: BTreeSet<u16> = ports.iter().copied().collect();
    let resolved = within(timeout, lookup_host((lookup_target, 0)))
        .await
        .context("DNS resolution timed out")?
        .with_context(|| format!("could not resolve {target}"))?;
    let all_addresses: BTreeSet<IpAddr> = resolved.map(|socket| socket.ip()).collect();
    if all_addresses.is_empty() {
        bail!("{target} resolved to no IP addresses");
    }
    let addresses: Vec<IpAddr> = all_addresses.iter().take(MAX_ADDRESSES).copied().collect();
    let omitted_addresses = all_addresses.len().saturating_sub(addresses.len());
    let endpoints: Vec<SocketAddr> = addresses
        .iter()
        .flat_map(|ip| {
            selected_ports
                .iter()
                .map(move |port| SocketAddr::new(*ip, *port))
        })
        .collect();

    let started = Instant::now();
    let mut events = Vec::new();
    let mut open = 0usize;
    let mut refused = 0usize;
    let mut timed_out = 0usize;
    let mut other_errors = 0usize;

    // Spawn only a fixed-size batch so a large port selection cannot create an
    // unbounded task queue or retain thousands of sockets at once.
    for batch in endpoints.chunks(MAX_CONCURRENT_CONNECTS) {
        let mut tasks = JoinSet::new();
        for &endpoint in batch {
            tasks.spawn(async move {
                let (outcome, banner) = match within(timeout, TcpStream::connect(endpoint)).await {
                    Ok(Ok(mut stream)) => {
                        let mut bytes = [0u8; 256];
                        let banner = match within(
                            timeout.min(Duration::from_millis(200)),
                            stream.read(&mut bytes),
                        )
                        .await
                        {
                            Ok(Ok(length)) if length > 0 => Some(display_banner(&bytes[..length])),
                            _ => None,
                        };
                        (ConnectOutcome::Open, banner)
                    }
                    Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => {
                        (ConnectOutcome::Refused, None)
                    }
                    Ok(Err(error)) if error.kind() == ErrorKind::TimedOut => {
                        (ConnectOutcome::TimedOut, None)
                    }
                    Err(_) => (ConnectOutcome::TimedOut, None),
                    Ok(Err(_)) => (ConnectOutcome::OtherError, None),
                };
                (endpoint, outcome, banner)
            });
        }
        while let Some(result) = tasks.join_next().await {
            let (endpoint, outcome, banner) = result.context("TCP probe task failed")?;
            match outcome {
                ConnectOutcome::Open => {
                    open += 1;
                    let mut event = Event::new(
                        "network",
                        "tcp_open",
                        format!("TCP {} open on {}", endpoint.port(), endpoint.ip()),
                        Some(subject.clone()),
                        Severity::Info,
                        SourceKind::Live,
                    )
                    .with_evidence("endpoint", endpoint.to_string(), "tcp_connect")
                    .with_evidence("address", endpoint.ip().to_string(), "dns_resolution")
                    .with_evidence(
                        "port",
                        endpoint.port().to_string(),
                        "tcp_connect",
                    );
                    if let Some(hint) = conventional_port_hint(endpoint.port()) {
                        event = event.with_evidence("port_hint", hint, "iana_convention");
                    }
                    if let Some(banner) = banner {
                        if let Some(protocol) = banner_protocol(&banner) {
                            event =
                                event.with_evidence("observed_protocol", protocol, "tcp_banner");
                        }
                        event = event.with_evidence("banner", banner, "tcp_banner");
                    }
                    events.push(event);
                }
                ConnectOutcome::Refused => refused += 1,
                ConnectOutcome::TimedOut => timed_out += 1,
                ConnectOutcome::OtherError => other_errors += 1,
            }
        }
    }

    let addresses_text = addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let summary = Event::new(
        "network",
        "tcp_scan_complete",
        format!(
            "{} TCP endpoints checked; {open} open, {refused} refused, {timed_out} timed out, {other_errors} other errors",
            endpoints.len()
        ),
        Some(subject),
        Severity::Info,
        SourceKind::Live,
    )
    .with_evidence("target", target, "user_scope")
    .with_evidence("resolved_addresses", addresses_text, "dns_resolution")
    .with_evidence("omitted_addresses", omitted_addresses.to_string(), "address_limit")
    .with_evidence("ports", selected_ports.iter().map(ToString::to_string).collect::<Vec<_>>().join(","), "user_scope")
    .with_evidence("elapsed_ms", started.elapsed().as_millis().to_string(), "monotonic_clock");
    events.push(summary);
    Ok(events)
}

fn scan_target(target: &str) -> Result<(&str, String)> {
    if target.is_empty()
        || target.chars().any(char::is_whitespace)
        || target.chars().any(|ch| matches!(ch, '/' | '@' | '?' | '#'))
        || target.contains("://")
    {
        bail!("TCP target must be a single hostname or IP address");
    }
    let host = if target.starts_with('[') || target.ends_with(']') {
        let host = target
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .context("bracketed TCP target must be an IPv6 address")?;
        if !matches!(host.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
            bail!("bracketed TCP target must be an IPv6 address");
        }
        host
    } else {
        target
    };
    let subject = host
        .parse::<IpAddr>()
        .map_or_else(|_| host.to_ascii_lowercase(), |address| address.to_string());
    Ok((host, subject))
}

/// Inspect one HTTP(S) response. Redirects are deliberately not followed, so
/// the evidence describes the exact URL selected by the user.
pub async fn inspect_http(url: &str, timeout: Duration) -> Result<Vec<Event>> {
    inspect_http_at(url, timeout, None).await
}

/// Inspect a URL while optionally pinning its name to an address from a prior
/// TCP observation. The URL host remains the HTTP Host and TLS SNI identity.
pub async fn inspect_http_at(
    url: &str,
    timeout: Duration,
    endpoint: Option<SocketAddr>,
) -> Result<Vec<Event>> {
    if timeout.is_zero() {
        bail!("HTTP timeout must be greater than zero");
    }
    let mut parsed = reqwest::Url::parse(url).context("HTTP target must be an absolute URL")?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        bail!("HTTP target must use http:// or https:// and include a host");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("HTTP URL credentials are not supported; use a configured authorization method");
    }
    parsed.set_fragment(None);
    let is_https = parsed.scheme() == "https";
    let url_host = parsed.host_str().unwrap_or_default().to_owned();
    let subject = url_host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(&url_host)
        .to_owned();
    let target_url = parsed.as_str().to_owned();
    if let Some(endpoint) = endpoint {
        let requested_port = parsed
            .port_or_known_default()
            .context("HTTP URL has no usable port")?;
        if endpoint.port() != requested_port {
            bail!("pinned endpoint port does not match the URL port");
        }
        if let Ok(host_ip) = subject.parse::<IpAddr>()
            && host_ip != endpoint.ip()
        {
            bail!("pinned endpoint IP does not match the URL host");
        }
    }
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(timeout)
        .no_proxy()
        .user_agent(concat!("spectre/", env!("CARGO_PKG_VERSION")));
    if let Some(endpoint) = endpoint
        && subject.parse::<IpAddr>().is_err()
    {
        builder = builder.resolve(&url_host, endpoint);
    }
    let client = builder
        .build()
        .context("could not initialize HTTP client")?;
    let started = Instant::now();
    let response = client
        .get(parsed)
        .send()
        .await
        .with_context(|| format!("HTTP request failed for {target_url}"))?;
    let status = response.status();
    let headers = response.headers();

    let mut response_event = Event::new(
        "web",
        "http_response",
        format!("HTTP {} from {}", status.as_u16(), target_url),
        Some(subject.clone()),
        Severity::Info,
        SourceKind::Live,
    )
    .with_evidence("url", target_url.clone(), "http_request")
    .with_evidence("method", "GET", "http_request")
    .with_evidence("status", status.as_u16().to_string(), "http_response")
    .with_evidence(
        "elapsed_ms",
        started.elapsed().as_millis().to_string(),
        "monotonic_clock",
    );
    if let Some(endpoint) = endpoint {
        response_event =
            response_event.with_evidence("resolved_endpoint", endpoint.to_string(), "tcp_scan");
    }
    let mut events = vec![response_event];

    // A successful HTTPS response implies that the client's default TLS trust
    // checks accepted the peer. It does not establish a particular cipher or
    // certificate quality, which this transport does not expose.
    if is_https {
        events.push(
            Event::new(
                "web",
                "tls_trust_accepted",
                "HTTPS peer accepted by the client's TLS verifier",
                Some(subject.clone()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("url", target_url.clone(), "tls_handshake")
            .with_evidence(
                "scope",
                "trust validation only; cipher and certificate details not inspected",
                "client_capability",
            ),
        );
    }

    const OBSERVED_HEADERS: [&str; 11] = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "cache-control",
        "access-control-allow-origin",
        "location",
        "content-type",
        "server",
    ];
    for name in OBSERVED_HEADERS {
        let header_name = HeaderName::from_static(name);
        for value in headers.get_all(&header_name).iter() {
            let observed = bounded_header_value(value);
            events.push(
                Event::new(
                    "web",
                    "http_header",
                    format!("{}: {}", name, observed),
                    Some(subject.clone()),
                    Severity::Info,
                    SourceKind::Live,
                )
                .with_evidence("url", target_url.clone(), "http_request")
                .with_evidence("header", name, "http_response")
                .with_evidence("value", observed, "http_response"),
            );
        }
    }

    events.extend(hsts_events(is_https, &subject, &target_url, headers));

    for value in headers.get_all(SET_COOKIE).iter() {
        if let Some(cookie) = parse_cookie_flags(value) {
            let summary = format!(
                "Cookie {}: Secure {}, HttpOnly {}, SameSite {}",
                cookie.name,
                if cookie.secure { "set" } else { "absent" },
                if cookie.http_only { "set" } else { "absent" },
                cookie.same_site.as_deref().unwrap_or("absent")
            );
            events.push(
                Event::new(
                    "web",
                    "http_cookie",
                    summary,
                    Some(subject.clone()),
                    Severity::Info,
                    SourceKind::Live,
                )
                .with_evidence("url", target_url.clone(), "http_request")
                .with_evidence("cookie_name", cookie.name, "set_cookie_header")
                .with_evidence("secure", cookie.secure.to_string(), "set_cookie_header")
                .with_evidence(
                    "http_only",
                    cookie.http_only.to_string(),
                    "set_cookie_header",
                )
                .with_evidence(
                    "same_site",
                    cookie.same_site.unwrap_or_default(),
                    "set_cookie_header",
                ),
            );
        }
    }

    Ok(events)
}

fn hsts_events(is_https: bool, subject: &str, target_url: &str, headers: &HeaderMap) -> Vec<Event> {
    // HSTS policies do not apply to IP-literal hosts (RFC 6797, section 8.1.1).
    if !is_https || subject.parse::<IpAddr>().is_ok() {
        return Vec::new();
    }

    let mut events = Vec::new();
    match headers.get("strict-transport-security") {
        None => events.push(
            Event::new(
                "web",
                "http_header_absent",
                "Strict-Transport-Security absent from this HTTPS response",
                Some(subject.to_owned()),
                Severity::Low,
                SourceKind::Live,
            )
            .with_evidence("url", target_url, "http_request")
            .with_evidence("header", "strict-transport-security", "http_response"),
        ),
        Some(value) if parse_hsts_max_age(value).is_none() => events.push(
            Event::new(
                "web",
                "http_header_invalid",
                "Strict-Transport-Security has no valid max-age directive in this response",
                Some(subject.to_owned()),
                Severity::Low,
                SourceKind::Live,
            )
            .with_evidence("url", target_url, "http_request")
            .with_evidence("header", "strict-transport-security", "http_response")
            .with_evidence("value", bounded_header_value(value), "http_response"),
        ),
        Some(value) if parse_hsts_max_age(value) == Some(0) => events.push(
            Event::new(
                "web",
                "http_hsts_disabled",
                "Strict-Transport-Security max-age is zero in this response",
                Some(subject.to_owned()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("url", target_url, "http_request")
            .with_evidence("value", bounded_header_value(value), "http_response"),
        ),
        _ => {}
    }
    events
}

fn conventional_port_hint(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 => Some("http"),
        110 => Some("pop3"),
        143 => Some("imap"),
        443 => Some("https"),
        445 => Some("smb"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        3306 => Some("mysql"),
        5432 => Some("postgresql"),
        6379 => Some("redis"),
        8080 => Some("http-alt"),
        _ => None,
    }
}

fn display_banner(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&byte| match byte {
            b' '..=b'~' => byte as char,
            b'\r' | b'\n' | b'\t' => ' ',
            _ => '·',
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

fn banner_protocol(banner: &str) -> Option<&'static str> {
    if banner.starts_with("SSH-") {
        Some("ssh")
    } else if banner.starts_with("HTTP/") {
        Some("http")
    } else {
        None
    }
}

fn parse_hsts_max_age(value: &reqwest::header::HeaderValue) -> Option<u64> {
    let raw = value.to_str().ok()?;
    raw.split(';').find_map(|directive| {
        let (key, value) = directive.trim().split_once('=')?;
        if key.trim().eq_ignore_ascii_case("max-age") {
            value.trim().trim_matches('"').parse::<u64>().ok()
        } else {
            None
        }
    })
}

fn bounded_header_value(value: &reqwest::header::HeaderValue) -> String {
    match value.to_str() {
        Ok(text) => {
            let mut chars = text.chars();
            let bounded: String = chars.by_ref().take(MAX_HEADER_CHARS).collect();
            if chars.next().is_some() {
                format!("{bounded}…")
            } else {
                bounded
            }
        }
        Err(_) => "<non-UTF8 header value>".to_owned(),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CookieFlags {
    name: String,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
}

fn parse_cookie_flags(value: &reqwest::header::HeaderValue) -> Option<CookieFlags> {
    let raw = value.to_str().ok()?;
    let mut parts = raw.split(';');
    let first = parts.next()?.trim();
    let (name, _secret_value) = first.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }

    let mut cookie = CookieFlags {
        name: name.chars().take(128).collect(),
        secure: false,
        http_only: false,
        same_site: None,
    };
    for part in parts {
        let (key, value) = part.trim().split_once('=').unwrap_or((part.trim(), ""));
        if key.eq_ignore_ascii_case("secure") {
            cookie.secure = true;
        } else if key.eq_ignore_ascii_case("httponly") {
            cookie.http_only = true;
        } else if key.eq_ignore_ascii_case("samesite") {
            cookie.same_site = Some(value.trim().chars().take(32).collect());
        }
    }
    Some(cookie)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn tcp_scan_reports_a_real_open_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"SSH-2.0-test-server\r\n").await.unwrap();
        });
        let events = scan_tcp("127.0.0.1", &[port], Duration::from_secs(2))
            .await
            .unwrap();
        server.await.unwrap();
        assert!(events.iter().any(|event| event.kind == "tcp_open"));
        assert!(events.iter().any(|event| event.kind == "tcp_scan_complete"));
        assert!(events.iter().any(|event| {
            event
                .evidence
                .iter()
                .any(|item| item.label == "observed_protocol" && item.value == "ssh")
        }));
    }

    #[tokio::test]
    async fn tcp_scan_rejects_missing_or_implicit_scope() {
        let duration = Duration::from_secs(1);
        assert!(scan_tcp("", &[80], duration).await.is_err());
        assert!(scan_tcp("192.0.2.0/24", &[80], duration).await.is_err());
        assert!(scan_tcp("example.org", &[], duration).await.is_err());
        assert!(scan_tcp("example.org", &[0], duration).await.is_err());
    }

    #[test]
    fn scan_target_accepts_bracketed_ipv6_and_rejects_other_brackets() {
        assert_eq!(
            scan_target("[2001:0db8::1]").unwrap(),
            ("2001:0db8::1", "2001:db8::1".into())
        );
        assert_eq!(
            scan_target("EXAMPLE.ORG").unwrap(),
            ("EXAMPLE.ORG", "example.org".into())
        );
        assert!(scan_target("[example.org]").is_err());
        assert!(scan_target("[::1").is_err());
    }

    #[tokio::test]
    async fn tcp_scan_accepts_bracketed_ipv6_loopback_when_available() {
        let Ok(listener) = TcpListener::bind("[::1]:0").await else {
            return;
        };
        let port = listener.local_addr().unwrap().port();
        let events = scan_tcp("[::1]", &[port], Duration::from_secs(2))
            .await
            .unwrap();
        assert!(
            events
                .iter()
                .any(|event| event.kind == "tcp_open" && event.subject.as_deref() == Some("::1"))
        );
    }

    #[tokio::test]
    async fn http_inspection_records_headers_and_cookie_flags_without_following_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Security-Policy: default-src 'self'\r\nSet-Cookie: sid=private-value; Secure; HttpOnly; SameSite=Lax\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        });
        let events = inspect_http(&format!("http://127.0.0.1:{port}/"), Duration::from_secs(2))
            .await
            .unwrap();
        server.await.unwrap();
        assert!(
            events
                .iter()
                .any(|event| event.kind == "http_response" && event.summary.contains("302"))
        );
        assert!(events.iter().any(|event| event.kind == "http_header"
            && event.summary.contains("content-security-policy")));
        assert!(
            events
                .iter()
                .any(|event| event.kind == "http_cookie" && event.summary.contains("Secure set"))
        );
        assert!(
            !events
                .iter()
                .any(|event| event.summary.contains("private-value"))
        );
    }

    #[tokio::test]
    async fn http_follow_up_pins_address_and_keeps_hostname() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let length = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8_lossy(&request[..length]).into_owned()
        });
        let url = format!("http://spectre.invalid:{}/", endpoint.port());
        let events = inspect_http_at(&url, Duration::from_secs(2), Some(endpoint))
            .await
            .unwrap();
        let request = server.await.unwrap().to_ascii_lowercase();
        assert!(request.contains(&format!("host: spectre.invalid:{}", endpoint.port())));
        assert!(events.iter().any(|event| event.kind == "http_response"
            && event.evidence.iter().any(|item| {
                item.label == "resolved_endpoint" && item.value == endpoint.to_string()
            })));
        let wrong = SocketAddr::new(endpoint.ip(), endpoint.port() - 1);
        assert!(
            inspect_http_at(&url, Duration::from_secs(2), Some(wrong))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn pinned_ipv6_literal_rejects_a_different_address() {
        let wrong = "127.0.0.1:80".parse().unwrap();
        let error = inspect_http_at("http://[::1]:80/", Duration::from_secs(1), Some(wrong))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("pinned endpoint IP"));
    }

    #[test]
    fn cookie_parser_does_not_expose_cookie_value() {
        let header =
            reqwest::header::HeaderValue::from_static("auth=secret; httponly; samesite=Strict");
        let parsed = parse_cookie_flags(&header).unwrap();
        assert_eq!(parsed.name, "auth");
        assert!(parsed.http_only);
        assert_eq!(parsed.same_site.as_deref(), Some("Strict"));
        assert!(!format!("{parsed:?}").contains("secret"));
    }

    #[test]
    fn hsts_parser_requires_numeric_max_age() {
        let valid =
            reqwest::header::HeaderValue::from_static("max-age=31536000; includeSubDomains");
        let invalid =
            reqwest::header::HeaderValue::from_static("includeSubDomains; max-age=forever");
        assert_eq!(parse_hsts_max_age(&valid), Some(31_536_000));
        assert_eq!(parse_hsts_max_age(&invalid), None);
    }

    #[test]
    fn missing_hsts_is_reported_for_dns_names_but_not_https_ip_literals() {
        let headers = HeaderMap::new();
        assert!(hsts_events(true, "127.0.0.1", "https://127.0.0.1/", &headers).is_empty());
        assert!(hsts_events(true, "::1", "https://[::1]/", &headers).is_empty());

        let hostname_events = hsts_events(true, "example.test", "https://example.test/", &headers);
        assert_eq!(hostname_events.len(), 1);
        assert_eq!(hostname_events[0].kind, "http_header_absent");
        assert!(
            hostname_events[0]
                .evidence
                .iter()
                .any(|item| item.label == "url" && item.value == "https://example.test/")
        );
    }
}
