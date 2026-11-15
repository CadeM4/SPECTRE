//! Real, explicitly started survey of one directly connected IPv4 segment.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use if_addrs::{IfAddr, Interface};
use tokio::{net::TcpSocket, task::JoinSet, time::timeout};

use crate::model::{Event, Severity, SourceKind};

/// A small set of common TCP services for discovery. A missing response does not
/// establish that the address is unused; only replies are reported as hosts.
const SURVEY_PORTS: [u16; 8] = [22, 53, 80, 443, 445, 3389, 8080, 8443];
const CONNECT_TIMEOUT: Duration = Duration::from_millis(400);
const CONCURRENT_PROBES: usize = 128;
const MAX_WEB_FOLLOWUPS: usize = 12;
const WEB_FOLLOWUP_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LanScope {
    pub interface: String,
    pub local_ip: Ipv4Addr,
    /// Exact segment selected for this session. A connected range wider than a
    /// /24 is narrowed to the /24 containing the machine's address.
    pub cidr: String,
    /// Candidate peer addresses, excluding network, broadcast, and this host.
    pub hosts: Vec<Ipv4Addr>,
}

/// Inspect local interface configuration and the operating system's route
/// choice. UDP `connect` selects a route but sends no packet.
pub fn detect_lan() -> Result<LanScope> {
    let routed_ip = default_route_ipv4();
    let interfaces = if_addrs::get_if_addrs().context("could not read local network interfaces")?;
    let mut candidates = interfaces
        .into_iter()
        .filter_map(scope_for_interface)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        bail!("no directly connected private IPv4 segment is available");
    }
    if let Some(routed_ip) = routed_ip
        && let Some(position) = candidates.iter().position(|candidate| {
            candidate.local_ip == routed_ip && !virtual_interface(&candidate.interface)
        })
    {
        return Ok(candidates.swap_remove(position));
    }
    // When the default route uses a tunnel, a public address, or is absent,
    // choose a local wired/Wi-Fi segment rather than surveying a VPN range.
    candidates.sort_by_key(|candidate| virtual_interface(&candidate.interface));
    if virtual_interface(&candidates[0].interface) {
        bail!("no directly connected physical private IPv4 segment is available");
    }
    Ok(candidates.remove(0))
}

fn default_route_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(198, 51, 100, 1), 80)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

fn virtual_interface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "utun",
        "tun",
        "tap",
        "wg",
        "tailscale",
        "zt",
        "docker",
        "veth",
        "virbr",
        "vmnet",
        "vbox",
        "vethernet",
        "bridge",
        "br-",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

fn scope_for_interface(interface: Interface) -> Option<LanScope> {
    let IfAddr::V4(address) = interface.addr else {
        return None;
    };
    if !address.ip.is_private() || !(1..=30).contains(&address.prefixlen) {
        return None;
    }
    let (cidr, hosts) = segment(address.ip, address.prefixlen)?;
    Some(LanScope {
        interface: interface.name,
        local_ip: address.ip,
        cidr,
        hosts,
    })
}

fn segment(local_ip: Ipv4Addr, connected_prefix: u8) -> Option<(String, Vec<Ipv4Addr>)> {
    if !(1..=30).contains(&connected_prefix) {
        return None;
    }
    let surveyed_prefix = connected_prefix.max(24);
    let mask = u32::MAX << (32 - surveyed_prefix);
    let network = u32::from(local_ip) & mask;
    let broadcast = network | !mask;
    let hosts = (network + 1..broadcast)
        .map(Ipv4Addr::from)
        .filter(|&ip| ip != local_ip)
        .collect();
    Some((
        format!("{}/{surveyed_prefix}", Ipv4Addr::from(network)),
        hosts,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeOutcome {
    Open,
    Refused,
    TimedOut,
    OtherError,
}

#[derive(Default)]
struct HostResult {
    open: BTreeSet<u16>,
    refused: BTreeSet<u16>,
    timed_out: usize,
    other_errors: usize,
}

impl HostResult {
    fn responded(&self) -> bool {
        !self.open.is_empty() || !self.refused.is_empty()
    }
}

/// Perform a real TCP reachability and service survey of the segment captured
/// in `scope`. Only an explicit caller action should invoke this function.
pub async fn survey_lan(scope: &LanScope) -> Result<Vec<Event>> {
    validate_scope(scope)?;
    let active = detect_lan()?;
    if active.interface != scope.interface
        || active.local_ip != scope.local_ip
        || active.cidr != scope.cidr
    {
        bail!("the active local network changed; refresh the LAN session before surveying");
    }
    let started = Instant::now();
    let observations =
        survey_targets(scope.local_ip, &scope.hosts, &SURVEY_PORTS, CONNECT_TIMEOUT).await?;
    let mut events = Vec::new();
    let mut responded = 0usize;
    let mut open_endpoints = 0usize;
    let mut probe_errors = 0usize;
    for (address, result) in observations {
        probe_errors += result.other_errors;
        if !result.responded() {
            continue;
        }
        responded += 1;
        open_endpoints += result.open.len();
        let open_ports = joined_ports(&result.open);
        let refused_ports = joined_ports(&result.refused);
        events.push(
            Event::new(
                "lan",
                "lan.host",
                format!(
                    "{} answered TCP probes; {} open port(s)",
                    address,
                    result.open.len()
                ),
                Some(address.to_string()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("address", address.to_string(), "tcp_connect")
            .with_evidence("interface", &scope.interface, "interface_inventory")
            .with_evidence("segment", &scope.cidr, "interface_netmask")
            .with_evidence(
                "requested_source_ip",
                scope.local_ip.to_string(),
                "socket_bind_configuration",
            )
            .with_evidence("open_ports", open_ports, "tcp_connect")
            .with_evidence("refused_ports", refused_ports, "tcp_connect")
            .with_evidence(
                "timed_out_probes",
                result.timed_out.to_string(),
                "tcp_connect",
            )
            .with_evidence(
                "other_probe_errors",
                result.other_errors.to_string(),
                "tcp_connect",
            ),
        );
        for port in result.open {
            events.push(
                Event::new(
                    "lan",
                    "lan.tcp_open",
                    format!("TCP {port} open on {address}"),
                    Some(address.to_string()),
                    Severity::Info,
                    SourceKind::Live,
                )
                .with_evidence("address", address.to_string(), "tcp_connect")
                .with_evidence("port", port.to_string(), "tcp_connect")
                .with_evidence(
                    "endpoint",
                    SocketAddr::from((address, port)).to_string(),
                    "tcp_connect",
                )
                .with_evidence("segment", &scope.cidr, "interface_netmask")
                .with_evidence(
                    "requested_source_ip",
                    scope.local_ip.to_string(),
                    "socket_bind_configuration",
                ),
            );
        }
    }
    events.push(
        Event::new(
            "lan",
            "lan.survey_complete",
            format!(
                "{} addresses probed in {}; {} answered, {} open TCP endpoint(s)",
                scope.hosts.len(),
                scope.cidr,
                responded,
                open_endpoints
            ),
            Some(scope.cidr.clone()),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("interface", &scope.interface, "interface_inventory")
        .with_evidence(
            "local_ip",
            scope.local_ip.to_string(),
            "interface_inventory",
        )
        .with_evidence("segment", &scope.cidr, "interface_netmask")
        .with_evidence(
            "probed_addresses",
            scope.hosts.len().to_string(),
            "tcp_connect",
        )
        .with_evidence("responded_hosts", responded.to_string(), "tcp_connect")
        .with_evidence("open_endpoints", open_endpoints.to_string(), "tcp_connect")
        .with_evidence(
            "other_probe_errors",
            probe_errors.to_string(),
            "tcp_connect",
        )
        .with_evidence(
            "requested_source_ip",
            scope.local_ip.to_string(),
            "socket_bind_configuration",
        )
        .with_evidence(
            "probe_ports",
            joined_ports(&SURVEY_PORTS.iter().copied().collect()),
            "survey_profile",
        )
        .with_evidence(
            "timeout_ms",
            CONNECT_TIMEOUT.as_millis().to_string(),
            "survey_profile",
        )
        .with_evidence(
            "elapsed_ms",
            started.elapsed().as_millis().to_string(),
            "monotonic_clock",
        )
        .with_evidence(
            "interpretation",
            "Only TCP replies establish a responsive host; silence is inconclusive.",
            "survey_method",
        ),
    );
    let followups = web_followups(scope, &events).await?;
    events.extend(followups);
    Ok(events)
}

#[derive(Clone, Debug)]
struct WebCandidate {
    endpoint: SocketAddr,
    url: String,
    source_event_id: String,
}

fn web_url(endpoint: SocketAddr) -> Option<String> {
    let IpAddr::V4(address) = endpoint.ip() else {
        return None;
    };
    match endpoint.port() {
        80 => Some(format!("http://{address}/")),
        443 => Some(format!("https://{address}/")),
        8080 => Some(format!("http://{address}:8080/")),
        8443 => Some(format!("https://{address}:8443/")),
        _ => None,
    }
}

fn selected_web_candidates(events: &[Event]) -> (Vec<WebCandidate>, usize) {
    let candidates = events
        .iter()
        .filter(|event| event.module == "lan" && event.kind == "lan.tcp_open")
        .filter_map(|event| {
            let endpoint = event
                .evidence
                .iter()
                .find(|item| item.label == "endpoint")?
                .value
                .parse::<SocketAddr>()
                .ok()?;
            let url = web_url(endpoint)?;
            Some(WebCandidate {
                endpoint,
                url,
                source_event_id: event.id.clone(),
            })
        })
        .collect::<Vec<_>>();
    let eligible = candidates.len();
    (
        candidates.into_iter().take(MAX_WEB_FOLLOWUPS).collect(),
        eligible,
    )
}

async fn web_followups(scope: &LanScope, tcp_events: &[Event]) -> Result<Vec<Event>> {
    let (selected, eligible) = selected_web_candidates(tcp_events);
    let attempted = selected.len();
    let mut tasks = JoinSet::new();
    let source_ip = IpAddr::V4(scope.local_ip);
    for candidate in selected {
        tasks.spawn(async move {
            let outcome = super::inspect_http_at_from(
                &candidate.url,
                WEB_FOLLOWUP_TIMEOUT,
                Some(candidate.endpoint),
                source_ip,
            )
            .await;
            (candidate, outcome)
        });
    }
    let mut completed = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        completed.push(joined.context("LAN HTTP follow-up task failed")?);
    }
    completed.sort_by_key(|(candidate, _)| candidate.endpoint);
    let mut events = Vec::new();
    let mut succeeded = 0usize;
    for (candidate, outcome) in completed {
        match outcome {
            Ok(mut observed) => {
                succeeded += 1;
                for event in &mut observed {
                    event.evidence.push(crate::model::Evidence {
                        label: "source_tcp_event_id".to_owned(),
                        value: candidate.source_event_id.clone(),
                        origin: "lan.tcp_open".to_owned(),
                    });
                    event.evidence.push(crate::model::Evidence {
                        label: "local_segment".to_owned(),
                        value: scope.cidr.clone(),
                        origin: "interface_netmask".to_owned(),
                    });
                }
                events.append(&mut observed);
            }
            Err(error) => events.push(
                Event::new(
                    "lan",
                    "lan.web_followup_error",
                    format!("HTTP follow-up failed for {}: {error}", candidate.endpoint),
                    Some(candidate.endpoint.ip().to_string()),
                    Severity::Info,
                    SourceKind::Live,
                )
                .with_evidence("endpoint", candidate.endpoint.to_string(), "tcp_connect")
                .with_evidence("url", &candidate.url, "http_request")
                .with_evidence(
                    "source_tcp_event_id",
                    &candidate.source_event_id,
                    "lan.tcp_open",
                )
                .with_evidence("local_segment", &scope.cidr, "interface_netmask")
                .with_evidence(
                    "requested_source_ip",
                    scope.local_ip.to_string(),
                    "client_bind_configuration",
                )
                .with_evidence("error", error.to_string(), "http_client"),
            ),
        }
    }
    events.push(
        Event::new(
            "lan",
            "lan.web_followup_complete",
            format!(
                "HTTP follow-up: {succeeded}/{attempted} open web endpoints returned a response"
            ),
            Some(scope.cidr.clone()),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("eligible_endpoints", eligible.to_string(), "tcp_connect")
        .with_evidence("attempted_endpoints", attempted.to_string(), "http_request")
        .with_evidence("responses", succeeded.to_string(), "http_response")
        .with_evidence("errors", (attempted - succeeded).to_string(), "http_client")
        .with_evidence(
            "omitted_by_limit",
            (eligible - attempted).to_string(),
            "followup_limit",
        )
        .with_evidence("limit", MAX_WEB_FOLLOWUPS.to_string(), "followup_limit")
        .with_evidence(
            "requested_source_ip",
            scope.local_ip.to_string(),
            "client_bind_configuration",
        )
        .with_evidence(
            "timeout_ms",
            WEB_FOLLOWUP_TIMEOUT.as_millis().to_string(),
            "followup_profile",
        ),
    );
    Ok(events)
}

fn validate_scope(scope: &LanScope) -> Result<()> {
    if !scope.local_ip.is_private() {
        bail!("local survey requires a private IPv4 interface");
    }
    let (_, prefix) = scope
        .cidr
        .split_once('/')
        .context("local survey segment is missing a prefix")?;
    let prefix: u8 = prefix
        .parse()
        .context("local survey segment has an invalid prefix")?;
    let (expected_cidr, expected_hosts) =
        segment(scope.local_ip, prefix).context("local survey segment cannot be enumerated")?;
    if scope.cidr != expected_cidr || scope.hosts != expected_hosts {
        bail!("local survey addresses differ from the selected interface segment");
    }
    Ok(())
}

fn joined_ports(ports: &BTreeSet<u16>) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

async fn survey_targets(
    source_ip: Ipv4Addr,
    hosts: &[Ipv4Addr],
    ports: &[u16],
    timeout_per_probe: Duration,
) -> Result<BTreeMap<Ipv4Addr, HostResult>> {
    // Fail before probing if the chosen source address is no longer bindable.
    drop(bound_socket(source_ip)?);
    let mut observations = hosts
        .iter()
        .copied()
        .map(|address| (address, HostResult::default()))
        .collect::<BTreeMap<_, _>>();
    let endpoints = hosts
        .iter()
        .flat_map(|&address| {
            ports
                .iter()
                .map(move |&port| SocketAddr::from((address, port)))
        })
        .collect::<Vec<_>>();
    for batch in endpoints.chunks(CONCURRENT_PROBES) {
        let mut tasks = JoinSet::new();
        for &endpoint in batch {
            tasks.spawn(async move {
                // An interface address can disappear after preflight. A bind
                // failure must fail the stage, not count as a quiet host.
                let socket = bound_socket(source_ip)?;
                let outcome = match timeout(timeout_per_probe, socket.connect(endpoint)).await {
                    Ok(Ok(_)) => ProbeOutcome::Open,
                    Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => {
                        ProbeOutcome::Refused
                    }
                    Ok(Err(error)) if error.kind() == ErrorKind::TimedOut => ProbeOutcome::TimedOut,
                    Err(_) => ProbeOutcome::TimedOut,
                    Ok(Err(_)) => ProbeOutcome::OtherError,
                };
                Ok::<_, anyhow::Error>((endpoint, outcome))
            });
        }
        while let Some(joined) = tasks.join_next().await {
            let (endpoint, outcome) = joined.context("local TCP probe task failed")??;
            let IpAddr::V4(address) = endpoint.ip() else {
                unreachable!("local survey only constructs IPv4 endpoints");
            };
            let result = observations
                .get_mut(&address)
                .context("local TCP probe reported an unknown address")?;
            match outcome {
                ProbeOutcome::Open => {
                    result.open.insert(endpoint.port());
                }
                ProbeOutcome::Refused => {
                    result.refused.insert(endpoint.port());
                }
                ProbeOutcome::TimedOut => result.timed_out += 1,
                ProbeOutcome::OtherError => result.other_errors += 1,
            }
        }
    }
    Ok(observations)
}

fn bound_socket(source_ip: Ipv4Addr) -> Result<TcpSocket> {
    let socket = TcpSocket::new_v4().context("could not create local survey socket")?;
    socket
        .bind(SocketAddr::from((source_ip, 0)))
        .with_context(|| format!("could not bind local survey source IP {source_ip}"))?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::{
        LanScope, segment, selected_web_candidates, survey_targets, validate_scope,
        virtual_interface, web_url,
    };
    use crate::model::{Event, Severity, SourceKind};
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };
    use tokio::net::TcpListener;

    #[test]
    fn segment_caps_wide_subnet_to_24_and_keeps_narrower_subnet() {
        let local = Ipv4Addr::new(192, 168, 50, 10);
        let (cidr, hosts) = segment(local, 24).unwrap();
        assert_eq!(cidr, "192.168.50.0/24");
        assert_eq!(hosts.len(), 253);
        assert!(!hosts.contains(&local));
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 50, 0)));
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 50, 255)));

        let (wide_cidr, wide_hosts) = segment(local, 16).unwrap();
        assert_eq!(wide_cidr, cidr);
        assert_eq!(wide_hosts, hosts);
        let (narrow_cidr, narrow_hosts) = segment(local, 27).unwrap();
        assert_eq!(narrow_cidr, "192.168.50.0/27");
        assert_eq!(narrow_hosts.len(), 29);
    }

    #[test]
    fn survey_rejects_addresses_outside_the_selected_segment() {
        let local_ip = Ipv4Addr::new(192, 168, 50, 10);
        let (cidr, mut hosts) = segment(local_ip, 24).unwrap();
        hosts[0] = Ipv4Addr::new(203, 0, 113, 1);
        let scope = LanScope {
            interface: "test".into(),
            local_ip,
            cidr,
            hosts,
        };
        assert!(validate_scope(&scope).is_err());
    }

    #[test]
    fn tunnel_interfaces_are_not_selected_for_automatic_lan_survey() {
        assert!(virtual_interface("utun4"));
        assert!(virtual_interface("vEthernet (Default Switch)"));
        assert!(virtual_interface("bridge100"));
        assert!(virtual_interface("br-48afb5"));
        assert!(!virtual_interface("en0"));
        assert!(!virtual_interface("Wi-Fi"));
    }

    #[test]
    fn web_followups_select_only_observed_web_ports_and_use_exact_ip_urls() {
        let address = Ipv4Addr::new(192, 168, 1, 8);
        for (port, expected) in [
            (80, "http://192.168.1.8/"),
            (443, "https://192.168.1.8/"),
            (8080, "http://192.168.1.8:8080/"),
            (8443, "https://192.168.1.8:8443/"),
        ] {
            assert_eq!(
                web_url(SocketAddr::from((address, port))).as_deref(),
                Some(expected)
            );
        }
        assert!(web_url(SocketAddr::from((address, 22))).is_none());

        let open = |address: Ipv4Addr, port: u16| {
            Event::new(
                "lan",
                "lan.tcp_open",
                "observed",
                Some(address.to_string()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence(
                "endpoint",
                SocketAddr::from((address, port)).to_string(),
                "tcp_connect",
            )
        };
        let mut events = (1..=14)
            .map(|last| open(Ipv4Addr::new(192, 168, 1, last), 80))
            .collect::<Vec<_>>();
        events.push(open(address, 22));
        events.push(Event::new(
            "lan",
            "lan.survey_complete",
            "summary",
            None,
            Severity::Info,
            SourceKind::Live,
        ));
        let (selected, eligible) = selected_web_candidates(&events);
        assert_eq!(eligible, 14);
        assert_eq!(selected.len(), 12);
        assert_eq!(selected[0].url, "http://192.168.1.1/");
        assert_eq!(selected[11].url, "http://192.168.1.12/");
        assert_eq!(selected[0].source_event_id, events[0].id);
    }

    #[tokio::test]
    async fn tcp_replies_produce_real_open_and_refused_observations() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = tokio::spawn(async move { listener.accept().await.unwrap().1.ip() });
        let observations = survey_targets(
            Ipv4Addr::LOCALHOST,
            &[Ipv4Addr::LOCALHOST],
            &[port],
            Duration::from_millis(500),
        )
        .await
        .unwrap();
        assert!(observations[&Ipv4Addr::LOCALHOST].open.contains(&port));
        assert!(observations[&Ipv4Addr::LOCALHOST].responded());
        assert_eq!(accepted.await.unwrap(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn unavailable_source_bind_fails_the_survey_before_any_probe() {
        let unavailable = Ipv4Addr::new(203, 0, 113, 77);
        let error = survey_targets(
            unavailable,
            &[Ipv4Addr::LOCALHOST],
            &[80],
            Duration::from_millis(100),
        )
        .await
        .err()
        .unwrap();
        assert!(
            error
                .to_string()
                .contains("could not bind local survey source IP")
        );
    }
}
