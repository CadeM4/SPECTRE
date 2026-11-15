//! Passive interface counters from the operating system. These describe bytes
//! crossing an interface, not packet contents, destinations, or processes.

use std::time::Duration;

use anyhow::{Context, Result};
use sysinfo::Networks;

use crate::model::{Event, Severity, SourceKind};

const MAX_SNAPSHOT_INTERFACES: usize = 16;
const MAX_SAMPLE_INTERFACES: usize = 8;

#[derive(Clone, Debug)]
struct InterfaceCounters {
    name: String,
    total_received: u64,
    total_transmitted: u64,
    received: u64,
    transmitted: u64,
    packets_received: u64,
    packets_transmitted: u64,
    ip_networks: String,
    mtu: u64,
}

fn loopback(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "lo" || name == "lo0" || name.contains("loopback")
}

fn read_interfaces(networks: &Networks) -> Vec<InterfaceCounters> {
    let mut interfaces = networks
        .iter()
        .filter_map(|(name, network)| {
            let name = name.to_string_lossy().into_owned();
            if loopback(&name) {
                return None;
            }
            Some(InterfaceCounters {
                name,
                total_received: network.total_received(),
                total_transmitted: network.total_transmitted(),
                received: network.received(),
                transmitted: network.transmitted(),
                packets_received: network.packets_received(),
                packets_transmitted: network.packets_transmitted(),
                ip_networks: network
                    .ip_networks()
                    .iter()
                    .take(8)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                mtu: network.mtu(),
            })
        })
        .collect::<Vec<_>>();
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
    interfaces
}

/// Read the current cumulative counters and interface addresses. This sends
/// no packets and needs no capture permissions.
pub fn traffic_snapshot() -> Result<Vec<Event>> {
    let networks =
        Networks::new_with_refreshed_list().context("could not read network interface counters")?;
    Ok(snapshot_events(read_interfaces(&networks)))
}

fn snapshot_events(mut interfaces: Vec<InterfaceCounters>) -> Vec<Event> {
    let observed = interfaces.len();
    interfaces.retain(|interface| {
        interface.total_received > 0
            || interface.total_transmitted > 0
            || !interface.ip_networks.is_empty()
    });
    let active_or_addressed = interfaces.len();
    interfaces.sort_by(|left, right| {
        right
            .total_received
            .saturating_add(right.total_transmitted)
            .cmp(&left.total_received.saturating_add(left.total_transmitted))
            .then_with(|| left.name.cmp(&right.name))
    });
    interfaces.truncate(MAX_SNAPSHOT_INTERFACES);
    let mut events = vec![
        Event::new(
            "traffic",
            "traffic.snapshot",
            format!(
                "{observed} nonloopback interfaces; {active_or_addressed} have addresses or counters"
            ),
            None,
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("observed_interfaces", observed.to_string(), "sysinfo")
        .with_evidence(
            "active_or_addressed_interfaces",
            active_or_addressed.to_string(),
            "sysinfo",
        )
        .with_evidence(
            "omitted_interfaces",
            active_or_addressed
                .saturating_sub(interfaces.len())
                .to_string(),
            "display_limit",
        ),
    ];
    for interface in interfaces {
        events.push(
            Event::new(
                "traffic",
                "traffic.interface",
                format!(
                    "{}: {} bytes received, {} transmitted (cumulative)",
                    interface.name, interface.total_received, interface.total_transmitted
                ),
                Some(interface.name.clone()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("interface", &interface.name, "sysinfo")
            .with_evidence(
                "total_received_bytes",
                interface.total_received.to_string(),
                "sysinfo",
            )
            .with_evidence(
                "total_transmitted_bytes",
                interface.total_transmitted.to_string(),
                "sysinfo",
            )
            .with_evidence("ip_networks", interface.ip_networks, "sysinfo")
            .with_evidence("mtu", interface.mtu.to_string(), "sysinfo"),
        );
    }
    events
}

/// Refresh an existing counter baseline and return bounded per-interface
/// deltas for the elapsed interval.
pub(crate) fn sample_networks(networks: &mut Networks, elapsed: Duration) -> Vec<Event> {
    networks.refresh(true);
    sample_events(read_interfaces(networks), elapsed)
}

fn sample_events(mut interfaces: Vec<InterfaceCounters>, elapsed: Duration) -> Vec<Event> {
    interfaces.retain(|interface| {
        interface.received > 0
            || interface.transmitted > 0
            || interface.packets_received > 0
            || interface.packets_transmitted > 0
    });
    let observed = interfaces.len();
    interfaces.sort_by(|left, right| {
        right
            .received
            .saturating_add(right.transmitted)
            .cmp(&left.received.saturating_add(left.transmitted))
            .then_with(|| left.name.cmp(&right.name))
    });
    interfaces.truncate(MAX_SAMPLE_INTERFACES);
    let elapsed_ms = elapsed.as_millis().max(1);
    let mut events = Vec::with_capacity(interfaces.len() + 1);
    for interface in interfaces {
        let received_rate = bytes_per_second(interface.received, elapsed_ms);
        let transmitted_rate = bytes_per_second(interface.transmitted, elapsed_ms);
        events.push(
            Event::new(
                "traffic",
                "traffic.sample",
                format!(
                    "{}: RX {received_rate} B/s · TX {transmitted_rate} B/s",
                    interface.name
                ),
                Some(interface.name.clone()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("interface", &interface.name, "sysinfo")
            .with_evidence("received_bytes", interface.received.to_string(), "sysinfo")
            .with_evidence(
                "transmitted_bytes",
                interface.transmitted.to_string(),
                "sysinfo",
            )
            .with_evidence(
                "received_packets",
                interface.packets_received.to_string(),
                "sysinfo",
            )
            .with_evidence(
                "transmitted_packets",
                interface.packets_transmitted.to_string(),
                "sysinfo",
            )
            .with_evidence("interval_ms", elapsed_ms.to_string(), "monotonic_clock")
            .with_evidence(
                "received_bytes_per_second",
                received_rate.to_string(),
                "counter_delta",
            )
            .with_evidence(
                "transmitted_bytes_per_second",
                transmitted_rate.to_string(),
                "counter_delta",
            ),
        );
    }
    if observed > MAX_SAMPLE_INTERFACES {
        events.push(
            Event::new(
                "traffic",
                "traffic.sample_limit",
                format!(
                    "{} additional interfaces omitted from this sample",
                    observed - MAX_SAMPLE_INTERFACES
                ),
                None,
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence(
                "omitted_interfaces",
                (observed - MAX_SAMPLE_INTERFACES).to_string(),
                "display_limit",
            ),
        );
    }
    events
}

fn bytes_per_second(bytes: u64, elapsed_ms: u128) -> u64 {
    ((u128::from(bytes) * 1_000) / elapsed_ms).min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::{InterfaceCounters, bytes_per_second, loopback, sample_events, snapshot_events};
    use std::time::Duration;

    fn counter(name: &str, received: u64, transmitted: u64) -> InterfaceCounters {
        InterfaceCounters {
            name: name.into(),
            total_received: 10_000,
            total_transmitted: 20_000,
            received,
            transmitted,
            packets_received: 3,
            packets_transmitted: 4,
            ip_networks: "192.168.1.5/24".into(),
            mtu: 1500,
        }
    }

    #[test]
    fn loopback_interfaces_are_separate_from_real_interface_counters() {
        assert!(loopback("lo0"));
        assert!(loopback("Loopback Pseudo-Interface 1"));
        assert!(!loopback("en0"));
        assert!(!loopback("eth0"));
    }

    #[test]
    fn sample_rate_uses_actual_elapsed_time_and_records_counter_origin() {
        let event =
            sample_events(vec![counter("en0", 1_500, 750)], Duration::from_millis(500)).remove(0);
        assert_eq!(event.kind, "traffic.sample");
        assert!(event.summary.contains("RX 3000 B/s · TX 1500 B/s"));
        assert!(event.evidence.iter().any(|item| {
            item.label == "received_bytes" && item.value == "1500" && item.origin == "sysinfo"
        }));
        assert_eq!(bytes_per_second(u64::MAX, 1), u64::MAX);
    }

    #[test]
    fn interface_output_is_bounded_and_reports_omissions() {
        let entries = (0..40)
            .map(|index| counter(&format!("if{index}"), 0, 0))
            .collect();
        let events = snapshot_events(entries);
        assert_eq!(events.len(), 17);
        assert!(
            events[0]
                .evidence
                .iter()
                .any(|item| item.label == "omitted_interfaces" && item.value == "24")
        );
        let mut idle = counter("en0", 0, 0);
        idle.packets_received = 0;
        idle.packets_transmitted = 0;
        assert!(sample_events(vec![idle], Duration::from_secs(1)).is_empty());
    }
}
