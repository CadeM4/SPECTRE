//! Bounded projections and distinct views of observations already made by SPECTRE.
//! Keeping these projections separate from the rolling event list lets an
//! investigation remain legible when a detailed binary analysis emits hundreds
//! of section and symbol observations.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use chrono::{DateTime, Utc};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::model::{Event, Severity};

use super::{Palette, panel_block, truncate};

const MAX_HOSTS: usize = 64;
const MAX_BINARIES: usize = 32;
const MAX_INTERFACES: usize = 24;
const MAX_PROCESS_STARTS: usize = 16;
const MAX_SIGNALS: usize = 48;
const MAX_RATE_SAMPLES: usize = 36;
const MAX_CAPTURE_ROWS: usize = 24;
const MAX_DISASM_ROWS: usize = 96;
const MAX_RUNTIME_ROWS: usize = 32;
const MAX_INTEL_ROWS: usize = 32;
const STALE_AFTER_SECONDS: i64 = 45;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Scene {
    Mission,
    Network,
    Host(usize),
    Processes,
    Traffic,
    Capture,
    Runtime,
    Binary,
    Disassembly,
    BinaryDetail(usize),
    Intel,
    Timeline,
}

impl Scene {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Mission => "MISSION",
            Self::Network => "NETWORK",
            Self::Host(0) => "HOST 01",
            Self::Host(_) => "HOST 02",
            Self::Processes => "PROCESSES",
            Self::Traffic => "TRAFFIC",
            Self::Capture => "PACKETS",
            Self::Runtime => "RUNTIME",
            Self::Binary => "BINARIES",
            Self::Disassembly => "DISASM",
            Self::BinaryDetail(_) => "DOSSIER",
            Self::Intel => "THREAT INTEL",
            Self::Timeline => "SIGNALS",
        }
    }
}

#[derive(Clone, Debug)]
struct LanHost {
    address: String,
    ports: BTreeSet<u16>,
    web_status: Option<String>,
    seen: DateTime<Utc>,
    observations: VecDeque<Signal>,
}

#[derive(Clone, Debug)]
struct Survey {
    probed: String,
    responded: String,
    open_endpoints: String,
    web_responses: Option<String>,
    web_attempted: Option<String>,
    seen: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct ScopedScan {
    summary: String,
    ports: String,
    resolved: String,
    seen: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct ScopedTarget {
    target: String,
    scan: Option<ScopedScan>,
    open_endpoints: VecDeque<(String, DateTime<Utc>)>,
    web_responses: VecDeque<Signal>,
    running: bool,
}

#[derive(Clone, Debug)]
struct ProcessRow {
    name: String,
    pid: String,
    resident_bytes: u64,
    seen: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct InterfaceRow {
    name: String,
    rx_total: Option<u64>,
    tx_total: Option<u64>,
    rx_rate: u64,
    tx_rate: u64,
    rates: VecDeque<u64>,
    addresses: String,
    seen: DateTime<Utc>,
    sampled_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
struct BinaryRow {
    subject: String,
    identity: String,
    sha256: Option<String>,
    imports: Option<String>,
    section_count: Option<String>,
    summary: Option<String>,
    seen: DateTime<Utc>,
    observations: VecDeque<Signal>,
}

#[derive(Clone, Debug)]
struct Signal {
    module: String,
    summary: String,
    severity: Severity,
    seen: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct CaptureView {
    interface: String,
    packets: String,
    captured_bytes: String,
    flows: String,
    filter: String,
    stop_reason: String,
    seen: DateTime<Utc>,
    flow_rows: VecDeque<Signal>,
    name_rows: VecDeque<Signal>,
}

#[derive(Clone, Debug)]
struct InstructionRow {
    summary: String,
    flow: String,
}

#[derive(Clone, Debug)]
struct DisassemblyView {
    subject: String,
    section: String,
    architecture: String,
    instructions: String,
    calls: u64,
    branches: u64,
    returns: u64,
    sha256: String,
    seen: DateTime<Utc>,
    rows: VecDeque<InstructionRow>,
}

#[derive(Clone, Debug)]
struct RuntimeView {
    pid: String,
    subject: String,
    sample: Option<String>,
    resources: Option<String>,
    trace: Option<String>,
    hot_frames: VecDeque<String>,
    observations: VecDeque<Signal>,
    seen: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct IntelRow {
    subject: String,
    provider: String,
    kind: String,
    summary: String,
    source_url: String,
    details: Vec<(String, String)>,
    severity: Severity,
    seen: DateTime<Utc>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct LiveProjection {
    segment: Option<String>,
    survey: Option<Survey>,
    survey_running: bool,
    lan_hosts: BTreeMap<String, LanHost>,
    current_survey_hosts: BTreeSet<String>,
    recent_network: VecDeque<Signal>,
    scoped: Option<ScopedTarget>,
    scoped_active: bool,
    process_count: Option<(String, DateTime<Utc>)>,
    top_processes: Vec<ProcessRow>,
    process_starts: VecDeque<ProcessRow>,
    traffic: BTreeMap<String, InterfaceRow>,
    capture: Option<CaptureView>,
    disassembly: Option<DisassemblyView>,
    runtime: Option<RuntimeView>,
    intel: VecDeque<IntelRow>,
    host_sample: Option<(String, String, String, DateTime<Utc>)>,
    binaries: VecDeque<BinaryRow>,
    indicator_matches: u64,
    signals: VecDeque<Signal>,
    session_total: Option<String>,
    session_phase: Option<String>,
    session_status: Option<String>,
    pending_scene: Option<Scene>,
}

impl LiveProjection {
    pub(super) fn ingest(&mut self, event: &Event) {
        if matches!(
            event.kind.as_str(),
            "assisted.session.start" | "assisted.session.stage.start"
        ) && let Some(scenario) = field(event, "scenario")
        {
            self.select_scenario(scenario);
        }
        match event.kind.as_str() {
            "lan.status" => {
                self.segment = field(event, "cidr").map(str::to_owned);
            }
            "lan.host" => self.observe_host(event),
            "lan.tcp_open" => self.observe_port(event),
            "lan.survey_complete" => self.observe_survey(event),
            "lan.web_followup_complete" => {
                if let Some(survey) = self.survey.as_mut() {
                    survey.web_responses = field(event, "responses").map(str::to_owned);
                    survey.web_attempted = field(event, "attempted_endpoints").map(str::to_owned);
                }
            }
            "http_response" if field(event, "local_segment").is_some() => self.observe_web(event),
            "http_response" => self.observe_scoped_web(event),
            "tcp_open" if event.module == "network" => self.observe_scoped_open(event),
            "tcp_scan_complete" if event.module == "network" => self.observe_scoped_scan(event),
            "process.top_summary" => {
                self.process_count = field(event, "visible_processes")
                    .map(|count| (count.to_owned(), event.timestamp));
                self.top_processes.clear();
            }
            "process.top" => {
                if let Some(row) = process_row(event)
                    && self.top_processes.len() < 32
                {
                    self.top_processes.push(row);
                }
            }
            "process.start" => {
                if let Some(row) = process_row(event) {
                    push_bounded(&mut self.process_starts, row, MAX_PROCESS_STARTS);
                }
            }
            "process.inventory" => {
                self.process_count = event
                    .summary
                    .split_whitespace()
                    .next()
                    .map(|count| (count.to_owned(), event.timestamp));
            }
            "traffic.interface" | "traffic.sample" => self.observe_traffic(event),
            "capture.summary" => self.observe_capture_summary(event),
            "capture.flow" | "capture.dns_question" | "capture.tls_sni" | "capture.http_host" => {
                self.observe_capture_detail(event)
            }
            "disasm.summary" => self.observe_disassembly_summary(event),
            "disasm.instruction" => self.observe_disassembly_instruction(event),
            kind if kind.starts_with("runtime.") => self.observe_runtime(event),
            kind if kind.starts_with("intel.") => self.observe_intel(event),
            "host.sample" => {
                if let (Some(cpu), Some(used), Some(total)) = (
                    field(event, "cpu_percent"),
                    field(event, "used_memory_bytes"),
                    field(event, "total_memory_bytes"),
                ) {
                    self.host_sample = Some((
                        cpu.to_owned(),
                        used.to_owned(),
                        total.to_owned(),
                        event.timestamp,
                    ));
                }
            }
            "binary.identity" | "binary.autonomous_summary" => {
                self.observe_binary(event);
            }
            "binary.section_summary" | "binary.imports" => self.observe_binary_detail(event),
            "indicator.match" if event.module == "detection" => {
                self.indicator_matches = self.indicator_matches.saturating_add(1);
            }
            "assisted.session.start" => {
                self.session_total = field(event, "stages").map(str::to_owned);
                self.session_phase = Some("Starting investigation".to_owned());
                self.session_status = Some("RUNNING".to_owned());
            }
            "assisted.session.stage.start" => {
                let phase = field(event, "phase").unwrap_or("Stage");
                let index = field(event, "step_index").unwrap_or("?");
                self.session_phase = Some(format!("{index} · {phase}"));
                self.session_status = Some("RUNNING".to_owned());
                self.pending_scene = field(event, "command")
                    .map(super::scene_for_command)
                    .filter(|scene| {
                        matches!(
                            scene,
                            Scene::Capture | Scene::Runtime | Scene::Disassembly | Scene::Intel
                        )
                    });
                if field(event, "command").is_some_and(|command| command.starts_with("lan survey"))
                {
                    self.lan_hosts.clear();
                    self.current_survey_hosts.clear();
                    self.recent_network.clear();
                    self.survey_running = true;
                }
                self.scoped_stage_started(event);
            }
            "assisted.session.stage" => {
                let phase = field(event, "phase").unwrap_or("Stage");
                let index = field(event, "step_index").unwrap_or("?");
                self.session_phase = Some(format!("{index} · {phase}"));
                self.session_status = Some(if field(event, "status") == Some("error") {
                    "FAILED".to_owned()
                } else {
                    "COMPLETE".to_owned()
                });
                self.pending_scene = None;
                if field(event, "command").is_some_and(|command| command.starts_with("lan survey"))
                {
                    self.survey_running = false;
                }
                if let Some(scoped) = self.scoped.as_mut() {
                    scoped.running = false;
                }
            }
            "assisted.session.complete" => {
                self.pending_scene = None;
                self.session_phase = Some("Initial investigation complete".to_owned());
                self.session_status = Some(event.summary.clone());
                self.survey_running = false;
                if let Some(scoped) = self.scoped.as_mut() {
                    scoped.running = false;
                }
            }
            "assisted.session.error" => {
                self.pending_scene = None;
                self.session_phase = Some("Investigation stopped".to_owned());
                self.session_status = Some(event.summary.clone());
                self.survey_running = false;
            }
            "assisted.watch.start" => {
                self.session_phase = Some(event.summary.clone());
                self.session_status = Some("LIVE FOLLOW-UP RUNNING".to_owned());
            }
            "assisted.watch.stage.start" => {
                let phase = field(event, "phase").unwrap_or("Follow-up");
                self.session_phase = Some(format!("Live follow-up · {phase}"));
                self.session_status = Some("RUNNING".to_owned());
                self.pending_scene = field(event, "command")
                    .map(super::scene_for_command)
                    .filter(|scene| {
                        matches!(
                            scene,
                            Scene::Capture | Scene::Runtime | Scene::Disassembly | Scene::Intel
                        )
                    });
                if field(event, "command").is_some_and(|command| command.starts_with("lan survey"))
                {
                    self.lan_hosts.clear();
                    self.current_survey_hosts.clear();
                    self.recent_network.clear();
                    self.survey_running = true;
                }
            }
            "assisted.watch.stage" => {
                let phase = field(event, "phase").unwrap_or("Follow-up");
                self.session_phase = Some(format!("Live follow-up · {phase}"));
                self.session_status = Some(if field(event, "status") == Some("error") {
                    "FAILED".to_owned()
                } else {
                    "COMPLETE".to_owned()
                });
                self.pending_scene = None;
                if field(event, "command").is_some_and(|command| command.starts_with("lan survey"))
                {
                    self.survey_running = false;
                }
            }
            "assisted.watch.complete" => {
                self.pending_scene = None;
                self.session_phase = Some(event.summary.clone());
                self.session_status = Some("LIVE WATCH ACTIVE".to_owned());
                self.survey_running = false;
            }
            "assisted.watch.error" => {
                self.pending_scene = None;
                self.session_phase = Some(event.summary.clone());
                self.session_status = Some("FOLLOW-UP FAILED".to_owned());
                self.survey_running = false;
            }
            _ => {}
        }
        if is_signal(event) {
            let signal = event_signal(event);
            if event.module == "lan"
                || event.module == "web" && field(event, "local_segment").is_some()
            {
                push_bounded(&mut self.recent_network, signal.clone(), 20);
            }
            push_signal(&mut self.signals, signal);
        }
    }

    pub(super) fn available_scenes(&self) -> Vec<Scene> {
        let mut scenes = vec![Scene::Mission];
        if self.segment.is_some()
            || self.survey.is_some()
            || !self.lan_hosts.is_empty()
            || self.scoped_active
        {
            scenes.push(Scene::Network);
        }
        let featured_hosts = if self.scoped_active {
            0
        } else {
            self.featured_hosts().len()
        };
        if featured_hosts > 0 {
            scenes.push(Scene::Host(0));
        }
        if self.process_count.is_some()
            || !self.top_processes.is_empty()
            || !self.process_starts.is_empty()
        {
            scenes.push(Scene::Processes);
        }
        if !self.traffic.is_empty() || self.host_sample.is_some() {
            scenes.push(Scene::Traffic);
        }
        if self.capture.is_some() || self.pending_scene == Some(Scene::Capture) {
            scenes.push(Scene::Capture);
        }
        if self.runtime.is_some() || self.pending_scene == Some(Scene::Runtime) {
            scenes.push(Scene::Runtime);
        }
        if featured_hosts > 1 {
            scenes.push(Scene::Host(1));
        }
        if !self.binaries.is_empty() {
            scenes.push(Scene::Binary);
        }
        if self.disassembly.is_some() || self.pending_scene == Some(Scene::Disassembly) {
            scenes.push(Scene::Disassembly);
        }
        if !self.intel.is_empty() || self.pending_scene == Some(Scene::Intel) {
            scenes.push(Scene::Intel);
        }
        if !self.signals.is_empty() {
            scenes.push(Scene::Timeline);
        }
        if !self.binaries.is_empty() {
            scenes.push(Scene::BinaryDetail(0));
        }
        scenes
    }

    pub(super) fn scene_item_count(&self, scene: Scene) -> usize {
        match scene {
            Scene::Mission => 0,
            Scene::Network if self.scoped_active => self.scoped.as_ref().map_or(0, |scoped| {
                scoped.open_endpoints.len().max(scoped.web_responses.len())
            }),
            Scene::Network => self.lan_hosts.len().max(self.recent_network.len()),
            Scene::Host(index) => self
                .featured_hosts()
                .get(index)
                .map_or(0, |host| host.observations.len().max(host.ports.len())),
            Scene::Processes => self.top_processes.len().max(self.process_starts.len()),
            Scene::Traffic => self.traffic.len(),
            Scene::Capture => self.capture.as_ref().map_or(0, |capture| {
                capture.flow_rows.len().max(capture.name_rows.len())
            }),
            Scene::Runtime => self.runtime.as_ref().map_or(0, |runtime| {
                runtime.observations.len().max(runtime.hot_frames.len())
            }),
            Scene::Binary => self.binaries.len(),
            Scene::Disassembly => self.disassembly.as_ref().map_or(0, |view| view.rows.len()),
            Scene::BinaryDetail(index) => self
                .binaries
                .get(index)
                .map_or(0, |row| row.observations.len()),
            Scene::Intel => self.intel.len(),
            Scene::Timeline => self.signals.len(),
        }
    }

    pub(super) fn select_scenario(&mut self, scenario: &str) {
        if let Some(target) = scenario.strip_prefix("scoped-network:") {
            self.ensure_scoped(target);
            self.scoped_active = true;
        } else {
            self.scoped_active = false;
        }
    }

    fn featured_hosts(&self) -> Vec<&LanHost> {
        let mut hosts = self.lan_hosts.values().collect::<Vec<_>>();
        hosts.sort_by(|a, b| {
            b.ports
                .len()
                .cmp(&a.ports.len())
                .then_with(|| b.seen.cmp(&a.seen))
                .then_with(|| a.address.cmp(&b.address))
        });
        hosts.truncate(2);
        hosts
    }

    fn ensure_scoped(&mut self, target: &str) -> &mut ScopedTarget {
        if self
            .scoped
            .as_ref()
            .is_none_or(|scoped| scoped.target != target)
        {
            self.scoped = Some(ScopedTarget {
                target: target.to_owned(),
                scan: None,
                open_endpoints: VecDeque::new(),
                web_responses: VecDeque::new(),
                running: false,
            });
        }
        self.scoped.as_mut().expect("scoped target was initialized")
    }

    fn scoped_stage_started(&mut self, event: &Event) {
        let Some(target) =
            field(event, "scenario").and_then(|scenario| scenario.strip_prefix("scoped-network:"))
        else {
            return;
        };
        let command = field(event, "command").unwrap_or("");
        let scoped = self.ensure_scoped(target);
        if command.starts_with("scan ") || command.starts_with("investigate ") {
            scoped.open_endpoints.clear();
            scoped.web_responses.clear();
        }
        if command.starts_with("scan ")
            || command.starts_with("investigate ")
            || command.starts_with("http ")
        {
            scoped.running = true;
        }
    }

    fn observe_scoped_open(&mut self, event: &Event) {
        let Some(target) = event.subject.as_deref() else {
            return;
        };
        let Some(endpoint) = field(event, "endpoint") else {
            return;
        };
        let scoped = self.ensure_scoped(target);
        if !scoped
            .open_endpoints
            .iter()
            .any(|(observed, _)| observed == endpoint)
        {
            push_bounded(
                &mut scoped.open_endpoints,
                (endpoint.to_owned(), event.timestamp),
                64,
            );
        }
    }

    fn observe_scoped_scan(&mut self, event: &Event) {
        let Some(target) = field(event, "target").or(event.subject.as_deref()) else {
            return;
        };
        self.ensure_scoped(target).scan = Some(ScopedScan {
            summary: event.summary.clone(),
            ports: field(event, "ports").unwrap_or("?").to_owned(),
            resolved: field(event, "resolved_addresses").unwrap_or("?").to_owned(),
            seen: event.timestamp,
        });
    }

    fn observe_scoped_web(&mut self, event: &Event) {
        let Some(target) = event.subject.as_deref() else {
            return;
        };
        let signal = Signal {
            module: "web".to_owned(),
            summary: event.summary.clone(),
            severity: event.severity,
            seen: event.timestamp,
        };
        push_bounded(&mut self.ensure_scoped(target).web_responses, signal, 24);
    }

    fn observe_host(&mut self, event: &Event) {
        let Some(address) = event.subject.as_deref() else {
            return;
        };
        if self.current_survey_hosts.insert(address.to_owned()) {
            self.lan_hosts.remove(address);
        }
        let host = self
            .lan_hosts
            .entry(address.to_owned())
            .or_insert_with(|| LanHost {
                address: address.to_owned(),
                ports: BTreeSet::new(),
                web_status: None,
                seen: event.timestamp,
                observations: VecDeque::new(),
            });
        host.seen = event.timestamp;
        push_bounded(&mut host.observations, event_signal(event), 16);
        if let Some(segment) = field(event, "segment") {
            self.segment = Some(segment.to_owned());
        }
        trim_oldest_host(&mut self.lan_hosts);
    }

    fn observe_port(&mut self, event: &Event) {
        let Some(address) = event.subject.as_deref() else {
            return;
        };
        let Some(port) = field(event, "port").and_then(|value| value.parse::<u16>().ok()) else {
            return;
        };
        if self.current_survey_hosts.insert(address.to_owned()) {
            self.lan_hosts.remove(address);
        }
        let host = self
            .lan_hosts
            .entry(address.to_owned())
            .or_insert_with(|| LanHost {
                address: address.to_owned(),
                ports: BTreeSet::new(),
                web_status: None,
                seen: event.timestamp,
                observations: VecDeque::new(),
            });
        host.ports.insert(port);
        host.seen = event.timestamp;
        push_bounded(&mut host.observations, event_signal(event), 16);
        trim_oldest_host(&mut self.lan_hosts);
    }

    fn observe_survey(&mut self, event: &Event) {
        self.lan_hosts
            .retain(|address, _| self.current_survey_hosts.contains(address));
        self.current_survey_hosts.clear();
        let segment = field(event, "segment")
            .or(event.subject.as_deref())
            .unwrap_or("unknown segment")
            .to_owned();
        self.segment = Some(segment.clone());
        self.survey = Some(Survey {
            probed: field(event, "probed_addresses").unwrap_or("?").to_owned(),
            responded: field(event, "responded_hosts").unwrap_or("?").to_owned(),
            open_endpoints: field(event, "open_endpoints").unwrap_or("?").to_owned(),
            web_responses: None,
            web_attempted: None,
            seen: event.timestamp,
        });
    }

    fn observe_web(&mut self, event: &Event) {
        let Some(address) = event.subject.as_deref() else {
            return;
        };
        if let Some(host) = self.lan_hosts.get_mut(address) {
            host.web_status = field(event, "status").map(|status| format!("HTTP {status}"));
            host.seen = event.timestamp;
            push_bounded(&mut host.observations, event_signal(event), 16);
        }
    }

    fn observe_traffic(&mut self, event: &Event) {
        let Some(name) = field(event, "interface").or(event.subject.as_deref()) else {
            return;
        };
        let interface = self
            .traffic
            .entry(name.to_owned())
            .or_insert_with(|| InterfaceRow {
                name: name.to_owned(),
                rx_total: None,
                tx_total: None,
                rx_rate: 0,
                tx_rate: 0,
                rates: VecDeque::new(),
                addresses: String::new(),
                seen: event.timestamp,
                sampled_at: None,
            });
        interface.seen = event.timestamp;
        if event.kind == "traffic.interface" {
            interface.rx_total = field(event, "total_received_bytes").and_then(|v| v.parse().ok());
            interface.tx_total =
                field(event, "total_transmitted_bytes").and_then(|v| v.parse().ok());
            interface.addresses = field(event, "ip_networks").unwrap_or("").to_owned();
        } else {
            interface.sampled_at = Some(event.timestamp);
            interface.rx_rate = field(event, "received_bytes_per_second")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            interface.tx_rate = field(event, "transmitted_bytes_per_second")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            push_bounded(
                &mut interface.rates,
                interface.rx_rate.saturating_add(interface.tx_rate),
                MAX_RATE_SAMPLES,
            );
        }
        while self.traffic.len() > MAX_INTERFACES {
            let Some(oldest) = self
                .traffic
                .iter()
                .min_by_key(|(_, row)| row.seen)
                .map(|(name, _)| name.clone())
            else {
                break;
            };
            self.traffic.remove(&oldest);
        }
    }

    fn observe_capture_summary(&mut self, event: &Event) {
        self.capture = Some(CaptureView {
            interface: field(event, "interface")
                .or(event.subject.as_deref())
                .unwrap_or("unknown")
                .to_owned(),
            packets: field(event, "packets").unwrap_or("?").to_owned(),
            captured_bytes: field(event, "captured_bytes").unwrap_or("?").to_owned(),
            flows: field(event, "flows").unwrap_or("?").to_owned(),
            filter: field(event, "filter").unwrap_or("all packets").to_owned(),
            stop_reason: field(event, "capture_stop_reason")
                .unwrap_or("completed")
                .to_owned(),
            seen: event.timestamp,
            flow_rows: VecDeque::new(),
            name_rows: VecDeque::new(),
        });
    }

    fn observe_capture_detail(&mut self, event: &Event) {
        let view = self.capture.get_or_insert_with(|| CaptureView {
            interface: field(event, "interface").unwrap_or("unknown").to_owned(),
            packets: "?".to_owned(),
            captured_bytes: "?".to_owned(),
            flows: "?".to_owned(),
            filter: "all packets".to_owned(),
            stop_reason: "running".to_owned(),
            seen: event.timestamp,
            flow_rows: VecDeque::new(),
            name_rows: VecDeque::new(),
        });
        view.seen = event.timestamp;
        let rows = if event.kind == "capture.flow" {
            &mut view.flow_rows
        } else {
            &mut view.name_rows
        };
        push_bounded(rows, event_signal(event), MAX_CAPTURE_ROWS);
    }

    fn observe_disassembly_summary(&mut self, event: &Event) {
        self.disassembly = Some(DisassemblyView {
            subject: event
                .subject
                .clone()
                .unwrap_or_else(|| "unknown binary".to_owned()),
            section: field(event, "section").unwrap_or("?").to_owned(),
            architecture: field(event, "architecture").unwrap_or("?").to_owned(),
            instructions: field(event, "instructions_retained")
                .unwrap_or("?")
                .to_owned(),
            calls: field(event, "calls")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            branches: field(event, "branches")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            returns: field(event, "returns")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            sha256: field(event, "sha256").unwrap_or("?").to_owned(),
            seen: event.timestamp,
            rows: VecDeque::new(),
        });
    }

    fn observe_disassembly_instruction(&mut self, event: &Event) {
        let subject = event.subject.as_deref().unwrap_or("unknown binary");
        let view = self.disassembly.get_or_insert_with(|| DisassemblyView {
            subject: subject.to_owned(),
            section: field(event, "section").unwrap_or("?").to_owned(),
            architecture: "?".to_owned(),
            instructions: "?".to_owned(),
            calls: 0,
            branches: 0,
            returns: 0,
            sha256: "?".to_owned(),
            seen: event.timestamp,
            rows: VecDeque::new(),
        });
        if view.subject != subject {
            return;
        }
        view.seen = event.timestamp;
        view.rows.push_back(InstructionRow {
            summary: event.summary.clone(),
            flow: field(event, "flow").unwrap_or("linear").to_owned(),
        });
        while view.rows.len() > MAX_DISASM_ROWS {
            view.rows.pop_front();
        }
    }

    fn observe_runtime(&mut self, event: &Event) {
        let pid = field(event, "pid").unwrap_or("?");
        if self.runtime.as_ref().is_none_or(|view| view.pid != pid) {
            self.runtime = Some(RuntimeView {
                pid: pid.to_owned(),
                subject: event
                    .subject
                    .clone()
                    .unwrap_or_else(|| format!("pid:{pid}")),
                sample: None,
                resources: None,
                trace: None,
                hot_frames: VecDeque::new(),
                observations: VecDeque::new(),
                seen: event.timestamp,
            });
        }
        let view = self.runtime.as_mut().expect("runtime view initialized");
        view.seen = event.timestamp;
        match event.kind.as_str() {
            "runtime.sample" => {
                view.sample = Some(event.summary.clone());
                view.subject = event
                    .subject
                    .clone()
                    .unwrap_or_else(|| format!("pid:{pid}"));
                view.hot_frames.clear();
                if let Some(frames) = field(event, "hot_frames") {
                    for frame in frames
                        .lines()
                        .filter(|line| !line.trim().is_empty())
                        .take(16)
                    {
                        view.hot_frames.push_back(frame.trim().to_owned());
                    }
                }
            }
            "runtime.resources" => view.resources = Some(event.summary.clone()),
            "runtime.trace_summary" => view.trace = Some(event.summary.clone()),
            "runtime.socket" | "runtime.file" | "runtime.function_call" => {
                push_bounded(
                    &mut view.observations,
                    event_signal(event),
                    MAX_RUNTIME_ROWS,
                );
            }
            _ => {}
        }
    }

    fn observe_intel(&mut self, event: &Event) {
        if matches!(
            event.kind.as_str(),
            "intel.status" | "intel.enrich_complete" | "intel.enrich_error"
        ) {
            return;
        }
        let details = [
            "malicious",
            "suspicious",
            "abuse_confidence_score",
            "total_reports_90d",
            "vulnerability_name",
            "date_added",
            "due_date",
            "file_name",
            "product",
            "interpretation",
            "lookup_utc",
        ]
        .into_iter()
        .filter_map(|key| field(event, key).map(|value| (key.to_owned(), value.to_owned())))
        .collect();
        push_bounded(
            &mut self.intel,
            IntelRow {
                subject: event.subject.clone().unwrap_or_else(|| "query".to_owned()),
                provider: field(event, "provider").unwrap_or("provider").to_owned(),
                kind: event.kind.clone(),
                summary: event.summary.clone(),
                source_url: field(event, "source_url").unwrap_or("").to_owned(),
                details,
                severity: event.severity,
                seen: event.timestamp,
            },
            MAX_INTEL_ROWS,
        );
    }

    fn observe_binary(&mut self, event: &Event) {
        let Some(subject) = event.subject.as_deref() else {
            return;
        };
        let mut row = self.take_binary(subject).unwrap_or_else(|| BinaryRow {
            subject: subject.to_owned(),
            identity: String::new(),
            sha256: None,
            imports: None,
            section_count: None,
            summary: None,
            seen: event.timestamp,
            observations: VecDeque::new(),
        });
        row.seen = event.timestamp;
        push_bounded(&mut row.observations, event_signal(event), 12);
        if event.kind == "binary.identity" {
            row.identity = event.summary.clone();
            row.sha256 = field(event, "sha256").map(str::to_owned);
        } else {
            row.summary = Some(event.summary.clone());
            row.sha256 = field(event, "sha256").map(str::to_owned).or(row.sha256);
            row.section_count = field(event, "sections").map(|count| format!("{count} sections"));
            row.imports = match (field(event, "imports"), field(event, "libraries")) {
                (Some(imports), Some(libraries)) => {
                    Some(format!("{imports} imports · {libraries} libraries"))
                }
                (Some(imports), None) => Some(format!("{imports} imports")),
                _ => row.imports,
            };
            if row.identity.is_empty() {
                row.identity = "Autonomous inspection".to_owned();
            }
        }
        push_bounded(&mut self.binaries, row, MAX_BINARIES);
    }

    fn observe_binary_detail(&mut self, event: &Event) {
        let Some(subject) = event.subject.as_deref() else {
            return;
        };
        let Some(mut row) = self.take_binary(subject) else {
            return;
        };
        row.seen = event.timestamp;
        push_bounded(&mut row.observations, event_signal(event), 12);
        match event.kind.as_str() {
            "binary.section_summary" => row.section_count = Some(event.summary.clone()),
            "binary.imports" => row.imports = Some(event.summary.clone()),
            _ => {}
        }
        push_bounded(&mut self.binaries, row, MAX_BINARIES);
    }

    fn take_binary(&mut self, subject: &str) -> Option<BinaryRow> {
        let position = self
            .binaries
            .iter()
            .position(|row| row.subject == subject)?;
        self.binaries.remove(position)
    }
}

fn field<'a>(event: &'a Event, label: &str) -> Option<&'a str> {
    event
        .evidence
        .iter()
        .find(|item| item.label == label)
        .map(|item| item.value.as_str())
}

fn event_signal(event: &Event) -> Signal {
    Signal {
        module: event.module.clone(),
        summary: event.summary.clone(),
        severity: event.severity,
        seen: event.timestamp,
    }
}

fn process_row(event: &Event) -> Option<ProcessRow> {
    let pid = field(event, "pid")?.to_owned();
    let name = field(event, "name").map(str::to_owned).unwrap_or_else(|| {
        event
            .summary
            .split(" [")
            .next()
            .unwrap_or("process")
            .to_owned()
    });
    Some(ProcessRow {
        name,
        pid,
        resident_bytes: field(event, "resident_bytes")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        seen: event.timestamp,
    })
}

fn push_bounded<T>(items: &mut VecDeque<T>, value: T, max: usize) {
    items.push_front(value);
    while items.len() > max {
        items.pop_back();
    }
}

fn push_signal(signals: &mut VecDeque<Signal>, signal: Signal) {
    let per_module_limit = match signal.module.as_str() {
        "binary" => 4,
        "traffic" => 4,
        "presentation" => 4,
        "lan" | "network" => 12,
        _ => 8,
    };
    while signals
        .iter()
        .filter(|stored| stored.module == signal.module)
        .count()
        >= per_module_limit
    {
        if let Some(oldest) = signals
            .iter()
            .rposition(|stored| stored.module == signal.module)
        {
            signals.remove(oldest);
        } else {
            break;
        }
    }
    push_bounded(signals, signal, MAX_SIGNALS);
}

fn trim_oldest_host(hosts: &mut BTreeMap<String, LanHost>) {
    while hosts.len() > MAX_HOSTS {
        let Some(oldest) = hosts
            .iter()
            .min_by_key(|(_, host)| host.seen)
            .map(|(address, _)| address.clone())
        else {
            break;
        };
        hosts.remove(&oldest);
    }
}

fn is_signal(event: &Event) -> bool {
    if event.kind == "traffic.sample" {
        let rx = field(event, "received_bytes_per_second")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let tx = field(event, "transmitted_bytes_per_second")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        return rx.saturating_add(tx) > 0;
    }
    matches!(
        event.kind.as_str(),
        "lan.host"
            | "lan.tcp_open"
            | "lan.survey_complete"
            | "lan.web_followup_complete"
            | "lan.web_followup_error"
            | "tcp_open"
            | "tcp_scan_complete"
            | "http_response"
            | "process.start"
            | "process.batch"
            | "binary.autonomous_summary"
            | "capture.summary"
            | "capture.dns_question"
            | "capture.tls_sni"
            | "capture.http_host"
            | "disasm.summary"
            | "runtime.sample"
            | "runtime.resources"
            | "runtime.trace_summary"
            | "intel.cisa.known_exploited"
            | "intel.cisa.not_listed"
            | "intel.circl.known_file"
            | "intel.vt.report"
            | "intel.abuseipdb.report"
            | "intel.no_record"
            | "intel.partial_error"
            | "intel.status"
            | "intel.enrich_complete"
            | "intel.enrich_error"
            | "indicator.match"
            | "assisted.session.complete"
            | "assisted.session.error"
            | "assisted.watch.complete"
            | "assisted.watch.error"
    )
}

pub(super) fn render_scene(
    frame: &mut Frame<'_>,
    area: Rect,
    scene: Scene,
    data: &LiveProjection,
    palette: Palette,
    scroll: usize,
) {
    if area.width < 48 || area.height < 6 {
        render_panel(
            frame,
            area,
            scene_title(scene),
            vec![muted("Expand the terminal to see this view", palette)],
            palette,
        );
        return;
    }
    match scene {
        Scene::Mission => render_mission(frame, area, data, palette),
        Scene::Network if data.scoped_active => {
            render_scoped_network(frame, area, data, palette, scroll)
        }
        Scene::Network => render_network(frame, area, data, palette, scroll),
        Scene::Host(index) => render_host(frame, area, data, index, palette, scroll),
        Scene::Processes => render_processes(frame, area, data, palette, scroll),
        Scene::Traffic => render_traffic(frame, area, data, palette, scroll),
        Scene::Capture => render_capture(frame, area, data, palette, scroll),
        Scene::Runtime => render_runtime(frame, area, data, palette, scroll),
        Scene::Binary => render_binaries(frame, area, data, palette, scroll),
        Scene::Disassembly => render_disassembly(frame, area, data, palette, scroll),
        Scene::BinaryDetail(index) => {
            render_binary_detail(frame, area, data, index, palette, scroll)
        }
        Scene::Intel => render_intel(frame, area, data, palette, scroll),
        Scene::Timeline => render_timeline(frame, area, data, palette, scroll),
    }
}

fn scene_title(scene: Scene) -> &'static str {
    match scene {
        Scene::Mission => " MISSION / LIVE INVESTIGATION ",
        Scene::Network => " NETWORK / LAN SURVEY ",
        Scene::Host(_) => " HOST / LIVE DOSSIER ",
        Scene::Processes => " PROCESSES / LIVE HOST ",
        Scene::Traffic => " TRAFFIC / INTERFACES ",
        Scene::Capture => " PACKETS / LIVE CAPTURE ",
        Scene::Runtime => " RUNTIME / PROCESS INSPECTION ",
        Scene::Binary => " BINARIES / FILE INTELLIGENCE ",
        Scene::Disassembly => " DISASSEMBLY / CONTROL FLOW ",
        Scene::BinaryDetail(_) => " BINARY / INSPECTION DOSSIER ",
        Scene::Intel => " THREAT INTEL / SOURCE CONTEXT ",
        Scene::Timeline => " TIMELINE / SIGNALS ",
    }
}

fn split_vertical(area: Rect, top: u16) -> (Rect, Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(top.min(area.height)), Constraint::Min(0)])
        .split(area);
    (rows[0], rows[1])
}

fn split_horizontal(area: Rect, left_percent: u16) -> (Rect, Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(left_percent),
            Constraint::Percentage(100 - left_percent),
        ])
        .split(area);
    (cols[0], cols[1])
}

fn render_panel(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    palette: Palette,
) {
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(palette.text).bg(palette.surface))
            .block(panel_block(title, palette)),
        area,
    );
}

fn text(value: impl Into<String>, palette: Palette) -> Line<'static> {
    Line::from(Span::styled(
        value.into(),
        Style::default().fg(palette.text),
    ))
}

fn muted(value: impl Into<String>, palette: Palette) -> Line<'static> {
    Line::from(Span::styled(
        value.into(),
        Style::default().fg(palette.muted),
    ))
}

fn accent(value: impl Into<String>, palette: Palette) -> Line<'static> {
    Line::from(Span::styled(
        value.into(),
        Style::default()
            .fg(palette.accent)
            .add_modifier(Modifier::BOLD),
    ))
}

fn label_value(label: &str, value: impl Into<String>, palette: Palette) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<14} "), Style::default().fg(palette.muted)),
        Span::styled(value.into(), Style::default().fg(palette.text)),
    ])
}

fn list_title(label: &str, total: usize, scroll: usize, visible: usize) -> String {
    if total <= visible && scroll == 0 {
        return format!(" {label} ");
    }
    let start = scroll.min(total);
    let first = if start < total { start + 1 } else { 0 };
    let last = (start + visible).min(total);
    format!(" {label} / {first}–{last} OF {total} ")
}

fn clip_line(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        value.to_owned()
    } else if width == 0 {
        String::new()
    } else if width == 1 {
        "…".to_owned()
    } else {
        format!("{}…", truncate(value, width - 1))
    }
}

fn wrap_words(value: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in value.split_whitespace() {
        let word_len = word.chars().count();
        if !line.is_empty() && line.chars().count() + word_len + 1 > width {
            lines.push(line);
            line = String::new();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(&clip_line(word, width));
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

fn render_mission(frame: &mut Frame<'_>, area: Rect, data: &LiveProjection, palette: Palette) {
    let (header, body) = split_vertical(area, 5);
    let session = data
        .session_phase
        .as_deref()
        .unwrap_or("Waiting for an investigation session");
    let status = data.session_status.as_deref().unwrap_or("READY");
    let total = data.session_total.as_deref().unwrap_or("—");
    let latest = data
        .signals
        .front()
        .map(|item| item.seen.format("%H:%M:%S").to_string());
    render_panel(
        frame,
        header,
        scene_title(Scene::Mission),
        vec![
            accent(format!("{session}  /  {status}"), palette),
            muted(
                format!(
                    "{total} planned stages   ·   {} recent high-signal entries   ·   latest {}",
                    data.signals.len(),
                    latest.as_deref().unwrap_or("—")
                ),
                palette,
            ),
        ],
        palette,
    );
    if body.height < 5 {
        return;
    }
    let (left, right) = split_horizontal(body, 52);
    let mut sources = vec![
        label_value(
            "LAN",
            data.survey.as_ref().map_or_else(
                || {
                    data.segment
                        .as_ref()
                        .map(|segment| format!("{segment} observed · survey pending"))
                        .unwrap_or_else(|| "awaiting survey".to_owned())
                },
                |survey| {
                    format!(
                        "last survey {} · {}",
                        survey.seen.format("%H:%M:%S"),
                        age_label(survey.seen)
                    )
                },
            ),
            palette,
        ),
        label_value(
            "LAN RESULT",
            data.survey.as_ref().map_or_else(
                || "no completed survey".to_owned(),
                |survey| {
                    format!(
                        "{} hosts · {} TCP endpoints",
                        survey.responded, survey.open_endpoints
                    )
                },
            ),
            palette,
        ),
        label_value(
            "PROCESSES",
            data.process_count.as_ref().map_or_else(
                || "awaiting inventory".to_owned(),
                |(count, seen)| format!("{count} visible · {}", freshness(*seen)),
            ),
            palette,
        ),
        label_value(
            "TRAFFIC",
            data.traffic
                .values()
                .filter_map(|row| row.sampled_at)
                .max()
                .map_or_else(
                    || {
                        if data.traffic.is_empty() {
                            "awaiting interface samples".to_owned()
                        } else {
                            "interface snapshot · rate pending".to_owned()
                        }
                    },
                    |seen| format!("{} sampled · {}", data.traffic.len(), freshness(seen)),
                ),
            palette,
        ),
        label_value(
            "BINARIES",
            format!("{} recent dossiers", data.binaries.len()),
            palette,
        ),
        label_value(
            "INDICATORS",
            format!("{} exact matches observed", data.indicator_matches),
            palette,
        ),
    ];
    if let Some(capture) = &data.capture {
        sources.push(label_value(
            "PACKETS",
            format!(
                "{} on {} · {}",
                capture.packets,
                capture.interface,
                freshness(capture.seen)
            ),
            palette,
        ));
    }
    if let Some(runtime) = &data.runtime {
        sources.push(label_value(
            "RUNTIME",
            format!("PID {} · {}", runtime.pid, freshness(runtime.seen)),
            palette,
        ));
    }
    if let Some(disassembly) = &data.disassembly {
        sources.push(label_value(
            "DISASM",
            format!(
                "{} instructions · {}",
                disassembly.instructions,
                basename(&disassembly.subject)
            ),
            palette,
        ));
    }
    if let Some(intel) = data.intel.front() {
        sources.push(label_value(
            "INTEL",
            format!("{} · {}", intel.provider, freshness(intel.seen)),
            palette,
        ));
    }
    if let Some((cpu, used, total, seen)) = &data.host_sample {
        let used = used
            .parse::<u64>()
            .ok()
            .map(format_bytes)
            .unwrap_or_else(|| "?".to_owned());
        let total = total
            .parse::<u64>()
            .ok()
            .map(format_bytes)
            .unwrap_or_else(|| "?".to_owned());
        sources.push(label_value(
            "HOST",
            format!("CPU {cpu}% · RAM {used}/{total} · {}", freshness(*seen)),
            palette,
        ));
    }
    let room = left.height.saturating_sub(2) as usize;
    if room > sources.len() + 2 {
        sources.push(Line::raw(""));
        sources.push(muted("LATEST FINDING BY SOURCE", palette));
        let mut covered = BTreeSet::new();
        for signal in &data.signals {
            if signal.module == "presentation" || !covered.insert(signal.module.as_str()) {
                continue;
            }
            if sources.len() >= room {
                break;
            }
            sources.push(label_value(
                &signal.module.to_ascii_uppercase(),
                clip_line(
                    &format!("{} {}", signal.seen.format("%H:%M"), signal.summary),
                    left.width.saturating_sub(18) as usize,
                ),
                palette,
            ));
        }
    }
    render_panel(
        frame,
        left,
        " SOURCES / LAST OBSERVATIONS ",
        sources,
        palette,
    );
    let mut recent_area = right;
    let mut pulse = Vec::new();
    if let Some(capture) = &data.capture {
        let detail = capture
            .name_rows
            .front()
            .or_else(|| capture.flow_rows.front())
            .map_or_else(
                || format!("{} packets on {}", capture.packets, capture.interface),
                |row| row.summary.clone(),
            );
        pulse.push(label_value(
            "OBSERVED / NET",
            clip_line(&detail, right.width.saturating_sub(20) as usize),
            palette,
        ));
    }
    if let Some(runtime) = &data.runtime {
        let detail = runtime
            .observations
            .front()
            .map(|row| row.summary.as_str())
            .or(runtime.trace.as_deref())
            .or(runtime.sample.as_deref())
            .or(runtime.resources.as_deref())
            .unwrap_or("runtime inspection recorded");
        pulse.push(label_value(
            "OBSERVED / PID",
            clip_line(detail, right.width.saturating_sub(20) as usize),
            palette,
        ));
    }
    if let Some(disassembly) = &data.disassembly {
        pulse.push(label_value(
            "DECODED / FILE",
            format!(
                "{} calls · {} branches · {} returns",
                disassembly.calls, disassembly.branches, disassembly.returns
            ),
            palette,
        ));
    }
    if let Some(intel) = data.intel.front() {
        pulse.push(label_value(
            "LOOKUP / INTEL",
            clip_line(
                &format!("{}: {}", intel.provider, intel.summary),
                right.width.saturating_sub(20) as usize,
            ),
            palette,
        ));
    }
    if !pulse.is_empty() && right.height >= 13 {
        let (pulse_area, remaining) = split_vertical(right, (pulse.len() as u16 + 2).min(7));
        render_panel(
            frame,
            pulse_area,
            " INVESTIGATION PULSE / SOURCE TYPE ",
            pulse,
            palette,
        );
        recent_area = remaining;
    }
    let mut recent = Vec::new();
    for signal in data
        .signals
        .iter()
        .take(recent_area.height.saturating_sub(2) as usize)
    {
        recent.push(signal_line(
            signal,
            recent_area.width.saturating_sub(3) as usize,
            palette,
        ));
    }
    if recent.is_empty() {
        recent.push(muted("No high-signal observations yet", palette));
    }
    render_panel(
        frame,
        recent_area,
        " RECENT / HIGH SIGNAL ",
        recent,
        palette,
    );
}

fn render_network(
    frame: &mut Frame<'_>,
    area: Rect,
    data: &LiveProjection,
    palette: Palette,
    scroll: usize,
) {
    let (header, body) = split_vertical(area, 5);
    let segment = data
        .segment
        .as_deref()
        .unwrap_or("No private IPv4 segment detected");
    let mut heading = if data.survey_running {
        format!("SURVEY RUNNING  ·  {segment}")
    } else {
        format!("OBSERVED SEGMENT  ·  {segment}")
    };
    if data.survey_running && data.survey.is_some() {
        heading.push_str("  ·  prior result below");
    }
    let second = if let Some(survey) = &data.survey {
        let prefix = if data.survey_running {
            "PRIOR SURVEY"
        } else {
            "LAST SURVEY"
        };
        let web = match (&survey.web_responses, &survey.web_attempted) {
            (Some(responses), Some(attempted)) => format!(" · web {responses}/{attempted}"),
            _ => String::new(),
        };
        format!(
            "{prefix} {} · {}  ·  {} probed  ·  {} answered  ·  {} open TCP{web}",
            survey.seen.format("%H:%M:%S"),
            age_label(survey.seen),
            survey.probed,
            survey.responded,
            survey.open_endpoints
        )
    } else {
        "No completed survey yet. Results appear here when probes return.".to_owned()
    };
    render_panel(
        frame,
        header,
        scene_title(Scene::Network),
        vec![accent(heading, palette), muted(second, palette)],
        palette,
    );
    if body.height < 3 {
        return;
    }
    let (left, right) = split_horizontal(body, 55);
    let mut hosts = data.lan_hosts.values().collect::<Vec<_>>();
    hosts.sort_by(|a, b| b.seen.cmp(&a.seen).then(a.address.cmp(&b.address)));
    let host_count = hosts.len();
    let host_visible = left.height.saturating_sub(2) as usize;
    let mut host_lines = Vec::new();
    for host in hosts.into_iter().skip(scroll).take(host_visible) {
        let ports = if host.ports.is_empty() {
            "answered · no open ports observed".to_owned()
        } else {
            format!(
                "TCP {}",
                host.ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        let web = host.web_status.as_deref().unwrap_or("");
        host_lines.push(Line::from(vec![
            Span::styled("● ", Style::default().fg(palette.accent)),
            Span::styled(
                format!("{:<16}", host.address),
                Style::default().fg(palette.text),
            ),
            Span::styled(
                truncate(
                    &format!("{ports}  {web}"),
                    left.width.saturating_sub(21) as usize,
                ),
                Style::default().fg(palette.muted),
            ),
        ]));
    }
    if host_lines.is_empty() {
        if host_count == 0 {
            host_lines.push(muted(
                "No host has answered the selected TCP probes",
                palette,
            ));
            host_lines.push(muted("Silence does not establish absence", palette));
        } else {
            host_lines.push(muted("No host rows at this scroll position", palette));
        }
    }
    render_panel(
        frame,
        left,
        &list_title("HOSTS / TCP RESPONSES", host_count, scroll, host_visible),
        host_lines,
        palette,
    );
    let network_visible = right.height.saturating_sub(2) as usize;
    let network_count = data.recent_network.len();
    let mut network_lines = Vec::new();
    for signal in data
        .recent_network
        .iter()
        .skip(scroll)
        .take(network_visible)
    {
        network_lines.push(signal_line(
            signal,
            right.width.saturating_sub(3) as usize,
            palette,
        ));
    }
    if network_lines.is_empty() {
        network_lines.push(muted("No LAN service or web response yet", palette));
    }
    render_panel(
        frame,
        right,
        &list_title(
            "RECENT NETWORK SIGNALS",
            network_count,
            scroll,
            network_visible,
        ),
        network_lines,
        palette,
    );
}

fn render_host(
    frame: &mut Frame<'_>,
    area: Rect,
    data: &LiveProjection,
    index: usize,
    palette: Palette,
    scroll: usize,
) {
    let hosts = data.featured_hosts();
    let Some(host) = hosts.get(index) else {
        render_panel(
            frame,
            area,
            scene_title(Scene::Host(index)),
            vec![muted(
                "Host dossier no longer in the current survey",
                palette,
            )],
            palette,
        );
        return;
    };
    let (header, body) = split_vertical(area, 6);
    let segment = data.segment.as_deref().unwrap_or("segment unknown");
    render_panel(
        frame,
        header,
        scene_title(Scene::Host(index)),
        vec![
            accent(format!("{}  /  {}", host.address, segment), palette),
            text(
                format!(
                    "{} observed open TCP endpoints  ·  {}",
                    host.ports.len(),
                    host.web_status
                        .as_deref()
                        .unwrap_or("no HTTP response observed")
                ),
                palette,
            ),
            muted(
                format!(
                    "Last observation {} · {}  /  source: selected LAN survey",
                    host.seen.format("%H:%M:%S"),
                    age_label(host.seen)
                ),
                palette,
            ),
        ],
        palette,
    );
    if body.height < 3 {
        return;
    }
    let (left, right) = split_horizontal(body, 37);
    let visible_ports = left.height.saturating_sub(2) as usize;
    let mut ports = host
        .ports
        .iter()
        .skip(scroll)
        .take(visible_ports)
        .map(|port| accent(format!("TCP  {port}"), palette))
        .collect::<Vec<_>>();
    if ports.is_empty() {
        ports.push(muted("No open TCP endpoint observed", palette));
    }
    render_panel(
        frame,
        left,
        &list_title(
            "OPEN TCP / OBSERVED",
            host.ports.len(),
            scroll,
            visible_ports,
        ),
        ports,
        palette,
    );
    let visible_events = right.height.saturating_sub(2) as usize;
    let mut observations = host
        .observations
        .iter()
        .skip(scroll)
        .take(visible_events)
        .map(|signal| signal_line(signal, right.width.saturating_sub(3) as usize, palette))
        .collect::<Vec<_>>();
    if observations.is_empty() {
        observations.push(muted("No observation at this scroll position", palette));
    }
    render_panel(
        frame,
        right,
        &list_title(
            "HOST EVIDENCE / RECENT FIRST",
            host.observations.len(),
            scroll,
            visible_events,
        ),
        observations,
        palette,
    );
}

fn render_scoped_network(
    frame: &mut Frame<'_>,
    area: Rect,
    data: &LiveProjection,
    palette: Palette,
    scroll: usize,
) {
    let (header, body) = split_vertical(area, 5);
    let Some(scoped) = data.scoped.as_ref() else {
        render_panel(
            frame,
            area,
            " NETWORK / SCOPED TARGET ",
            vec![muted(
                "Waiting for the selected target's observations",
                palette,
            )],
            palette,
        );
        return;
    };
    let heading = if scoped.running {
        format!("TARGET {}  ·  CHECK RUNNING", scoped.target)
    } else {
        format!("TARGET {}  ·  latest observed results", scoped.target)
    };
    let scan = scoped.scan.as_ref().map_or_else(
        || "No completed TCP scan for this target yet".to_owned(),
        |scan| {
            let prefix = if scoped.running {
                "PRIOR SCAN"
            } else {
                "LAST SCAN"
            };
            format!(
                "{prefix} {} · {} · ports {} · {}",
                scan.seen.format("%H:%M:%S"),
                age_label(scan.seen),
                scan.ports,
                scan.summary
            )
        },
    );
    render_panel(
        frame,
        header,
        " NETWORK / SCOPED TARGET ",
        vec![accent(heading, palette), muted(scan, palette)],
        palette,
    );
    if body.height < 3 {
        return;
    }
    let (left, right) = split_horizontal(body, 48);
    let open_visible = left.height.saturating_sub(2) as usize;
    let mut open_lines = Vec::new();
    for (endpoint, seen) in scoped.open_endpoints.iter().skip(scroll).take(open_visible) {
        open_lines.push(Line::from(vec![
            Span::styled("● ", Style::default().fg(palette.accent)),
            Span::styled(endpoint.clone(), Style::default().fg(palette.text)),
            Span::styled(
                format!(" · {}", seen.format("%H:%M:%S")),
                Style::default().fg(palette.muted),
            ),
        ]));
    }
    if open_lines.is_empty() {
        open_lines.push(muted("No open TCP endpoint observed in this scan", palette));
    }
    render_panel(
        frame,
        left,
        &list_title(
            "OPEN ENDPOINTS",
            scoped.open_endpoints.len(),
            scroll,
            open_visible,
        ),
        open_lines,
        palette,
    );
    let web_visible = right.height.saturating_sub(2) as usize;
    let mut web_lines = Vec::new();
    if let Some(scan) = &scoped.scan {
        web_lines.push(muted(
            format!(
                "Resolved: {}",
                truncate(&scan.resolved, right.width.saturating_sub(13) as usize)
            ),
            palette,
        ));
    }
    for signal in scoped
        .web_responses
        .iter()
        .skip(scroll)
        .take(web_visible.saturating_sub(web_lines.len()))
    {
        web_lines.push(signal_line(
            signal,
            right.width.saturating_sub(3) as usize,
            palette,
        ));
    }
    if scoped.web_responses.is_empty() {
        web_lines.push(muted("No HTTP response observed for this target", palette));
    }
    render_panel(
        frame,
        right,
        &list_title(
            "SCOPED WEB RESPONSES",
            scoped.web_responses.len(),
            scroll,
            web_visible,
        ),
        web_lines,
        palette,
    );
}

fn render_processes(
    frame: &mut Frame<'_>,
    area: Rect,
    data: &LiveProjection,
    palette: Palette,
    scroll: usize,
) {
    let (header, body) = split_vertical(area, 5);
    let inventory = data.process_count.as_ref().map_or_else(
        || "Process inventory pending".to_owned(),
        |(count, seen)| {
            format!(
                "{count} processes visible at {} · {}",
                seen.format("%H:%M:%S"),
                freshness(*seen)
            )
        },
    );
    let top_age = data.top_processes.first().map_or_else(
        || "Top-process snapshot pending".to_owned(),
        |row| format!("Top-process snapshot · {}", freshness(row.seen)),
    );
    render_panel(
        frame,
        header,
        scene_title(Scene::Processes),
        vec![
            accent(inventory, palette),
            muted(
                format!("{top_age}  ·  last {} starts", data.process_starts.len()),
                palette,
            ),
        ],
        palette,
    );
    if body.height < 3 {
        return;
    }
    let (left, right) = split_horizontal(body, 53);
    let mut top = Vec::new();
    let top_visible = left.height.saturating_sub(2) as usize;
    let largest = data
        .top_processes
        .iter()
        .map(|row| row.resident_bytes)
        .max()
        .unwrap_or(0);
    for (index, row) in data
        .top_processes
        .iter()
        .skip(scroll)
        .take(top_visible)
        .enumerate()
    {
        let bar = scaled_bar(row.resident_bytes, largest, 8);
        top.push(Line::from(vec![
            Span::styled(
                format!("{:>2} ", scroll + index + 1),
                Style::default().fg(palette.muted),
            ),
            Span::styled(format!("{bar} "), Style::default().fg(palette.accent)),
            Span::styled(
                truncate(&row.name, left.width.saturating_sub(27) as usize),
                Style::default().fg(palette.text),
            ),
            Span::styled(
                format!("  {}", format_bytes(row.resident_bytes)),
                Style::default().fg(palette.muted),
            ),
        ]));
    }
    if top.is_empty() {
        top.push(muted(
            "A live top-process snapshot has not arrived",
            palette,
        ));
    }
    render_panel(
        frame,
        left,
        &list_title(
            "TOP / RESIDENT MEMORY",
            data.top_processes.len(),
            scroll,
            top_visible,
        ),
        top,
        palette,
    );
    let mut starts = Vec::new();
    let starts_visible = right.height.saturating_sub(2) as usize;
    for row in data.process_starts.iter().skip(scroll).take(starts_visible) {
        starts.push(Line::from(vec![
            Span::styled(
                format!("{} ", row.seen.format("%H:%M:%S")),
                Style::default().fg(palette.muted),
            ),
            Span::styled(
                truncate(
                    &format!("{} [{}]", row.name, row.pid),
                    right.width.saturating_sub(13) as usize,
                ),
                Style::default().fg(palette.text),
            ),
        ]));
    }
    if starts.is_empty() {
        starts.push(muted(
            "No new process start observed in this session",
            palette,
        ));
    }
    render_panel(
        frame,
        right,
        &list_title(
            "NEW EXECUTIONS / OBSERVED",
            data.process_starts.len(),
            scroll,
            starts_visible,
        ),
        starts,
        palette,
    );
}

fn render_traffic(
    frame: &mut Frame<'_>,
    area: Rect,
    data: &LiveProjection,
    palette: Palette,
    scroll: usize,
) {
    let (header, body) = split_vertical(area, 5);
    let fresh_interfaces = data
        .traffic
        .values()
        .filter(|interface| fresh_rate(interface))
        .collect::<Vec<_>>();
    let rx = data
        .traffic
        .values()
        .filter(|interface| fresh_rate(interface))
        .fold(0u64, |total, item| total.saturating_add(item.rx_rate));
    let tx = data
        .traffic
        .values()
        .filter(|interface| fresh_rate(interface))
        .fold(0u64, |total, item| total.saturating_add(item.tx_rate));
    let latest_sample = data.traffic.values().filter_map(|row| row.sampled_at).max();
    let rates = if fresh_interfaces.is_empty() {
        latest_sample.map_or_else(
            || {
                format!(
                    "{} interfaces observed · rate samples pending",
                    data.traffic.len()
                )
            },
            |seen| {
                format!(
                    "Rates STALE · last sample {} · {}",
                    seen.format("%H:%M:%S"),
                    age_label(seen)
                )
            },
        )
    } else {
        format!(
            "{} fresh of {} interfaces · RX {}/s · TX {}/s",
            fresh_interfaces.len(),
            data.traffic.len(),
            format_bytes(rx),
            format_bytes(tx)
        )
    };
    let host = data.host_sample.as_ref().map_or_else(
        || "Host CPU/memory sample pending".to_owned(),
        |(cpu, used, total, seen)| {
            let used = used
                .parse::<u64>()
                .ok()
                .map(format_bytes)
                .unwrap_or_else(|| "?".to_owned());
            let total = total
                .parse::<u64>()
                .ok()
                .map(format_bytes)
                .unwrap_or_else(|| "?".to_owned());
            format!(
                "Host CPU {cpu}% · memory {used}/{total} · {}",
                freshness(*seen)
            )
        },
    );
    render_panel(
        frame,
        header,
        scene_title(Scene::Traffic),
        vec![accent(rates, palette), muted(host, palette)],
        palette,
    );
    if body.height < 3 {
        return;
    }
    let (left, right) = split_horizontal(body, 52);
    let mut interfaces = data.traffic.values().collect::<Vec<_>>();
    interfaces.sort_by(|a, b| {
        fresh_rate(b)
            .cmp(&fresh_rate(a))
            .then_with(|| {
                b.rx_rate
                    .saturating_add(b.tx_rate)
                    .cmp(&a.rx_rate.saturating_add(a.tx_rate))
            })
            .then(a.name.cmp(&b.name))
    });
    let mut interface_lines = Vec::new();
    let interface_visible = left.height.saturating_sub(2) as usize;
    for row in interfaces.iter().skip(scroll).take(interface_visible) {
        let rate = row.sampled_at.map_or_else(
            || "rate pending".to_owned(),
            |seen| {
                format!(
                    "RX {}/s · TX {}/s · {}",
                    format_bytes(row.rx_rate),
                    format_bytes(row.tx_rate),
                    freshness(seen)
                )
            },
        );
        interface_lines.push(Line::from(vec![
            Span::styled(
                format!("{:<10}", row.name),
                Style::default().fg(palette.accent),
            ),
            Span::styled(
                truncate(&rate, left.width.saturating_sub(13) as usize),
                Style::default().fg(palette.text),
            ),
        ]));
    }
    if interface_lines.is_empty() {
        interface_lines.push(muted("Waiting for OS interface counters", palette));
    }
    render_panel(
        frame,
        left,
        &list_title(
            "INTERFACES / LAST OBSERVED RATE",
            interfaces.len(),
            scroll,
            interface_visible,
        ),
        interface_lines,
        palette,
    );
    let mut history = Vec::new();
    if let Some(busiest) = interfaces.get(scroll) {
        history.push(accent(
            format!("{}  /  combined RX + TX", busiest.name),
            palette,
        ));
        history.push(text(
            sparkline(&busiest.rates, right.width.saturating_sub(4) as usize),
            palette,
        ));
        history.push(muted(
            format!(
                "{} real counter samples; scale is relative",
                busiest.rates.len()
            ),
            palette,
        ));
        history.push(Line::raw(""));
        if let (Some(received), Some(transmitted)) = (busiest.rx_total, busiest.tx_total) {
            history.push(label_value(
                "CUMULATIVE RX",
                format_bytes(received),
                palette,
            ));
            history.push(label_value(
                "CUMULATIVE TX",
                format_bytes(transmitted),
                palette,
            ));
        }
        if !busiest.addresses.is_empty() {
            history.push(label_value(
                "ADDRESSES",
                truncate(&busiest.addresses, right.width.saturating_sub(18) as usize),
                palette,
            ));
        }
        history.push(label_value(
            "LAST RATE",
            busiest.sampled_at.map_or_else(
                || "pending".to_owned(),
                |seen| format!("{} · {}", seen.format("%H:%M:%S"), freshness(seen)),
            ),
            palette,
        ));
        history.push(label_value(
            "LAST OBSERVED",
            format!(
                "{} · {}",
                busiest.seen.format("%H:%M:%S"),
                age_label(busiest.seen)
            ),
            palette,
        ));
    } else {
        history.push(muted("No interface samples yet", palette));
    }
    render_panel(frame, right, " ACTIVITY / RATE HISTORY ", history, palette);
}

fn render_capture(
    frame: &mut Frame<'_>,
    area: Rect,
    data: &LiveProjection,
    palette: Palette,
    scroll: usize,
) {
    let Some(view) = &data.capture else {
        render_panel(
            frame,
            area,
            scene_title(Scene::Capture),
            vec![
                accent("Capture stage running", palette),
                muted(
                    "Awaiting decoded packets from the selected interface",
                    palette,
                ),
            ],
            palette,
        );
        return;
    };
    let (header, body) = split_vertical(area, 5);
    let bytes = view
        .captured_bytes
        .parse::<u64>()
        .ok()
        .map(format_bytes)
        .unwrap_or_else(|| format!("{} bytes", view.captured_bytes));
    render_panel(
        frame,
        header,
        scene_title(Scene::Capture),
        vec![
            accent(
                format!(
                    "{} PACKETS  /  {}  /  {} FLOWS  /  {}",
                    view.packets, bytes, view.flows, view.interface
                ),
                palette,
            ),
            muted(
                format!(
                    "tcpdump · filter {} · stop {} · {} · {}",
                    view.filter,
                    view.stop_reason,
                    view.seen.format("%H:%M:%S"),
                    age_label(view.seen)
                ),
                palette,
            ),
        ],
        palette,
    );
    if body.height < 3 {
        return;
    }
    let (left, right) = split_horizontal(body, 57);
    let flow_visible = left.height.saturating_sub(2) as usize;
    let mut flows = view
        .flow_rows
        .iter()
        .skip(scroll)
        .take(flow_visible)
        .map(|row| {
            Line::from(vec![
                Span::styled("↔ ", Style::default().fg(palette.accent)),
                Span::styled(
                    clip_line(&row.summary, left.width.saturating_sub(5) as usize),
                    Style::default().fg(palette.text),
                ),
            ])
        })
        .collect::<Vec<_>>();
    if flows.is_empty() {
        flows.push(muted("No flow decoded in this capture", palette));
    }
    render_panel(
        frame,
        left,
        &list_title(
            "FLOWS / OBSERVED",
            view.flow_rows.len(),
            scroll,
            flow_visible,
        ),
        flows,
        palette,
    );
    let name_visible = right.height.saturating_sub(2) as usize;
    let mut names = view
        .name_rows
        .iter()
        .skip(scroll)
        .take(name_visible)
        .map(|row| {
            Line::from(vec![
                Span::styled("● ", Style::default().fg(palette.severity(&row.severity))),
                Span::styled(
                    clip_line(&row.summary, right.width.saturating_sub(5) as usize),
                    Style::default().fg(palette.text),
                ),
            ])
        })
        .collect::<Vec<_>>();
    if names.is_empty() {
        names.push(muted("No DNS, HTTP or TLS name decoded", palette));
    }
    render_panel(
        frame,
        right,
        &list_title(
            "APPLICATION / DNS · HTTP · TLS",
            view.name_rows.len(),
            scroll,
            name_visible,
        ),
        names,
        palette,
    );
}

fn render_runtime(
    frame: &mut Frame<'_>,
    area: Rect,
    data: &LiveProjection,
    palette: Palette,
    scroll: usize,
) {
    let Some(view) = &data.runtime else {
        render_panel(
            frame,
            area,
            scene_title(Scene::Runtime),
            vec![
                accent("Runtime stage running", palette),
                muted("Awaiting stack, resource or function observations", palette),
            ],
            palette,
        );
        return;
    };
    let (header, body) = split_vertical(area, 5);
    render_panel(
        frame,
        header,
        scene_title(Scene::Runtime),
        vec![
            accent(
                format!("PID {}  /  {}", view.pid, basename(&view.subject)),
                palette,
            ),
            muted(
                format!(
                    "OS sample · open resources · function trace   /   last {} · {}",
                    view.seen.format("%H:%M:%S"),
                    age_label(view.seen)
                ),
                palette,
            ),
        ],
        palette,
    );
    if body.height < 3 {
        return;
    }
    let (left, right) = split_horizontal(body, 46);
    let mut profile = vec![
        muted("CALL STACK", palette),
        text(
            view.sample.as_deref().unwrap_or("No stack sample recorded"),
            palette,
        ),
        Line::raw(""),
        muted("RESOURCES", palette),
        text(
            view.resources
                .as_deref()
                .unwrap_or("No descriptor snapshot recorded"),
            palette,
        ),
        Line::raw(""),
        muted("FUNCTION TRACE", palette),
        text(
            view.trace
                .as_deref()
                .unwrap_or("No function trace recorded"),
            palette,
        ),
    ];
    if !view.hot_frames.is_empty() {
        profile.push(Line::raw(""));
        profile.push(muted("HOT FRAMES / SAMPLED", palette));
        for (index, hot_frame) in view.hot_frames.iter().take(8).enumerate() {
            profile.push(Line::from(vec![
                Span::styled(
                    format!("{:02} ", index + 1),
                    Style::default().fg(palette.accent),
                ),
                Span::styled(
                    clip_line(hot_frame, left.width.saturating_sub(7) as usize),
                    Style::default().fg(palette.text),
                ),
            ]));
        }
    }
    render_panel(frame, left, " PROCESS / LIVE PROFILE ", profile, palette);
    let visible = right.height.saturating_sub(2) as usize;
    let mut observed = view
        .observations
        .iter()
        .skip(scroll)
        .take(visible)
        .map(|signal| signal_line(signal, right.width.saturating_sub(3) as usize, palette))
        .collect::<Vec<_>>();
    if observed.is_empty() {
        observed.push(muted("No socket, file or function event recorded", palette));
    }
    render_panel(
        frame,
        right,
        &list_title(
            "OPEN RESOURCES / TRACE",
            view.observations.len(),
            scroll,
            visible,
        ),
        observed,
        palette,
    );
}

fn render_binaries(
    frame: &mut Frame<'_>,
    area: Rect,
    data: &LiveProjection,
    palette: Palette,
    scroll: usize,
) {
    let (header, body) = split_vertical(area, 5);
    let latest = data.binaries.front();
    render_panel(
        frame,
        header,
        scene_title(Scene::Binary),
        vec![
            accent(
                format!(
                    "{} recent binary dossiers with recorded identities or summaries",
                    data.binaries.len()
                ),
                palette,
            ),
            muted(
                latest.map_or_else(
                    || "No binary inspected yet".to_owned(),
                    |row| {
                        format!(
                            "Latest: {}  ·  {}",
                            basename(&row.subject),
                            row.seen.format("%H:%M:%S")
                        )
                    },
                ),
                palette,
            ),
        ],
        palette,
    );
    if body.height < 3 {
        return;
    }
    let (left, right) = split_horizontal(body, 42);
    let mut list = Vec::new();
    let list_visible = left.height.saturating_sub(2) as usize;
    for (index, row) in data
        .binaries
        .iter()
        .skip(scroll)
        .take(list_visible)
        .enumerate()
    {
        list.push(Line::from(vec![
            Span::styled(
                if index == 0 { "▸ " } else { "  " },
                Style::default().fg(palette.accent),
            ),
            Span::styled(
                truncate(
                    basename(&row.subject),
                    left.width.saturating_sub(15) as usize,
                ),
                Style::default().fg(palette.text),
            ),
            Span::styled(
                format!("  {}", row.seen.format("%H:%M:%S")),
                Style::default().fg(palette.muted),
            ),
        ]));
    }
    if list.is_empty() {
        list.push(muted("No binary identity or summary observed", palette));
    }
    render_panel(
        frame,
        left,
        &list_title(
            "RECENT EXECUTABLES",
            data.binaries.len(),
            scroll,
            list_visible,
        ),
        list,
        palette,
    );
    let mut detail = Vec::new();
    if let Some(row) = data.binaries.get(scroll) {
        detail.push(accent(basename(&row.subject), palette));
        detail.push(muted(
            truncate(&row.subject, right.width.saturating_sub(3) as usize),
            palette,
        ));
        detail.push(Line::raw(""));
        detail.push(label_value(
            "IDENTITY",
            truncate(&row.identity, right.width.saturating_sub(19) as usize),
            palette,
        ));
        if let Some(hash) = &row.sha256 {
            detail.push(label_value(
                "SHA-256",
                truncate(hash, right.width.saturating_sub(19) as usize),
                palette,
            ));
        }
        if let Some(sections) = &row.section_count {
            detail.push(label_value(
                "SECTIONS",
                truncate(sections, right.width.saturating_sub(19) as usize),
                palette,
            ));
        }
        if let Some(imports) = &row.imports {
            detail.push(label_value(
                "IMPORTS",
                truncate(imports, right.width.saturating_sub(19) as usize),
                palette,
            ));
        }
        if let Some(summary) = &row.summary {
            detail.push(Line::raw(""));
            detail.push(text(
                truncate(summary, right.width.saturating_sub(3) as usize),
                palette,
            ));
        }
    } else {
        detail.push(muted("No binary dossier at this scroll position", palette));
    }
    render_panel(frame, right, " DOSSIER / SELECTED ", detail, palette);
}

fn render_disassembly(
    frame: &mut Frame<'_>,
    area: Rect,
    data: &LiveProjection,
    palette: Palette,
    scroll: usize,
) {
    let Some(view) = &data.disassembly else {
        render_panel(
            frame,
            area,
            scene_title(Scene::Disassembly),
            vec![
                accent("Disassembly stage running", palette),
                muted(
                    "Awaiting decoded instructions from the selected binary",
                    palette,
                ),
            ],
            palette,
        );
        return;
    };
    let (header, body) = split_vertical(area, 5);
    render_panel(
        frame,
        header,
        scene_title(Scene::Disassembly),
        vec![
            accent(
                format!(
                    "{}  /  {}  /  {} INSTRUCTIONS",
                    basename(&view.subject),
                    view.architecture,
                    view.instructions
                ),
                palette,
            ),
            muted(
                format!(
                    "{} section · SHA-256 {} · last {}",
                    view.section,
                    clip_line(&view.sha256, 32),
                    view.seen.format("%H:%M:%S")
                ),
                palette,
            ),
        ],
        palette,
    );
    if body.height < 3 {
        return;
    }
    let (left, right) = split_horizontal(body, 31);
    let max_flow = view.calls.max(view.branches).max(view.returns);
    let mut profile = vec![muted("CONTROL FLOW / DECODED", palette), Line::raw("")];
    for (name, count) in [
        ("CALLS", view.calls),
        ("BRANCHES", view.branches),
        ("RETURNS", view.returns),
    ] {
        profile.push(Line::from(vec![
            Span::styled(format!("{name:<9}"), Style::default().fg(palette.muted)),
            Span::styled(
                scaled_bar(count, max_flow, 8),
                Style::default().fg(palette.accent),
            ),
            Span::styled(format!(" {count}"), Style::default().fg(palette.text)),
        ]));
    }
    profile.push(Line::raw(""));
    profile.push(label_value("SECTION", &view.section, palette));
    profile.push(label_value("RETAINED", &view.instructions, palette));
    profile.push(label_value("SOURCE", "local binary", palette));
    render_panel(frame, left, " STRUCTURE / FLOW", profile, palette);
    let visible = right.height.saturating_sub(2) as usize;
    let mut instructions = view
        .rows
        .iter()
        .skip(scroll)
        .take(visible)
        .map(|row| {
            let marker = match row.flow.as_str() {
                "call" => "↗",
                "branch" => "↪",
                "return" => "↵",
                _ => "·",
            };
            Line::from(vec![
                Span::styled(format!("{marker} "), Style::default().fg(palette.accent)),
                Span::styled(
                    clip_line(&row.summary, right.width.saturating_sub(5) as usize),
                    Style::default().fg(palette.text),
                ),
            ])
        })
        .collect::<Vec<_>>();
    if instructions.is_empty() {
        instructions.push(muted("No instruction decoded in this section", palette));
    }
    render_panel(
        frame,
        right,
        &list_title(
            "INSTRUCTIONS / ADDRESS ORDER",
            view.rows.len(),
            scroll,
            visible,
        ),
        instructions,
        palette,
    );
}

fn render_intel(
    frame: &mut Frame<'_>,
    area: Rect,
    data: &LiveProjection,
    palette: Palette,
    scroll: usize,
) {
    let Some(selected) = data.intel.get(scroll) else {
        render_panel(
            frame,
            area,
            scene_title(Scene::Intel),
            vec![
                accent("Threat-intelligence stage running", palette),
                muted(
                    "Awaiting a sourced provider report or lookup result",
                    palette,
                ),
            ],
            palette,
        );
        return;
    };
    let (header, body) = split_vertical(area, 5);
    render_panel(
        frame,
        header,
        scene_title(Scene::Intel),
        vec![
            accent(
                format!(
                    "{} PROVIDER OBSERVATIONS  /  {}",
                    data.intel.len(),
                    selected.subject
                ),
                palette,
            ),
            muted(
                format!(
                    "Latest source {} · {} · {}",
                    selected.provider,
                    selected.seen.format("%H:%M:%S"),
                    age_label(selected.seen)
                ),
                palette,
            ),
        ],
        palette,
    );
    if body.height < 3 {
        return;
    }
    let (left, right) = split_horizontal(body, 43);
    let visible = left.height.saturating_sub(2) as usize;
    let mut rows = data
        .intel
        .iter()
        .skip(scroll)
        .take(visible)
        .map(|row| {
            Line::from(vec![
                Span::styled(
                    format!("{} ", row.seen.format("%H:%M")),
                    Style::default().fg(palette.muted),
                ),
                Span::styled(
                    format!("{:<14} ", clip_line(&row.provider, 14)),
                    Style::default().fg(palette.severity(&row.severity)),
                ),
                Span::styled(
                    clip_line(&row.subject, left.width.saturating_sub(24) as usize),
                    Style::default().fg(palette.text),
                ),
            ])
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        rows.push(muted("No source observation at this position", palette));
    }
    render_panel(
        frame,
        left,
        &list_title("PROVIDERS / RECENT", data.intel.len(), scroll, visible),
        rows,
        palette,
    );
    let mut detail = vec![
        accent(
            clip_line(&selected.summary, right.width.saturating_sub(4) as usize),
            palette,
        ),
        muted(
            clip_line(&selected.kind, right.width.saturating_sub(4) as usize),
            palette,
        ),
        Line::raw(""),
    ];
    for (key, value) in &selected.details {
        if detail.len() >= right.height.saturating_sub(4) as usize {
            break;
        }
        if key == "interpretation" {
            detail.push(muted("INTERPRETATION / PROVIDER SCOPE", palette));
            for line in wrap_words(value, right.width.saturating_sub(4) as usize) {
                detail.push(text(line, palette));
            }
        } else {
            detail.push(label_value(
                &key.to_ascii_uppercase(),
                clip_line(value, right.width.saturating_sub(20) as usize),
                palette,
            ));
        }
    }
    if !selected.source_url.is_empty() {
        detail.push(Line::raw(""));
        detail.push(muted("SOURCE / DIRECT", palette));
        detail.push(text(
            clip_line(&selected.source_url, right.width.saturating_sub(4) as usize),
            palette,
        ));
    }
    render_panel(frame, right, " SOURCE / DOSSIER ", detail, palette);
}

fn render_binary_detail(
    frame: &mut Frame<'_>,
    area: Rect,
    data: &LiveProjection,
    index: usize,
    palette: Palette,
    scroll: usize,
) {
    let Some(row) = data.binaries.get(index) else {
        render_panel(
            frame,
            area,
            scene_title(Scene::BinaryDetail(index)),
            vec![muted("Binary dossier no longer in the recent set", palette)],
            palette,
        );
        return;
    };
    let (header, body) = split_vertical(area, 6);
    render_panel(
        frame,
        header,
        scene_title(Scene::BinaryDetail(index)),
        vec![
            accent(
                clip_line(
                    basename(&row.subject),
                    area.width.saturating_sub(4) as usize,
                ),
                palette,
            ),
            text(
                clip_line(&row.subject, area.width.saturating_sub(4) as usize),
                palette,
            ),
            muted(
                format!(
                    "Last inspection {} · {}  /  recorded file evidence",
                    row.seen.format("%H:%M:%S"),
                    age_label(row.seen)
                ),
                palette,
            ),
        ],
        palette,
    );
    if body.height < 3 {
        return;
    }
    let (left, right) = split_horizontal(body, 50);
    let value_width = left.width.saturating_sub(18) as usize;
    let mut profile = vec![
        label_value("IDENTITY", clip_line(&row.identity, value_width), palette),
        label_value(
            "SECTIONS",
            row.section_count
                .as_deref()
                .map(|value| clip_line(value, value_width))
                .unwrap_or_else(|| "not summarized".to_owned()),
            palette,
        ),
        label_value(
            "IMPORTS",
            row.imports
                .as_deref()
                .map(|value| clip_line(value, value_width))
                .unwrap_or_else(|| "not summarized".to_owned()),
            palette,
        ),
    ];
    if let Some(hash) = &row.sha256 {
        profile.push(Line::raw(""));
        profile.push(muted("SHA-256 / RECORDED", palette));
        let chars = hash.chars().collect::<Vec<_>>();
        for chunk in chars.chunks(left.width.saturating_sub(4).min(40) as usize) {
            profile.push(text(chunk.iter().collect::<String>(), palette));
        }
    }
    if let Some(summary) = &row.summary {
        profile.push(Line::raw(""));
        profile.push(muted("INSPECTION SUMMARY", palette));
        profile.push(text(
            clip_line(summary, left.width.saturating_sub(4) as usize),
            palette,
        ));
    }
    render_panel(frame, left, " FILE / STRUCTURE ", profile, palette);
    let visible_events = right.height.saturating_sub(2) as usize;
    let mut observations = row
        .observations
        .iter()
        .skip(scroll)
        .take(visible_events)
        .map(|signal| signal_line(signal, right.width.saturating_sub(3) as usize, palette))
        .collect::<Vec<_>>();
    if observations.is_empty() {
        observations.push(muted("No observation at this scroll position", palette));
    }
    render_panel(
        frame,
        right,
        &list_title(
            "INSPECTION TRACE / RECENT FIRST",
            row.observations.len(),
            scroll,
            visible_events,
        ),
        observations,
        palette,
    );
}

fn render_timeline(
    frame: &mut Frame<'_>,
    area: Rect,
    data: &LiveProjection,
    palette: Palette,
    scroll: usize,
) {
    let (header, body) = split_vertical(area, 4);
    render_panel(
        frame,
        header,
        scene_title(Scene::Timeline),
        vec![accent(
            format!(
                "{} latest signals  ·  detailed binary sections omitted from this view",
                data.signals.len()
            ),
            palette,
        )],
        palette,
    );
    let mut lines = Vec::new();
    let visible = body.height.saturating_sub(2) as usize;
    for signal in data.signals.iter().skip(scroll).take(visible) {
        lines.push(signal_line(
            signal,
            body.width.saturating_sub(3) as usize,
            palette,
        ));
    }
    if lines.is_empty() {
        lines.push(muted(
            "Waiting for host, process, binary, or network signals",
            palette,
        ));
    }
    render_panel(
        frame,
        body,
        &list_title(
            "CHRONOLOGY / RECENT FIRST",
            data.signals.len(),
            scroll,
            visible,
        ),
        lines,
        palette,
    );
}

fn signal_line(signal: &Signal, width: usize, palette: Palette) -> Line<'static> {
    let fixed = 18usize;
    Line::from(vec![
        Span::styled(
            format!("{} ", signal.seen.format("%H:%M:%S")),
            Style::default().fg(palette.muted),
        ),
        Span::styled(
            format!("{:<8} ", truncate(&signal.module, 8)),
            Style::default().fg(palette.severity(&signal.severity)),
        ),
        Span::styled(
            clip_line(&signal.summary, width.saturating_sub(fixed)),
            Style::default().fg(palette.text),
        ),
    ])
}

fn scaled_bar(value: u64, maximum: u64, width: usize) -> String {
    if maximum == 0 {
        return "·".repeat(width);
    }
    let filled = ((u128::from(value) * width as u128) / u128::from(maximum)) as usize;
    "█".repeat(filled.min(width)) + &"·".repeat(width.saturating_sub(filled))
}

fn sparkline(values: &VecDeque<u64>, width: usize) -> String {
    if values.is_empty() {
        return "Awaiting rate samples".to_owned();
    }
    let maximum = *values.iter().max().unwrap_or(&0);
    let glyphs = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    values
        .iter()
        .take(width.max(1))
        .rev()
        .map(|value| {
            if maximum == 0 {
                glyphs[0]
            } else {
                let index = (u128::from(*value) * 7 / u128::from(maximum)) as usize;
                glyphs[index.min(7)]
            }
        })
        .collect()
}

fn format_bytes(bytes: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit = 0usize;
    while size >= 1024.0 && unit + 1 < units.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", units[unit])
    }
}

fn age_seconds(seen: DateTime<Utc>) -> i64 {
    Utc::now().signed_duration_since(seen).num_seconds().max(0)
}

fn age_label(seen: DateTime<Utc>) -> String {
    let seconds = age_seconds(seen);
    match seconds {
        0..=59 => format!("{seconds}s ago"),
        60..=3599 => format!("{}m ago", seconds / 60),
        3600..=86399 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86400),
    }
}

fn freshness(seen: DateTime<Utc>) -> String {
    let age = age_label(seen);
    if age_seconds(seen) > STALE_AFTER_SECONDS {
        format!("{age} · STALE")
    } else {
        age
    }
}

fn fresh_rate(interface: &InterfaceRow) -> bool {
    interface
        .sampled_at
        .is_some_and(|seen| age_seconds(seen) <= STALE_AFTER_SECONDS)
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SourceKind;
    use ratatui::{Terminal, backend::TestBackend};

    fn render_text_at(
        scene: Scene,
        data: &LiveProjection,
        width: u16,
        height: u16,
        scroll: usize,
    ) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                render_scene(
                    frame,
                    frame.area(),
                    scene,
                    data,
                    super::super::Theme::Slate.palette(),
                    scroll,
                );
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..height {
            for x in 0..width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    fn render_text(scene: Scene, data: &LiveProjection, width: u16, height: u16) -> String {
        render_text_at(scene, data, width, height, 0)
    }

    #[test]
    fn scenes_appear_from_real_observations_and_survive_event_rollover() {
        let mut data = LiveProjection::default();
        assert_eq!(data.available_scenes(), vec![Scene::Mission]);
        let status = Event::new(
            "lan",
            "lan.status",
            "active segment",
            Some("192.168.1.0/24".into()),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("cidr", "192.168.1.0/24", "interface_netmask");
        data.ingest(&status);
        let host = Event::new(
            "lan",
            "lan.host",
            "host answered",
            Some("192.168.1.4".into()),
            Severity::Info,
            SourceKind::Live,
        );
        data.ingest(&host);
        let open = Event::new(
            "lan",
            "lan.tcp_open",
            "TCP 443 open",
            Some("192.168.1.4".into()),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("port", "443", "tcp_connect");
        data.ingest(&open);
        for index in 0..2_100 {
            data.ingest(&Event::new(
                "binary",
                "binary.section",
                format!("section {index}"),
                Some("/tmp/noisy-binary".into()),
                Severity::Info,
                SourceKind::File,
            ));
        }
        assert!(data.available_scenes().contains(&Scene::Network));
        assert!(data.available_scenes().contains(&Scene::Host(0)));
        let rendered = render_text(Scene::Network, &data, 120, 20);
        assert!(rendered.contains("NETWORK / LAN SURVEY"));
        assert!(rendered.contains("192.168.1.4"));
        assert!(rendered.contains("TCP 443"));
        assert!(!rendered.contains("section 2099"));
        let dossier = render_text(Scene::Host(0), &data, 120, 20);
        assert!(dossier.contains("HOST / LIVE DOSSIER"));
        assert!(dossier.contains("TCP  443"));
    }

    #[test]
    fn running_survey_labels_previous_results_and_watch_pulses_update_mission() {
        let mut data = LiveProjection::default();
        data.ingest(
            &Event::new(
                "lan",
                "lan.survey_complete",
                "previous survey",
                Some("192.168.1.0/24".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("segment", "192.168.1.0/24", "interface_netmask")
            .with_evidence("probed_addresses", "253", "tcp_connect")
            .with_evidence("responded_hosts", "5", "tcp_connect")
            .with_evidence("open_endpoints", "7", "tcp_connect"),
        );
        data.ingest(
            &Event::new(
                "presentation",
                "assisted.watch.stage.start",
                "LAN survey running",
                None,
                Severity::Info,
                SourceKind::Derived,
            )
            .with_evidence("phase", "LAN survey", "assisted_watch")
            .with_evidence("command", "lan survey", "assisted_watch"),
        );
        let network = render_text(Scene::Network, &data, 120, 20);
        assert!(network.contains("SURVEY RUNNING"));
        assert!(network.contains("PRIOR SURVEY"));
        let mission = render_text(Scene::Mission, &data, 120, 20);
        assert!(mission.contains("Live follow-up"));
        assert!(mission.contains("RUNNING"));
        data.ingest(
            &Event::new(
                "presentation",
                "assisted.watch.stage",
                "LAN survey failed",
                None,
                Severity::Low,
                SourceKind::Derived,
            )
            .with_evidence("command", "lan survey", "assisted_watch")
            .with_evidence("status", "error", "execution"),
        );
        assert!(!render_text(Scene::Network, &data, 120, 20).contains("SURVEY RUNNING"));
    }

    #[test]
    fn traffic_history_is_based_on_actual_samples() {
        let mut data = LiveProjection::default();
        let sample = Event::new(
            "traffic",
            "traffic.sample",
            "en0 sample",
            Some("en0".into()),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("interface", "en0", "sysinfo")
        .with_evidence("received_bytes_per_second", "2048", "counter_delta")
        .with_evidence("transmitted_bytes_per_second", "1024", "counter_delta");
        data.ingest(&sample);
        assert!(data.available_scenes().contains(&Scene::Traffic));
        let rendered = render_text(Scene::Traffic, &data, 120, 20);
        assert!(rendered.contains("TRAFFIC / INTERFACES"));
        assert!(rendered.contains("en0"));
        assert!(rendered.contains("2.0 KiB/s"));
        assert_eq!(sparkline(&VecDeque::new(), 12), "Awaiting rate samples");
    }

    #[test]
    fn completed_zero_host_resurvey_drops_prior_host_rows() {
        let mut data = LiveProjection::default();
        let first_host = Event::new(
            "lan",
            "lan.host",
            "first survey host",
            Some("192.168.1.4".into()),
            Severity::Info,
            SourceKind::Live,
        );
        data.ingest(&first_host);
        let mut first_completion = Event::new(
            "lan",
            "lan.survey_complete",
            "first survey",
            Some("192.168.1.0/24".into()),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("responded_hosts", "1", "tcp_connect");
        first_completion.timestamp = first_host.timestamp + chrono::Duration::seconds(1);
        data.ingest(&first_completion);
        assert_eq!(data.lan_hosts.len(), 1);
        let mut later_web = Event::new(
            "web",
            "http_response",
            "HTTP 200 from first host",
            Some("192.168.1.4".into()),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("local_segment", "192.168.1.0/24", "test")
        .with_evidence("status", "200", "test");
        later_web.timestamp = first_completion.timestamp + chrono::Duration::seconds(1);
        data.ingest(&later_web);
        let mut second_completion = Event::new(
            "lan",
            "lan.survey_complete",
            "second survey",
            Some("192.168.1.0/24".into()),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("responded_hosts", "0", "tcp_connect");
        second_completion.timestamp = later_web.timestamp + chrono::Duration::seconds(1);
        data.ingest(&second_completion);
        assert!(data.lan_hosts.is_empty());
        assert!(render_text(Scene::Network, &data, 120, 20).contains("No host has answered"));
    }

    #[test]
    fn resurvey_replaces_old_ports_and_web_status_for_same_host() {
        let mut data = LiveProjection::default();
        let host = || {
            Event::new(
                "lan",
                "lan.host",
                "Host answered",
                Some("192.168.1.4".into()),
                Severity::Info,
                SourceKind::Live,
            )
        };
        let open = |port: &str| {
            Event::new(
                "lan",
                "lan.tcp_open",
                format!("TCP {port} open"),
                Some("192.168.1.4".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("port", port, "test")
        };
        let complete = || {
            Event::new(
                "lan",
                "lan.survey_complete",
                "Survey complete",
                Some("192.168.1.0/24".into()),
                Severity::Info,
                SourceKind::Live,
            )
        };
        data.ingest(&host());
        data.ingest(&open("443"));
        data.ingest(&complete());
        data.ingest(
            &Event::new(
                "web",
                "http_response",
                "HTTP 200",
                Some("192.168.1.4".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("local_segment", "192.168.1.0/24", "test")
            .with_evidence("status", "200", "test"),
        );
        data.ingest(&host());
        data.ingest(&open("80"));
        data.ingest(&complete());
        let current = data.lan_hosts.get("192.168.1.4").unwrap();
        assert_eq!(current.ports.iter().copied().collect::<Vec<_>>(), vec![80]);
        assert!(current.web_status.is_none());
    }

    #[test]
    fn autonomous_binary_digest_populates_dossier_without_detail_flood() {
        let mut data = LiveProjection::default();
        data.ingest(
            &Event::new(
                "binary",
                "binary.autonomous_summary",
                "Binary dossier: tool · 12 sections · 24 imports",
                Some("/usr/bin/tool".into()),
                Severity::Info,
                SourceKind::File,
            )
            .with_evidence("sha256", "0123456789abcdef", "static_binary_analysis")
            .with_evidence("sections", "12", "static_binary_analysis")
            .with_evidence("imports", "24", "static_binary_analysis")
            .with_evidence("libraries", "3", "static_binary_analysis"),
        );
        assert!(data.available_scenes().contains(&Scene::Binary));
        assert!(data.available_scenes().contains(&Scene::BinaryDetail(0)));
        let rendered = render_text(Scene::Binary, &data, 120, 20);
        assert!(rendered.contains("BINARIES / FILE INTELLIGENCE"));
        assert!(rendered.contains("12 sections"));
        assert!(rendered.contains("24 imports"));
        assert!(rendered.contains("0123456789abcdef"));
        let dossier = render_text(Scene::BinaryDetail(0), &data, 120, 20);
        assert!(dossier.contains("BINARY / INSPECTION DOSSIER"));
        assert!(dossier.contains("0123456789abcdef"));
    }

    #[test]
    fn expired_rates_and_process_inventory_are_labeled_stale() {
        let mut data = LiveProjection::default();
        let old = Utc::now() - chrono::Duration::seconds(90);
        let mut inventory = Event::new(
            "process",
            "process.top_summary",
            "snapshot",
            None,
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("visible_processes", "42", "process_inventory");
        inventory.timestamp = old;
        data.ingest(&inventory);
        let mut sample = Event::new(
            "traffic",
            "traffic.sample",
            "en0 sample",
            Some("en0".into()),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("interface", "en0", "sysinfo")
        .with_evidence("received_bytes_per_second", "2048", "counter_delta")
        .with_evidence("transmitted_bytes_per_second", "1024", "counter_delta");
        sample.timestamp = old;
        data.ingest(&sample);
        data.ingest(
            &Event::new(
                "traffic",
                "traffic.interface",
                "en0 counters",
                Some("en0".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("interface", "en0", "sysinfo"),
        );
        let mission = render_text(Scene::Mission, &data, 120, 22);
        assert!(mission.contains("42 visible"));
        assert!(mission.contains("STALE"));
        let traffic = render_text(Scene::Traffic, &data, 120, 22);
        assert!(traffic.contains("Rates STALE"));
        assert!(traffic.contains(&old.format("%H:%M:%S").to_string()));
    }

    #[test]
    fn scoped_network_shows_exact_target_without_prior_lan_result() {
        let mut data = LiveProjection::default();
        data.ingest(
            &Event::new(
                "lan",
                "lan.survey_complete",
                "prior LAN survey",
                Some("192.168.1.0/24".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("responded_hosts", "5", "tcp_connect"),
        );
        data.ingest(
            &Event::new(
                "presentation",
                "assisted.session.stage.start",
                "targeted scan",
                None,
                Severity::Info,
                SourceKind::Derived,
            )
            .with_evidence(
                "scenario",
                "scoped-network:example.test",
                "assisted_session",
            )
            .with_evidence("command", "scan example.test", "assisted_session"),
        );
        data.ingest(
            &Event::new(
                "network",
                "tcp_open",
                "TCP 443 open on 203.0.113.3",
                Some("example.test".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("endpoint", "203.0.113.3:443", "tcp_connect"),
        );
        data.ingest(
            &Event::new(
                "network",
                "tcp_scan_complete",
                "1 TCP endpoint checked; 1 open",
                Some("example.test".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("target", "example.test", "user_scope")
            .with_evidence("ports", "443", "user_scope")
            .with_evidence("resolved_addresses", "203.0.113.3", "dns_resolution"),
        );
        data.ingest(
            &Event::new(
                "web",
                "http_response",
                "HTTP 200 from https://example.test/",
                Some("example.test".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("status", "200", "http_response"),
        );
        let view = render_text(Scene::Network, &data, 120, 22);
        assert!(view.contains("NETWORK / SCOPED TARGET"));
        assert!(view.contains("example.test"));
        assert!(view.contains("203.0.113.3:443"));
        assert!(view.contains("HTTP 200"));
        assert!(!view.contains("192.168.1.0/24"));
    }

    #[test]
    fn timeline_omits_stage_chatter_and_scrolls_observed_hosts() {
        let mut data = LiveProjection::default();
        data.ingest(&Event::new(
            "presentation",
            "assisted.watch.stage.start",
            "scheduler stage start",
            None,
            Severity::Info,
            SourceKind::Derived,
        ));
        data.ingest(&Event::new(
            "presentation",
            "assisted.session.stage",
            "scheduler stage done",
            None,
            Severity::Info,
            SourceKind::Derived,
        ));
        for index in 1..=20 {
            data.ingest(&Event::new(
                "lan",
                "lan.host",
                format!("Host {index} answered"),
                Some(format!("192.168.1.{index}")),
                Severity::Info,
                SourceKind::Live,
            ));
        }
        let timeline = render_text(Scene::Timeline, &data, 120, 16);
        assert!(!timeline.contains("scheduler stage"));
        assert!(timeline.contains("Host 20 answered"));
        assert_eq!(data.scene_item_count(Scene::Network), 20);
        let scrolled = render_text_at(Scene::Network, &data, 120, 12, 10);
        assert!(scrolled.contains("OF 20"));
        assert!(scrolled.contains("192.168.1.10"));
        assert!(!scrolled.contains("192.168.1.20"));
    }

    #[test]
    fn new_scenes_render_recorded_capture_disassembly_runtime_and_intel_evidence() {
        let mut data = LiveProjection::default();
        data.ingest(
            &Event::new(
                "capture",
                "capture.summary",
                "7 packets, 900 captured bytes, 6 IP packets, 3 flows",
                Some("en0".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("interface", "en0", "local_interface")
            .with_evidence("packets", "7", "pcap_decoder")
            .with_evidence("captured_bytes", "900", "pcap_decoder")
            .with_evidence("flows", "3", "pcap_decoder")
            .with_evidence("filter", "tcp or udp", "request")
            .with_evidence("capture_stop_reason", "duration", "tcpdump"),
        );
        data.ingest(
            &Event::new(
                "capture",
                "capture.flow",
                "192.0.2.2:51000 → 198.51.100.9:443 TCP: 3 packets",
                Some("en0".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("interface", "en0", "local_interface"),
        );
        data.ingest(
            &Event::new(
                "capture",
                "capture.tls_sni",
                "TLS SNI observed: example.test",
                Some("en0".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("interface", "en0", "local_interface"),
        );
        data.ingest(
            &Event::new(
                "disasm",
                "disasm.summary",
                "Aarch64: 2 instructions decoded",
                Some("/tmp/sample-bin".into()),
                Severity::Info,
                SourceKind::File,
            )
            .with_evidence("section", "__text", "file")
            .with_evidence("architecture", "Aarch64", "file")
            .with_evidence("instructions_retained", "2", "file")
            .with_evidence("calls", "1", "decoded_instructions")
            .with_evidence("branches", "0", "decoded_instructions")
            .with_evidence("returns", "1", "decoded_instructions")
            .with_evidence("sha256", "abc123", "file"),
        );
        data.ingest(
            &Event::new(
                "disasm",
                "disasm.instruction",
                "0x100003f20 bl 0x100003f90",
                Some("/tmp/sample-bin".into()),
                Severity::Info,
                SourceKind::File,
            )
            .with_evidence("flow", "call", "instruction_classification"),
        );
        data.ingest(
            &Event::new(
                "runtime",
                "runtime.sample",
                "Sampled sample-bin for 2s; 200 stack observations",
                Some("/tmp/sample-bin".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("pid", "1234", "sample(1)")
            .with_evidence("hot_frames", "main + 48\nwork + 12", "sample(1)"),
        );
        data.ingest(
            &Event::new(
                "runtime",
                "runtime.resources",
                "PID 1234: 8 descriptors, 1 sockets, 4 regular files",
                Some("pid:1234".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("pid", "1234", "lsof"),
        );
        data.ingest(
            &Event::new(
                "runtime",
                "runtime.socket",
                "PID 1234 FD 8u · 192.0.2.2:51000->198.51.100.9:443",
                Some("pid:1234".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("pid", "1234", "lsof"),
        );
        data.ingest(
            &Event::new(
                "intel",
                "intel.vt.report",
                "VirusTotal report: 2 malicious and 0 suspicious of 70 classified results",
                Some("abc123".into()),
                Severity::Medium,
                SourceKind::Live,
            )
            .with_evidence("provider", "VirusTotal", "external_source")
            .with_evidence(
                "source_url",
                "https://www.virustotal.com/gui/file/abc123",
                "external_source",
            )
            .with_evidence("malicious", "2", "provider_report")
            .with_evidence(
                "interpretation",
                "Provider classifications can disagree and are not proof by themselves",
                "source_scope",
            ),
        );
        data.ingest(&Event::new(
            "intel",
            "intel.enrich_complete",
            "Intelligence pivot: 1 observation",
            None,
            Severity::Info,
            SourceKind::Derived,
        ));
        assert_eq!(data.intel.len(), 1);
        assert_eq!(data.intel.front().unwrap().provider, "VirusTotal");

        for scene in [
            Scene::Capture,
            Scene::Disassembly,
            Scene::Runtime,
            Scene::Intel,
        ] {
            assert!(data.available_scenes().contains(&scene));
            assert!(!render_text(scene, &data, 120, 26).is_empty());
            let _ = render_text(scene, &data, 82, 18);
        }
        let capture = render_text(Scene::Capture, &data, 120, 26);
        assert!(capture.contains("7 PACKETS"));
        assert!(capture.contains("example.test"));
        let disassembly = render_text(Scene::Disassembly, &data, 120, 26);
        assert!(disassembly.contains("CONTROL FLOW"));
        assert!(disassembly.contains("0x100003f20"));
        let runtime = render_text(Scene::Runtime, &data, 120, 26);
        assert!(runtime.contains("main + 48"));
        assert!(runtime.contains("192.0.2.2"));
        let intel = render_text(Scene::Intel, &data, 120, 26);
        assert!(intel.contains("VirusTotal"));
        assert!(intel.contains("classifications can disagree"));
        assert!(intel.contains("themselves"));
        let mission = render_text(Scene::Mission, &data, 120, 30);
        assert!(mission.contains("OBSERVED / NET"));
        assert!(mission.contains("DECODED / FILE"));
        assert!(mission.contains("LOOKUP / INTEL"));
    }

    #[test]
    fn instruction_projection_is_bounded_and_timeline_stays_high_signal() {
        let mut data = LiveProjection::default();
        data.ingest(&Event::new(
            "disasm",
            "disasm.summary",
            "decoded section",
            Some("/tmp/bin".into()),
            Severity::Info,
            SourceKind::File,
        ));
        for address in 0..150 {
            data.ingest(&Event::new(
                "disasm",
                "disasm.instruction",
                format!("0x{address:x} nop"),
                Some("/tmp/bin".into()),
                Severity::Info,
                SourceKind::File,
            ));
        }
        assert_eq!(data.scene_item_count(Scene::Disassembly), MAX_DISASM_ROWS);
        assert!(data.signals.len() <= 1);
        let view = render_text(Scene::Disassembly, &data, 110, 24);
        assert!(!view.contains("0x0 nop"));
    }

    #[test]
    fn pending_stage_has_a_view_without_claiming_an_observation() {
        let mut data = LiveProjection::default();
        data.ingest(
            &Event::new(
                "presentation",
                "assisted.session.stage.start",
                "Capture starting",
                None,
                Severity::Info,
                SourceKind::Derived,
            )
            .with_evidence("command", "capture live auto", "assisted_session"),
        );
        assert!(data.available_scenes().contains(&Scene::Capture));
        let view = render_text(Scene::Capture, &data, 100, 20);
        assert!(view.contains("Awaiting decoded packets"));
        assert!(!view.contains("7 PACKETS"));
        data.ingest(&Event::new(
            "presentation",
            "assisted.session.stage",
            "Capture failed",
            None,
            Severity::Low,
            SourceKind::Derived,
        ));
        assert!(!data.available_scenes().contains(&Scene::Capture));
    }
}
