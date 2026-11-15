use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{
    self, Event as TerminalEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use tokio::sync::{broadcast, mpsc};

use crate::assisted::{self, Execution, Scenario, ScenarioStep};
use crate::command::WorkspaceRequest;
use crate::config::Config;
use crate::engine::referenced_source_ids;
use crate::model::{Event, Severity};

mod scenes;
use scenes::{LiveProjection, Scene, render_scene};

const MINIMUM_WIDTH: u16 = 48;
const MAX_DRAIN: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InteractionMode {
    Autonomous,
    Interactive,
    Assisted,
}

impl InteractionMode {
    fn label(self) -> &'static str {
        match self {
            Self::Autonomous => "AUTONOMOUS",
            Self::Interactive => "INTERACTIVE",
            Self::Assisted => "ASSISTED",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum View {
    Overview,
    Timeline,
    Evidence,
}

impl View {
    fn next(self) -> Self {
        match self {
            Self::Overview => Self::Timeline,
            Self::Timeline => Self::Evidence,
            Self::Evidence => Self::Overview,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Overview => "OVERVIEW",
            Self::Timeline => "TIMELINE",
            Self::Evidence => "EVIDENCE",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Theme {
    Slate,
    Arctic,
    Amber,
    Monochrome,
}

enum SettingChange {
    Theme(Theme),
    Profile(String),
    Refresh(u64),
    AutonomousToggle,
    LanToggle,
}

impl Theme {
    fn from_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "arctic" => Self::Arctic,
            "amber" => Self::Amber,
            "monochrome" | "minimal" => Self::Monochrome,
            _ => Self::Slate,
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Slate => Self::Arctic,
            Self::Arctic => Self::Amber,
            Self::Amber => Self::Monochrome,
            Self::Monochrome => Self::Slate,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Slate => "intelligence",
            Self::Arctic => "arctic",
            Self::Amber => "amber",
            Self::Monochrome => "monochrome",
        }
    }

    fn palette(self) -> Palette {
        match self {
            Self::Slate => Palette {
                background: Color::Rgb(9, 14, 20),
                surface: Color::Rgb(15, 23, 31),
                border: Color::Rgb(52, 72, 83),
                text: Color::Rgb(207, 221, 226),
                muted: Color::Rgb(112, 136, 147),
                accent: Color::Rgb(76, 190, 183),
                selected: Color::Rgb(30, 57, 64),
                warning: Color::Rgb(219, 165, 90),
                critical: Color::Rgb(232, 104, 98),
            },
            Self::Arctic => Palette {
                background: Color::Rgb(10, 18, 24),
                surface: Color::Rgb(17, 29, 38),
                border: Color::Rgb(59, 84, 98),
                text: Color::Rgb(222, 236, 241),
                muted: Color::Rgb(126, 157, 170),
                accent: Color::Rgb(123, 200, 227),
                selected: Color::Rgb(36, 68, 84),
                warning: Color::Rgb(224, 183, 115),
                critical: Color::Rgb(230, 119, 112),
            },
            Self::Amber => Palette {
                background: Color::Rgb(18, 16, 13),
                surface: Color::Rgb(28, 24, 18),
                border: Color::Rgb(93, 74, 45),
                text: Color::Rgb(229, 215, 188),
                muted: Color::Rgb(154, 134, 101),
                accent: Color::Rgb(222, 171, 86),
                selected: Color::Rgb(65, 47, 27),
                warning: Color::Rgb(238, 181, 74),
                critical: Color::Rgb(232, 116, 91),
            },
            Self::Monochrome => Palette {
                background: Color::Black,
                surface: Color::Black,
                border: Color::DarkGray,
                text: Color::White,
                muted: Color::Gray,
                accent: Color::White,
                selected: Color::DarkGray,
                warning: Color::White,
                critical: Color::White,
            },
        }
    }
}

#[derive(Clone, Copy)]
struct Palette {
    background: Color,
    surface: Color,
    border: Color,
    text: Color,
    muted: Color,
    accent: Color,
    selected: Color,
    warning: Color,
    critical: Color,
}

impl Palette {
    fn severity(self, severity: &Severity) -> Color {
        match severity {
            Severity::Critical | Severity::High => self.critical,
            Severity::Medium => self.warning,
            Severity::Low => self.accent,
            Severity::Info => self.muted,
        }
    }
}

/// A prepared input reveals one Unicode scalar value per ordinary key press.
/// The revealed text is presentation state and is never submitted as a command.
#[derive(Clone, Debug)]
pub struct PreparedInput {
    steps: Vec<String>,
    index: usize,
    revealed: usize,
    presented: bool,
}

impl PreparedInput {
    pub fn new(steps: Vec<String>) -> Self {
        Self {
            steps,
            index: 0,
            revealed: 0,
            presented: false,
        }
    }

    pub fn current(&self) -> Option<&str> {
        self.steps.get(self.index).map(String::as_str)
    }

    pub fn visible(&self) -> String {
        self.current()
            .unwrap_or_default()
            .chars()
            .take(self.revealed)
            .collect()
    }

    pub fn advance(&mut self) {
        if let Some(step) = self.current() {
            self.revealed = (self.revealed + 1).min(step.chars().count());
        }
    }

    pub fn backspace(&mut self) {
        self.revealed = self.revealed.saturating_sub(1);
    }

    pub fn complete(&self) -> bool {
        self.current()
            .is_some_and(|step| self.revealed == step.chars().count())
    }

    pub fn next_step(&mut self) -> bool {
        if !self.complete() || self.index + 1 >= self.steps.len() {
            return false;
        }
        self.index += 1;
        self.revealed = 0;
        self.presented = false;
        true
    }

    pub fn reset_step(&mut self) {
        self.revealed = 0;
        self.presented = false;
    }

    pub fn is_presented(&self) -> bool {
        self.presented
    }

    pub fn mark_presented(&mut self) {
        self.presented = true;
    }

    pub fn position(&self) -> (usize, usize) {
        (self.index + 1, self.steps.len())
    }
}

pub struct TuiState {
    pub events: VecDeque<Event>,
    pub command_input: String,
    pub selected_event: usize,
    pub mode: InteractionMode,
    pub status: String,
    pub prepared: PreparedInput,
    scenarios: Vec<Scenario>,
    scenario_index: usize,
    pending_step: Option<(String, usize)>,
    pending_explicit_runs: HashSet<(String, usize)>,
    completed_explicit_runs: HashSet<(String, usize)>,
    running_session: Option<String>,
    running_started_at: Option<Instant>,
    failed_session_stages: HashSet<(String, usize)>,
    subject_counts: BTreeMap<String, usize>,
    detail_scroll: u16,
    view: View,
    scene: Scene,
    scene_scroll: usize,
    projection: LiveProjection,
    scene_auto: bool,
    seen_network_discoveries: HashSet<String>,
    last_discovery_spotlight: Instant,
    manual_scene_until: Option<Instant>,
    last_scene_change: Instant,
    auto_focus_step: usize,
    live_watch: bool,
    watch_pending: bool,
    watch_started_at: Option<Instant>,
    uncertain_request: bool,
    watch_cycle: u64,
    watch_scenario: Option<String>,
    watch_lan_allowed: bool,
    last_full_succeeded: Option<(usize, usize)>,
    next_watch: Instant,
    last_lan_watch: Instant,
    theme: Theme,
    show_help: bool,
    show_settings: bool,
    history: VecDeque<String>,
    history_index: Option<usize>,
    max_events: usize,
    profile: String,
    refresh_ms: u64,
    config: Config,
    config_path: PathBuf,
}

impl TuiState {
    pub fn new(config: Config, config_path: PathBuf) -> Self {
        let scenarios = assisted::scenarios(&config);
        let prepared = PreparedInput::new(
            scenarios
                .first()
                .map(|scenario| {
                    scenario
                        .steps
                        .iter()
                        .map(|step| step.input.clone())
                        .collect()
                })
                .unwrap_or_default(),
        );
        Self {
            events: VecDeque::new(),
            command_input: String::new(),
            selected_event: 0,
            mode: if config.autonomous {
                InteractionMode::Autonomous
            } else {
                InteractionMode::Interactive
            },
            status: "Ready. Waiting for observations.".to_string(),
            prepared,
            scenarios,
            scenario_index: 0,
            pending_step: None,
            pending_explicit_runs: HashSet::new(),
            completed_explicit_runs: HashSet::new(),
            running_session: None,
            running_started_at: None,
            failed_session_stages: HashSet::new(),
            subject_counts: BTreeMap::new(),
            detail_scroll: 0,
            view: View::Overview,
            scene: Scene::Mission,
            scene_scroll: 0,
            projection: LiveProjection::default(),
            scene_auto: true,
            seen_network_discoveries: HashSet::new(),
            last_discovery_spotlight: Instant::now() - Duration::from_secs(6),
            manual_scene_until: None,
            last_scene_change: Instant::now(),
            auto_focus_step: 0,
            live_watch: false,
            watch_pending: false,
            watch_started_at: None,
            uncertain_request: false,
            watch_cycle: 0,
            watch_scenario: None,
            watch_lan_allowed: false,
            last_full_succeeded: None,
            next_watch: Instant::now() + Duration::from_secs(20),
            last_lan_watch: Instant::now(),
            theme: Theme::from_name(&config.theme),
            show_help: false,
            show_settings: false,
            history: VecDeque::new(),
            history_index: None,
            max_events: config.retention_events.max(100),
            profile: config.profile.clone(),
            refresh_ms: config.refresh_ms.clamp(50, 2_000),
            config,
            config_path,
        }
    }

    fn ingest(&mut self, observation: Event) {
        let spotlight = match observation.kind.as_str() {
            "lan.host" => observation
                .subject
                .as_ref()
                .map(|address| (format!("host:{address}"), Scene::Network)),
            "lan.tcp_open" => event_evidence(&observation, "endpoint")
                .map(|endpoint| (format!("endpoint:{endpoint}"), Scene::Network)),
            "indicator.match" => Some((format!("indicator:{}", observation.id), Scene::Timeline)),
            "capture.summary"
            | "capture.dns_question"
            | "capture.tls_sni"
            | "capture.http_host" => Some((format!("capture:{}", observation.id), Scene::Capture)),
            "disasm.summary" => Some((format!("disasm:{}", observation.id), Scene::Disassembly)),
            "runtime.sample" | "runtime.resources" | "runtime.trace_summary" => {
                Some((format!("runtime:{}", observation.id), Scene::Runtime))
            }
            kind if kind.starts_with("intel.")
                && !matches!(
                    kind,
                    "intel.status" | "intel.enrich_complete" | "intel.enrich_error"
                ) =>
            {
                Some((format!("intel:{}", observation.id), Scene::Intel))
            }
            _ => None,
        };
        let new_discovery = spotlight.as_ref().is_some_and(|(key, _)| {
            if key.starts_with("indicator:") {
                true
            } else {
                if self.seen_network_discoveries.len() >= 4096 {
                    self.seen_network_discoveries.clear();
                }
                self.seen_network_discoveries.insert(key.clone())
            }
        });
        self.update_assisted_progress(&observation);
        self.projection.ingest(&observation);
        if new_discovery
            && self.mode == InteractionMode::Assisted
            && self.scene_auto
            && self
                .manual_scene_until
                .is_none_or(|until| Instant::now() >= until)
            && self.last_discovery_spotlight.elapsed() >= Duration::from_secs(5)
            && let Some((_, scene)) = spotlight
        {
            self.focus_scene(scene);
            self.last_discovery_spotlight = Instant::now();
        }
        if referenced_source_ids(&observation)
            .iter()
            .any(|source_id| !self.events.iter().any(|event| event.id == *source_id))
        {
            return;
        }
        if observation.kind.starts_with("config.")
            || observation.module == "command" && observation.kind == "command.result"
        {
            self.sync_config_from_disk();
        }
        if self.selected_event != 0 {
            self.selected_event += 1;
        } else {
            self.detail_scroll = 0;
        }
        if let Some(subject) = &observation.subject {
            *self.subject_counts.entry(subject.clone()).or_default() += 1;
        }
        self.events.push_front(observation);
        let mut evicted_ids = HashSet::new();
        while self.events.len() > self.max_events {
            let Some(removed) = self.events.pop_back() else {
                break;
            };
            evicted_ids.insert(removed.id);
        }
        if !evicted_ids.is_empty() {
            self.events.retain(|event| {
                !referenced_source_ids(event)
                    .iter()
                    .any(|source_id| evicted_ids.contains(source_id))
            });
            self.subject_counts.clear();
            for event in &self.events {
                if let Some(subject) = &event.subject {
                    *self.subject_counts.entry(subject.clone()).or_default() += 1;
                }
            }
        }
        self.selected_event = self.selected_event.min(self.events.len().saturating_sub(1));
    }

    fn update_assisted_progress(&mut self, event: &Event) {
        if self.uncertain_request
            && matches!(
                event.kind.as_str(),
                "assisted.session.complete"
                    | "assisted.session.error"
                    | "assisted.watch.complete"
                    | "assisted.watch.error"
            )
        {
            self.uncertain_request = false;
            self.status = "Delayed completion received; F6 can start a new run".to_string();
        }
        match event.kind.as_str() {
            "assisted.step.complete" | "assisted.step.error" => {
                let Some(key) = assisted_event_stage_key(event) else {
                    return;
                };
                if self.pending_step.as_ref() != Some(&key) {
                    return;
                }
                self.pending_step = None;
                if self.current_stage_key().as_ref() != Some(&key) {
                    return;
                }
                if event.kind == "assisted.step.error" {
                    self.status = "Stage failed; press Enter to retry".to_string();
                    return;
                }
                let skipped_explicit_action = self
                    .scenario_step()
                    .is_some_and(|step| step.execution == Execution::Explicit)
                    && !self.pending_explicit_runs.contains(&key)
                    && !self.completed_explicit_runs.contains(&key);
                self.prepared.mark_presented();
                if self.prepared.next_step() {
                    let (index, count) = self.prepared.position();
                    self.status = if skipped_explicit_action {
                        format!("Network step skipped; stage {index}/{count}")
                    } else {
                        format!("Stage {index}/{count} ready")
                    };
                } else {
                    self.status = if skipped_explicit_action {
                        "Scenario complete; network step was skipped".to_string()
                    } else {
                        "Scenario complete".to_string()
                    };
                }
            }
            "assisted.run.complete" | "assisted.run.error" => {
                let Some(key) = assisted_event_stage_key(event) else {
                    return;
                };
                if !self.pending_explicit_runs.remove(&key) {
                    return;
                }
                if event.kind == "assisted.run.complete" {
                    self.completed_explicit_runs.insert(key.clone());
                }
                if self.current_stage_key().as_ref() == Some(&key) {
                    self.status = if event.kind == "assisted.run.complete" {
                        "Network step complete; Enter continues".to_string()
                    } else {
                        "Network step failed; Ctrl+R retries".to_string()
                    };
                }
            }
            "assisted.session.stage.start" => {
                let Some(scenario_id) = event_evidence(event, "scenario") else {
                    return;
                };
                if self.running_session.as_deref() != Some(scenario_id) {
                    return;
                }
                let phase = event_evidence(event, "phase").unwrap_or("stage");
                let command = event_evidence(event, "command").unwrap_or("");
                if command.starts_with("lan survey") {
                    self.last_lan_watch = Instant::now();
                }
                self.focus_scene(scene_for_command(command));
                self.status = format!("{} · {phase} running", session_label(scenario_id));
            }
            "assisted.session.stage" => {
                let Some(scenario_id) = event_evidence(event, "scenario") else {
                    return;
                };
                if self.running_session.as_deref() != Some(scenario_id) {
                    return;
                }
                let Some(index) = event_evidence(event, "step_index")
                    .and_then(|value| value.parse::<usize>().ok())
                else {
                    return;
                };
                let phase = event_evidence(event, "phase").unwrap_or("stage");
                let command = event_evidence(event, "command").unwrap_or("");
                self.focus_scene(scene_for_command(command));
                let stage_status = event_evidence(event, "status");
                let failed = matches!(stage_status, Some("error" | "partial"));
                if failed {
                    self.failed_session_stages
                        .insert((scenario_id.to_owned(), index));
                }
                if self
                    .scenario()
                    .is_some_and(|scenario| scenario.id == scenario_id)
                    && index > 0
                    && index <= self.prepared.steps.len()
                {
                    self.prepared.index = index - 1;
                    self.prepared.revealed = self
                        .prepared
                        .current()
                        .map(|text| text.chars().count())
                        .unwrap_or(0);
                    self.prepared.mark_presented();
                }
                let count = self
                    .scenarios
                    .iter()
                    .find(|scenario| scenario.id == scenario_id)
                    .map(|scenario| scenario.steps.len())
                    .unwrap_or(0);
                self.status = format!(
                    "{} session {index}/{count}: {phase} {}",
                    session_label(scenario_id),
                    match stage_status {
                        Some("partial") => "partial",
                        Some("error") => "failed",
                        _ => "complete",
                    }
                );
            }
            "assisted.session.complete" | "assisted.session.error" => {
                let Some(scenario_id) = event_evidence(event, "scenario") else {
                    return;
                };
                if self.running_session.as_deref() != Some(scenario_id) {
                    return;
                }
                self.running_session = None;
                self.running_started_at = None;
                self.status = if event.kind == "assisted.session.complete" {
                    let succeeded = event_evidence(event, "succeeded").unwrap_or("?");
                    let total = event_evidence(event, "failed")
                        .and_then(|failed| {
                            Some(succeeded.parse::<usize>().ok()? + failed.parse::<usize>().ok()?)
                        })
                        .or_else(|| {
                            self.scenarios
                                .iter()
                                .find(|scenario| scenario.id == scenario_id)
                                .map(|scenario| scenario.steps.len())
                        })
                        .unwrap_or(0);
                    self.last_full_succeeded = succeeded
                        .parse::<usize>()
                        .ok()
                        .map(|succeeded| (succeeded, total));
                    self.next_watch = Instant::now() + Duration::from_secs(20);
                    self.focus_scene(Scene::Mission);
                    if succeeded.parse::<usize>().ok() == Some(total) {
                        format!(
                            "{} {succeeded}/{total} stages complete",
                            session_label(scenario_id)
                        )
                    } else {
                        format!(
                            "{} {succeeded}/{total} stages passed",
                            session_label(scenario_id)
                        )
                    }
                } else {
                    self.live_watch = false;
                    self.watch_scenario = None;
                    format!("{} run stopped; F6 retries", session_label(scenario_id))
                };
            }
            "assisted.watch.stage.start" => {
                if !self.watch_pending {
                    return;
                }
                let phase = event_evidence(event, "phase").unwrap_or("check");
                let command = event_evidence(event, "command").unwrap_or("");
                if command.starts_with("lan survey") {
                    self.focus_scene(Scene::Network);
                }
                self.status = format!("Live follow-up {} · {phase} running", self.watch_cycle);
            }
            "assisted.watch.stage" => {
                if !self.watch_pending {
                    return;
                }
                let phase = event_evidence(event, "phase").unwrap_or("check");
                let stage_status = event_evidence(event, "status");
                self.status = format!(
                    "Live follow-up {} · {phase} {}",
                    self.watch_cycle,
                    match stage_status {
                        Some("partial") => "partial",
                        Some("error") => "failed",
                        _ => "complete",
                    }
                );
            }
            "assisted.watch.complete" | "assisted.watch.error" => {
                if !self.watch_pending {
                    return;
                }
                self.watch_pending = false;
                self.watch_started_at = None;
                self.next_watch = Instant::now() + Duration::from_secs(20);
                let succeeded = event_evidence(event, "succeeded").unwrap_or("0");
                let failed = event_evidence(event, "failed").unwrap_or("1");
                self.status = if event.kind == "assisted.watch.error" || failed != "0" {
                    format!(
                        "Live follow-up {}: {succeeded} passed, {failed} failed",
                        self.watch_cycle
                    )
                } else {
                    format!("Live follow-up {} complete", self.watch_cycle)
                };
            }
            _ => {}
        }
    }

    fn sync_config_from_disk(&mut self) {
        let Ok(config) = Config::load(&self.config_path) else {
            return;
        };
        let selected_id = self.scenario().map(|scenario| scenario.id.clone());
        let scenarios = assisted::scenarios(&config);
        let scenario_index = selected_id
            .as_ref()
            .and_then(|id| scenarios.iter().position(|scenario| &scenario.id == id))
            .unwrap_or(0);
        let steps: Vec<String> = scenarios
            .get(scenario_index)
            .map(|scenario| {
                scenario
                    .steps
                    .iter()
                    .map(|step| step.input.clone())
                    .collect()
            })
            .unwrap_or_default();
        if self.scenario_index != scenario_index || self.prepared.steps != steps {
            self.prepared = PreparedInput::new(steps);
        }
        self.scenarios = scenarios;
        self.scenario_index = scenario_index;
        if let Some(scenario_id) = self
            .scenarios
            .get(scenario_index)
            .map(|scenario| scenario.id.clone())
        {
            self.projection.select_scenario(&scenario_id);
        }
        self.theme = Theme::from_name(&config.theme);
        self.profile = config.profile.clone();
        self.refresh_ms = config.refresh_ms;
        self.max_events = config.retention_events;
        self.config = config;
    }

    fn selected(&self) -> Option<&Event> {
        self.events.get(self.selected_event)
    }

    fn scenario(&self) -> Option<&Scenario> {
        self.scenarios.get(self.scenario_index)
    }

    fn scenario_step(&self) -> Option<&ScenarioStep> {
        self.scenario()?.steps.get(self.prepared.index)
    }

    fn current_stage_key(&self) -> Option<(String, usize)> {
        Some((self.scenario()?.id.clone(), self.prepared.index + 1))
    }

    fn cycle_scenario(&mut self, reverse: bool) {
        if self.scenarios.is_empty() {
            return;
        }
        if let Some(id) = self.scenario().map(|scenario| scenario.id.clone()) {
            self.completed_explicit_runs
                .retain(|(scenario_id, _)| scenario_id != &id);
        }
        let count = self.scenarios.len();
        self.scenario_index = if reverse {
            (self.scenario_index + count - 1) % count
        } else {
            (self.scenario_index + 1) % count
        };
        let scenario = &self.scenarios[self.scenario_index];
        self.projection.select_scenario(&scenario.id);
        self.prepared = PreparedInput::new(
            scenario
                .steps
                .iter()
                .map(|step| step.input.clone())
                .collect(),
        );
        self.status = format!("Scenario: {}", scenario.title);
    }

    fn previous_assisted_stage(&mut self) {
        if self.prepared.index > 0 {
            self.prepared.index -= 1;
        }
        if let Some(key) = self.current_stage_key() {
            self.completed_explicit_runs.remove(&key);
        }
        self.prepared.reset_step();
        let (index, count) = self.prepared.position();
        self.status = format!("Stage {index}/{count} ready to review");
    }

    fn cycle_mode(&mut self) {
        self.mode = match self.mode {
            InteractionMode::Autonomous => InteractionMode::Interactive,
            InteractionMode::Interactive => InteractionMode::Assisted,
            InteractionMode::Assisted => InteractionMode::Autonomous,
        };
        if self.mode == InteractionMode::Assisted {
            if let Some(scenario_id) = self
                .scenarios
                .get(self.scenario_index)
                .map(|scenario| scenario.id.clone())
            {
                self.projection.select_scenario(&scenario_id);
            }
            self.scene = Scene::Mission;
            self.scene_scroll = 0;
            self.scene_auto = true;
            self.manual_scene_until = None;
            self.last_scene_change = Instant::now();
            self.auto_focus_step = 0;
        }
        self.status = format!("{} mode", self.mode.label().to_ascii_lowercase());
    }

    fn focus_scene(&mut self, scene: Scene) {
        if self.mode == InteractionMode::Assisted
            && self.scene_auto
            && self
                .manual_scene_until
                .is_none_or(|until| Instant::now() >= until)
        {
            if self.scene != scene {
                self.scene = scene;
                self.scene_scroll = 0;
            }
            self.last_scene_change = Instant::now();
        }
    }

    fn scroll_scene(&mut self, delta: isize) {
        let max = self
            .projection
            .scene_item_count(self.scene)
            .saturating_sub(1);
        self.scene_scroll = self.scene_scroll.saturating_add_signed(delta).min(max);
        self.manual_scene_until = Some(Instant::now() + Duration::from_secs(30));
    }

    fn next_scene_manual(&mut self) {
        let available = self.projection.available_scenes();
        if available.is_empty() {
            return;
        }
        let index = available
            .iter()
            .position(|scene| *scene == self.scene)
            .unwrap_or(0);
        self.scene = available[(index + 1) % available.len()];
        self.scene_scroll = 0;
        self.manual_scene_until = Some(Instant::now() + Duration::from_secs(30));
        self.last_scene_change = Instant::now();
        self.status = format!("{} view selected", self.scene.label());
    }

    fn toggle_live_watch(&mut self) {
        if self.uncertain_request {
            self.status = "Previous request status unknown; restart SPECTRE to resume".to_string();
            return;
        }
        if self.watch_scenario.is_none() {
            self.status = "Press F6 to start a live investigation first".to_string();
            return;
        }
        self.live_watch = !self.live_watch;
        if self.live_watch {
            self.next_watch = Instant::now();
        }
        self.status = if self.live_watch {
            "Live follow-ups on".to_string()
        } else {
            "Live follow-ups paused".to_string()
        };
    }

    fn tick(&mut self, command_tx: &mpsc::Sender<WorkspaceRequest>) -> bool {
        if self.mode != InteractionMode::Assisted {
            return false;
        }
        let now = Instant::now();
        let mut changed = false;
        if self
            .running_started_at
            .is_some_and(|started| now.duration_since(started) >= Duration::from_secs(120))
        {
            self.running_session = None;
            self.running_started_at = None;
            self.live_watch = false;
            self.uncertain_request = true;
            self.status = "Session completion not received; wait or restart SPECTRE".to_string();
            changed = true;
        }
        if self
            .watch_started_at
            .is_some_and(|started| now.duration_since(started) >= Duration::from_secs(120))
        {
            self.watch_pending = false;
            self.watch_started_at = None;
            self.live_watch = false;
            self.uncertain_request = true;
            self.status = "Follow-up completion not received; wait or restart SPECTRE".to_string();
            changed = true;
        }
        if self.manual_scene_until.is_some_and(|until| now >= until) {
            self.manual_scene_until = None;
            changed = true;
        }
        if self.scene_auto && self.manual_scene_until.is_none() {
            let available = self.projection.available_scenes();
            if !available.contains(&self.scene) {
                self.scene = match self.scene {
                    Scene::Host(_) if available.contains(&Scene::Network) => Scene::Network,
                    Scene::BinaryDetail(_) if available.contains(&Scene::Binary) => Scene::Binary,
                    _ => Scene::Mission,
                };
                self.scene_scroll = 0;
                self.last_scene_change = now;
                changed = true;
            }
        }
        if self.scene_auto
            && self.manual_scene_until.is_none()
            && now.duration_since(self.last_scene_change)
                >= Duration::from_secs(if self.running_session.is_some() { 5 } else { 7 })
        {
            let available = self.projection.available_scenes();
            if available.len() > 1 {
                let index = available
                    .iter()
                    .position(|scene| *scene == self.scene)
                    .unwrap_or(0);
                self.scene = available[(index + 1) % available.len()];
                self.auto_focus_step = self.auto_focus_step.wrapping_add(1);
                let items = self.projection.scene_item_count(self.scene);
                self.scene_scroll = if items > 0 && self.auto_focus_step >= available.len() {
                    (self.auto_focus_step / available.len()).wrapping_mul(5) % items
                } else {
                    0
                };
                self.last_scene_change = now;
                changed = true;
            }
        }
        if self.live_watch
            && self.running_session.is_none()
            && !self.watch_pending
            && self.pending_step.is_none()
            && self.pending_explicit_runs.is_empty()
            && now >= self.next_watch
        {
            let include_lan = self.watch_lan_allowed
                && self.config.lan_assessment_enabled
                && now.duration_since(self.last_lan_watch) >= Duration::from_secs(120);
            let cycle = self.watch_cycle + 1;
            match command_tx.try_send(WorkspaceRequest::AssistedLivePulse { cycle, include_lan }) {
                Ok(()) => {
                    self.watch_cycle = cycle;
                    self.watch_pending = true;
                    self.watch_started_at = Some(now);
                    if include_lan {
                        self.last_lan_watch = now;
                    }
                    self.status = format!("Live follow-up {cycle} running");
                    changed = true;
                }
                Err(error) => {
                    self.status = format!("Live follow-up could not start: {error}");
                    self.next_watch = now + Duration::from_secs(5);
                    changed = true;
                }
            }
        }
        changed
    }

    fn move_selection(&mut self, delta: isize) {
        if self.events.is_empty() {
            return;
        }
        let max = self.events.len() as isize - 1;
        self.selected_event = (self.selected_event as isize + delta).clamp(0, max) as usize;
        self.detail_scroll = 0;
    }

    fn cycle_theme(&mut self, command_tx: &mpsc::Sender<WorkspaceRequest>) {
        self.apply_setting(SettingChange::Theme(self.theme.next()), command_tx);
    }

    fn cycle_profile(&mut self, command_tx: &mpsc::Sender<WorkspaceRequest>) {
        const PROFILES: [&str; 5] = [
            "local-research",
            "binary-monitor",
            "focused",
            "offline",
            "custom",
        ];
        let current = PROFILES
            .iter()
            .position(|name| *name == self.profile)
            .unwrap_or(0);
        let profile = PROFILES[(current + 1) % PROFILES.len()];
        self.apply_setting(SettingChange::Profile(profile.to_string()), command_tx);
    }

    fn toggle_lan_assessment(&mut self, command_tx: &mpsc::Sender<WorkspaceRequest>) {
        if self.running_session.is_some()
            || self.pending_step.is_some()
            || !self.pending_explicit_runs.is_empty()
            || self.watch_pending
        {
            self.status = "Wait for the current assisted work to finish".to_string();
            return;
        }
        self.apply_setting(SettingChange::LanToggle, command_tx);
        self.sync_config_from_disk();
    }

    fn apply_setting(
        &mut self,
        change: SettingChange,
        command_tx: &mpsc::Sender<WorkspaceRequest>,
    ) {
        let next = (|| -> Result<Config> {
            let mut next = if self.config_path.exists() {
                Config::load(&self.config_path)?
            } else {
                self.config.clone()
            };
            match &change {
                SettingChange::Theme(theme) => next.theme = theme.label().to_string(),
                SettingChange::Profile(profile) => next.apply_profile(profile)?,
                SettingChange::Refresh(refresh_ms) => next.refresh_ms = *refresh_ms,
                SettingChange::AutonomousToggle => next.autonomous = !next.autonomous,
                SettingChange::LanToggle => {
                    next.lan_assessment_enabled = !next.lan_assessment_enabled
                }
            }
            next.save(&self.config_path)?;
            Ok(next)
        })();
        match next {
            Ok(config) => {
                self.status = match change {
                    SettingChange::Theme(_) => format!("Theme: {}", config.theme),
                    SettingChange::Profile(_) => format!("Profile: {}", config.profile),
                    SettingChange::Refresh(_) => {
                        format!("Display refresh: {} ms", config.refresh_ms)
                    }
                    SettingChange::AutonomousToggle => format!(
                        "Autonomous collection: {}",
                        if config.autonomous { "on" } else { "off" }
                    ),
                    SettingChange::LanToggle => format!(
                        "LAN survey: {}",
                        if config.lan_assessment_enabled {
                            "on"
                        } else {
                            "off"
                        }
                    ),
                };
                self.theme = Theme::from_name(&config.theme);
                self.profile = config.profile.clone();
                self.refresh_ms = config.refresh_ms;
                self.max_events = config.retention_events;
                self.config = config;
                if let Err(error) =
                    command_tx.try_send(WorkspaceRequest::Command("config reload".to_string()))
                {
                    self.status = format!("Saved for next launch; runtime update failed: {error}");
                }
            }
            Err(error) => self.status = format!("Settings could not be saved: {error:#}"),
        }
    }

    fn recall(&mut self, previous: bool) {
        if self.history.is_empty() {
            return;
        }
        let index = match (self.history_index, previous) {
            (None, true) => 0,
            (None, false) => return,
            (Some(i), true) => (i + 1).min(self.history.len() - 1),
            (Some(0), false) => {
                self.history_index = None;
                self.command_input.clear();
                return;
            }
            (Some(i), false) => i - 1,
        };
        self.history_index = Some(index);
        self.command_input = self.history[index].clone();
    }
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalSession {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(error.into());
        }
        match Terminal::new(CrosstermBackend::new(io::stdout())) {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                let _ = execute!(io::stdout(), LeaveAlternateScreen);
                let _ = disable_raw_mode();
                Err(error.into())
            }
        }
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = self.terminal.show_cursor();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

/// Runs the terminal UI on the caller's thread. Run it from a blocking task when
/// collectors use the same Tokio runtime.
pub fn run_tui(
    config: Config,
    config_path: PathBuf,
    mut bus: broadcast::Receiver<Event>,
    command_tx: mpsc::Sender<WorkspaceRequest>,
) -> Result<()> {
    let mut session = TerminalSession::enter()?;
    let mut state = TuiState::new(config, config_path);
    let mut last_draw = Instant::now() - Duration::from_secs(1);
    loop {
        let mut changed = false;
        for _ in 0..MAX_DRAIN {
            match bus.try_recv() {
                Ok(observation) => {
                    state.ingest(observation);
                    changed = true;
                }
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Lagged(count)) => {
                    state.status = format!("{} observations skipped; collection continues", count);
                    changed = true;
                }
                Err(broadcast::error::TryRecvError::Closed) => {
                    state.status = "Event stream closed".to_string();
                    break;
                }
            }
        }

        changed |= state.tick(&command_tx);

        if changed || last_draw.elapsed() >= Duration::from_millis(state.refresh_ms) {
            session.terminal.draw(|frame| render(frame, &state))?;
            last_draw = Instant::now();
        }

        if event::poll(Duration::from_millis(25))? {
            match event::read()? {
                TerminalEvent::Key(key)
                    if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
                {
                    if handle_key(&mut state, key, &command_tx) {
                        break;
                    }
                    session.terminal.draw(|frame| render(frame, &state))?;
                    last_draw = Instant::now();
                }
                TerminalEvent::Resize(_, _) => {
                    session.terminal.draw(|frame| render(frame, &state))?;
                    last_draw = Instant::now();
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn handle_key(
    state: &mut TuiState,
    key: KeyEvent,
    command_tx: &mpsc::Sender<WorkspaceRequest>,
) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return true;
    }
    if key.code == KeyCode::F(1)
        || key.code == KeyCode::Char('?') && state.mode == InteractionMode::Autonomous
    {
        state.show_help = !state.show_help;
        state.show_settings = false;
        return false;
    }
    if key.code == KeyCode::Esc && (state.show_help || state.show_settings) {
        state.show_help = false;
        state.show_settings = false;
        return false;
    }
    if state.show_help {
        return false;
    }
    if key.code == KeyCode::F(5) {
        state.show_settings = !state.show_settings;
        return false;
    }
    if state.show_settings {
        match key.code {
            KeyCode::Char('t') => state.cycle_theme(command_tx),
            KeyCode::Char('l') if state.mode == InteractionMode::Assisted => {
                state.next_scene_manual()
            }
            KeyCode::Char('l') => state.view = state.view.next(),
            KeyCode::Char('p') => state.cycle_profile(command_tx),
            KeyCode::Char('n') => state.toggle_lan_assessment(command_tx),
            KeyCode::Char('r') => {
                let refresh_ms = match state.refresh_ms {
                    0..=100 => 250,
                    101..=250 => 500,
                    _ => 100,
                };
                state.apply_setting(SettingChange::Refresh(refresh_ms), command_tx);
            }
            KeyCode::Char('a') => state.apply_setting(SettingChange::AutonomousToggle, command_tx),
            _ => {}
        }
        return false;
    }
    match key.code {
        KeyCode::F(2) => {
            state.cycle_mode();
            return false;
        }
        KeyCode::F(3) => {
            if state.mode == InteractionMode::Assisted {
                state.next_scene_manual();
            } else {
                state.view = state.view.next();
            }
            return false;
        }
        KeyCode::F(4) => {
            state.cycle_theme(command_tx);
            return false;
        }
        KeyCode::F(6) if state.mode == InteractionMode::Assisted => {
            run_assisted_session(state, command_tx);
            return false;
        }
        KeyCode::F(7) if state.mode == InteractionMode::Assisted => {
            state.toggle_live_watch();
            return false;
        }
        KeyCode::F(8) if state.mode == InteractionMode::Assisted => {
            state.scene_auto = !state.scene_auto;
            state.manual_scene_until = None;
            state.last_scene_change = Instant::now();
            state.status = if state.scene_auto {
                "Automatic views on".to_string()
            } else {
                "Automatic views paused".to_string()
            };
            return false;
        }
        KeyCode::PageUp => {
            if state.mode == InteractionMode::Assisted {
                state.scroll_scene(-10);
            } else {
                state.move_selection(10);
            }
            return false;
        }
        KeyCode::PageDown => {
            if state.mode == InteractionMode::Assisted {
                state.scroll_scene(10);
            } else {
                state.move_selection(-10);
            }
            return false;
        }
        _ => {}
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('j') if state.mode == InteractionMode::Assisted => state.scroll_scene(1),
            KeyCode::Char('k') if state.mode == InteractionMode::Assisted => state.scroll_scene(-1),
            KeyCode::Char('j') => state.move_selection(-1),
            KeyCode::Char('k') => state.move_selection(1),
            KeyCode::Char('l') if state.mode == InteractionMode::Assisted => {
                state.next_scene_manual()
            }
            KeyCode::Char('l') => state.view = state.view.next(),
            KeyCode::Char('u') if state.mode == InteractionMode::Assisted => state.scroll_scene(-3),
            KeyCode::Char('d') if state.mode == InteractionMode::Assisted => state.scroll_scene(3),
            KeyCode::Char('u') => state.detail_scroll = state.detail_scroll.saturating_sub(3),
            KeyCode::Char('d') => state.detail_scroll = state.detail_scroll.saturating_add(3),
            KeyCode::Char('r') if state.mode == InteractionMode::Assisted => {
                run_assisted_explicit(state, command_tx)
            }
            _ => {}
        }
        return false;
    }
    if state.mode == InteractionMode::Assisted
        && (state.running_session.is_some()
            || state.pending_step.is_some()
            || !state.pending_explicit_runs.is_empty())
        && matches!(
            key.code,
            KeyCode::Tab
                | KeyCode::BackTab
                | KeyCode::Left
                | KeyCode::Char(_)
                | KeyCode::Backspace
                | KeyCode::Enter
                | KeyCode::Esc
        )
    {
        state.status = if state.running_session.is_some() {
            "Session running; wait for the result".to_string()
        } else if !state.pending_explicit_runs.is_empty() {
            "Network step running; wait for the result".to_string()
        } else {
            "Stage running; wait for the result".to_string()
        };
        return false;
    }
    match state.mode {
        InteractionMode::Autonomous => match key.code {
            KeyCode::Char('/') => {
                state.mode = InteractionMode::Interactive;
                state.command_input.clear();
                state.status = "Interactive command input".to_string();
            }
            KeyCode::Char('q') => return true,
            KeyCode::Up => state.move_selection(1),
            KeyCode::Down => state.move_selection(-1),
            _ => {}
        },
        InteractionMode::Interactive => match key.code {
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::ALT) => {
                state.command_input.push(c);
                state.history_index = None;
            }
            KeyCode::Backspace => {
                state.command_input.pop();
            }
            KeyCode::Enter => {
                let command = state.command_input.trim().to_string();
                if !command.is_empty() {
                    match command_tx.try_send(WorkspaceRequest::Command(command.clone())) {
                        Ok(()) => {
                            state.history.push_front(command);
                            state.history.truncate(100);
                            state.history_index = None;
                            state.command_input.clear();
                            state.status = "Command submitted".to_string();
                        }
                        Err(error) => state.status = format!("Command not submitted: {error}"),
                    }
                }
            }
            KeyCode::Up => state.recall(true),
            KeyCode::Down => state.recall(false),
            KeyCode::Esc => {
                state.command_input.clear();
                state.mode = InteractionMode::Autonomous;
            }
            _ => {}
        },
        InteractionMode::Assisted => match key.code {
            KeyCode::Up => state.scroll_scene(-1),
            KeyCode::Down => state.scroll_scene(1),
            KeyCode::Tab => state.cycle_scenario(key.modifiers.contains(KeyModifiers::SHIFT)),
            KeyCode::BackTab => state.cycle_scenario(true),
            KeyCode::Left => state.previous_assisted_stage(),
            KeyCode::Char(_) if !key.modifiers.contains(KeyModifiers::ALT) => {
                state.prepared.advance()
            }
            KeyCode::Backspace => state.prepared.backspace(),
            KeyCode::Enter => {
                if !state.prepared.complete() {
                    state.status = "Finish the current input to continue".to_string();
                } else if state.prepared.is_presented() {
                    state.status = "Scenario complete; Tab selects another".to_string();
                } else {
                    let (index, _) = state.prepared.position();
                    let Some(scenario) = state.scenario() else {
                        state.status = "No assisted scenario available".to_string();
                        return false;
                    };
                    let scenario_id = scenario.id.clone();
                    let Some(step) = state.scenario_step() else {
                        state.status = "No assisted stage available".to_string();
                        return false;
                    };
                    let execution = step.execution.clone();
                    let text = step.input.clone();
                    match command_tx.try_send(WorkspaceRequest::AssistedStep {
                        scenario_id: scenario_id.clone(),
                        index,
                        text,
                    }) {
                        Ok(()) => {
                            state.pending_step = Some((scenario_id, index));
                            state.status = if execution == Execution::Local {
                                "Local stage running…".to_string()
                            } else {
                                "Stage recording…".to_string()
                            };
                        }
                        Err(error) => {
                            state.status = format!("Assisted stage was not submitted: {error}");
                        }
                    }
                }
            }
            KeyCode::Esc => {
                if let Some(key) = state.current_stage_key() {
                    state.completed_explicit_runs.remove(&key);
                }
                state.prepared.reset_step();
                state.status = "Stage reset; reveal it again".to_string();
            }
            _ => {}
        },
    }
    false
}

fn run_assisted_explicit(state: &mut TuiState, command_tx: &mpsc::Sender<WorkspaceRequest>) {
    if state.running_session.is_some() || state.pending_step.is_some() {
        state.status = "Wait for the current stage to finish".to_string();
        return;
    }
    if state.prepared.is_presented() {
        state.status = "This stage is complete; Left returns to an earlier stage".to_string();
        return;
    }
    if !state.prepared.complete() {
        state.status = "Reveal the full stage before running it".to_string();
        return;
    }
    let Some(scenario) = state.scenario() else {
        state.status = "No assisted scenario available".to_string();
        return;
    };
    let Some(step) = state.scenario_step() else {
        state.status = "No assisted stage available".to_string();
        return;
    };
    if step.execution != Execution::Explicit {
        state.status = "This stage has no separate run action".to_string();
        return;
    }
    let scenario_id = scenario.id.clone();
    let (index, _) = state.prepared.position();
    let key = (scenario_id.clone(), index);
    if state.pending_explicit_runs.contains(&key) {
        state.status = "Network step is still pending".to_string();
        return;
    }
    if state.completed_explicit_runs.contains(&key) {
        state.status = "Network step already completed for this stage".to_string();
        return;
    }
    let text = step.input.clone();
    match command_tx.try_send(WorkspaceRequest::AssistedRun {
        scenario_id,
        index,
        text,
    }) {
        Ok(()) => {
            state.pending_explicit_runs.insert(key);
            state.status = "Network step requested; wait for the result".to_string();
        }
        Err(error) => state.status = format!("Network step was not submitted: {error}"),
    }
}

fn run_assisted_session(state: &mut TuiState, command_tx: &mpsc::Sender<WorkspaceRequest>) {
    if state.uncertain_request {
        state.status = "Previous request status unknown; wait or restart SPECTRE".to_string();
        return;
    }
    if state.running_session.is_some() {
        state.status = "A session is already running".to_string();
        return;
    }
    if state.watch_pending {
        state.status = "Wait for the live follow-up to finish".to_string();
        return;
    }
    if state.pending_step.is_some() || !state.pending_explicit_runs.is_empty() {
        state.status = "Wait for the current stage to finish".to_string();
        return;
    }
    let Some(scenario) = state.scenario() else {
        state.status = "No assisted scenario available".to_string();
        return;
    };
    if !matches!(
        scenario.id.as_str(),
        "system-network" | "local-research" | "local-network" | "process-investigation"
    ) && !scenario.id.starts_with("scoped-network:")
    {
        state.status =
            "F6 runs built-in scenarios; custom text remains presentation-only".to_string();
        return;
    }
    let scenario_id = scenario.id.clone();
    let label = session_label(&scenario_id);
    let inputs = scenario
        .steps
        .iter()
        .map(|step| step.input.clone())
        .collect();
    match command_tx.try_send(WorkspaceRequest::AssistedRunSession {
        scenario_id: scenario_id.clone(),
    }) {
        Ok(()) => {
            state.prepared = PreparedInput::new(inputs);
            state.running_session = Some(scenario_id.clone());
            state.running_started_at = Some(Instant::now());
            state.watch_scenario = Some(scenario_id.clone());
            state.watch_lan_allowed =
                matches!(scenario_id.as_str(), "system-network" | "local-network");
            state.live_watch = true;
            state.watch_cycle = 0;
            state.last_full_succeeded = None;
            state.last_lan_watch = Instant::now();
            state.scene = Scene::Mission;
            state.scene_scroll = 0;
            state.last_scene_change = Instant::now();
            state.auto_focus_step = 0;
            state
                .failed_session_stages
                .retain(|(id, _)| id != &scenario_id);
            state.status = format!("{label} session running…");
        }
        Err(error) => state.status = format!("{label} session was not submitted: {error}"),
    }
}

fn session_label(scenario_id: &str) -> &'static str {
    match scenario_id {
        "system-network" => "Survey",
        "local-research" => "Local",
        "local-network" => "LAN",
        "process-investigation" => "Process",
        _ if scenario_id.starts_with("scoped-network:") => "Target",
        _ => "Assisted",
    }
}

fn scene_for_command(command: &str) -> Scene {
    if command.starts_with("capture ") {
        Scene::Capture
    } else if command.starts_with("runtime ") {
        Scene::Runtime
    } else if command.starts_with("disasm ") {
        Scene::Disassembly
    } else if command.starts_with("intel ") {
        Scene::Intel
    } else if command.starts_with("lan ")
        || command.starts_with("scan ")
        || command.starts_with("investigate ")
        || command.starts_with("http ")
    {
        Scene::Network
    } else if command.starts_with("process ") {
        Scene::Processes
    } else if command.starts_with("traffic ") {
        Scene::Traffic
    } else if command.starts_with("binary ") {
        Scene::Binary
    } else {
        Scene::Mission
    }
}

fn event_evidence<'a>(event: &'a Event, label: &str) -> Option<&'a str> {
    event
        .evidence
        .iter()
        .find(|item| item.label == label)
        .map(|item| item.value.as_str())
}

fn assisted_event_stage_key(event: &Event) -> Option<(String, usize)> {
    let scenario_id = event_evidence(event, "scenario")?.to_string();
    let index = event_evidence(event, "step_index")?.parse().ok()?;
    Some((scenario_id, index))
}

fn render(frame: &mut Frame<'_>, state: &TuiState) {
    let area = frame.area();
    let palette = state.theme.palette();
    frame.render_widget(
        Block::default().style(Style::default().bg(palette.background)),
        area,
    );
    if area.width < MINIMUM_WIDTH || area.height < 10 {
        frame.render_widget(
            Paragraph::new("SPECTRE  ·  Expand the terminal to at least 48 × 10")
                .style(Style::default().fg(palette.text).bg(palette.background)),
            area,
        );
        return;
    }

    let input_height =
        if state.mode == InteractionMode::Assisted && area.width >= 78 && area.height >= 20 {
            8
        } else {
            3
        };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(input_height),
            Constraint::Length(1),
        ])
        .split(area);
    render_header(frame, rows[0], state, palette);
    render_workspace(frame, rows[1], state, palette);
    render_input(frame, rows[2], state, palette);
    render_footer(frame, rows[3], state, palette);
    if state.show_help {
        render_help(frame, area, palette);
    } else if state.show_settings {
        render_settings(frame, area, state, palette);
    }
}

fn render_header(frame: &mut Frame<'_>, area: Rect, state: &TuiState, palette: Palette) {
    let latest = state
        .events
        .front()
        .map(|event| event.timestamp.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "—".to_string());
    let title = Line::from(vec![
        Span::styled(
            " SPECTRE ",
            Style::default()
                .fg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("/  SECURITY RESEARCH", Style::default().fg(palette.muted)),
    ]);
    let context = if state.mode == InteractionMode::Assisted {
        let activity = if state.running_session.is_some() {
            "SESSION RUNNING"
        } else if state.watch_pending {
            "FOLLOW-UP RUNNING"
        } else if state.live_watch {
            "LIVE WATCH"
        } else {
            "AUTO VIEWS"
        };
        format!(
            "{}  •  {}  •  {} scenes  •  last {}  ",
            state.profile,
            activity,
            state.projection.available_scenes().len(),
            latest
        )
    } else {
        format!(
            "{}  •  {}  •  {} events  •  last {}  ",
            state.profile,
            state.mode.label(),
            state.events.len(),
            latest
        )
    };
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(area);
    frame.render_widget(
        Paragraph::new(title).block(panel_block("", palette)),
        cols[0],
    );
    frame.render_widget(
        Paragraph::new(context)
            .alignment(Alignment::Right)
            .style(Style::default().fg(palette.muted).bg(palette.surface))
            .block(panel_block("", palette)),
        cols[1],
    );
}

fn render_workspace(frame: &mut Frame<'_>, area: Rect, state: &TuiState, palette: Palette) {
    if state.mode == InteractionMode::Assisted {
        render_scene(
            frame,
            area,
            state.scene,
            &state.projection,
            palette,
            state.scene_scroll,
        );
        return;
    }
    if area.width >= 110 && state.view == View::Overview {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(24),
                Constraint::Percentage(46),
                Constraint::Percentage(30),
            ])
            .split(area);
        render_subjects(frame, cols[0], state, palette);
        render_events(frame, cols[1], state, palette);
        render_evidence(frame, cols[2], state, palette);
    } else if area.width >= 78 {
        let (left, right) = match state.view {
            View::Overview | View::Timeline => {
                (Constraint::Percentage(62), Constraint::Percentage(38))
            }
            View::Evidence => (Constraint::Percentage(38), Constraint::Percentage(62)),
        };
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([left, right])
            .split(area);
        render_events(frame, cols[0], state, palette);
        render_evidence(frame, cols[1], state, palette);
    } else {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
            .split(area);
        render_events(frame, rows[0], state, palette);
        render_evidence(frame, rows[1], state, palette);
    }
}

fn render_subjects(frame: &mut Frame<'_>, area: Rect, state: &TuiState, palette: Palette) {
    let mut subjects: Vec<_> = state.subject_counts.iter().collect();
    subjects.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let items: Vec<ListItem<'_>> = if subjects.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "No subjects observed",
            Style::default().fg(palette.muted),
        )))]
    } else {
        subjects
            .iter()
            .take(area.height.saturating_sub(2) as usize)
            .map(|(subject, count)| {
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{count:>3}  "), Style::default().fg(palette.accent)),
                    Span::styled((**subject).to_string(), Style::default().fg(palette.text)),
                ]))
            })
            .collect()
    };
    frame.render_widget(
        List::new(items)
            .block(panel_block(" SUBJECTS ", palette))
            .style(Style::default().bg(palette.surface)),
        area,
    );
}

fn render_events(frame: &mut Frame<'_>, area: Rect, state: &TuiState, palette: Palette) {
    let visible = area.height.saturating_sub(2).max(1) as usize;
    let offset = state.selected_event.saturating_sub(visible - 1);
    let items: Vec<ListItem<'_>> = if state.events.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "No observations yet",
            Style::default().fg(palette.muted),
        )))]
    } else {
        state
            .events
            .iter()
            .skip(offset)
            .take(visible)
            .map(|event| {
                let color = palette.severity(&event.severity);
                let severity = format!("{:>4}", severity_label(&event.severity));
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{} ", event.timestamp.format("%H:%M:%S")),
                        Style::default().fg(palette.muted),
                    ),
                    Span::styled(format!("{severity} "), Style::default().fg(color)),
                    Span::styled(
                        format!("{:<8} ", truncate(&event.module, 8)),
                        Style::default().fg(palette.accent),
                    ),
                    Span::styled(event.summary.clone(), Style::default().fg(palette.text)),
                ]))
            })
            .collect()
    };
    let list = List::new(items)
        .block(panel_block(" OBSERVATIONS ", palette))
        .style(Style::default().bg(palette.surface))
        .highlight_style(
            Style::default()
                .bg(palette.selected)
                .fg(palette.text)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");
    let mut selected = ListState::default();
    if !state.events.is_empty() {
        selected.select(Some(state.selected_event - offset));
    }
    frame.render_stateful_widget(list, area, &mut selected);
}

fn render_evidence(frame: &mut Frame<'_>, area: Rect, state: &TuiState, palette: Palette) {
    let mut lines = Vec::new();
    if let Some(event) = state.selected() {
        lines.push(Line::from(Span::styled(
            event.summary.clone(),
            Style::default()
                .fg(palette.text)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::raw(""));
        lines.push(detail_line("TIME", event.timestamp.to_rfc3339(), palette));
        lines.push(detail_line(
            "SOURCE",
            format!("{:?}", event.source),
            palette,
        ));
        if let Some(subject) = &event.subject {
            lines.push(detail_line("SUBJECT", subject.clone(), palette));
        }
        if !event.evidence.is_empty() {
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                "EVIDENCE",
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            )));
            for evidence in &event.evidence {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{}  ", evidence.label),
                        Style::default().fg(palette.muted),
                    ),
                    Span::styled(evidence.value.clone(), Style::default().fg(palette.text)),
                ]));
                lines.push(Line::from(Span::styled(
                    format!("  ↳ {}", evidence.origin),
                    Style::default().fg(palette.muted),
                )));
            }
        }
        lines.push(Line::raw(""));
        lines.push(detail_line("MODULE", event.module.clone(), palette));
        lines.push(detail_line("TYPE", event.kind.clone(), palette));
        lines.push(detail_line("ID", event.id.clone(), palette));
    } else {
        lines.push(Line::from(Span::styled(
            "Select an observation to inspect its evidence and provenance.",
            Style::default().fg(palette.muted),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((state.detail_scroll, 0))
            .style(Style::default().bg(palette.surface))
            .block(panel_block(" EVIDENCE ", palette)),
        area,
    );
}

fn render_input(frame: &mut Frame<'_>, area: Rect, state: &TuiState, palette: Palette) {
    if state.mode == InteractionMode::Assisted {
        render_assisted_input(frame, area, state, palette);
        return;
    }
    let (title, text): (String, String) = match state.mode {
        InteractionMode::Autonomous => (
            " COMMAND ".to_string(),
            "Press / to enter a research command".to_string(),
        ),
        InteractionMode::Interactive => (
            " COMMAND ".to_string(),
            format!("› {}", state.command_input),
        ),
        InteractionMode::Assisted => unreachable!(),
    };
    let available_width = area.width.saturating_sub(3) as usize;
    let mut display_width = 0usize;
    let mut reversed = Vec::new();
    for character in text.chars().rev() {
        let width = Line::from(character.to_string()).width();
        if display_width + width > available_width {
            break;
        }
        display_width += width;
        reversed.push(character);
    }
    let display: String = reversed.into_iter().rev().collect();
    frame.render_widget(
        Paragraph::new(display)
            .style(
                Style::default()
                    .fg(if state.mode == InteractionMode::Autonomous {
                        palette.muted
                    } else {
                        palette.text
                    })
                    .bg(palette.surface),
            )
            .block(panel_block(&title, palette)),
        area,
    );
    if state.mode != InteractionMode::Autonomous && !state.show_help && !state.show_settings {
        let x = area
            .x
            .saturating_add(1)
            .saturating_add(display_width as u16)
            .min(area.right().saturating_sub(2));
        frame.set_cursor_position((x, area.y.saturating_add(1)));
    }
}

fn render_assisted_input(frame: &mut Frame<'_>, area: Rect, state: &TuiState, palette: Palette) {
    let Some(scenario) = state.scenario() else {
        frame.render_widget(
            Paragraph::new("No assisted scenario available")
                .style(Style::default().fg(palette.text).bg(palette.surface))
                .block(panel_block(" ASSISTED ", palette)),
            area,
        );
        return;
    };
    if state.running_session.is_none()
        && state.watch_scenario.as_deref() == Some(scenario.id.as_str())
        && (state.last_full_succeeded.is_some() || state.watch_cycle > 0)
    {
        render_assisted_watch_input(frame, area, state, scenario, palette);
        return;
    }
    let (stage_index, stage_count) = state.prepared.position();
    let Some(step) = state.scenario_step() else {
        frame.render_widget(
            Paragraph::new("No stage available")
                .style(Style::default().fg(palette.text).bg(palette.surface))
                .block(panel_block(" ASSISTED ", palette)),
            area,
        );
        return;
    };

    let visible = state.prepared.visible();
    let input = if visible.is_empty() {
        "› [type any key to reveal]".to_string()
    } else {
        format!("› {visible}")
    };
    let input = fit_tail(&input, area.width.saturating_sub(4) as usize);
    let wide = area.height >= 8;
    if wide {
        let start = if scenario.steps.len() > 8 {
            state.prepared.index.saturating_sub(2)
        } else {
            0
        };
        let stage_progress = scenario
            .steps
            .iter()
            .enumerate()
            .skip(start)
            .take(if scenario.steps.len() > 8 { 5 } else { 8 })
            .map(|(index, step)| {
                let mark = if state
                    .failed_session_stages
                    .contains(&(scenario.id.clone(), index + 1))
                {
                    "!"
                } else if index < state.prepared.index
                    || index == state.prepared.index && state.prepared.is_presented()
                {
                    "✓"
                } else if index == state.prepared.index {
                    "›"
                } else {
                    "·"
                };
                format!("{mark}{} {}", index + 1, step.phase)
            })
            .collect::<Vec<_>>()
            .join("  ");
        let stage_progress = truncate(&stage_progress, area.width.saturating_sub(4) as usize);
        let stage_key = (scenario.id.clone(), stage_index);
        let action = match step.execution {
            _ if state.running_session.as_deref() == Some(&scenario.id) => "SESSION RUNNING",
            Execution::Local => "LOCAL: Enter or F6 full session",
            Execution::Explicit if state.pending_explicit_runs.contains(&stage_key) => {
                "NETWORK RUN PENDING"
            }
            Execution::Explicit if state.completed_explicit_runs.contains(&stage_key) => {
                "NETWORK RUN COMPLETE"
            }
            Execution::Explicit => "NETWORK: Ctrl+R step or F6 full session",
            Execution::PresentationOnly => "PRESENTATION: records only",
        };
        let instruction = match step.execution {
            _ if state.running_session.as_deref() == Some(&scenario.id) => {
                "F6 session running  ·  Results and stage progress appear above"
            }
            Execution::Local if scenario.id == "local-research" => {
                "F6 runs full local session  ·  Enter runs one revealed step  ·  Left goes back"
            }
            Execution::Local => {
                "F6 runs full scenario  ·  Enter runs one revealed step  ·  Left goes back"
            }
            Execution::Explicit => {
                "F6 runs full scenario  ·  Ctrl+R runs revealed step  ·  Enter records only"
            }
            Execution::PresentationOnly => {
                "Type to reveal  ·  Enter records text only  ·  Left goes back  ·  Tab selects"
            }
        };
        let lines = vec![
            Line::from(vec![
                Span::styled(
                    format!(
                        "SCENARIO {}/{}  ",
                        state.scenario_index + 1,
                        state.scenarios.len()
                    ),
                    Style::default().fg(palette.muted),
                ),
                Span::styled(
                    scenario.title.clone(),
                    Style::default()
                        .fg(palette.accent)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(Span::styled(
                stage_progress,
                Style::default().fg(palette.muted),
            )),
            Line::from(vec![
                Span::styled(
                    format!("STAGE {stage_index}/{stage_count}  {}  ", step.phase),
                    Style::default()
                        .fg(palette.text)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(action, Style::default().fg(palette.accent)),
            ]),
            Line::from(Span::styled(
                step.context.clone(),
                Style::default().fg(palette.text),
            )),
            Line::from(Span::styled(
                input.clone(),
                Style::default().fg(palette.accent),
            )),
            Line::from(Span::styled(
                instruction,
                Style::default().fg(palette.muted),
            )),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .style(Style::default().bg(palette.surface))
                .block(panel_block(" ASSISTED / GUIDED SESSION ", palette)),
            area,
        );
    } else {
        let title = if scenario.id != "custom" {
            format!(
                " ASSISTED  {stage_index}/{stage_count}  {}  F6 Run ",
                step.phase
            )
        } else {
            format!(" ASSISTED  {stage_index}/{stage_count}  {} ", step.phase)
        };
        frame.render_widget(
            Paragraph::new(input.clone())
                .style(Style::default().fg(palette.accent).bg(palette.surface))
                .block(panel_block(&title, palette)),
            area,
        );
    }
    if !state.show_help && !state.show_settings {
        let x = area
            .x
            .saturating_add(1)
            .saturating_add(Line::from(input).width() as u16)
            .min(area.right().saturating_sub(2));
        let y = if wide {
            area.y.saturating_add(5)
        } else {
            area.y.saturating_add(1)
        };
        frame.set_cursor_position((x, y));
    }
}

fn render_assisted_watch_input(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &TuiState,
    scenario: &Scenario,
    palette: Palette,
) {
    let run_result = state
        .last_full_succeeded
        .map(|(succeeded, total)| format!("Initial pass: {succeeded}/{total} stages succeeded"))
        .unwrap_or_else(|| "Initial pass not run".to_string());
    let activity = if state.watch_pending {
        format!("FOLLOW-UP {} RUNNING", state.watch_cycle)
    } else if state.live_watch {
        "LIVE FOLLOW-UPS ON".to_string()
    } else {
        "FOLLOW-UPS PAUSED".to_string()
    };
    let next_check = if state.watch_pending {
        "Current follow-up is collecting real observations".to_string()
    } else if state.live_watch {
        let seconds = state
            .next_watch
            .saturating_duration_since(Instant::now())
            .as_secs();
        let lan = if !state.watch_lan_allowed || !state.config.lan_assessment_enabled {
            "LAN off".to_string()
        } else {
            let seconds = Duration::from_secs(120)
                .saturating_sub(state.last_lan_watch.elapsed())
                .as_secs();
            format!("LAN refresh eligible in {seconds}s")
        };
        format!("Next local check in {seconds}s  ·  {lan}")
    } else {
        "Press F7 to resume live follow-ups".to_string()
    };
    let carousel = assisted_scene_carousel(state, area.width.saturating_sub(4) as usize);
    let lines = vec![
        Line::from(vec![
            Span::styled(
                format!("{}  ", scenario.title),
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(activity, Style::default().fg(palette.text)),
        ]),
        Line::from(Span::styled(run_result, Style::default().fg(palette.text))),
        Line::from(Span::styled(
            format!("Current screen: {}", state.scene.label()),
            Style::default().fg(palette.accent),
        )),
        Line::from(Span::styled(carousel, Style::default().fg(palette.muted))),
        Line::from(Span::styled(next_check, Style::default().fg(palette.text))),
        Line::from(Span::styled(
            "F3 browse  ·  Up/Down scroll  ·  F8 auto views  ·  F7 pause/resume",
            Style::default().fg(palette.muted),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().bg(palette.surface))
            .block(panel_block(" ASSISTED / LIVE INVESTIGATION ", palette)),
        area,
    );
}

fn assisted_scene_carousel(state: &TuiState, max_width: usize) -> String {
    let available = state.projection.available_scenes();
    let Some(center) = available.iter().position(|scene| *scene == state.scene) else {
        return format!(
            "Current stage: {} · waiting for evidence",
            state.scene.label()
        );
    };
    let count = available.len();
    if count == 1 {
        return format!("01/01  [{}]", state.scene.label());
    }
    let radius = if max_width >= 104 && count >= 5 { 2 } else { 1 };
    let mut labels = Vec::new();
    for offset in -(radius as isize)..=(radius as isize) {
        let index = (center as isize + offset).rem_euclid(count as isize) as usize;
        let label = available[index].label();
        labels.push(if offset == 0 {
            format!("[{label}]")
        } else {
            label.to_owned()
        });
    }
    let text = format!(
        "{:02}/{:02}  ◀  {}  ▶",
        center + 1,
        count,
        labels.join("  ·  ")
    );
    truncate(&text, max_width)
}

fn fit_tail(value: &str, max_width: usize) -> String {
    let mut width = 0usize;
    let mut reversed = Vec::new();
    for character in value.chars().rev() {
        let character_width = Line::from(character.to_string()).width();
        if width + character_width > max_width {
            break;
        }
        width += character_width;
        reversed.push(character);
    }
    reversed.into_iter().rev().collect()
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, state: &TuiState, palette: Palette) {
    let shortcuts = if state.mode == InteractionMode::Assisted && area.width >= 112 {
        "F3 Screen  F6 Run  F7 Watch  F8 Auto  F5 Setup  Tab Scenario"
    } else if state.mode == InteractionMode::Assisted && area.width >= 78 {
        "F3 Screen  F6 Run  F7 Watch  F8 Auto  Tab Next"
    } else if state.mode == InteractionMode::Assisted {
        "F3 View  F6 Run  F7 Watch  F1 Help"
    } else if area.width >= 112 {
        "F1 Help  F2 Mode  F3 View  F4 Theme  F5 Settings  Ctrl+J/K Select  Ctrl+U/D Evidence  Ctrl+C Exit"
    } else {
        "F1 Help  F2 Mode  F3 View  F5 Settings  Ctrl+C Exit"
    };
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(area);
    frame.render_widget(
        Paragraph::new(shortcuts).style(Style::default().fg(palette.muted).bg(palette.background)),
        columns[0],
    );
    let view_label = if state.mode == InteractionMode::Assisted {
        state.scene.label()
    } else {
        state.view.label()
    };
    let status = format!("{}  ·  {}", view_label, state.status);
    let status = fit_tail(&status, columns[1].width as usize);
    frame.render_widget(
        Paragraph::new(status)
            .alignment(Alignment::Right)
            .style(Style::default().fg(palette.accent).bg(palette.background)),
        columns[1],
    );
}

fn render_help(frame: &mut Frame<'_>, area: Rect, palette: Palette) {
    let popup = centered(area, 74, 24);
    frame.render_widget(Clear, popup);
    let help = [
        "SPECTRE / KEYBOARD",
        "F2             Cycle autonomous, interactive and assisted input",
        "F3             Browse and hold a screen for 30 seconds",
        "F4             Cycle theme                    F5  Settings",
        "F7             Pause / resume live follow-ups",
        "F8             Pause / resume automatic screen changes",
        "Ctrl+J / K     Scroll Assisted; select observations otherwise",
        "Ctrl+U / D     Scroll Assisted; scroll evidence otherwise",
        "Page Down / Up Scroll Assisted; select ten observations otherwise",
        "AUTONOMOUS     / opens command input; Up/Down inspect events",
        "INTERACTIVE    Enter submits command; Up/Down recall history",
        "ASSISTED       Up/Down scroll; Tab / Shift+Tab selects a scenario",
        "               Left revisits; Esc resets a stage to rerun",
        "               Each character reveals one prepared character",
        "               Enter runs local steps, records and advances",
        "               F6 runs the full session and starts live follow-ups",
        "               Ctrl+R runs a revealed network step",
        "               Custom steps are recorded, never executed",
        "               F5 then n toggles LAN assessment",
        "Esc closes this panel. Ctrl+C exits.",
    ];
    frame.render_widget(
        Paragraph::new(help.join("\n"))
            .style(Style::default().fg(palette.text).bg(palette.surface))
            .block(panel_block(" HELP ", palette)),
        popup,
    );
}

fn render_settings(frame: &mut Frame<'_>, area: Rect, state: &TuiState, palette: Palette) {
    let popup = centered(area, 64, 18);
    frame.render_widget(Clear, popup);
    let arrangement = if state.mode == InteractionMode::Assisted {
        state.scene.label().to_ascii_lowercase()
    } else {
        state.view.label().to_ascii_lowercase()
    };
    let content = format!(
        "WORKSPACE SETTINGS\n\n  p  Profile            {}\n  t  Theme              {}\n  l  Arrangement        {}\n  r  Display refresh    {} ms\n  a  Autonomous work    {}\n  n  LAN survey         {}\n\nSettings are saved; arrangement is session-only.\nF6 starts live Assisted follow-ups; F7 pauses them.\nLAN refreshes while watch is on, unless turned off.\n\nEsc closes settings.",
        state.profile,
        state.theme.label(),
        arrangement,
        state.refresh_ms,
        if state.config.autonomous { "on" } else { "off" },
        if state.config.lan_assessment_enabled {
            "on"
        } else {
            "off"
        }
    );
    frame.render_widget(
        Paragraph::new(content)
            .style(Style::default().fg(palette.text).bg(palette.surface))
            .block(panel_block(" SETTINGS ", palette)),
        popup,
    );
}

fn centered(area: Rect, preferred_width: u16, preferred_height: u16) -> Rect {
    let width = preferred_width.min(area.width.saturating_sub(4)).max(1);
    let height = preferred_height.min(area.height.saturating_sub(2)).max(1);
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}

fn panel_block<'a>(title: &'a str, palette: Palette) -> Block<'a> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(palette.border))
        .style(Style::default().bg(palette.surface))
}

fn detail_line(label: &str, value: String, palette: Palette) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<8} "), Style::default().fg(palette.muted)),
        Span::styled(value, Style::default().fg(palette.text)),
    ])
}

fn severity_label(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn truncate(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SourceKind;
    use ratatui::backend::TestBackend;

    fn assisted_event(kind: &str, scenario: &str, index: usize) -> Event {
        Event::new(
            "presentation",
            kind,
            kind,
            None,
            Severity::Info,
            SourceKind::Prepared,
        )
        .with_evidence("scenario", scenario, "test")
        .with_evidence("step_index", index.to_string(), "test")
    }

    fn render_state_to_text(state: &TuiState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, state)).unwrap();
        let mut text = String::new();
        let buffer = terminal.backend().buffer();
        for y in 0..height {
            for x in 0..width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    fn render_to_text(width: u16, height: u16) -> String {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.ingest(
            Event::new(
                "binary",
                "binary.format",
                "ELF x86_64 executable inspected",
                Some("/tmp/sample".to_string()),
                Severity::Info,
                SourceKind::File,
            )
            .with_evidence("sha256", "abc123", "file bytes"),
        );
        render_state_to_text(&state, width, height)
    }

    fn select_scenario(state: &mut TuiState, id: &str) {
        for _ in 0..state.scenarios.len() {
            if state.scenario().is_some_and(|scenario| scenario.id == id) {
                return;
            }
            state.cycle_scenario(false);
        }
        panic!("assisted scenario {id} not found");
    }

    #[test]
    fn prepared_input_reveals_text_by_character_not_typed_key() {
        let mut input = PreparedInput::new(vec![
            "nmap -sV 127.0.0.1".to_string(),
            "inspect 127.0.0.1".to_string(),
        ]);
        for _ in 0..4 {
            input.advance();
        }
        assert_eq!(input.visible(), "nmap");
        assert!(!input.complete());
        input.backspace();
        assert_eq!(input.visible(), "nma");
        assert!(!input.next_step());
        for _ in 0..100 {
            input.advance();
        }
        assert!(input.complete());
        assert!(input.next_step());
        assert_eq!(input.visible(), "");
        assert_eq!(input.position(), (2, 2));
    }

    #[test]
    fn prepared_input_supports_unicode_and_empty_sequences() {
        let mut input = PreparedInput::new(vec!["αβ".to_string()]);
        input.advance();
        assert_eq!(input.visible(), "α");
        input.advance();
        assert_eq!(input.visible(), "αβ");
        assert!(input.complete());
        assert!(!input.next_step());
        let mut empty = PreparedInput::new(vec![]);
        empty.advance();
        assert!(empty.visible().is_empty());
        assert!(!empty.complete());
    }

    #[test]
    fn layout_rect_remains_inside_small_terminal() {
        let area = Rect::new(0, 0, 20, 8);
        let popup = centered(area, 74, 18);
        assert!(popup.right() <= area.right());
        assert!(popup.bottom() <= area.bottom());
    }

    #[test]
    fn overview_renders_real_event_at_standard_and_wide_sizes() {
        for (width, height) in [(80, 24), (120, 36)] {
            let screen = render_to_text(width, height);
            assert!(screen.contains("SPECTRE"));
            assert!(screen.contains("OBSERVATIONS"));
            assert!(screen.contains("EVIDENCE"));
            assert!(screen.contains("ELF x86_64"));
            assert!(screen.contains("sha256"), "{width}x{height}:\n{screen}");
            if width == 120 {
                assert!(screen.contains("SUBJECTS"));
            }
        }
    }

    #[test]
    fn assisted_starts_with_full_system_and_network_scenario() {
        let state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        assert_eq!(state.scenario().unwrap().id, "system-network");
        assert!(state.prepared.steps.len() >= 8);
        assert!(state.prepared.current().is_some());
    }

    #[test]
    fn assisted_stage_focus_and_auto_rotation_show_distinct_real_scenes() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        state.running_session = Some("system-network".into());
        state.ingest(
            Event::new(
                "lan",
                "lan.status",
                "Active private IPv4 segment",
                Some("192.168.1.0/24".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("cidr", "192.168.1.0/24", "test"),
        );
        state.ingest(
            assisted_event("assisted.session.stage.start", "system-network", 9)
                .with_evidence("phase", "Host and service survey", "test")
                .with_evidence("command", "lan survey 192.168.1.0/24", "test"),
        );
        assert_eq!(state.scene, Scene::Network);
        let network = render_state_to_text(&state, 120, 30);
        assert!(network.contains("NETWORK / LAN SURVEY"));
        assert!(network.contains("192.168.1.0/24"));
        assert!(!network.contains("SUBJECTS"));
        state.last_scene_change = Instant::now() - Duration::from_secs(6);
        let (tx, _rx) = mpsc::channel(4);
        assert!(state.tick(&tx));
        assert_ne!(state.scene, Scene::Network);
        let next = render_state_to_text(&state, 120, 30);
        assert_ne!(network, next);
    }

    #[test]
    fn assisted_stage_commands_focus_evidence_scenes() {
        assert_eq!(scene_for_command("capture en0"), Scene::Capture);
        assert_eq!(scene_for_command("runtime sample 1234"), Scene::Runtime);
        assert_eq!(scene_for_command("disasm /tmp/bin"), Scene::Disassembly);
        assert_eq!(scene_for_command("intel cve CVE-2025-1234"), Scene::Intel);
    }

    #[test]
    fn carousel_keeps_current_scene_readable_and_rotation_reaches_intel() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        state.running_session = Some("system-network".into());
        for (module, kind, subject, evidence) in [
            ("capture", "capture.summary", "en0", ("interface", "en0")),
            (
                "disasm",
                "disasm.summary",
                "/tmp/bin",
                ("section", "__text"),
            ),
            ("runtime", "runtime.resources", "pid:1234", ("pid", "1234")),
            (
                "intel",
                "intel.no_record",
                "abc123",
                ("provider", "CIRCL hashlookup"),
            ),
        ] {
            state.ingest(
                Event::new(
                    module,
                    kind,
                    "recorded observation",
                    Some(subject.into()),
                    Severity::Info,
                    SourceKind::Live,
                )
                .with_evidence(evidence.0, evidence.1, "test"),
            );
        }
        let (tx, _rx) = mpsc::channel(4);
        let mut seen = Vec::new();
        for _ in 0..state.projection.available_scenes().len() {
            state.last_scene_change = Instant::now() - Duration::from_secs(6);
            assert!(state.tick(&tx));
            seen.push(state.scene);
        }
        assert!(seen.contains(&Scene::Intel));
        state.scene = Scene::Intel;
        for width in [76, 116] {
            let carousel = assisted_scene_carousel(&state, width);
            assert!(carousel.contains("[THREAT INTEL]"), "{carousel}");
            assert!(carousel.chars().count() <= width);
            assert!(carousel.contains("/"));
        }
    }

    #[test]
    fn live_watch_queues_one_pulse_and_respects_lan_interval() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        state.live_watch = true;
        state.watch_scenario = Some("system-network".into());
        state.watch_lan_allowed = true;
        state.next_watch = Instant::now() - Duration::from_secs(1);
        state.last_lan_watch = Instant::now() - Duration::from_secs(121);
        let (tx, mut rx) = mpsc::channel(4);
        assert!(state.tick(&tx));
        assert_eq!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedLivePulse {
                cycle: 1,
                include_lan: true
            }
        );
        state.next_watch = Instant::now() - Duration::from_secs(1);
        state.tick(&tx);
        assert!(rx.try_recv().is_err());
        state.ingest(
            Event::new(
                "presentation",
                "assisted.watch.complete",
                "Live follow-up complete",
                None,
                Severity::Info,
                SourceKind::Derived,
            )
            .with_evidence("succeeded", "6", "test")
            .with_evidence("failed", "0", "test"),
        );
        assert!(!state.watch_pending);
        state.next_watch = Instant::now() - Duration::from_secs(1);
        assert!(state.tick(&tx));
        assert_eq!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedLivePulse {
                cycle: 2,
                include_lan: false
            }
        );
    }

    #[test]
    fn local_follow_up_does_not_restart_the_screen_rotation() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        state.watch_pending = true;
        state.watch_cycle = 1;
        state.scene = Scene::Binary;
        state.last_scene_change = Instant::now() - Duration::from_secs(3);
        let previous = state.last_scene_change;
        state.ingest(
            Event::new(
                "presentation",
                "assisted.watch.stage.start",
                "Traffic refresh running",
                None,
                Severity::Info,
                SourceKind::Derived,
            )
            .with_evidence("phase", "Interface traffic", "test")
            .with_evidence("command", "traffic snapshot", "test"),
        );
        assert_eq!(state.scene, Scene::Binary);
        assert_eq!(state.last_scene_change, previous);
        state.ingest(
            Event::new(
                "presentation",
                "assisted.watch.stage.start",
                "LAN refresh running",
                None,
                Severity::Info,
                SourceKind::Derived,
            )
            .with_evidence("phase", "LAN survey", "test")
            .with_evidence("command", "lan survey", "test"),
        );
        assert_eq!(state.scene, Scene::Network);
    }

    #[test]
    fn newly_observed_lan_host_spotlights_network_without_repeating_old_host() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        let host = |address: &str| {
            Event::new(
                "lan",
                "lan.host",
                format!("{address} answered TCP probes"),
                Some(address.to_string()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("address", address, "test")
        };
        state.ingest(host("192.168.1.10"));
        assert_eq!(state.scene, Scene::Network);
        state.scene = Scene::Mission;
        state.last_discovery_spotlight = Instant::now() - Duration::from_secs(6);
        state.ingest(host("192.168.1.10"));
        assert_eq!(state.scene, Scene::Mission);
        state.ingest(host("192.168.1.11"));
        assert_eq!(state.scene, Scene::Network);
    }

    #[test]
    fn assisted_scroll_holds_scene_and_moves_visible_evidence() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        for number in 1..=15 {
            let address = format!("192.168.1.{number}");
            state.ingest(Event::new(
                "lan",
                "lan.host",
                format!("{address} answered TCP probes"),
                Some(address),
                Severity::Info,
                SourceKind::Live,
            ));
        }
        state.scene = Scene::Network;
        state.last_scene_change = Instant::now() - Duration::from_secs(8);
        let (tx, _rx) = mpsc::channel(4);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(state.scene_scroll, 10);
        assert!(state.manual_scene_until.is_some());
        assert!(render_state_to_text(&state, 120, 30).contains("11–15 OF 15"));
        state.tick(&tx);
        assert_eq!(state.scene, Scene::Network);
    }

    #[test]
    fn failed_full_run_does_not_start_follow_ups() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        let (tx, mut rx) = mpsc::channel(4);
        run_assisted_session(&mut state, &tx);
        assert!(matches!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedRunSession { .. }
        ));
        state.ingest(
            Event::new(
                "presentation",
                "assisted.session.error",
                "Session could not start",
                None,
                Severity::Low,
                SourceKind::Derived,
            )
            .with_evidence("scenario", "system-network", "test"),
        );
        assert!(!state.live_watch);
        assert!(state.watch_scenario.is_none());
        state.next_watch = Instant::now() - Duration::from_secs(1);
        state.tick(&tx);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn scenario_change_switches_network_context_away_from_prior_target() {
        let config = Config {
            allowed_targets: vec!["example.org".into()],
            ..Config::default()
        };
        let mut state = TuiState::new(config, PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        select_scenario(&mut state, "scoped-network:example.org");
        state.ingest(
            Event::new(
                "network",
                "tcp_scan_complete",
                "example.org scan complete",
                Some("example.org".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("target", "example.org", "test"),
        );
        state.scene = Scene::Network;
        assert!(render_state_to_text(&state, 120, 30).contains("NETWORK / SCOPED TARGET"));
        select_scenario(&mut state, "system-network");
        let screen = render_state_to_text(&state, 120, 30);
        assert!(screen.contains("NETWORK / LAN SURVEY"));
        assert!(!screen.contains("NETWORK / SCOPED TARGET"));
    }

    #[test]
    fn disappearing_host_dossier_returns_to_network_during_resurvey() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        state.ingest(
            Event::new(
                "lan",
                "lan.host",
                "Host answered",
                Some("192.168.1.4".into()),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("segment", "192.168.1.0/24", "test"),
        );
        assert!(
            state
                .projection
                .available_scenes()
                .contains(&Scene::Host(0))
        );
        state.scene = Scene::Host(0);
        state.ingest(
            Event::new(
                "presentation",
                "assisted.watch.stage.start",
                "LAN resurvey running",
                None,
                Severity::Info,
                SourceKind::Derived,
            )
            .with_evidence("command", "lan survey", "test"),
        );
        let (tx, _rx) = mpsc::channel(4);
        assert!(state.tick(&tx));
        assert_eq!(state.scene, Scene::Network);
    }

    #[test]
    fn missing_completion_event_does_not_leave_assisted_stuck_forever() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        state.live_watch = true;
        state.running_session = Some("system-network".into());
        state.running_started_at = Some(Instant::now() - Duration::from_secs(121));
        state.next_watch = Instant::now() + Duration::from_secs(20);
        let (tx, _rx) = mpsc::channel(4);
        assert!(state.tick(&tx));
        assert!(state.running_session.is_none());
        assert!(!state.live_watch);
        assert!(state.uncertain_request);
        assert!(state.status.contains("completion not received"));

        state.live_watch = true;
        state.watch_pending = true;
        state.watch_started_at = Some(Instant::now() - Duration::from_secs(121));
        assert!(state.tick(&tx));
        assert!(!state.watch_pending);
        assert!(!state.live_watch);
        assert!(state.uncertain_request);
        assert!(state.status.contains("Follow-up completion not received"));
    }

    #[test]
    fn tab_cycles_scenarios_and_resets_prepared_input() {
        let config = Config {
            lan_assessment_enabled: false,
            allowed_targets: vec!["example.org".into()],
            prepared_workflow: vec!["saved text".into()],
            ..Config::default()
        };
        let mut state = TuiState::new(config, PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        let (tx, mut rx) = mpsc::channel(4);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(state.prepared.visible().chars().count(), 1);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(state.scenario().unwrap().id, "local-research");
        assert_eq!(state.prepared.visible(), "");
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(state.scenario().unwrap().id, "process-investigation");
        assert_eq!(state.prepared.visible(), "");
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(state.scenario().unwrap().id, "scoped-network:example.org");
        assert_eq!(state.prepared.visible(), "");
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(state.scenario().unwrap().id, "custom");
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT),
            &tx,
        );
        assert_eq!(state.scenario().unwrap().id, "scoped-network:example.org");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn custom_scenario_stays_selected_after_config_refresh() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "spectre-assisted-custom-{}-{id}.toml",
            std::process::id()
        ));
        let mut config = Config {
            lan_assessment_enabled: false,
            prepared_workflow: vec!["first step".into()],
            ..Config::default()
        };
        config.save(&path).unwrap();
        let mut state = TuiState::new(config.clone(), path.clone());
        select_scenario(&mut state, "custom");
        assert_eq!(state.scenario().unwrap().id, "custom");
        config.prepared_workflow.push("second step".into());
        config.save(&path).unwrap();
        state.sync_config_from_disk();
        assert_eq!(state.scenario().unwrap().id, "custom");
        assert_eq!(state.prepared.steps, config.prepared_workflow);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn assisted_enter_submits_only_after_reveal() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        select_scenario(&mut state, "local-research");
        let (tx, mut rx) = mpsc::channel(4);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &tx,
        );
        assert!(rx.try_recv().is_err());
        for _ in 0.."doctor".len() {
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE),
                &tx,
            );
        }
        assert!(state.prepared.complete());
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedStep {
                scenario_id: "local-research".to_string(),
                index: 1,
                text: "doctor".to_string(),
            }
        );
        assert_eq!(state.prepared.position(), (1, 7));
        assert_eq!(state.pending_step, Some(("local-research".to_string(), 1)));
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &tx,
        );
        assert!(rx.try_recv().is_err());
        state.ingest(assisted_event(
            "assisted.step.complete",
            "local-research",
            1,
        ));
        assert_eq!(state.prepared.position(), (2, 7));
        assert!(state.pending_step.is_none());
    }

    #[test]
    fn failed_manual_stage_stays_revealed_and_enter_retries() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        select_scenario(&mut state, "local-research");
        let (tx, mut rx) = mpsc::channel(4);
        while !state.prepared.complete() {
            state.prepared.advance();
        }
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &tx,
        );
        assert!(matches!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedStep { index: 1, .. }
        ));
        state.ingest(assisted_event("assisted.step.error", "local-research", 1));
        assert_eq!(state.prepared.position(), (1, 7));
        assert!(state.prepared.complete());
        assert!(state.pending_step.is_none());
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &tx,
        );
        assert!(matches!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedStep { index: 1, .. }
        ));
        state.ingest(assisted_event(
            "assisted.step.complete",
            "local-research",
            1,
        ));
        assert_eq!(state.prepared.position(), (2, 7));
    }

    #[test]
    fn f6_runs_local_session_once_and_updates_stage_progress() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        select_scenario(&mut state, "local-research");
        let (tx, mut rx) = mpsc::channel(4);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::F(6), KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedRunSession {
                scenario_id: "local-research".to_string(),
            }
        );
        assert_eq!(state.running_session.as_deref(), Some("local-research"));
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::F(6), KeyModifiers::NONE),
            &tx,
        );
        assert!(rx.try_recv().is_err());
        state.ingest(
            assisted_event("assisted.session.stage", "local-research", 1).with_evidence(
                "phase",
                "Environment",
                "test",
            ),
        );
        assert_eq!(state.prepared.position(), (1, 7));
        assert_eq!(state.prepared.visible(), "doctor");
        state.ingest(
            assisted_event("assisted.session.stage", "local-research", 2)
                .with_evidence("phase", "Collection", "test")
                .with_evidence("status", "error", "test"),
        );
        assert_eq!(state.prepared.position(), (2, 7));
        assert!(state.status.contains("2/7"));
        assert!(state.status.contains("failed"));
        let screen = render_state_to_text(&state, 120, 30);
        assert!(screen.contains("STAGE 2/7"), "{screen}");
        assert!(screen.contains("!2 Collection"), "{screen}");
        state.ingest(
            assisted_event("assisted.session.stage", "local-research", 3)
                .with_evidence("phase", "Intel lookup", "test")
                .with_evidence("status", "partial", "test"),
        );
        assert!(state.status.contains("partial"));
        assert!(
            state
                .failed_session_stages
                .contains(&("local-research".to_string(), 3))
        );
        state.ingest(
            Event::new(
                "presentation",
                "assisted.session.complete",
                "Local session complete",
                None,
                Severity::Info,
                SourceKind::Derived,
            )
            .with_evidence("scenario", "local-research", "test")
            .with_evidence("succeeded", "6", "test"),
        );
        assert!(state.running_session.is_none());
        assert_eq!(state.status, "Local 6/7 stages passed");
    }

    #[test]
    fn f6_runs_default_system_network_scenario_with_one_request() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        assert_eq!(state.scenario().unwrap().id, "system-network");
        let (tx, mut rx) = mpsc::channel(4);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::F(6), KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedRunSession {
                scenario_id: "system-network".into(),
            }
        );
        assert_eq!(state.running_session.as_deref(), Some("system-network"));
        assert!(state.status.contains("Survey session running"));
    }

    #[test]
    fn f6_runs_entire_scoped_network_scenario_with_one_request() {
        let config = Config {
            lan_assessment_enabled: false,
            allowed_targets: vec!["example.org".into()],
            ..Config::default()
        };
        let mut state = TuiState::new(config, PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        select_scenario(&mut state, "scoped-network:example.org");
        assert_eq!(state.scenario().unwrap().id, "scoped-network:example.org");
        let (tx, mut rx) = mpsc::channel(4);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::F(6), KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedRunSession {
                scenario_id: "scoped-network:example.org".to_string(),
            }
        );
        assert_eq!(
            state.running_session.as_deref(),
            Some("scoped-network:example.org")
        );
        state.ingest(
            assisted_event("assisted.session.stage", "scoped-network:example.org", 2)
                .with_evidence("phase", "Port check", "test")
                .with_evidence("status", "complete", "test"),
        );
        assert!(state.status.contains("Target session 2/5"));
        state.ingest(
            Event::new(
                "presentation",
                "assisted.session.complete",
                "Target session complete",
                None,
                Severity::Info,
                SourceKind::Derived,
            )
            .with_evidence("scenario", "scoped-network:example.org", "test")
            .with_evidence("succeeded", "5", "test"),
        );
        assert!(state.running_session.is_none());
        assert_eq!(state.status, "Target 5/5 stages complete");
    }

    #[test]
    fn f6_runs_entire_local_network_scenario_with_one_request() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        select_scenario(&mut state, "local-network");
        assert_eq!(state.scenario().unwrap().id, "local-network");
        let (tx, mut rx) = mpsc::channel(4);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::F(6), KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedRunSession {
                scenario_id: "local-network".to_string(),
            }
        );
        assert_eq!(state.running_session.as_deref(), Some("local-network"));
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::F(6), KeyModifiers::NONE),
            &tx,
        );
        assert!(rx.try_recv().is_err());
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::F(5), KeyModifiers::NONE),
            &tx,
        );
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
            &tx,
        );
        assert!(rx.try_recv().is_err());
        assert!(state.config.lan_assessment_enabled);
        assert!(state.status.contains("Wait for the current assisted work"));
    }

    #[test]
    fn f6_runs_process_investigation_and_tracks_progress() {
        let config = Config {
            lan_assessment_enabled: false,
            ..Config::default()
        };
        let mut state = TuiState::new(config, PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        select_scenario(&mut state, "process-investigation");
        assert_eq!(state.scenario().unwrap().id, "process-investigation");
        let (tx, mut rx) = mpsc::channel(4);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::F(6), KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedRunSession {
                scenario_id: "process-investigation".to_string(),
            }
        );
        state.ingest(
            assisted_event("assisted.session.stage", "process-investigation", 1)
                .with_evidence("phase", "Process inventory", "test")
                .with_evidence("status", "complete", "test"),
        );
        assert!(state.status.contains("Process session 1/3"));
        state.ingest(
            Event::new(
                "presentation",
                "assisted.session.complete",
                "Process investigation complete",
                None,
                Severity::Info,
                SourceKind::Derived,
            )
            .with_evidence("scenario", "process-investigation", "test")
            .with_evidence("succeeded", "3", "test")
            .with_evidence("failed", "0", "test"),
        );
        assert!(state.running_session.is_none());
        assert_eq!(state.status, "Process 3/3 stages complete");
    }

    #[test]
    fn settings_n_rapid_toggle_uses_current_saved_state() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "spectre-tui-lan-toggle-{}-{id}.toml",
            std::process::id()
        ));
        let config = Config::default();
        config.save(&path).unwrap();
        let mut state = TuiState::new(config, path.clone());
        let (tx, mut rx) = mpsc::channel(4);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::F(5), KeyModifiers::NONE),
            &tx,
        );
        assert!(state.show_settings);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::Command("config reload".into())
        );
        assert!(!state.config.lan_assessment_enabled);
        assert!(!Config::load(&path).unwrap().lan_assessment_enabled);
        assert!(state.status.contains("LAN survey: off"));
        assert!(
            state
                .scenarios
                .iter()
                .all(|scenario| scenario.id != "local-network")
        );
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::Command("config reload".into())
        );
        assert!(state.config.lan_assessment_enabled);
        assert!(Config::load(&path).unwrap().lan_assessment_enabled);
        assert!(state.status.contains("LAN survey: on"));
        assert!(
            state
                .scenarios
                .iter()
                .any(|scenario| scenario.id == "local-network")
        );
        let screen = render_state_to_text(&state, 80, 24);
        assert!(screen.contains("LAN survey"));
        assert!(screen.contains("Esc closes settings."));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn help_keeps_lan_control_and_exit_visible_at_standard_height() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.show_help = true;
        let screen = render_state_to_text(&state, 80, 24);
        assert!(
            screen.contains("F5 then n toggles LAN assessment"),
            "{screen}"
        );
        assert!(screen.contains("Esc closes this panel."), "{screen}");
    }

    #[test]
    fn f6_does_not_execute_custom_prepared_text() {
        let config = Config {
            lan_assessment_enabled: false,
            prepared_workflow: vec!["scan example.org 443".into()],
            ..Config::default()
        };
        let mut state = TuiState::new(config, PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        select_scenario(&mut state, "custom");
        assert_eq!(state.scenario().unwrap().id, "custom");
        let (tx, mut rx) = mpsc::channel(4);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::F(6), KeyModifiers::NONE),
            &tx,
        );
        assert!(rx.try_recv().is_err());
        assert!(state.running_session.is_none());
        assert!(state.status.contains("presentation-only"));
    }

    #[test]
    fn left_returns_to_previous_stage_with_hidden_input() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        select_scenario(&mut state, "local-research");
        let (tx, mut rx) = mpsc::channel(4);
        while !state.prepared.complete() {
            state.prepared.advance();
        }
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &tx,
        );
        assert!(rx.try_recv().is_ok());
        state.ingest(assisted_event(
            "assisted.step.complete",
            "local-research",
            1,
        ));
        assert_eq!(state.prepared.position(), (2, 7));
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(state.prepared.position(), (1, 7));
        assert_eq!(state.prepared.visible(), "");
        assert!(!state.prepared.is_presented());
    }

    #[test]
    fn explicit_assisted_stage_requires_ctrl_r_and_only_queues_once() {
        let config = Config {
            lan_assessment_enabled: false,
            allowed_targets: vec!["example.org".into()],
            ..Config::default()
        };
        let mut state = TuiState::new(config, PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        let (tx, mut rx) = mpsc::channel(4);
        select_scenario(&mut state, "scoped-network:example.org");
        assert_eq!(state.scenario().unwrap().id, "scoped-network:example.org");
        for _ in 0.."scope list".len() {
            state.prepared.advance();
        }
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &tx,
        );
        assert!(matches!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedStep { index: 1, .. }
        ));
        state.ingest(assisted_event(
            "assisted.step.complete",
            "scoped-network:example.org",
            1,
        ));
        assert_eq!(
            state.scenario_step().unwrap().execution,
            Execution::Explicit
        );
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
            &tx,
        );
        assert!(rx.try_recv().is_err());
        while !state.prepared.complete() {
            state.prepared.advance();
        }
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
            &tx,
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedRun {
                scenario_id: "scoped-network:example.org".to_string(),
                index: 2,
                text: "scan \"example.org\" 22,80,443,8080,8443".to_string(),
            }
        );
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
            &tx,
        );
        assert!(rx.try_recv().is_err());
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &tx,
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(state.prepared.position().0, 2);
        assert!(state.status.contains("Network step running"));
        state.ingest(assisted_event(
            "assisted.run.error",
            "scoped-network:example.org",
            2,
        ));
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
            &tx,
        );
        assert!(matches!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedRun { index: 2, .. }
        ));
        state.ingest(assisted_event(
            "assisted.run.complete",
            "scoped-network:example.org",
            2,
        ));
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
            &tx,
        );
        assert!(rx.try_recv().is_err());
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(state.prepared.visible(), "");
        while !state.prepared.complete() {
            state.prepared.advance();
        }
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
            &tx,
        );
        assert!(matches!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedRun { index: 2, .. }
        ));
        state.ingest(assisted_event(
            "assisted.run.complete",
            "scoped-network:example.org",
            2,
        ));
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &tx,
        );
        assert!(matches!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedStep { index: 2, .. }
        ));
        state.ingest(assisted_event(
            "assisted.step.complete",
            "scoped-network:example.org",
            2,
        ));
        assert_eq!(state.prepared.position().0, 3);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(state.prepared.position().0, 2);
        while !state.prepared.complete() {
            state.prepared.advance();
        }
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
            &tx,
        );
        assert!(matches!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedRun { index: 2, .. }
        ));
    }

    #[test]
    fn explicit_stage_enter_does_not_request_network_run() {
        let config = Config {
            lan_assessment_enabled: false,
            allowed_targets: vec!["example.org".into()],
            ..Config::default()
        };
        let mut state = TuiState::new(config, PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        select_scenario(&mut state, "scoped-network:example.org");
        let (tx, mut rx) = mpsc::channel(4);
        while !state.prepared.complete() {
            state.prepared.advance();
        }
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &tx,
        );
        assert!(matches!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedStep { index: 1, .. }
        ));
        state.ingest(assisted_event(
            "assisted.step.complete",
            "scoped-network:example.org",
            1,
        ));
        while !state.prepared.complete() {
            state.prepared.advance();
        }
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedStep {
                scenario_id: "scoped-network:example.org".to_string(),
                index: 2,
                text: "scan \"example.org\" 22,80,443,8080,8443".to_string(),
            }
        );
        assert!(rx.try_recv().is_err());
        state.ingest(assisted_event(
            "assisted.step.complete",
            "scoped-network:example.org",
            2,
        ));
        assert!(state.status.contains("Network step skipped"));
    }

    #[test]
    fn assisted_panel_shows_scenario_and_stage_at_wide_and_compact_sizes() {
        let mut state = TuiState::new(
            Config {
                lan_assessment_enabled: false,
                ..Config::default()
            },
            PathBuf::from("unused.toml"),
        );
        state.mode = InteractionMode::Assisted;
        select_scenario(&mut state, "local-research");
        let wide = render_state_to_text(&state, 120, 30);
        assert!(wide.contains("SCENARIO 2/3"), "{wide}");
        assert!(wide.contains("STAGE 1/7"), "{wide}");
        assert!(wide.contains("Environment"), "{wide}");
        assert!(wide.contains("Check the platform"), "{wide}");
        assert!(wide.contains("F6 runs full local session"), "{wide}");

        let compact = render_state_to_text(&state, 48, 10);
        assert!(compact.contains("ASSISTED"), "{compact}");
        assert!(compact.contains("1/7"), "{compact}");
        assert!(compact.contains("type any key"), "{compact}");
        assert!(compact.contains("F6"), "{compact}");
    }

    #[test]
    fn assisted_footer_keeps_controls_and_completion_visible() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        state.status = "Local 7/7 stages complete".into();
        let screen = render_state_to_text(&state, 120, 30);
        let footer = screen.lines().last().unwrap();
        assert!(footer.contains("F7 Watch"), "{footer}");
        assert!(footer.contains("7/7 stages complete"), "{footer}");
    }

    #[test]
    fn observations_are_bounded_and_subject_counts_follow_retention() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.max_events = 100;
        for index in 0..101 {
            state.ingest(Event::new(
                "process",
                "start",
                format!("process {index}"),
                Some("/bin/sample".into()),
                Severity::Info,
                SourceKind::Live,
            ));
        }
        assert_eq!(state.events.len(), 100);
        assert_eq!(state.subject_counts["/bin/sample"], 100);
        assert_eq!(state.selected().unwrap().summary, "process 100");
    }

    #[test]
    fn retained_view_drops_links_when_source_observations_expire() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.max_events = 100;
        let source = Event::new(
            "process",
            "process.start",
            "observed",
            Some("/bin/sample".into()),
            Severity::Info,
            SourceKind::Live,
        );
        let source_id = source.id.clone();
        let link = Event::new(
            "correlation",
            "subject.link",
            "linked",
            Some("/bin/sample".into()),
            Severity::Info,
            SourceKind::Derived,
        )
        .with_evidence("process", &source_id, "event id");
        state.ingest(link.clone());
        assert!(state.events.is_empty());
        state.ingest(source);
        state.ingest(link);
        assert_eq!(state.subject_counts["/bin/sample"], 2);

        for index in 0..99 {
            state.ingest(Event::new(
                "host",
                "host.sample",
                index.to_string(),
                None,
                Severity::Info,
                SourceKind::Live,
            ));
        }
        assert!(
            state
                .events
                .iter()
                .all(|event| event.kind != "subject.link")
        );
        assert!(!state.subject_counts.contains_key("/bin/sample"));
    }

    #[test]
    fn config_events_refresh_theme_and_profile_from_disk() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("spectre-tui-{}-{id}.toml", std::process::id()));
        let config = Config::default();
        config.save(&path).unwrap();
        let mut state = TuiState::new(config, path.clone());
        let mut updated = Config::load(&path).unwrap();
        updated.theme = "amber".into();
        updated.apply_profile("focused").unwrap();
        updated.save(&path).unwrap();
        state.ingest(
            Event::new(
                "config",
                "config.theme",
                "Theme changed",
                None,
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("name", "amber", "config"),
        );
        assert_eq!(state.theme, Theme::Amber);
        assert_eq!(state.profile, "focused");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn successful_command_results_refresh_tui_config() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "spectre-tui-command-{}-{id}.toml",
            std::process::id()
        ));
        let config = Config::default();
        config.save(&path).unwrap();
        let mut state = TuiState::new(config, path.clone());

        let mut updated = Config::load(&path).unwrap();
        updated.autonomous = false;
        updated.save(&path).unwrap();
        state.ingest(Event::new(
            "command",
            "command.error",
            "invalid command",
            None,
            Severity::Low,
            SourceKind::Live,
        ));
        assert!(state.config.autonomous);
        state.ingest(Event::new(
            "command",
            "command.result",
            "Autonomous collection: off",
            None,
            Severity::Info,
            SourceKind::Live,
        ));
        assert!(!state.config.autonomous);

        updated.profile = "custom".into();
        updated.enabled_modules.push("binary".into());
        updated.save(&path).unwrap();
        state.ingest(Event::new(
            "command",
            "command.result",
            "Module binary: enabled",
            None,
            Severity::Info,
            SourceKind::Live,
        ));
        assert_eq!(state.profile, "custom");
        assert!(
            state
                .config
                .enabled_modules
                .iter()
                .any(|module| module == "binary")
        );

        updated.theme = "amber".into();
        updated.save(&path).unwrap();
        state.ingest(Event::new(
            "command",
            "command.result",
            "Configuration reloaded",
            None,
            Severity::Info,
            SourceKind::Live,
        ));
        assert_eq!(state.theme, Theme::Amber);
        std::fs::remove_file(path).unwrap();
    }
}
