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
    session_running: bool,
    failed_session_stages: HashSet<usize>,
    subject_counts: BTreeMap<String, usize>,
    detail_scroll: u16,
    view: View,
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
            session_running: false,
            failed_session_stages: HashSet::new(),
            subject_counts: BTreeMap::new(),
            detail_scroll: 0,
            view: View::Overview,
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
        self.update_assisted_progress(&observation);
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
                        format!("Scoped action skipped; stage {index}/{count}")
                    } else {
                        format!("Stage {index}/{count} ready")
                    };
                } else {
                    self.status = if skipped_explicit_action {
                        "Scenario complete; scoped action was skipped".to_string()
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
                        "Scoped run complete; Enter continues".to_string()
                    } else {
                        "Scoped run failed; Ctrl+R retries".to_string()
                    };
                }
            }
            "assisted.session.stage" => {
                if !self.session_running
                    || event_evidence(event, "scenario") != Some("local-research")
                {
                    return;
                }
                let Some(index) = event_evidence(event, "step_index")
                    .and_then(|value| value.parse::<usize>().ok())
                else {
                    return;
                };
                let phase = event_evidence(event, "phase").unwrap_or("stage");
                let failed = event_evidence(event, "status") == Some("error");
                if failed {
                    self.failed_session_stages.insert(index);
                }
                if self
                    .scenario()
                    .is_some_and(|scenario| scenario.id == "local-research")
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
                    .find(|scenario| scenario.id == "local-research")
                    .map(|scenario| scenario.steps.len())
                    .unwrap_or(0);
                self.status = format!(
                    "Local session {index}/{count}: {phase} {}",
                    if failed { "failed" } else { "complete" }
                );
            }
            "assisted.session.complete" | "assisted.session.error" => {
                if event_evidence(event, "scenario") != Some("local-research") {
                    return;
                }
                self.session_running = false;
                self.status = if event.kind == "assisted.session.complete" {
                    let succeeded = event_evidence(event, "succeeded").unwrap_or("?");
                    let total = self
                        .scenarios
                        .iter()
                        .find(|scenario| scenario.id == "local-research")
                        .map(|scenario| scenario.steps.len())
                        .unwrap_or(0);
                    if succeeded.parse::<usize>().ok() == Some(total) {
                        format!("Local {succeeded}/{total} stages complete")
                    } else {
                        format!("Local {succeeded}/{total} stages passed")
                    }
                } else {
                    "Local run stopped; F6 retries".to_string()
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
        let count = self.scenarios.len();
        self.scenario_index = if reverse {
            (self.scenario_index + count - 1) % count
        } else {
            (self.scenario_index + 1) % count
        };
        let scenario = &self.scenarios[self.scenario_index];
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
        self.status = format!("{} mode", self.mode.label().to_ascii_lowercase());
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
            KeyCode::Char('l') => state.view = state.view.next(),
            KeyCode::Char('p') => state.cycle_profile(command_tx),
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
            state.view = state.view.next();
            return false;
        }
        KeyCode::F(4) => {
            state.cycle_theme(command_tx);
            return false;
        }
        KeyCode::F(6) if state.mode == InteractionMode::Assisted => {
            run_local_assisted_session(state, command_tx);
            return false;
        }
        KeyCode::PageUp => {
            state.move_selection(10);
            return false;
        }
        KeyCode::PageDown => {
            state.move_selection(-10);
            return false;
        }
        _ => {}
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('j') => state.move_selection(-1),
            KeyCode::Char('k') => state.move_selection(1),
            KeyCode::Char('l') => state.view = state.view.next(),
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
        && (state.session_running || state.pending_step.is_some())
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
        state.status = if state.session_running {
            "Local session running; wait for the result".to_string()
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
            KeyCode::Esc => state.prepared.reset_step(),
            _ => {}
        },
    }
    false
}

fn run_assisted_explicit(state: &mut TuiState, command_tx: &mpsc::Sender<WorkspaceRequest>) {
    if state.session_running || state.pending_step.is_some() {
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
        state.status = "Scoped run is still pending".to_string();
        return;
    }
    if state.completed_explicit_runs.contains(&key) {
        state.status = "Scoped run already completed for this stage".to_string();
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
            state.status = "Scoped run requested; wait for the result".to_string();
        }
        Err(error) => state.status = format!("Scoped run was not submitted: {error}"),
    }
}

fn run_local_assisted_session(state: &mut TuiState, command_tx: &mpsc::Sender<WorkspaceRequest>) {
    if state.session_running {
        state.status = "Local session is already running".to_string();
        return;
    }
    if state.pending_step.is_some() {
        state.status = "Wait for the current stage to finish".to_string();
        return;
    }
    let Some(scenario) = state.scenario() else {
        state.status = "No assisted scenario available".to_string();
        return;
    };
    if scenario.id != "local-research" {
        state.status = "F6 runs the built-in local research session only".to_string();
        return;
    }
    let scenario_id = scenario.id.clone();
    let inputs = scenario
        .steps
        .iter()
        .map(|step| step.input.clone())
        .collect();
    match command_tx.try_send(WorkspaceRequest::AssistedRunLocalSession { scenario_id }) {
        Ok(()) => {
            state.prepared = PreparedInput::new(inputs);
            state.session_running = true;
            state.failed_session_stages.clear();
            state.status = "Local session running…".to_string();
        }
        Err(error) => state.status = format!("Local session was not submitted: {error}"),
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
    let context = format!(
        "{}  •  {}  •  {} events  •  last {}  ",
        state.profile,
        state.mode.label(),
        state.events.len(),
        latest
    );
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
                let mark = if scenario.id == "local-research"
                    && state.failed_session_stages.contains(&(index + 1))
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
            Execution::Local if state.session_running => "LOCAL SESSION RUNNING",
            Execution::Local => "LOCAL: Enter or F6 full session",
            Execution::Explicit if state.pending_explicit_runs.contains(&stage_key) => {
                "SCOPED RUN PENDING"
            }
            Execution::Explicit if state.completed_explicit_runs.contains(&stage_key) => {
                "SCOPED RUN COMPLETE"
            }
            Execution::Explicit => "SCOPED: Ctrl+R to run",
            Execution::PresentationOnly => "PRESENTATION: records only",
        };
        let instruction = match step.execution {
            Execution::Local if state.session_running => {
                "F6 session running  ·  Results and stage progress appear above"
            }
            Execution::Local => {
                "F6 runs full local session  ·  Enter runs one revealed step  ·  Left goes back"
            }
            Execution::Explicit => {
                "Ctrl+R runs revealed scoped action  ·  Enter records and continues  ·  Left goes back"
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
        let title = if scenario.id == "local-research" {
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
        "F6 Run all  F1 Help  F2 Mode  Tab Scenario  Left Prev  Ctrl+R Scoped"
    } else if state.mode == InteractionMode::Assisted && area.width >= 78 {
        "F6 Run  F2 Mode  Tab Next  Left Prev  Ctrl+R"
    } else if state.mode == InteractionMode::Assisted {
        "F6 Run  F2 Mode  F1 Help"
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
    let status = format!("{}  ·  {}", state.view.label(), state.status);
    let status = fit_tail(&status, columns[1].width as usize);
    frame.render_widget(
        Paragraph::new(status)
            .alignment(Alignment::Right)
            .style(Style::default().fg(palette.accent).bg(palette.background)),
        columns[1],
    );
}

fn render_help(frame: &mut Frame<'_>, area: Rect, palette: Palette) {
    let popup = centered(area, 74, 23);
    frame.render_widget(Clear, popup);
    let help = [
        "SPECTRE / KEYBOARD",
        "",
        "F2             Cycle autonomous, interactive and assisted input",
        "F3             Cycle overview, timeline and evidence views",
        "F4             Cycle theme                    F5  Settings",
        "Ctrl+J / K     Select newer / older observation",
        "Ctrl+U / D     Scroll evidence up / down",
        "Page Down / Up Select newer / older observations by ten",
        "",
        "AUTONOMOUS     / opens command input; Up/Down inspect events",
        "INTERACTIVE    Enter submits command; Up/Down recall history",
        "ASSISTED       Tab / Shift+Tab selects a guided scenario",
        "               Left returns to the previous stage to retry",
        "               Each character reveals one prepared character",
        "               Enter runs local steps, records and advances",
        "               F6 runs the full built-in local session",
        "               Ctrl+R explicitly runs a revealed scoped step",
        "               Custom steps are recorded, never executed",
        "",
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
    let popup = centered(area, 64, 16);
    frame.render_widget(Clear, popup);
    let content = format!(
        "WORKSPACE SETTINGS\n\n  p  Profile            {}\n  t  Theme              {}\n  l  Arrangement        {}\n  r  Display refresh    {} ms\n  a  Autonomous work    {}\n\nProfile, theme, refresh and autonomous work are saved.\nArrangement applies to this session.\nScope and modules: spectre configure\n\nEsc closes settings.",
        state.profile,
        state.theme.label(),
        state.view.label().to_ascii_lowercase(),
        state.refresh_ms,
        if state.config.autonomous { "on" } else { "off" }
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
    fn assisted_starts_with_multistep_local_scenario() {
        let state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        assert_eq!(state.scenario().unwrap().id, "local-research");
        assert!(state.prepared.steps.len() > 1);
        assert_eq!(state.prepared.current(), Some("doctor"));
    }

    #[test]
    fn tab_cycles_scenarios_and_resets_prepared_input() {
        let config = Config {
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
        assert_eq!(state.prepared.visible(), "d");
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
            prepared_workflow: vec!["first step".into()],
            ..Config::default()
        };
        config.save(&path).unwrap();
        let mut state = TuiState::new(config.clone(), path.clone());
        state.cycle_scenario(false);
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
        assert_eq!(state.prepared.position(), (1, 6));
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
        assert_eq!(state.prepared.position(), (2, 6));
        assert!(state.pending_step.is_none());
    }

    #[test]
    fn failed_manual_stage_stays_revealed_and_enter_retries() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
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
        assert_eq!(state.prepared.position(), (1, 6));
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
        assert_eq!(state.prepared.position(), (2, 6));
    }

    #[test]
    fn f6_runs_local_session_once_and_updates_stage_progress() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        let (tx, mut rx) = mpsc::channel(4);
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::F(6), KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            WorkspaceRequest::AssistedRunLocalSession {
                scenario_id: "local-research".to_string(),
            }
        );
        assert!(state.session_running);
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
        assert_eq!(state.prepared.position(), (1, 6));
        assert_eq!(state.prepared.visible(), "doctor");
        state.ingest(
            assisted_event("assisted.session.stage", "local-research", 2)
                .with_evidence("phase", "Collection", "test")
                .with_evidence("status", "error", "test"),
        );
        assert_eq!(state.prepared.position(), (2, 6));
        assert!(state.status.contains("2/6"));
        assert!(state.status.contains("failed"));
        let screen = render_state_to_text(&state, 120, 30);
        assert!(screen.contains("STAGE 2/6"), "{screen}");
        assert!(screen.contains("!2 Collection"), "{screen}");
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
            .with_evidence("succeeded", "5", "test"),
        );
        assert!(!state.session_running);
        assert_eq!(state.status, "Local 5/6 stages passed");
    }

    #[test]
    fn left_returns_to_previous_stage_with_hidden_input() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
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
        assert_eq!(state.prepared.position(), (2, 6));
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
            &tx,
        );
        assert_eq!(state.prepared.position(), (1, 6));
        assert_eq!(state.prepared.visible(), "");
        assert!(!state.prepared.is_presented());
    }

    #[test]
    fn explicit_assisted_stage_requires_ctrl_r_and_only_queues_once() {
        let config = Config {
            allowed_targets: vec!["example.org".into()],
            ..Config::default()
        };
        let mut state = TuiState::new(config, PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        let (tx, mut rx) = mpsc::channel(4);
        state.cycle_scenario(false);
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
    }

    #[test]
    fn explicit_stage_enter_does_not_request_network_run() {
        let config = Config {
            allowed_targets: vec!["example.org".into()],
            ..Config::default()
        };
        let mut state = TuiState::new(config, PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        state.cycle_scenario(false);
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
        assert!(state.status.contains("Scoped action skipped"));
    }

    #[test]
    fn assisted_panel_shows_scenario_and_stage_at_wide_and_compact_sizes() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        let wide = render_state_to_text(&state, 120, 30);
        assert!(wide.contains("SCENARIO 1/1"), "{wide}");
        assert!(wide.contains("STAGE 1/6"), "{wide}");
        assert!(wide.contains("Environment"), "{wide}");
        assert!(wide.contains("Check the platform"), "{wide}");
        assert!(wide.contains("F6 runs full local session"), "{wide}");

        let compact = render_state_to_text(&state, 48, 10);
        assert!(compact.contains("ASSISTED"), "{compact}");
        assert!(compact.contains("1/6"), "{compact}");
        assert!(compact.contains("type any key"), "{compact}");
        assert!(compact.contains("F6"), "{compact}");
    }

    #[test]
    fn assisted_footer_keeps_controls_and_completion_visible() {
        let mut state = TuiState::new(Config::default(), PathBuf::from("unused.toml"));
        state.mode = InteractionMode::Assisted;
        state.status = "Local 6/6 stages complete".into();
        let screen = render_state_to_text(&state, 120, 30);
        let footer = screen.lines().last().unwrap();
        assert!(footer.contains("Ctrl+R Scoped"), "{footer}");
        assert!(footer.contains("6/6 stages complete"), "{footer}");
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
