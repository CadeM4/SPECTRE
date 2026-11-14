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
            prepared: PreparedInput::new(config.prepared_workflow.clone()),
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

    fn sync_config_from_disk(&mut self) {
        let Ok(config) = Config::load(&self.config_path) else {
            return;
        };
        if self.prepared.steps != config.prepared_workflow {
            self.prepared = PreparedInput::new(config.prepared_workflow.clone());
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
            _ => {}
        }
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
            KeyCode::Char(_) if !key.modifiers.contains(KeyModifiers::ALT) => {
                state.prepared.advance()
            }
            KeyCode::Backspace => state.prepared.backspace(),
            KeyCode::Enter => {
                if !state.prepared.complete() {
                    state.status = "Finish the current input to continue".to_string();
                } else if state.prepared.is_presented() {
                    state.status = "Prepared sequence complete".to_string();
                } else {
                    let (index, _) = state.prepared.position();
                    let step = state.prepared.current().unwrap_or_default();
                    match command_tx.try_send(WorkspaceRequest::AssistedCompletion {
                        index,
                        text: step.to_string(),
                    }) {
                        Ok(()) => {
                            state.prepared.mark_presented();
                            if state.prepared.next_step() {
                                let (next, count) = state.prepared.position();
                                state.status = format!("Prepared step {next}/{count}");
                            } else {
                                state.status = "Prepared sequence complete".to_string();
                            }
                        }
                        Err(error) => {
                            state.status = format!("Prepared input was not recorded: {error}");
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

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
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
    let (title, text): (String, String) = match state.mode {
        InteractionMode::Autonomous => (
            " COMMAND ".to_string(),
            "Press / to enter a research command".to_string(),
        ),
        InteractionMode::Interactive => (
            " COMMAND ".to_string(),
            format!("› {}", state.command_input),
        ),
        InteractionMode::Assisted => {
            let (index, count) = state.prepared.position();
            let title = format!(" PREPARED INPUT  {index}/{count} ");
            let text = if state.prepared.current().is_some() {
                format!("› {}", state.prepared.visible())
            } else {
                "No prepared sequence configured".to_string()
            };
            (title, text)
        }
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

fn render_footer(frame: &mut Frame<'_>, area: Rect, state: &TuiState, palette: Palette) {
    let shortcuts = if area.width >= 112 {
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
    frame.render_widget(
        Paragraph::new(format!("{}  ·  {}", state.view.label(), state.status))
            .alignment(Alignment::Right)
            .style(Style::default().fg(palette.accent).bg(palette.background)),
        columns[1],
    );
}

fn render_help(frame: &mut Frame<'_>, area: Rect, palette: Palette) {
    let popup = centered(area, 74, 18);
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
        "ASSISTED       Each character reveals one prepared character",
        "               Backspace retracts; Enter advances a complete step",
        "               Enter records completed text without executing it",
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
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, &state)).unwrap();
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
    fn assisted_keystrokes_only_record_completed_prepared_text() {
        let config = Config {
            prepared_workflow: vec!["inspect 127.0.0.1".into()],
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
        assert_eq!(state.prepared.visible(), "i");
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &tx,
        );
        assert!(rx.try_recv().is_err());
        for _ in 0..100 {
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
            WorkspaceRequest::AssistedCompletion {
                index: 1,
                text: "inspect 127.0.0.1".to_string(),
            }
        );
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &tx,
        );
        assert!(rx.try_recv().is_err());
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
