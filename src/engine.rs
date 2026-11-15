use crate::{
    analysis,
    config::Config,
    detection::{self, Indicator},
    model::{Event, Severity, SourceKind},
    traffic,
};
use anyhow::{Context, Result};
use serde_json::to_string;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use sysinfo::{Networks, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use tokio::{
    sync::{Semaphore, broadcast, watch},
    task::JoinHandle,
    time,
};

const MAX_CORRELATED_MODULES: usize = 16;
const BINARY_SLOTS: usize = 2;

fn traffic_enabled(config: &Config) -> bool {
    config.autonomous
        && config
            .enabled_modules
            .iter()
            .any(|module| module == "traffic")
}

fn start_traffic_counters(hub: &EventHub) -> Option<Networks> {
    match Networks::new_with_refreshed_list() {
        Ok(networks) => Some(networks),
        Err(error) => {
            hub.publish(Event::new(
                "traffic",
                "traffic.collector.error",
                format!("network interface counters unavailable: {error}"),
                None,
                Severity::Low,
                SourceKind::Live,
            ));
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BinaryBudget {
    initial_paths: usize,
    tracked_paths: usize,
    pending_paths: usize,
    concurrent: usize,
}

impl BinaryBudget {
    fn for_profile(profile: &str) -> Self {
        if profile == "binary-monitor" {
            Self {
                initial_paths: 128,
                tracked_paths: 512,
                pending_paths: 256,
                concurrent: 2,
            }
        } else {
            Self {
                initial_paths: 16,
                tracked_paths: 64,
                pending_paths: 64,
                concurrent: 1,
            }
        }
    }
}

#[derive(Clone)]
pub struct EventHub {
    inner: Arc<Mutex<HubState>>,
    sender: broadcast::Sender<Event>,
    capacity: usize,
    correlation_enabled: Arc<AtomicBool>,
    indicators: Arc<RwLock<Vec<Indicator>>>,
}

#[derive(Default)]
struct HubState {
    history: VecDeque<Event>,
    subjects: HashMap<String, Vec<(String, String)>>,
    correlated: HashSet<String>,
    source_dependents: HashMap<String, HashSet<String>>,
    derived_sources: HashMap<String, Vec<String>>,
}

impl HubState {
    fn forget_event(&mut self, event: &Event) {
        if let Some(source_ids) = self.derived_sources.remove(&event.id) {
            for source_id in source_ids {
                if let Some(dependents) = self.source_dependents.get_mut(&source_id) {
                    dependents.remove(&event.id);
                    if dependents.is_empty() {
                        self.source_dependents.remove(&source_id);
                    }
                }
            }
        }
        if event.module == "correlation"
            && event.kind == "subject.link"
            && let Some(subject) = &event.subject
        {
            self.correlated.remove(subject);
        }
        if let Some(subject) = &event.subject
            && let Some(references) = self.subjects.get_mut(subject)
        {
            references.retain(|(_, id)| id != &event.id);
            if references.is_empty() {
                self.subjects.remove(subject);
            }
        }
    }

    fn evict_oldest(&mut self) {
        let Some(evicted) = self.history.pop_front() else {
            return;
        };
        if let Some(dependents) = self.source_dependents.remove(&evicted.id) {
            let mut removed = Vec::new();
            self.history.retain(|event| {
                if dependents.contains(&event.id) {
                    removed.push(event.clone());
                    false
                } else {
                    true
                }
            });
            for event in removed {
                self.forget_event(&event);
            }
        }
        self.forget_event(&evicted);
    }
}

pub(crate) fn referenced_source_ids(event: &Event) -> Vec<String> {
    match (event.module.as_str(), event.kind.as_str()) {
        ("correlation", "subject.link") => event
            .evidence
            .iter()
            .filter(|evidence| evidence.origin == "event id")
            .map(|evidence| evidence.value.clone())
            .collect(),
        ("detection", "indicator.match") => event
            .evidence
            .iter()
            .filter(|evidence| evidence.label == "source_event_id")
            .map(|evidence| evidence.value.clone())
            .collect(),
        // Assisted markers are operation logs. Their cited result IDs may age
        // out of bounded history, but the progress acknowledgement must remain
        // visible so the workspace never waits forever for a completed step.
        _ => Vec::new(),
    }
}

impl EventHub {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.clamp(128, 8192));
        Self {
            inner: Arc::new(Mutex::new(HubState::default())),
            sender,
            capacity: capacity.max(100),
            correlation_enabled: Arc::new(AtomicBool::new(true)),
            indicators: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }

    pub fn set_correlation_enabled(&self, enabled: bool) {
        self.correlation_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn set_indicators(&self, indicators: Vec<Indicator>) {
        *self
            .indicators
            .write()
            .unwrap_or_else(|error| error.into_inner()) = indicators;
    }

    pub fn publish(&self, event: Event) {
        let matches = {
            let indicators = self
                .indicators
                .read()
                .unwrap_or_else(|error| error.into_inner());
            detection::evaluate(&event, &indicators)
        };
        let correlation = {
            let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let source_ids = referenced_source_ids(&event);
            if !source_ids.is_empty() {
                let oldest_id = (state.history.len() >= self.capacity)
                    .then(|| state.history.front().map(|oldest| oldest.id.as_str()))
                    .flatten();
                if source_ids.iter().any(|source_id| {
                    oldest_id == Some(source_id.as_str())
                        || !state.history.iter().any(|stored| stored.id == *source_id)
                }) {
                    if event.module == "correlation"
                        && event.kind == "subject.link"
                        && let Some(subject) = &event.subject
                    {
                        state.correlated.remove(subject);
                    }
                    return;
                }
            }
            state.history.push_back(event.clone());
            if !source_ids.is_empty() {
                for source_id in &source_ids {
                    state
                        .source_dependents
                        .entry(source_id.clone())
                        .or_default()
                        .insert(event.id.clone());
                }
                state.derived_sources.insert(event.id.clone(), source_ids);
            }
            while state.history.len() > self.capacity {
                state.evict_oldest();
            }
            let mut correlation = None;
            if !matches!(event.source, SourceKind::Derived | SourceKind::Prepared)
                && event.module != "correlation"
                && self.correlation_enabled.load(Ordering::Relaxed)
                && let Some(subject) = &event.subject
            {
                let subject = subject.clone();
                let references = state.subjects.entry(subject.clone()).or_default();
                if references.len() < MAX_CORRELATED_MODULES
                    && !references.iter().any(|(module, _)| module == &event.module)
                {
                    references.push((event.module.clone(), event.id.clone()));
                }
                let linked_references = (references.len() >= 2).then(|| references.clone());
                if let Some(linked_references) = linked_references
                    && state.correlated.insert(subject.clone())
                {
                    correlation = Some((subject, linked_references));
                }
            }
            let _ = self.sender.send(event.clone());
            correlation
        };
        if let Some((subject, refs)) = correlation {
            let modules = refs
                .iter()
                .map(|(module, _)| module.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let mut linked = Event::new(
                "correlation",
                "subject.link",
                format!("{modules} observations share {subject}"),
                Some(subject),
                Severity::Info,
                SourceKind::Derived,
            );
            for (module, id) in refs {
                linked = linked.with_evidence(module, id, "event id");
            }
            self.publish(linked);
        }
        for matched in matches {
            self.publish(matched);
        }
    }

    pub fn snapshot(&self) -> Vec<Event> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .history
            .iter()
            .cloned()
            .collect()
    }

    pub fn export_jsonl(&self, path: &Path) -> Result<usize> {
        let events = self.snapshot();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(path).with_context(|| {
            format!(
                "cannot create {} (choose a new path if it exists)",
                path.display()
            )
        })?;
        let mut writer = BufWriter::new(file);
        for event in &events {
            writeln!(writer, "{}", to_string(event)?)?;
        }
        writer.flush()?;
        writer.into_inner()?.sync_all()?;
        Ok(events.len())
    }
}

pub fn spawn_autonomous(hub: EventHub, mut control: watch::Receiver<Config>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut config = control.borrow_and_update().clone();
        let mut system = match System::new_all() {
            Ok(system) => system,
            Err(error) => {
                hub.publish(Event::new(
                    "host",
                    "collector.error",
                    format!("system collector unavailable: {error}"),
                    None,
                    Severity::Low,
                    SourceKind::Live,
                ));
                return;
            }
        };
        let mut previous: HashSet<(String, u64)> = system
            .processes()
            .iter()
            .map(|(pid, process)| (pid.to_string(), process.start_time()))
            .collect();
        let mut traffic_counters = if traffic_enabled(&config) {
            start_traffic_counters(&hub)
        } else {
            None
        };
        let mut traffic_last_sample = Instant::now();
        let mut binary_budget = BinaryBudget::for_profile(&config.profile);
        let mut inspected_paths: HashSet<PathBuf> = HashSet::new();
        let mut baseline_queue = if config.autonomous
            && config
                .enabled_modules
                .iter()
                .any(|module| module == "binary")
        {
            baseline_executables(&system, binary_budget.initial_paths)
        } else {
            VecDeque::new()
        };
        let mut watched_paths: VecDeque<(PathBuf, FileStamp)> = VecDeque::new();
        let analysis_slots = Arc::new(Semaphore::new(BINARY_SLOTS));
        let mut tick = time::interval(Duration::from_secs(5));
        tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut cycle = 0u64;
        if config.autonomous {
            publish_baseline(&hub, &system, previous.len());
        }
        loop {
            tokio::select! {
                changed = control.changed() => {
                    if changed.is_err() { return; }
                    let next = control.borrow_and_update().clone();
                    let autonomous_resumed = next.autonomous && !config.autonomous;
                    let traffic_was_enabled = traffic_enabled(&config);
                    let traffic_now_enabled = traffic_enabled(&next);
                    if traffic_now_enabled && !traffic_was_enabled {
                        traffic_counters = start_traffic_counters(&hub);
                        traffic_last_sample = Instant::now();
                    } else if !traffic_now_enabled {
                        traffic_counters = None;
                    }
                    if autonomous_resumed || process_collection_resumed(&config, &next) {
                        system.refresh_processes_specifics(
                            ProcessesToUpdate::All,
                            true,
                            ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
                        );
                        previous = system.processes().iter()
                            .map(|(pid, process)| (pid.to_string(), process.start_time())).collect();
                    }
                    if autonomous_resumed {
                        publish_baseline(&hub, &system, previous.len());
                    }
                    let next_budget = BinaryBudget::for_profile(&next.profile);
                    let binary_was_enabled = config.enabled_modules.iter().any(|module| module == "binary");
                    let binary_now_enabled = next.enabled_modules.iter().any(|module| module == "binary");
                    if next.autonomous
                        && binary_now_enabled
                        && (autonomous_resumed || !binary_was_enabled || next_budget != binary_budget)
                    {
                        baseline_queue = baseline_executables(&system, next_budget.initial_paths)
                            .into_iter()
                            .filter(|(path, _)| !inspected_paths.contains(path))
                            .collect();
                        watched_paths.truncate(next_budget.tracked_paths);
                    } else if !binary_now_enabled {
                        baseline_queue.clear();
                    }
                    binary_budget = next_budget;
                    config = next;
                    continue;
                }
                _ = tick.tick() => {}
            }
            if !config.autonomous {
                continue;
            }
            cycle = cycle.wrapping_add(1);
            if config.enabled_modules.iter().any(|m| m == "host") && cycle.is_multiple_of(3) {
                system.refresh_memory();
                system.refresh_cpu_usage();
                let cpu = system.global_cpu_usage();
                let used = system.used_memory();
                let total = system.total_memory();
                hub.publish(
                    Event::new(
                        "host",
                        "host.sample",
                        format!(
                            "CPU {cpu:.1}% · memory {:.1}/{:.1} GiB",
                            used as f64 / 1_073_741_824.0,
                            total as f64 / 1_073_741_824.0
                        ),
                        None,
                        Severity::Info,
                        SourceKind::Live,
                    )
                    .with_evidence("cpu_percent", format!("{cpu:.2}"), "sysinfo")
                    .with_evidence("used_memory_bytes", used.to_string(), "sysinfo")
                    .with_evidence(
                        "total_memory_bytes",
                        total.to_string(),
                        "sysinfo",
                    ),
                );
            }
            if traffic_enabled(&config) && cycle.is_multiple_of(3) {
                if let Some(counters) = traffic_counters.as_mut() {
                    let elapsed = traffic_last_sample.elapsed();
                    traffic_last_sample = Instant::now();
                    for event in traffic::sample_networks(counters, elapsed) {
                        hub.publish(event);
                    }
                } else {
                    traffic_counters = start_traffic_counters(&hub);
                    traffic_last_sample = Instant::now();
                }
            }
            if !config.enabled_modules.iter().any(|m| m == "process") {
                continue;
            }
            system.refresh_processes_specifics(
                ProcessesToUpdate::All,
                true,
                ProcessRefreshKind::nothing()
                    .with_memory()
                    .with_exe(UpdateKind::OnlyIfNotSet),
            );
            let current: HashSet<(String, u64)> = system
                .processes()
                .iter()
                .map(|(pid, process)| (pid.to_string(), process.start_time()))
                .collect();
            let mut additions = 0usize;
            let mut examined = 0usize;
            for (pid, process) in system.processes() {
                let key = (pid.to_string(), process.start_time());
                if previous.contains(&key) {
                    continue;
                }
                additions += 1;
                if examined >= 24 {
                    continue;
                }
                examined += 1;
                let path = process.exe().map(|p| p.to_path_buf());
                let subject = path.as_ref().map(|p| p.display().to_string());
                let mut event = Event::new(
                    "process",
                    "process.start",
                    format!("{} [{}] started", process.name().to_string_lossy(), pid),
                    subject,
                    Severity::Info,
                    SourceKind::Live,
                )
                .with_evidence("pid", pid.to_string(), "sysinfo")
                .with_evidence("start_time", process.start_time().to_string(), "sysinfo")
                .with_evidence(
                    "resident_bytes",
                    process.memory().to_string(),
                    "sysinfo",
                );
                if let Some(parent) = process.parent() {
                    event = event.with_evidence("parent_pid", parent.to_string(), "sysinfo");
                }
                hub.publish(event);
                if config.enabled_modules.iter().any(|m| m == "binary")
                    && inspected_paths.len() < binary_budget.tracked_paths
                    && let Some(path) = path.filter(|p| p.is_file())
                    && !inspected_paths.contains(&path)
                    && let Some(stamp) = FileStamp::read(&path)
                {
                    if schedule_binary(path.clone(), &hub, &analysis_slots, binary_budget) {
                        inspected_paths.insert(path.clone());
                        watched_paths.push_back((path, stamp));
                    } else if baseline_queue.len() < binary_budget.pending_paths {
                        baseline_queue.push_front((path, pid.to_string()));
                    }
                }
            }
            if additions > examined {
                hub.publish(Event::new(
                    "process",
                    "process.batch",
                    format!(
                        "{} additional processes started in this interval",
                        additions - examined
                    ),
                    None,
                    Severity::Info,
                    SourceKind::Live,
                ));
            }
            if cycle.is_multiple_of(12) {
                hub.publish(Event::new(
                    "process",
                    "process.inventory",
                    format!("{} processes currently observed", current.len()),
                    None,
                    Severity::Info,
                    SourceKind::Live,
                ));
            }
            if config.enabled_modules.iter().any(|m| m == "binary") {
                if inspected_paths.len() >= binary_budget.tracked_paths {
                    baseline_queue.clear();
                }
                let mut scheduled = false;
                while let Some((path, pid)) = baseline_queue.pop_front() {
                    if inspected_paths.contains(&path) {
                        continue;
                    }
                    let Some(stamp) = FileStamp::read(&path) else {
                        continue;
                    };
                    if !schedule_binary(path.clone(), &hub, &analysis_slots, binary_budget) {
                        baseline_queue.push_front((path, pid));
                        break;
                    }
                    inspected_paths.insert(path.clone());
                    watched_paths.push_back((path.clone(), stamp));
                    let own_executable = pid == std::process::id().to_string();
                    hub.publish(
                        Event::new(
                            "process",
                            "process.baseline_executable",
                            format!("Executable present in process baseline: {}", path.display()),
                            Some(path.display().to_string()),
                            Severity::Info,
                            SourceKind::Live,
                        )
                        .with_evidence(
                            "executable_path",
                            path.display().to_string(),
                            if own_executable {
                                "std::env::current_exe"
                            } else {
                                "sysinfo"
                            },
                        )
                        .with_evidence(
                            "pid",
                            pid,
                            if own_executable {
                                "std::process::id"
                            } else {
                                "sysinfo"
                            },
                        ),
                    );
                    scheduled = true;
                    break;
                }
                if !scheduled
                    && baseline_queue.is_empty()
                    && let Some((path, previous_stamp)) = watched_paths.pop_front()
                {
                    if let Some(current_stamp) = FileStamp::read(&path) {
                        if current_stamp != previous_stamp {
                            hub.publish(
                                Event::new(
                                    "binary",
                                    "binary.metadata_change",
                                    format!("Executable metadata changed: {}", path.display()),
                                    Some(path.display().to_string()),
                                    Severity::Low,
                                    SourceKind::Live,
                                )
                                .with_evidence(
                                    "previous_size",
                                    previous_stamp.len.to_string(),
                                    "filesystem_metadata",
                                )
                                .with_evidence(
                                    "current_size",
                                    current_stamp.len.to_string(),
                                    "filesystem_metadata",
                                )
                                .with_evidence(
                                    "previous_modified_utc",
                                    format_modified(previous_stamp.modified),
                                    "filesystem_metadata",
                                )
                                .with_evidence(
                                    "current_modified_utc",
                                    format_modified(current_stamp.modified),
                                    "filesystem_metadata",
                                ),
                            );
                            if schedule_binary(path.clone(), &hub, &analysis_slots, binary_budget) {
                                watched_paths.push_back((path, current_stamp));
                            } else {
                                watched_paths.push_back((path, previous_stamp));
                            }
                        } else {
                            watched_paths.push_back((path, previous_stamp));
                        }
                    } else {
                        hub.publish(
                            Event::new(
                                "binary",
                                "binary.file_unavailable",
                                format!(
                                    "Previously observed executable is unavailable: {}",
                                    path.display()
                                ),
                                Some(path.display().to_string()),
                                Severity::Info,
                                SourceKind::Live,
                            )
                            .with_evidence(
                                "previous_size",
                                previous_stamp.len.to_string(),
                                "filesystem_metadata",
                            ),
                        );
                    }
                }
            }
            previous = current;
        }
    })
}

fn process_collection_resumed(previous: &Config, next: &Config) -> bool {
    next.autonomous
        && next
            .enabled_modules
            .iter()
            .any(|module| module == "process")
        && (!previous.autonomous
            || !previous
                .enabled_modules
                .iter()
                .any(|module| module == "process"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
}

impl FileStamp {
    fn read(path: &Path) -> Option<Self> {
        let metadata = fs::metadata(path).ok()?;
        if !metadata.is_file() {
            return None;
        }
        Some(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

fn format_modified(value: Option<SystemTime>) -> String {
    value
        .map(|time| chrono::DateTime::<chrono::Utc>::from(time).to_rfc3339())
        .unwrap_or_else(|| "unavailable".into())
}

fn baseline_executables(system: &System, limit: usize) -> VecDeque<(PathBuf, String)> {
    if limit == 0 {
        return VecDeque::new();
    }
    let mut candidates = system
        .processes()
        .iter()
        .filter_map(|(pid, process)| {
            process
                .exe()
                .map(|path| (process.memory(), path.to_path_buf(), pid.to_string()))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|item| std::cmp::Reverse(item.0));
    let mut unique = HashSet::new();
    let mut baseline = VecDeque::new();
    if let Ok(current_exe) = std::env::current_exe()
        && current_exe.is_file()
    {
        unique.insert(current_exe.clone());
        baseline.push_back((current_exe, std::process::id().to_string()));
    }
    baseline.extend(
        candidates
            .into_iter()
            .filter(|(_, path, _)| path.is_file() && unique.insert(path.clone()))
            .take(limit.saturating_sub(baseline.len()))
            .map(|(_, path, pid)| (path, pid)),
    );
    baseline
}

fn schedule_binary(
    path: PathBuf,
    hub: &EventHub,
    slots: &Arc<Semaphore>,
    budget: BinaryBudget,
) -> bool {
    if BINARY_SLOTS.saturating_sub(slots.available_permits()) >= budget.concurrent {
        return false;
    }
    let Ok(permit) = slots.clone().try_acquire_owned() else {
        return false;
    };
    let hub = hub.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        match analysis::analyze_binary(&path) {
            Ok(events) => {
                for event in events {
                    hub.publish(event);
                }
            }
            Err(error) => hub.publish(Event::new(
                "binary",
                "analysis.error",
                format!("{}: {error}", path.display()),
                Some(path.display().to_string()),
                Severity::Low,
                SourceKind::Live,
            )),
        }
    });
    true
}

fn publish_baseline(hub: &EventHub, system: &System, process_count: usize) {
    hub.publish(
        Event::new(
            "host",
            "host.baseline",
            format!(
                "{} {}; {} processes observed",
                std::env::consts::OS,
                std::env::consts::ARCH,
                process_count
            ),
            None,
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence(
            "total_memory_bytes",
            system.total_memory().to_string(),
            "sysinfo",
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_history_and_links_distinct_modules() {
        let hub = EventHub::new(100);
        for i in 0..110 {
            hub.publish(Event::new(
                "binary",
                "sample",
                format!("{i}"),
                None,
                Severity::Info,
                SourceKind::File,
            ));
        }
        assert_eq!(hub.snapshot().len(), 100);
        hub.publish(Event::new(
            "process",
            "start",
            "started",
            Some("/bin/x".into()),
            Severity::Info,
            SourceKind::Live,
        ));
        hub.publish(Event::new(
            "binary",
            "format",
            "ELF",
            Some("/bin/x".into()),
            Severity::Info,
            SourceKind::File,
        ));
        assert_eq!(
            hub.snapshot()
                .iter()
                .filter(|e| e.kind == "subject.link")
                .count(),
            1
        );
    }

    #[test]
    fn export_is_jsonl_and_refuses_to_replace_existing_evidence() {
        let path = std::env::temp_dir().join(format!(
            "spectre-export-test-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let hub = EventHub::new(100);
        hub.publish(Event::new(
            "test",
            "observation",
            "actual observation",
            None,
            Severity::Info,
            SourceKind::File,
        ));
        assert_eq!(hub.export_jsonl(&path).unwrap(), 1);
        let original = std::fs::read_to_string(&path).unwrap();
        assert!(original.contains("\"source\":\"file\""));
        assert!(hub.export_jsonl(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn configured_indicator_links_to_source_event_without_creating_a_false_subject_link() {
        let hub = EventHub::new(100);
        let hash = "a".repeat(64);
        hub.set_indicators(vec![
            Indicator::parse("sha256", &hash, "case sample").unwrap(),
        ]);
        let source = Event::new(
            "binary",
            "binary.identity",
            "Mach-O",
            Some("/tmp/sample".into()),
            Severity::Info,
            SourceKind::File,
        )
        .with_evidence("sha256", &hash, "/tmp/sample");
        let source_id = source.id.clone();
        hub.publish(source);
        let events = hub.snapshot();
        let matched = events
            .iter()
            .find(|event| event.kind == "indicator.match")
            .unwrap();
        assert_eq!(matched.source, SourceKind::Derived);
        assert!(
            matched
                .evidence
                .iter()
                .any(|item| item.label == "source_event_id" && item.value == source_id)
        );
        assert!(!events.iter().any(|event| event.kind == "subject.link"));
    }

    #[test]
    fn eviction_removes_derived_events_that_reference_missing_sources() {
        let hub = EventHub::new(100);
        let subject = "/tmp/observed";
        let hash = "a".repeat(64);
        hub.set_indicators(vec![
            Indicator::parse("sha256", &hash, "case sample").unwrap(),
        ]);
        hub.publish(Event::new(
            "process",
            "process.start",
            "started",
            Some(subject.into()),
            Severity::Info,
            SourceKind::Live,
        ));
        hub.publish(
            Event::new(
                "binary",
                "binary.identity",
                "Mach-O",
                Some(subject.into()),
                Severity::Info,
                SourceKind::File,
            )
            .with_evidence("sha256", &hash, subject),
        );
        assert!(
            hub.snapshot()
                .iter()
                .any(|event| event.kind == "subject.link")
        );
        assert!(
            hub.snapshot()
                .iter()
                .any(|event| event.kind == "indicator.match")
        );
        for index in 0..101 {
            hub.publish(Event::new(
                "host",
                "host.sample",
                index.to_string(),
                None,
                Severity::Info,
                SourceKind::Live,
            ));
        }
        let remaining = hub.snapshot();
        let ids = remaining
            .iter()
            .map(|event| event.id.as_str())
            .collect::<HashSet<_>>();
        assert!(remaining.iter().all(|event| {
            referenced_source_ids(event)
                .iter()
                .all(|source_id| ids.contains(source_id.as_str()))
        }));
        assert!(
            !remaining
                .iter()
                .any(|event| matches!(event.kind.as_str(), "subject.link" | "indicator.match"))
        );

        hub.publish(Event::new(
            "process",
            "process.start",
            "started again",
            Some(subject.into()),
            Severity::Info,
            SourceKind::Live,
        ));
        hub.publish(Event::new(
            "binary",
            "binary.section",
            "reinspected",
            Some(subject.into()),
            Severity::Info,
            SourceKind::File,
        ));
        let relinked = hub.snapshot();
        assert_eq!(
            relinked
                .iter()
                .filter(|event| event.kind == "subject.link")
                .count(),
            1
        );
    }

    #[test]
    fn concurrent_publish_keeps_broadcast_in_history_order() {
        let hub = EventHub::new(1000);
        let mut receiver = hub.subscribe();
        let mut threads = Vec::new();
        for worker in 0..4 {
            let hub = hub.clone();
            threads.push(std::thread::spawn(move || {
                for index in 0..100 {
                    hub.publish(Event::new(
                        "test",
                        "concurrent",
                        format!("{worker}:{index}"),
                        None,
                        Severity::Info,
                        SourceKind::Live,
                    ));
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        let stored = hub
            .snapshot()
            .into_iter()
            .map(|event| event.id)
            .collect::<Vec<_>>();
        let broadcast = (0..400)
            .map(|_| receiver.try_recv().unwrap().id)
            .collect::<Vec<_>>();
        assert_eq!(stored, broadcast);
    }

    #[test]
    fn process_module_reenable_requires_a_new_baseline() {
        let mut disabled = Config::default();
        disabled
            .enabled_modules
            .retain(|module| module != "process");
        let enabled = Config::default();
        assert!(process_collection_resumed(&disabled, &enabled));
        assert!(!process_collection_resumed(&enabled, &enabled));
        let mut paused = enabled.clone();
        paused.autonomous = false;
        assert!(process_collection_resumed(&paused, &enabled));
        assert!(!process_collection_resumed(&enabled, &paused));
    }

    #[test]
    fn local_binary_budget_is_smaller_and_has_a_quiet_host_candidate() {
        let local = BinaryBudget::for_profile("local-research");
        let monitor = BinaryBudget::for_profile("binary-monitor");
        assert!(local.initial_paths < monitor.initial_paths);
        assert!(local.tracked_paths < monitor.tracked_paths);
        assert!(local.pending_paths < monitor.pending_paths);
        assert!(local.concurrent < monitor.concurrent);
        let system = System::new().unwrap();
        let baseline = baseline_executables(&system, local.initial_paths);
        assert!(!baseline.is_empty());
        assert!(baseline.len() <= local.initial_paths);
        assert_eq!(
            baseline.front().unwrap().0,
            std::env::current_exe().unwrap()
        );
    }

    #[test]
    fn correlation_references_have_a_fixed_per_subject_limit() {
        let hub = EventHub::new(100);
        for index in 0..32 {
            hub.publish(Event::new(
                format!("module-{index}"),
                "observation",
                "observed",
                Some("shared-subject".into()),
                Severity::Info,
                SourceKind::Live,
            ));
        }
        let state = hub.inner.lock().unwrap();
        assert_eq!(
            state.subjects["shared-subject"].len(),
            MAX_CORRELATED_MODULES
        );
    }

    #[test]
    fn late_derived_event_is_not_published_when_its_source_would_be_evicted() {
        let hub = EventHub::new(100);
        let source = Event::new(
            "binary",
            "binary.identity",
            "observed",
            Some("/tmp/sample".into()),
            Severity::Info,
            SourceKind::File,
        );
        let source_id = source.id.clone();
        hub.publish(source);
        for index in 0..99 {
            hub.publish(Event::new(
                "host",
                "host.sample",
                index.to_string(),
                None,
                Severity::Info,
                SourceKind::Live,
            ));
        }
        let mut receiver = hub.subscribe();
        hub.publish(
            Event::new(
                "detection",
                "indicator.match",
                "late match",
                Some("/tmp/sample".into()),
                Severity::Medium,
                SourceKind::Derived,
            )
            .with_evidence("source_event_id", source_id, "source event"),
        );
        assert!(
            hub.snapshot()
                .iter()
                .all(|event| event.kind != "indicator.match")
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn assisted_progress_survives_bounded_result_eviction() {
        let hub = EventHub::new(100);
        let first = Event::new(
            "lan",
            "lan.host",
            "observed",
            Some("192.168.1.2".into()),
            Severity::Info,
            SourceKind::Live,
        );
        let first_id = first.id.clone();
        hub.publish(first);
        for index in 0..150 {
            hub.publish(Event::new(
                "lan",
                "lan.tcp_open",
                index.to_string(),
                Some("192.168.1.2".into()),
                Severity::Info,
                SourceKind::Live,
            ));
        }
        assert!(hub.snapshot().iter().all(|event| event.id != first_id));
        let marker = Event::new(
            "presentation",
            "assisted.session.stage",
            "survey completed",
            None,
            Severity::Info,
            SourceKind::Derived,
        )
        .with_evidence("result_event_ids", first_id, "historical_results");
        let marker_id = marker.id.clone();
        hub.publish(marker);
        assert!(hub.snapshot().iter().any(|event| event.id == marker_id));
    }

    #[test]
    fn file_stamp_observes_size_changes() {
        let path = std::env::temp_dir().join(format!(
            "spectre-stamp-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"a").unwrap();
        let first = FileStamp::read(&path).unwrap();
        std::fs::write(&path, b"abcdef").unwrap();
        let second = FileStamp::read(&path).unwrap();
        assert_ne!(first, second);
        assert_eq!(second.len, 6);
        std::fs::remove_file(path).unwrap();
    }
}
