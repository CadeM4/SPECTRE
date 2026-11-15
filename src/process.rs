//! Read-only snapshots of processes visible to the current user.

use anyhow::{Context, Result, bail};
use sysinfo::{Pid, Process, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::model::{Event, Severity, SourceKind};

const MAX_TOP_PROCESSES: usize = 32;

/// Return a live process count and the largest visible processes by resident memory.
/// A process can exit immediately after this snapshot; events describe the instant read.
pub fn top_processes(limit: usize) -> Result<Vec<Event>> {
    if !(1..=MAX_TOP_PROCESSES).contains(&limit) {
        bail!("process top requires a count from 1 to {MAX_TOP_PROCESSES}");
    }
    let mut system = System::new().context("could not initialize process inspection")?;
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_memory()
            .with_exe(UpdateKind::OnlyIfNotSet),
    );
    let count = system.processes().len();
    let mut processes = system.processes().iter().collect::<Vec<_>>();
    processes.sort_by(|(left_pid, left), (right_pid, right)| {
        right
            .memory()
            .cmp(&left.memory())
            .then_with(|| left_pid.cmp(right_pid))
    });
    let selected = processes.len().min(limit);
    let mut events = vec![
        Event::new(
            "process",
            "process.top_summary",
            format!("{count} processes visible; showing {selected} by resident memory"),
            None,
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("visible_processes", count.to_string(), "sysinfo")
        .with_evidence("shown_processes", selected.to_string(), "sysinfo")
        .with_evidence("sort", "resident_bytes_descending", "process_snapshot"),
    ];
    for (rank, (pid, process)) in processes.into_iter().take(limit).enumerate() {
        events.push(process_event("process.top", *pid, process, Some(rank + 1)));
    }
    Ok(events)
}

/// Inspect one process by PID without attaching to it or reading its memory.
pub fn inspect_process(pid: u32) -> Result<Vec<Event>> {
    let mut system = System::new().context("could not initialize process inspection")?;
    let pid = Pid::from_u32(pid);
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing()
            .with_memory()
            .with_exe(UpdateKind::OnlyIfNotSet),
    );
    let process = system
        .process(pid)
        .with_context(|| format!("process {pid} is not running or is unavailable"))?;
    Ok(vec![process_event("process.inspect", pid, process, None)])
}

fn process_event(kind: &str, pid: Pid, process: &Process, rank: Option<usize>) -> Event {
    let name = process.name().to_string_lossy().into_owned();
    let executable = process.exe().map(|path| path.display().to_string());
    let memory = process.memory();
    let mut event = Event::new(
        "process",
        kind,
        format!(
            "{name} [{pid}] · {:.1} MiB resident",
            memory as f64 / 1_048_576.0
        ),
        executable.clone(),
        Severity::Info,
        SourceKind::Live,
    )
    .with_evidence("pid", pid.to_string(), "sysinfo")
    .with_evidence("name", name, "sysinfo")
    .with_evidence("resident_bytes", memory.to_string(), "sysinfo")
    .with_evidence(
        "virtual_bytes",
        process.virtual_memory().to_string(),
        "sysinfo",
    )
    .with_evidence("start_time", process.start_time().to_string(), "sysinfo")
    .with_evidence(
        "run_time_seconds",
        process.run_time().to_string(),
        "sysinfo",
    )
    .with_evidence("status", format!("{:?}", process.status()), "sysinfo");
    if let Some(parent) = process.parent() {
        event = event.with_evidence("parent_pid", parent.to_string(), "sysinfo");
    }
    if let Some(executable) = executable {
        event = event.with_evidence("executable", executable, "sysinfo");
    }
    if let Some(rank) = rank {
        event = event.with_evidence("memory_rank", rank.to_string(), "process_snapshot");
    }
    event
}

#[cfg(test)]
mod tests {
    use super::{inspect_process, top_processes};
    use crate::model::SourceKind;

    #[test]
    fn inspect_current_process_returns_real_pid_and_start_time() {
        let pid = std::process::id();
        let observed = inspect_process(pid).unwrap();
        assert_eq!(observed.len(), 1);
        let event = &observed[0];
        assert_eq!(event.module, "process");
        assert_eq!(event.kind, "process.inspect");
        assert_eq!(event.source, SourceKind::Live);
        assert!(
            event
                .evidence
                .iter()
                .any(|item| { item.label == "pid" && item.value == pid.to_string() })
        );
        assert!(
            event
                .evidence
                .iter()
                .any(|item| { item.label == "start_time" && item.value.parse::<u64>().is_ok() })
        );
    }

    #[test]
    fn top_processes_reports_memory_order_with_a_bounded_count() {
        let events = top_processes(8).unwrap();
        assert_eq!(events[0].kind, "process.top_summary");
        assert!((2..=9).contains(&events.len()));
        let sizes = events[1..]
            .iter()
            .map(|event| {
                event
                    .evidence
                    .iter()
                    .find(|item| item.label == "resident_bytes")
                    .unwrap()
                    .value
                    .parse::<u64>()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(sizes.windows(2).all(|pair| pair[0] >= pair[1]));
        assert!(top_processes(0).is_err());
        assert!(top_processes(33).is_err());
    }
}
