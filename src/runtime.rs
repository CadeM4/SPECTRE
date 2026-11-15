//! Explicit, bounded observations of a running process.
//!
//! Sampling and file-descriptor inspection do not execute code in the target.
//! Function tracing uses an installed Frida CLI and attaches only to the PID
//! named in the command. The platform may deny access to another process.

use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

use crate::model::{Event, Severity, SourceKind};

const MAX_REPORT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TRACE_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TRACE_EVENTS: usize = 96;

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> Result<Self> {
        for attempt in 0..8 {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = env::temp_dir().join(format!(
                "spectre-runtime-{}-{nonce}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    }
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).context("create temporary runtime report directory");
                }
            }
        }
        bail!("could not allocate a temporary runtime report directory")
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tool(name: &str, known: &[&str]) -> Result<PathBuf> {
    for path in known {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
    }
    if let Some(path) = env::var_os("PATH") {
        for directory in env::split_paths(&path) {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    if let Some(home) = dirs::home_dir() {
        let candidate = home.join(".local/bin").join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!("{name} is not installed or is not on PATH")
}

fn read_limited(path: &Path) -> Result<(String, bool)> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let length = file.metadata()?.len();
    let mut reader = file.take(MAX_REPORT_BYTES);
    let mut bytes = Vec::with_capacity(length.min(MAX_REPORT_BYTES) as usize);
    reader.read_to_end(&mut bytes)?;
    Ok((
        String::from_utf8_lossy(&bytes).into_owned(),
        length > MAX_REPORT_BYTES,
    ))
}

#[derive(Default)]
struct SampleSummary {
    name: String,
    path: String,
    arch: String,
    footprint: String,
    stack_samples: Option<u64>,
    hot_frames: Vec<String>,
}

fn parse_sample(report: &str) -> SampleSummary {
    let mut summary = SampleSummary::default();
    let mut in_call_graph = false;
    let mut in_hot_frames = false;
    for line in report.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("Process:") {
            summary.name = value.trim().to_owned();
        } else if let Some(value) = trimmed.strip_prefix("Path:") {
            summary.path = value.trim().to_owned();
        } else if let Some(value) = trimmed.strip_prefix("Code Type:") {
            summary.arch = value.trim().to_owned();
        } else if let Some(value) = trimmed.strip_prefix("Physical footprint:") {
            summary.footprint = value.trim().to_owned();
        } else if trimmed == "Call graph:" {
            in_call_graph = true;
            in_hot_frames = false;
        } else if trimmed.starts_with("Sort by top of stack") {
            in_hot_frames = true;
            in_call_graph = false;
        } else if trimmed == "Binary Images:" {
            in_hot_frames = false;
        } else if in_call_graph && summary.stack_samples.is_none() && !trimmed.is_empty() {
            summary.stack_samples = trimmed
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok());
        } else if in_hot_frames && !trimmed.is_empty() && summary.hot_frames.len() < 12 {
            summary.hot_frames.push(trimmed.to_owned());
        }
    }
    summary
}

/// Sample real call stacks on macOS. The report is summarized and the private
/// temporary copy is removed after reading.
pub async fn sample_process(pid: u32, seconds: u64) -> Result<Vec<Event>> {
    if pid == 0 || !(1..=10).contains(&seconds) {
        bail!("runtime sample needs a PID and a duration of 1 to 10 seconds")
    }
    if !cfg!(target_os = "macos") {
        bail!("runtime sample currently requires macOS sample(1)")
    }
    let executable = tool("sample", &["/usr/bin/sample"])?;
    let scratch = ScratchDir::new()?;
    let report_path = scratch.path("sample.txt");
    let mut command = Command::new(&executable);
    command
        .arg(pid.to_string())
        .arg(seconds.to_string())
        .arg("10")
        .arg("-file")
        .arg(&report_path)
        .kill_on_drop(true);
    let output = timeout(Duration::from_secs(seconds + 15), command.output())
        .await
        .context("process sampling timed out")??;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        bail!("sample could not inspect PID {pid}: {}", detail.trim());
    }
    let (report, truncated) = read_limited(&report_path)?;
    let parsed = parse_sample(&report);
    if parsed.name.is_empty() || !report.contains("Call graph:") {
        bail!("sample did not produce a usable call-stack report for PID {pid}")
    }
    let subject = if parsed.path.is_empty() {
        format!("pid:{pid}")
    } else {
        parsed.path.clone()
    };
    let mut event = Event::new(
        "runtime",
        "runtime.sample",
        format!(
            "Sampled {} for {seconds}s; {} stack observations",
            parsed.name,
            parsed.stack_samples.unwrap_or(0)
        ),
        Some(subject),
        Severity::Info,
        SourceKind::Live,
    )
    .with_evidence("pid", pid.to_string(), "sample(1)")
    .with_evidence("duration_seconds", seconds.to_string(), "sample(1)")
    .with_evidence("interval_milliseconds", "10", "sample(1)")
    .with_evidence("code_type", parsed.arch, "sample(1)")
    .with_evidence("physical_footprint", parsed.footprint, "sample(1)")
    .with_evidence(
        "stack_samples",
        parsed.stack_samples.unwrap_or(0).to_string(),
        "sample(1)",
    )
    .with_evidence("report_truncated", truncated.to_string(), "bounded_report");
    if !parsed.hot_frames.is_empty() {
        event = event.with_evidence("hot_frames", parsed.hot_frames.join("\n"), "sample(1)");
    }
    Ok(vec![event])
}

#[derive(Default)]
struct Descriptor {
    fd: String,
    kind: String,
    name: String,
}

fn parse_lsof(report: &str) -> Vec<Descriptor> {
    let mut descriptors = Vec::new();
    let mut current = Descriptor::default();
    for line in report.lines() {
        let Some((tag, value)) = line.split_at_checked(1) else {
            continue;
        };
        match tag {
            "f" => {
                if !current.fd.is_empty() {
                    descriptors.push(std::mem::take(&mut current));
                }
                current.fd = value.to_owned();
            }
            "t" => current.kind = value.to_owned(),
            "n" => current.name = value.to_owned(),
            _ => {}
        }
    }
    if !current.fd.is_empty() {
        descriptors.push(current);
    }
    descriptors
}

/// Inspect open sockets and file descriptors for one running PID.
pub async fn process_resources(pid: u32) -> Result<Vec<Event>> {
    if pid == 0 {
        bail!("runtime resources needs a numeric PID or self")
    }
    let executable = tool("lsof", &["/usr/sbin/lsof", "/usr/bin/lsof"])?;
    let mut command = Command::new(&executable);
    command
        .args(["-nP", "-p", &pid.to_string(), "-F", "pftn"])
        .kill_on_drop(true);
    let output = timeout(Duration::from_secs(8), command.output())
        .await
        .context("runtime resource inspection timed out")??;
    if !output.status.success() && output.stdout.is_empty() {
        bail!(
            "lsof could not inspect PID {pid}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let report = String::from_utf8_lossy(&output.stdout);
    let descriptors = parse_lsof(&report);
    if descriptors.is_empty() {
        bail!("lsof reported no open descriptors for PID {pid}")
    }
    let sockets = descriptors
        .iter()
        .filter(|row| matches!(row.kind.as_str(), "IPv4" | "IPv6"))
        .count();
    let regular = descriptors.iter().filter(|row| row.kind == "REG").count();
    let mut events = vec![
        Event::new(
            "runtime",
            "runtime.resources",
            format!(
                "PID {pid}: {} descriptors, {sockets} sockets, {regular} regular files",
                descriptors.len()
            ),
            Some(format!("pid:{pid}")),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("pid", pid.to_string(), "lsof")
        .with_evidence("descriptors", descriptors.len().to_string(), "lsof")
        .with_evidence("sockets", sockets.to_string(), "lsof")
        .with_evidence("regular_files", regular.to_string(), "lsof"),
    ];
    for row in descriptors
        .into_iter()
        .filter(|row| matches!(row.kind.as_str(), "IPv4" | "IPv6" | "REG") && !row.name.is_empty())
        .take(48)
    {
        let kind = if matches!(row.kind.as_str(), "IPv4" | "IPv6") {
            "runtime.socket"
        } else {
            "runtime.file"
        };
        events.push(
            Event::new(
                "runtime",
                kind,
                format!("PID {pid} FD {} · {}", row.fd, row.name),
                Some(format!("pid:{pid}")),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("pid", pid.to_string(), "lsof")
            .with_evidence("fd", row.fd, "lsof")
            .with_evidence("type", row.kind, "lsof")
            .with_evidence("name", row.name, "lsof"),
        );
    }
    Ok(events)
}

/// Attach Frida's function tracer to one explicit PID and collect a bounded
/// sample of observed function calls. Frida must be installed separately.
pub async fn trace_functions(pid: u32, pattern: &str, seconds: u64) -> Result<Vec<Event>> {
    if pid == 0 || !(1..=20).contains(&seconds) {
        bail!("runtime trace needs a PID and a duration of 1 to 20 seconds")
    }
    if !cfg!(unix) {
        bail!("runtime trace currently requires macOS or Linux")
    }
    if pid == std::process::id() {
        bail!(
            "tracing SPECTRE's own event loop can interrupt the session; choose a separate process PID"
        )
    }
    if pattern.is_empty()
        || pattern.len() > 128
        || pattern.starts_with('-')
        || pattern.chars().any(char::is_control)
    {
        bail!("runtime trace needs a function pattern of 1 to 128 printable characters")
    }
    let executable =
        tool("frida-trace", &[]).context("install frida-tools to enable function tracing")?;
    let scratch = ScratchDir::new()?;
    let report_path = scratch.path("trace.txt");
    let stderr_path = scratch.path("stderr.txt");
    let stderr = File::create(&stderr_path)?;
    let mut command = Command::new(&executable);
    command
        .args(["-p", &pid.to_string(), "-i", pattern, "-q", "-o"])
        .arg(&report_path)
        .current_dir(&scratch.0)
        // frida-tools reads stdin even in quiet mode. Keep a pipe open so
        // its CLI can stay alive without taking over SPECTRE's terminal.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true);
    let mut child = command.spawn().context("start frida-trace")?;
    let _stdin = child.stdin.take().context("keep frida-trace input open")?;
    let stdout = child.stdout.take().context("read frida-trace readiness")?;
    let mut lines = BufReader::new(stdout).lines();
    let startup = async {
        loop {
            tokio::select! {
                line = lines.next_line() => match line? {
                    Some(line) if line.contains("Started tracing") => break Ok::<_, anyhow::Error>(line),
                    Some(_) => {},
                    None => bail!("frida-trace closed output before instrumentation started"),
                },
                status = child.wait() => bail!("frida-trace exited before instrumentation started: {}", status?),
            }
        }
    };
    let ready_line = match timeout(Duration::from_secs(20), startup).await {
        Ok(Ok(line)) => line,
        Ok(Err(error)) => {
            let (diagnostic, _) = read_limited(&stderr_path)?;
            bail!(
                "frida-trace could not attach to PID {pid}: {error}; {}",
                diagnostic.trim()
            );
        }
        Err(_) => bail!("frida-trace did not attach to PID {pid} within 20 seconds"),
    };
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let mut check_size = tokio::time::interval(Duration::from_millis(200));
    let mut stop_reason = "requested_duration";
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            _ = check_size.tick() => {
                if fs::metadata(&report_path).is_ok_and(|meta| meta.len() > MAX_TRACE_FILE_BYTES) {
                    stop_reason = "report_size_limit";
                    break;
                }
            }
            status = child.wait() => {
                let _ = status.context("wait for frida-trace")?;
                stop_reason = "target_exited";
                break;
            }
        }
    }
    let actual_milliseconds = started.elapsed().as_millis();
    if stop_reason != "target_exited" {
        let child_pid = child.id().context("frida-trace process has no PID")?;
        let signaled = Command::new("/bin/kill")
            .args(["-INT", &child_pid.to_string()])
            .output()
            .await
            .context("stop frida-trace after observation window")?;
        if !signaled.status.success() && child.try_wait()?.is_none() {
            child.kill().await.context("stop frida-trace")?;
        }
        if timeout(Duration::from_secs(6), child.wait()).await.is_err() {
            child.kill().await.context("force-stop frida-trace")?;
            let _ = child.wait().await;
        }
    }
    let (diagnostic, _) = read_limited(&stderr_path)?;
    if !report_path.exists() && !diagnostic.is_empty() {
        bail!(
            "frida-trace could not attach to PID {pid}: {}",
            diagnostic.trim()
        )
    }
    let (report, read_truncated) = if report_path.exists() {
        read_limited(&report_path)?
    } else {
        (String::new(), false)
    };
    let lines = report
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let mut events = vec![
        Event::new(
            "runtime",
            "runtime.trace_summary",
            format!(
                "Frida observed {} trace lines for PID {pid} in {seconds}s",
                lines.len()
            ),
            Some(format!("pid:{pid}")),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("pid", pid.to_string(), "frida-trace")
        .with_evidence(
            "readiness",
            ready_line.split(". Web UI").next().unwrap_or(&ready_line),
            "frida-trace",
        )
        .with_evidence("function_pattern", pattern, "explicit_request")
        .with_evidence("duration_seconds", seconds.to_string(), "explicit_request")
        .with_evidence(
            "actual_duration_milliseconds",
            actual_milliseconds.to_string(),
            "local_clock",
        )
        .with_evidence("stop_reason", stop_reason, "tracer_lifecycle")
        .with_evidence(
            "report_truncated",
            (read_truncated || stop_reason == "report_size_limit").to_string(),
            "bounded_report",
        ),
    ];
    for line in lines.into_iter().take(MAX_TRACE_EVENTS) {
        events.push(
            Event::new(
                "runtime",
                "runtime.function_call",
                line,
                Some(format!("pid:{pid}")),
                Severity::Info,
                SourceKind::Live,
            )
            .with_evidence("function_pattern", pattern, "explicit_request")
            .with_evidence("pid", pid.to_string(), "frida-trace"),
        );
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::{parse_lsof, parse_sample};

    #[test]
    fn parses_real_sample_report_shape() {
        let sample = "Process: sleep [42]\nPath: /bin/sleep\nCode Type: ARM64E\nPhysical footprint: 1248K\nCall graph:\n 92 Thread_1\nSort by top of stack, same collapsed (when >= 5):\n __semwait_signal (in libsystem) 92\nBinary Images:\n";
        let parsed = parse_sample(sample);
        assert_eq!(parsed.name, "sleep [42]");
        assert_eq!(parsed.path, "/bin/sleep");
        assert_eq!(parsed.stack_samples, Some(92));
        assert!(parsed.hot_frames[0].contains("__semwait_signal"));
    }

    #[test]
    fn parses_descriptor_fields_without_shell_text() {
        let rows = parse_lsof("p42\nf0\ntCHR\nn/dev/null\nf3\ntIPv4\nn127.0.0.1:80\n");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].fd, "3");
        assert_eq!(rows[1].kind, "IPv4");
        assert_eq!(rows[1].name, "127.0.0.1:80");
    }
}
