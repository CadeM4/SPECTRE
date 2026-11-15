//! Explicit, bounded live packet capture backed by the platform's `tcpdump`.
//!
//! The raw capture is kept in a private temporary file only long enough to
//! reuse SPECTRE's classic-PCAP decoder. The returned events contain summaries
//! and provenance, not packet payloads or a retained capture file.

use std::env;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::analysis;
use crate::model::{Event, SourceKind};
use crate::network::lan;

const MAX_SECONDS: u64 = 60;
const MAX_PACKETS: u32 = 1_024;
const MAX_SNAPLEN: u32 = 2_048;
const MAX_FILTER_CHARS: usize = 256;
const STDERR_LIMIT: u64 = 8_192;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

/// A single explicit observation window. The defaults capture at most 256
/// packets in ten seconds and retain only 1,536 bytes per packet while parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRequest {
    pub interface: String,
    pub seconds: u64,
    pub max_packets: u32,
    pub snaplen: u32,
    pub filter: Option<String>,
}

impl CaptureRequest {
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            seconds: 10,
            max_packets: 256,
            snaplen: 1_536,
            filter: Some("ip or ip6".to_owned()),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !(1..=MAX_SECONDS).contains(&self.seconds) {
            bail!("capture duration must be 1 to {MAX_SECONDS} seconds");
        }
        if !(1..=MAX_PACKETS).contains(&self.max_packets) {
            bail!("capture packet limit must be 1 to {MAX_PACKETS}");
        }
        if !(96..=MAX_SNAPLEN).contains(&self.snaplen) {
            bail!("capture snaplen must be 96 to {MAX_SNAPLEN} bytes");
        }
        if self.interface.is_empty()
            || self.interface.len() > 64
            || !self
                .interface
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            bail!("capture interface must be an interface name, such as en0 or eth0");
        }
        if let Some(filter) = &self.filter
            && (filter.is_empty()
                || filter.chars().count() > MAX_FILTER_CHARS
                || filter.starts_with('-')
                || filter.chars().any(char::is_control))
        {
            bail!(
                "capture filter must be a printable tcpdump expression of at most {MAX_FILTER_CHARS} characters"
            );
        }
        Ok(())
    }
}

/// Choose the active physical/private IPv4 interface used by the LAN survey.
/// Callers may supply a different interface explicitly.
pub fn default_interface() -> Result<String> {
    lan::detect_lan()
        .map(|scope| scope.interface)
        .context("no active physical LAN interface found; pass an explicit capture interface")
}

/// Capture real packets without a shell and return only bounded decoded events.
/// `tcpdump` needs OS permission to open the interface's capture device.
pub async fn capture_once(request: &CaptureRequest) -> Result<Vec<Event>> {
    request.validate()?;
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        bail!("live capture currently supports macOS and Linux");
    }
    let present = if_addrs::get_if_addrs()
        .context("list local interfaces before live capture")?
        .into_iter()
        .any(|interface| interface.name == request.interface);
    if !present {
        bail!(
            "capture interface {} is not present on this computer",
            request.interface
        );
    }
    let tool = tcpdump_path()?;
    let (temporary, output) = TempCapture::create()?;
    let mut command = Command::new(&tool);
    command
        .arg("-i")
        .arg(&request.interface)
        .arg("-n")
        .arg("-U")
        .arg("-s")
        .arg(request.snaplen.to_string())
        .arg("-c")
        .arg(request.max_packets.to_string())
        .arg("-w")
        .arg("-")
        .stdout(Stdio::from(output))
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(filter) = &request.filter {
        command.arg(filter);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("start {} for live capture", tool.display()))?;
    let stderr = child.stderr.take().context("read tcpdump diagnostics")?;
    let diagnostics = tokio::spawn(async move {
        let mut bytes = Vec::new();
        let _ = stderr.take(STDERR_LIMIT).read_to_end(&mut bytes).await;
        String::from_utf8_lossy(&bytes).into_owned()
    });
    let elapsed = tokio::time::timeout(Duration::from_secs(request.seconds), child.wait()).await;
    let (status, timed_out) = match elapsed {
        Ok(status) => (status.context("wait for tcpdump")?, false),
        Err(_) => {
            // Cancellation is also covered by `kill_on_drop`; explicitly wait
            // here so the decoder never reads a file still being written.
            let _ = child.start_kill();
            (
                child
                    .wait()
                    .await
                    .context("stop tcpdump after capture window")?,
                true,
            )
        }
    };
    let diagnostic = diagnostics.await.unwrap_or_default();
    if !timed_out && !status.success() {
        let trimmed = diagnostic.trim();
        if trimmed.contains("Permission denied")
            || trimmed.contains("permission denied")
            || trimmed.contains("Operation not permitted")
            || trimmed.contains("You don't have permission")
        {
            bail!(
                "tcpdump cannot open {}; grant packet-capture/BPF permission or run this explicit capture from a suitably privileged terminal: {trimmed}",
                request.interface
            );
        }
        bail!("tcpdump capture failed on {}: {trimmed}", request.interface);
    }
    let metadata = std::fs::metadata(&temporary.path).context("read captured PCAP size")?;
    if metadata.len() < 24 {
        let detail = diagnostic.trim();
        bail!(
            "tcpdump produced no classic-PCAP header on {}: {detail}",
            request.interface
        );
    }
    // The command's count/snaplen bounds are enforced by tcpdump. This bound
    // also catches an unexpected tool that ignores them before parsing.
    let maximum_bytes = 24 + u64::from(request.max_packets) * (16 + u64::from(request.snaplen));
    if metadata.len() > maximum_bytes {
        bail!("capture exceeded its configured packet and snaplen byte limit");
    }
    let decoded_path = temporary.path.clone();
    let events = tokio::task::spawn_blocking(move || analysis::analyze_pcap(&decoded_path))
        .await
        .context("join live capture decoder")??;
    Ok(convert_live_events(events, request, timed_out))
}

fn convert_live_events(
    events: Vec<Event>,
    request: &CaptureRequest,
    timed_out: bool,
) -> Vec<Event> {
    events
        .into_iter()
        .map(|mut event| {
            event.module = "capture".to_owned();
            event.kind = event.kind.replacen("pcap.", "capture.", 1);
            event.source = SourceKind::Live;
            if event.kind == "capture.summary" {
                event.subject = Some(request.interface.clone());
                let summary_parts = event.summary.split(',').collect::<Vec<_>>();
                let numbers = summary_parts
                    .iter()
                    .take(4)
                    .filter_map(|part| part.split_whitespace().next())
                    .filter_map(|value| value.parse::<u64>().ok())
                    .collect::<Vec<_>>();
                if numbers.len() == 4 {
                    for (label, value) in ["packets", "captured_bytes", "ip_packets", "flows"]
                        .into_iter()
                        .zip(numbers)
                    {
                        event = event.with_evidence(label, value.to_string(), "pcap_decoder");
                    }
                }
                event = event
                    .with_evidence(
                        "capture_window_seconds",
                        request.seconds.to_string(),
                        "request",
                    )
                    .with_evidence("capture_stopped_by_time", timed_out.to_string(), "tcpdump")
                    .with_evidence(
                        "capture_stop_reason",
                        if timed_out {
                            "duration"
                        } else {
                            "packet_limit"
                        },
                        "tcpdump",
                    )
                    .with_evidence("packet_limit", request.max_packets.to_string(), "request")
                    .with_evidence("requested_snaplen", request.snaplen.to_string(), "request");
                if let Some(filter) = &request.filter {
                    event = event.with_evidence("filter", filter, "request");
                }
            }
            event
                .evidence
                .retain(|evidence| evidence.label != "capture");
            for evidence in &mut event.evidence {
                if evidence.origin != "request" && evidence.origin != "tcpdump" {
                    evidence.origin = "live_tcpdump_pcap".to_owned();
                }
            }
            event
                .with_evidence("interface", &request.interface, "local_interface")
                .with_evidence("capture_method", "tcpdump", "local_process")
        })
        .collect()
}

fn tcpdump_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os("PATH") {
        for directory in env::split_paths(&path) {
            let candidate = directory.join("tcpdump");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    for candidate in ["/usr/sbin/tcpdump", "/usr/bin/tcpdump"] {
        let candidate = Path::new(candidate);
        if candidate.is_file() {
            return Ok(candidate.to_path_buf());
        }
    }
    bail!("tcpdump was not found; install it to use live packet capture")
}

struct TempCapture {
    path: PathBuf,
}

impl TempCapture {
    fn create() -> Result<(Self, File)> {
        for _ in 0..32 {
            let count = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("read system time for capture file")?
                .as_nanos();
            let path = env::temp_dir().join(format!(
                "spectre-live-capture-{}-{nanos}-{count}.pcap",
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => return Ok((Self { path }, file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error).context("create private temporary capture file"),
            }
        }
        bail!("could not create a unique temporary capture file")
    }
}

impl Drop for TempCapture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Severity, SourceKind};

    #[test]
    fn request_limits_and_interface_validation_are_explicit() {
        let mut request = CaptureRequest::new("en0");
        assert!(request.validate().is_ok());
        request.seconds = 0;
        assert!(request.validate().is_err());
        request.seconds = 61;
        assert!(request.validate().is_err());
        request.seconds = 10;
        request.max_packets = 1_025;
        assert!(request.validate().is_err());
        request.max_packets = 256;
        request.interface = "en0; touch /tmp/nope".to_owned();
        assert!(request.validate().is_err());
        request.interface = "en0".to_owned();
        request.filter = Some("-w /tmp/nope".to_owned());
        assert!(request.validate().is_err());
    }

    #[test]
    fn decoded_events_keep_live_provenance_without_temp_path() {
        let request = CaptureRequest::new("en0");
        let pcap = Event::new(
            "pcap",
            "pcap.flow",
            "one observed flow",
            Some("192.0.2.1:1 → 192.0.2.2:2 (TCP)".into()),
            Severity::Info,
            SourceKind::File,
        )
        .with_evidence("capture", "/tmp/secret.pcap", "/tmp/secret.pcap")
        .with_evidence("src_ip", "192.0.2.1", "/tmp/secret.pcap");
        let converted = convert_live_events(vec![pcap], &request, false);
        let event = &converted[0];
        assert_eq!(event.kind, "capture.flow");
        assert_eq!(event.source, SourceKind::Live);
        assert_eq!(event.module, "capture");
        assert_eq!(event.evidence[0].origin, "live_tcpdump_pcap");
        assert!(
            !event
                .evidence
                .iter()
                .any(|item| item.value.contains("secret"))
        );
    }

    #[test]
    fn summary_exposes_observed_counts_and_stop_reason() {
        let request = CaptureRequest::new("en0");
        let pcap = Event::new(
            "pcap",
            "pcap.summary",
            "7 packets, 900 captured bytes, 6 IP packets, 3 flows",
            Some("/tmp/private.pcap".into()),
            Severity::Info,
            SourceKind::File,
        );
        let converted = convert_live_events(vec![pcap], &request, true);
        let event = &converted[0];
        assert_eq!(event.kind, "capture.summary");
        assert_eq!(event.subject.as_deref(), Some("en0"));
        for (label, expected) in [
            ("packets", "7"),
            ("captured_bytes", "900"),
            ("ip_packets", "6"),
            ("flows", "3"),
            ("capture_stop_reason", "duration"),
        ] {
            assert!(
                event
                    .evidence
                    .iter()
                    .any(|item| item.label == label && item.value == expected)
            );
        }
    }
}
