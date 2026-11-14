use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Live,
    File,
    Recorded,
    Prepared,
    Derived,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub label: String,
    pub value: String,
    pub origin: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub module: String,
    pub kind: String,
    pub summary: String,
    pub subject: Option<String>,
    pub severity: Severity,
    pub source: SourceKind,
    pub evidence: Vec<Evidence>,
}

impl Event {
    pub fn new(
        module: impl Into<String>,
        kind: impl Into<String>,
        summary: impl Into<String>,
        subject: Option<String>,
        severity: Severity,
        source: SourceKind,
    ) -> Self {
        let timestamp = Utc::now();
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            id: format!("{}-{sequence:08x}", timestamp.timestamp_millis()),
            timestamp,
            module: clean(module.into(), 64, false),
            kind: clean(kind.into(), 96, false),
            summary: clean(summary.into(), 1024, false),
            subject: subject.map(|value| clean(value, 2048, false)),
            severity,
            source,
            evidence: Vec::new(),
        }
    }

    pub fn with_evidence(
        mut self,
        label: impl Into<String>,
        value: impl Into<String>,
        origin: impl Into<String>,
    ) -> Self {
        self.evidence.push(Evidence {
            label: clean(label.into(), 128, false),
            value: clean(value.into(), 65_536, true),
            origin: clean(origin.into(), 2048, false),
        });
        self
    }
}

fn clean(value: String, limit: usize, multiline: bool) -> String {
    value
        .chars()
        .take(limit)
        .map(|character| {
            if character == '\n' && multiline {
                '\n'
            } else if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_bytes_do_not_enter_terminal_lines() {
        let event = Event::new(
            "test",
            "sample",
            "line\n\u{1b}[31m",
            Some("x\r".into()),
            Severity::Info,
            SourceKind::File,
        )
        .with_evidence("value", "first\nsecond\u{1b}[0m", "fixture");
        assert!(!event.summary.contains('\u{1b}'));
        assert!(!event.subject.unwrap().contains('\r'));
        assert!(event.evidence[0].value.contains('\n'));
        assert!(!event.evidence[0].value.contains('\u{1b}'));
    }
}
