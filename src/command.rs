use crate::{
    analysis,
    assisted::{self, Execution},
    capability,
    config::{Config, normalize_target},
    detection::Indicator,
    engine::EventHub,
    model::{Event, Severity, SourceKind},
    network, process, traffic,
};
use anyhow::{Context, Result, bail};
use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkspaceRequest {
    Command(String),
    AssistedCompletion {
        index: usize,
        text: String,
    },
    AssistedStep {
        scenario_id: String,
        index: usize,
        text: String,
    },
    AssistedRun {
        scenario_id: String,
        index: usize,
        text: String,
    },
    AssistedRunSession {
        scenario_id: String,
    },
    AssistedLivePulse {
        cycle: u64,
        include_lan: bool,
    },
}

pub async fn execute_workspace_request(
    request: WorkspaceRequest,
    hub: &EventHub,
    config_path: &Path,
) -> Result<Vec<Event>> {
    match request {
        WorkspaceRequest::Command(line) => execute_line(&line, hub, config_path).await,
        WorkspaceRequest::AssistedCompletion { index, text } => {
            let config = Config::load_or_default(config_path)?;
            if index == 0 || config.prepared_workflow.get(index - 1) != Some(&text) {
                bail!("completed assisted step does not match the configured workflow");
            }
            let event = Event::new(
                "presentation",
                "prepared.input",
                format!("Prepared step {index} revealed"),
                None,
                Severity::Info,
                SourceKind::Prepared,
            )
            .with_evidence("step_index", index.to_string(), "prepared_workflow")
            .with_evidence("input", text, "prepared_workflow");
            hub.publish(event.clone());
            Ok(vec![event])
        }
        WorkspaceRequest::AssistedStep {
            scenario_id,
            index,
            text,
        } => match complete_assisted_step(&scenario_id, index, &text, hub, config_path).await {
            Ok(mut output) => {
                let acknowledgement = assisted_ack(
                    "assisted.step.complete",
                    "Assisted stage completed",
                    &scenario_id,
                    index,
                    Severity::Info,
                );
                hub.publish(acknowledgement.clone());
                output.push(acknowledgement);
                Ok(output)
            }
            Err(error) => {
                let acknowledgement = assisted_ack(
                    "assisted.step.error",
                    format!("Assisted stage failed: {error}"),
                    &scenario_id,
                    index,
                    Severity::Low,
                )
                .with_evidence("error", error.to_string(), "execution");
                hub.publish(acknowledgement.clone());
                Ok(vec![acknowledgement])
            }
        },
        WorkspaceRequest::AssistedRun {
            scenario_id,
            index,
            text,
        } => match run_scoped_assisted_step(&scenario_id, index, &text, hub, config_path).await {
            Ok(mut output) => {
                let (result_ids, omitted) = retained_result_ids(hub, &output);
                let acknowledgement = assisted_ack(
                    "assisted.run.complete",
                    "Scoped assisted action completed",
                    &scenario_id,
                    index,
                    Severity::Info,
                )
                .with_evidence("command", &text, "assisted_scenario")
                .with_evidence("result_event_ids", result_ids, "retained_results")
                .with_evidence(
                    "result_event_count",
                    output.len().to_string(),
                    "observed_results",
                )
                .with_evidence(
                    "uncited_result_count",
                    omitted.to_string(),
                    "bounded_provenance",
                );
                hub.publish(acknowledgement.clone());
                output.push(acknowledgement);
                Ok(output)
            }
            Err(error) => {
                let acknowledgement = assisted_ack(
                    "assisted.run.error",
                    format!("Scoped assisted action failed: {error}"),
                    &scenario_id,
                    index,
                    Severity::Low,
                )
                .with_evidence("command", &text, "assisted_scenario")
                .with_evidence("error", error.to_string(), "execution");
                hub.publish(acknowledgement.clone());
                Ok(vec![acknowledgement])
            }
        },
        WorkspaceRequest::AssistedRunSession { scenario_id } => {
            match run_full_assisted_session(&scenario_id, hub, config_path).await {
                Ok(output) => Ok(output),
                Err(error) => {
                    let acknowledgement = Event::new(
                        "presentation",
                        "assisted.session.error",
                        format!("Assisted session failed: {error}"),
                        None,
                        Severity::Low,
                        SourceKind::Derived,
                    )
                    .with_evidence("scenario", &scenario_id, "assisted_scenario")
                    .with_evidence("error", error.to_string(), "execution");
                    hub.publish(acknowledgement.clone());
                    Ok(vec![acknowledgement])
                }
            }
        }
        WorkspaceRequest::AssistedLivePulse { cycle, include_lan } => {
            match run_live_assisted_pulse(cycle, include_lan, hub, config_path).await {
                Ok(events) => Ok(events),
                Err(error) => {
                    let acknowledgement = Event::new(
                        "presentation",
                        "assisted.watch.error",
                        format!("Live follow-up {cycle} failed: {error}"),
                        None,
                        Severity::Low,
                        SourceKind::Derived,
                    )
                    .with_evidence("cycle", cycle.to_string(), "assisted_watch")
                    .with_evidence("error", error.to_string(), "execution");
                    hub.publish(acknowledgement.clone());
                    Ok(vec![acknowledgement])
                }
            }
        }
    }
}

fn assisted_ack(
    kind: &str,
    summary: impl Into<String>,
    scenario_id: &str,
    index: usize,
    severity: Severity,
) -> Event {
    Event::new(
        "presentation",
        kind,
        summary,
        None,
        severity,
        SourceKind::Derived,
    )
    .with_evidence("scenario", scenario_id, "assisted_scenario")
    .with_evidence("step_index", index.to_string(), "assisted_scenario")
}

const MAX_ASSISTED_RESULT_REFS: usize = 8;

fn retained_result_ids(hub: &EventHub, results: &[Event]) -> (String, usize) {
    // Cite only recent results. A stage may produce more events than the hub's
    // retention capacity; citing an evicted ID would make the marker itself
    // disappear, leaving the TUI waiting for an acknowledgement.
    let recent = hub
        .snapshot()
        .into_iter()
        .rev()
        .take(32)
        .map(|event| event.id)
        .collect::<HashSet<_>>();
    let mut ids = results
        .iter()
        .rev()
        .filter(|event| recent.contains(&event.id))
        .take(MAX_ASSISTED_RESULT_REFS)
        .map(|event| event.id.as_str())
        .collect::<Vec<_>>();
    ids.reverse();
    let omitted = results.len().saturating_sub(ids.len());
    (ids.join(","), omitted)
}

fn assisted_scenario(scenario_id: &str, config_path: &Path) -> Result<assisted::Scenario> {
    let config = Config::load_or_default(config_path)?;
    assisted::scenarios(&config)
        .into_iter()
        .find(|scenario| scenario.id == scenario_id)
        .context("assisted scenario is no longer available")
}

async fn complete_assisted_step(
    scenario_id: &str,
    index: usize,
    text: &str,
    hub: &EventHub,
    config_path: &Path,
) -> Result<Vec<Event>> {
    let scenario = assisted_scenario(scenario_id, config_path)?;
    let step = scenario
        .steps
        .get(index.saturating_sub(1))
        .filter(|_| index > 0)
        .context("assisted step is outside the selected scenario")?;
    if step.input != text {
        bail!("completed assisted step does not match the selected scenario");
    }
    if step.execution == Execution::Local && !is_safe_local_assisted_command(text)? {
        bail!("assisted local step is not an approved read-only command");
    }
    let prepared = Event::new(
        "presentation",
        "prepared.input",
        format!("{} · {} revealed", scenario.title, step.phase),
        None,
        Severity::Info,
        SourceKind::Prepared,
    )
    .with_evidence("scenario", &scenario.id, "assisted_scenario")
    .with_evidence("step_index", index.to_string(), "assisted_scenario")
    .with_evidence("phase", &step.phase, "assisted_scenario")
    .with_evidence("input", text, "assisted_scenario");
    hub.publish(prepared.clone());
    let prepared_id = prepared.id.clone();
    let mut output = vec![prepared];
    if step.execution == Execution::Local {
        let results = execute_line(text, hub, config_path).await?;
        let (event_ids, omitted) = retained_result_ids(hub, &results);
        let mut completion = assisted_ack(
            "assisted.action",
            format!("{} · {} completed", scenario.title, step.phase),
            &scenario.id,
            index,
            Severity::Info,
        )
        .with_evidence("command", text, "assisted_scenario")
        .with_evidence("result_event_ids", event_ids, "retained_results")
        .with_evidence(
            "result_event_count",
            results.len().to_string(),
            "observed_results",
        )
        .with_evidence(
            "uncited_result_count",
            omitted.to_string(),
            "bounded_provenance",
        );
        if hub
            .snapshot()
            .iter()
            .rev()
            .take(32)
            .any(|event| event.id == prepared_id)
        {
            completion = completion.with_evidence("prepared_event_id", prepared_id, "event id");
        } else {
            completion = completion.with_evidence(
                "expired_prepared_event_id",
                prepared_id,
                "bounded_history",
            );
        }
        hub.publish(completion.clone());
        output.extend(results);
        output.push(completion);
    }
    Ok(output)
}

async fn run_scoped_assisted_step(
    scenario_id: &str,
    index: usize,
    text: &str,
    hub: &EventHub,
    config_path: &Path,
) -> Result<Vec<Event>> {
    let scenario = assisted_scenario(scenario_id, config_path)?;
    let step = scenario
        .steps
        .get(index.saturating_sub(1))
        .filter(|_| index > 0)
        .context("assisted step is outside the selected scenario")?;
    if step.input != text {
        bail!("scoped assisted action changed; reveal the stage again");
    }
    if step.execution != Execution::Explicit || !is_scoped_assisted_command(text)? {
        bail!("this assisted step has no explicit network action");
    }
    execute_line(text, hub, config_path).await
}

async fn run_full_assisted_session(
    scenario_id: &str,
    hub: &EventHub,
    config_path: &Path,
) -> Result<Vec<Event>> {
    let scenario = assisted_scenario(scenario_id, config_path)?;
    if !matches!(
        scenario.id.as_str(),
        "system-network" | "local-research" | "local-network" | "process-investigation"
    ) && !scenario.id.starts_with("scoped-network:")
    {
        bail!("only built-in scenarios support a full run");
    }
    if scenario.steps.is_empty()
        || scenario
            .steps
            .iter()
            .any(|step| step.execution == Execution::PresentationOnly)
    {
        bail!("scenario has no executable stages");
    }
    let started = Event::new(
        "presentation",
        "assisted.session.start",
        format!("{} session started", scenario.title),
        None,
        Severity::Info,
        SourceKind::Derived,
    )
    .with_evidence("scenario", &scenario.id, "assisted_scenario")
    .with_evidence(
        "stages",
        scenario.steps.len().to_string(),
        "assisted_scenario",
    );
    hub.publish(started.clone());
    let mut output = vec![started];
    let mut succeeded = 0usize;
    let mut current_lan_survey_id: Option<String> = None;
    for (position, step) in scenario.steps.iter().enumerate() {
        let index = position + 1;
        let stage_started = assisted_ack(
            "assisted.session.stage.start",
            format!("{} · {} running", scenario.title, step.phase),
            &scenario.id,
            index,
            Severity::Info,
        )
        .with_evidence("phase", &step.phase, "assisted_scenario")
        .with_evidence("command", &step.input, "assisted_scenario");
        hub.publish(stage_started.clone());
        output.push(stage_started);
        let result = if step.input == "lan report" {
            match current_lan_survey_id.as_deref() {
                Some(survey_id) => lan_report(&hub.snapshot(), Some(survey_id)).map(|report| {
                    hub.publish(report.clone());
                    vec![report]
                }),
                None => Err(anyhow::anyhow!(
                    "no successful LAN survey in this session to review"
                )),
            }
        } else {
            match step.execution {
                Execution::Local if is_safe_local_assisted_command(&step.input)? => {
                    execute_line(&step.input, hub, config_path).await
                }
                Execution::Explicit if is_scoped_assisted_command(&step.input)? => {
                    run_scoped_assisted_step(&scenario.id, index, &step.input, hub, config_path)
                        .await
                }
                _ => anyhow::bail!("bundled stage has an unsupported action"),
            }
        };
        let mut stage = assisted_ack(
            "assisted.session.stage",
            format!("{} · {}", scenario.title, step.phase),
            &scenario.id,
            index,
            Severity::Info,
        )
        .with_evidence("phase", &step.phase, "assisted_scenario")
        .with_evidence("command", &step.input, "assisted_scenario");
        match result {
            Ok(events) => {
                if step.input.starts_with("lan survey") {
                    current_lan_survey_id = events
                        .iter()
                        .find(|event| event.module == "lan" && event.kind == "lan.survey_complete")
                        .map(|event| event.id.clone());
                }
                succeeded += 1;
                let (event_ids, omitted) = retained_result_ids(hub, &events);
                stage = stage
                    .with_evidence("status", "complete", "execution")
                    .with_evidence("result_event_ids", event_ids, "retained_results")
                    .with_evidence(
                        "result_event_count",
                        events.len().to_string(),
                        "observed_results",
                    )
                    .with_evidence(
                        "uncited_result_count",
                        omitted.to_string(),
                        "bounded_provenance",
                    );
                output.extend(events);
            }
            Err(error) => {
                if step.input.starts_with("lan survey") {
                    current_lan_survey_id = None;
                }
                stage.severity = Severity::Low;
                stage = stage
                    .with_evidence("status", "error", "execution")
                    .with_evidence("error", error.to_string(), "execution");
            }
        }
        hub.publish(stage.clone());
        output.push(stage);
    }
    let completed = Event::new(
        "presentation",
        "assisted.session.complete",
        format!(
            "{} session complete: {succeeded}/{} stages succeeded",
            scenario.title,
            scenario.steps.len()
        ),
        None,
        if succeeded == scenario.steps.len() {
            Severity::Info
        } else {
            Severity::Low
        },
        SourceKind::Derived,
    )
    .with_evidence("scenario", &scenario.id, "assisted_scenario")
    .with_evidence("succeeded", succeeded.to_string(), "execution")
    .with_evidence(
        "failed",
        (scenario.steps.len() - succeeded).to_string(),
        "execution",
    );
    hub.publish(completed.clone());
    output.push(completed);
    Ok(output)
}

async fn run_live_assisted_pulse(
    cycle: u64,
    include_lan: bool,
    hub: &EventHub,
    config_path: &Path,
) -> Result<Vec<Event>> {
    let config = Config::load_or_default(config_path)?;
    let survey_lan = include_lan && config.lan_assessment_enabled;
    let mut stages = vec![
        ("Interface traffic", "traffic snapshot"),
        ("Process inventory", "process top 6"),
    ];
    if survey_lan {
        stages.extend([
            ("LAN context", "lan status"),
            ("LAN survey", "lan survey"),
            ("LAN review", "lan report"),
        ]);
    }
    stages.push(("Evidence review", "triage"));
    let started = Event::new(
        "presentation",
        "assisted.watch.start",
        format!("Live follow-up {cycle} started"),
        None,
        Severity::Info,
        SourceKind::Derived,
    )
    .with_evidence("cycle", cycle.to_string(), "assisted_watch")
    .with_evidence("lan_requested", include_lan.to_string(), "assisted_watch")
    .with_evidence("lan_enabled", survey_lan.to_string(), "config.toml")
    .with_evidence("stages", stages.len().to_string(), "assisted_watch");
    hub.publish(started.clone());
    let mut output = vec![started];
    let mut succeeded = 0usize;
    let mut current_lan_survey_id: Option<String> = None;
    for (phase, command) in &stages {
        let stage_started = Event::new(
            "presentation",
            "assisted.watch.stage.start",
            format!("Live follow-up {cycle}: {phase} running"),
            None,
            Severity::Info,
            SourceKind::Derived,
        )
        .with_evidence("cycle", cycle.to_string(), "assisted_watch")
        .with_evidence("phase", *phase, "assisted_watch")
        .with_evidence("command", *command, "assisted_watch");
        hub.publish(stage_started.clone());
        output.push(stage_started);
        let result = if *command == "lan report" {
            match current_lan_survey_id.as_deref() {
                Some(survey_id) => lan_report(&hub.snapshot(), Some(survey_id)).map(|report| {
                    hub.publish(report.clone());
                    vec![report]
                }),
                None => Err(anyhow::anyhow!(
                    "no successful LAN survey in this follow-up to review"
                )),
            }
        } else {
            execute_line(command, hub, config_path).await
        };
        let mut stage = Event::new(
            "presentation",
            "assisted.watch.stage",
            format!("Live follow-up {cycle}: {phase}"),
            None,
            Severity::Info,
            SourceKind::Derived,
        )
        .with_evidence("cycle", cycle.to_string(), "assisted_watch")
        .with_evidence("phase", *phase, "assisted_watch")
        .with_evidence("command", *command, "assisted_watch");
        match result {
            Ok(events) => {
                if *command == "lan survey" {
                    current_lan_survey_id = events
                        .iter()
                        .find(|event| event.module == "lan" && event.kind == "lan.survey_complete")
                        .map(|event| event.id.clone());
                }
                succeeded += 1;
                let (event_ids, omitted) = retained_result_ids(hub, &events);
                stage = stage
                    .with_evidence("status", "complete", "execution")
                    .with_evidence("result_event_ids", event_ids, "retained_results")
                    .with_evidence(
                        "result_event_count",
                        events.len().to_string(),
                        "observed_results",
                    )
                    .with_evidence(
                        "uncited_result_count",
                        omitted.to_string(),
                        "bounded_provenance",
                    );
                output.extend(events);
            }
            Err(error) => {
                if *command == "lan survey" {
                    current_lan_survey_id = None;
                }
                stage.severity = Severity::Low;
                stage = stage
                    .with_evidence("status", "error", "execution")
                    .with_evidence("error", error.to_string(), "execution");
            }
        }
        hub.publish(stage.clone());
        output.push(stage);
    }
    let completed = Event::new(
        "presentation",
        "assisted.watch.complete",
        format!(
            "Live follow-up {cycle}: {succeeded}/{} checks complete",
            stages.len()
        ),
        None,
        if succeeded == stages.len() {
            Severity::Info
        } else {
            Severity::Low
        },
        SourceKind::Derived,
    )
    .with_evidence("cycle", cycle.to_string(), "assisted_watch")
    .with_evidence("succeeded", succeeded.to_string(), "execution")
    .with_evidence(
        "failed",
        (stages.len() - succeeded).to_string(),
        "execution",
    )
    .with_evidence("lan_enabled", survey_lan.to_string(), "config.toml");
    hub.publish(completed.clone());
    output.push(completed);
    Ok(output)
}

pub async fn execute_line(line: &str, hub: &EventHub, config_path: &Path) -> Result<Vec<Event>> {
    let words = tokenize(line)?;
    if words.is_empty() {
        return Ok(Vec::new());
    }
    let config = Config::load_or_default(config_path)?;
    let canonical_indicators = canonicalize_indicators(&config.indicators)?;
    hub.set_indicators(canonical_indicators.clone());
    let output = match words[0].as_str() {
        "help" => vec![Event::new("command", "command.help", "Command reference (F1 for keyboard controls)", None, Severity::Info, SourceKind::Live)
            .with_evidence("commands", "binary <file>\npcap <file>\nprocess top [limit]|inspect <PID|self>\ntraffic snapshot\nscan <target> [ports]\ninvestigate <target> [ports]\nhttp <url>\nlan status|survey [detected CIDR]|report|on|off\nscope add|remove|list\nindicator add|remove|list\nprofile <name>|list\ntheme <name>|list\nmodule enable|disable|list\nautonomous on|off\nworkflow list|add|remove|clear\nretention [set COUNT]\ntriage\nexport <file>\ndoctor", "built_in")],
        "doctor" => {
            let report = capability::inspect();
            let found = report.tools.iter().filter(|tool| tool.path.is_some()).count();
            vec![Event::new("command", "command.doctor", format!("{} {}; {found} optional tools found", report.os, report.arch), None, Severity::Info, SourceKind::Live)
                .with_evidence("report", serde_json::to_string_pretty(&report)?, "capability_inspection")]
        },
        "binary" if words.len() == 2 => {
            let path = PathBuf::from(&words[1]);
            tokio::task::spawn_blocking(move || analysis::analyze_binary(&path)).await??
        }
        "process" if words.len() >= 2 => match words[1].as_str() {
            "top" if (2..=3).contains(&words.len()) => {
                let limit = words
                    .get(2)
                    .map(|value| value.parse::<usize>())
                    .transpose()
                    .context("process top limit must be a number")?
                    .unwrap_or(10);
                tokio::task::spawn_blocking(move || process::top_processes(limit)).await??
            }
            "inspect" if words.len() == 3 => {
                let pid = if words[2] == "self" {
                    std::process::id()
                } else {
                    words[2]
                        .parse::<u32>()
                        .context("process inspect expects a numeric PID or self")?
                };
                tokio::task::spawn_blocking(move || process::inspect_process(pid)).await??
            }
            _ => bail!("usage: process top [1..32], or process inspect <PID|self>"),
        },
        "traffic" if words.len() == 2 && words[1] == "snapshot" => {
            tokio::task::spawn_blocking(traffic::traffic_snapshot).await??
        }
        "triage" if words.len() == 1 => vec![triage_snapshot(&hub.snapshot())],
        "pcap" if words.len() == 2 => {
            let path = PathBuf::from(&words[1]);
            tokio::task::spawn_blocking(move || analysis::analyze_pcap(&path)).await??
        }
        "scan" if (2..=3).contains(&words.len()) => {
            let target = normalize_target(&words[1])?;
            if !config.target_allowed(&target) {
                bail!(
                    "target {} is outside configured scope; use `spectre scope add {}`",
                    words[1],
                    words[1]
                );
            }
            let ports = parse_ports(
                words
                    .get(2)
                    .map(String::as_str)
                    .unwrap_or("21,22,25,53,80,110,143,443,445,3389,5432,6379,8080,8443"),
            )?;
            network::scan_tcp(&target, &ports, Duration::from_secs(2)).await?
        }
        "investigate" if (2..=3).contains(&words.len()) => {
            let target = normalize_target(&words[1])?;
            if !config.target_allowed(&target) {
                bail!(
                    "target {target} is outside configured scope; use `spectre scope add {target}`"
                );
            }
            let ports = parse_ports(
                words
                    .get(2)
                    .map(String::as_str)
                    .unwrap_or("22,80,443,8080,8443"),
            )?;
            let mut events = network::scan_tcp(&target, &ports, Duration::from_secs(2)).await?;
            let mut followed = 0usize;
            let mut web_events = 0usize;
            let open_endpoints = events
                .iter()
                .filter(|event| event.kind == "tcp_open")
                .filter_map(|event| event.evidence.iter().find(|item| item.label == "endpoint"))
                .filter_map(|item| item.value.parse::<std::net::SocketAddr>().ok())
                .filter(|endpoint| [80, 443, 8080, 8443].contains(&endpoint.port()))
                .collect::<std::collections::BTreeSet<_>>();
            for endpoint in open_endpoints.into_iter().take(4) {
                followed += 1;
                let url = follow_up_url(&target, endpoint)?;
                match network::inspect_http_at(&url, Duration::from_secs(8), Some(endpoint)).await {
                    Ok(result) => {
                        web_events += result.len();
                        events.extend(result);
                    }
                    Err(error) => events.push(follow_up_error(&target, &url, endpoint, &error)),
                }
            }
            events.push(
                Event::new(
                    "investigation",
                    "investigation.complete",
                    format!(
                        "Investigation of {target} completed; {followed} web endpoint(s) checked"
                    ),
                    None,
                    Severity::Info,
                    SourceKind::Derived,
                )
                .with_evidence("target", target, "configured_scope")
                .with_evidence(
                    "web_events",
                    web_events.to_string(),
                    "observed_results",
                ),
            );
            events
        }
        "http" if words.len() == 2 => {
            let url =
                reqwest::Url::parse(&words[1]).context("expected a valid HTTP or HTTPS URL")?;
            if !matches!(url.scheme(), "http" | "https") {
                bail!("only HTTP and HTTPS URLs are supported");
            }
            let host = url.host_str().context("URL has no host")?;
            if !config.target_allowed(host) {
                bail!("host {host} is outside configured scope; use `spectre scope add {host}`");
            }
            network::inspect_http(&words[1], Duration::from_secs(8)).await?
        }
        "lan" if words.len() >= 2 => match words[1].as_str() {
            "status" if words.len() == 2 => {
                let scope = network::lan::detect_lan()?;
                vec![Event::new(
                    "lan",
                    "lan.status",
                    format!(
                        "Active private IPv4 segment {} on {} ({})",
                        scope.cidr, scope.interface, scope.local_ip
                    ),
                    Some(scope.cidr.clone()),
                    Severity::Info,
                    SourceKind::Live,
                )
                .with_evidence("interface", scope.interface, "interface_inventory")
                .with_evidence("local_ip", scope.local_ip.to_string(), "interface_inventory")
                .with_evidence("cidr", scope.cidr, "interface_netmask")
                .with_evidence("survey_enabled", config.lan_assessment_enabled.to_string(), "config.toml")]
            }
            "survey" if (2..=3).contains(&words.len()) => {
                if !config.lan_assessment_enabled {
                    bail!("local network assessment is off; use `lan on` or F5 then n");
                }
                let scope = network::lan::detect_lan()?;
                if let Some(expected) = words.get(2)
                    && expected != &scope.cidr
                {
                    bail!(
                        "active local segment changed from {expected} to {}; review the new target before surveying",
                        scope.cidr
                    );
                }
                network::lan::survey_lan(&scope).await?
            }
            "report" if words.len() == 2 => vec![lan_report(&hub.snapshot(), None)?],
            "on" | "off" if words.len() == 2 => {
                let mut next = config;
                next.lan_assessment_enabled = words[1] == "on";
                next.save(config_path)?;
                vec![Event::new(
                    "config",
                    "config.lan_assessment",
                    format!("Local network assessment: {}", words[1]),
                    None,
                    Severity::Info,
                    SourceKind::Live,
                )
                .with_evidence("enabled", next.lan_assessment_enabled.to_string(), "config.toml")]
            }
            _ => bail!("usage: lan status|survey [detected CIDR]|report|on|off"),
        },
        "scope" if words.len() >= 2 => match words[1].as_str() {
            "list" if words.len() == 2 => vec![status(if config.allowed_targets.is_empty() {
                "No targets configured".into()
            } else {
                config.allowed_targets.join(", ")
            })],
            "add" if words.len() == 3 => {
                let target = normalize_target(&words[2])?;
                let mut next = config;
                if !next.target_allowed(&target) {
                    next.allowed_targets.push(target.clone());
                }
                next.save(config_path)?;
                vec![status(format!("Target added to scope: {target}"))]
            }
            "remove" if words.len() == 3 => {
                let target = normalize_target(&words[2])?;
                let mut next = config;
                next.allowed_targets
                    .retain(|value| normalize_target(value).is_ok_and(|value| value != target));
                next.save(config_path)?;
                vec![status(format!("Target removed from scope: {target}"))]
            }
            _ => bail!("usage: scope add|remove <host>, or scope list"),
        },
        "profile" if words.len() == 2 => {
            if words[1] == "list" {
                vec![status(format!("Profiles: {}", Config::PROFILES.join(", ")))]
            } else {
                let mut next = config;
                next.apply_profile(&words[1])?;
                next.save(config_path)?;
                vec![
                    Event::new(
                        "config",
                        "config.profile",
                        format!("Profile: {}", words[1]),
                        None,
                        Severity::Info,
                        SourceKind::Live,
                    )
                    .with_evidence("name", &words[1], "config.toml"),
                ]
            }
        }
        "theme" if words.len() == 2 => {
            if words[1] == "list" {
                vec![status("Themes: intelligence, arctic, amber, monochrome")]
            } else {
                let mut next = config;
                next.theme = words[1].clone();
                next.save(config_path)?;
                vec![
                    Event::new(
                        "config",
                        "config.theme",
                        format!("Theme: {}", words[1]),
                        None,
                        Severity::Info,
                        SourceKind::Live,
                    )
                    .with_evidence("name", &words[1], "config.toml"),
                ]
            }
        }
        "module" if words.len() >= 2 => {
            let available = ["host", "process", "binary", "traffic", "correlation"];
            match words[1].as_str() {
                "list" if words.len() == 2 => vec![status(format!(
                    "Autonomous modules: {}; enabled: {}",
                    available.join(", "),
                    config.enabled_modules.join(", ")
                ))],
                "enable" | "disable" if words.len() == 3 => {
                    if !available.contains(&words[2].as_str()) {
                        bail!("unknown autonomous module: {}", words[2]);
                    }
                    let mut next = config;
                    if words[1] == "enable" && !next.enabled_modules.contains(&words[2]) {
                        next.enabled_modules.push(words[2].clone());
                    }
                    if words[1] == "disable" {
                        next.enabled_modules.retain(|name| name != &words[2]);
                    }
                    next.profile = "custom".into();
                    next.save(config_path)?;
                    vec![status(format!(
                        "Module {}: {}",
                        words[2],
                        if words[1] == "enable" {
                            "enabled"
                        } else {
                            "disabled"
                        }
                    ))]
                }
                _ => bail!("usage: module enable|disable <name>, or module list"),
            }
        }
        "indicator" if words.len() >= 2 => match words[1].as_str() {
            "list" if words.len() == 2 => {
                let listing = canonical_indicators.iter()
                    .map(|indicator| format!("{} {}  {}", indicator.kind.as_str(), indicator.value, indicator.label))
                    .collect::<Vec<_>>().join("\n");
                vec![Event::new("config", "indicator.list", format!("{} indicators configured", canonical_indicators.len()), None, Severity::Info, SourceKind::Live)
                    .with_evidence("indicators", listing, "config.toml")]
            }
            "add" if (4..=5).contains(&words.len()) => {
                let label = words.get(4).map(String::as_str).unwrap_or("configured indicator");
                let indicator = Indicator::parse(&words[2], &words[3], label)?;
                let mut next = config;
                next.indicators = canonical_indicators;
                next.indicators.retain(|existing| existing.kind != indicator.kind || existing.value != indicator.value);
                next.indicators.push(indicator.clone());
                next.save(config_path)?;
                hub.set_indicators(next.indicators);
                vec![status(format!("Indicator added: {} {}", indicator.kind.as_str(), indicator.value))]
            }
            "remove" if words.len() == 4 => {
                let indicator = Indicator::parse(&words[2], &words[3], "configured indicator")?;
                let mut next = config;
                next.indicators = canonical_indicators;
                next.indicators.retain(|existing| existing.kind != indicator.kind || existing.value != indicator.value);
                next.save(config_path)?;
                hub.set_indicators(next.indicators);
                vec![status(format!("Indicator removed: {} {}", indicator.kind.as_str(), indicator.value))]
            }
            _ => bail!("usage: indicator add <sha256|domain|ip> <value> [label], indicator remove <kind> <value>, or indicator list"),
        },
        "autonomous" if words.len() == 2 => {
            let mut next = config;
            next.autonomous = match words[1].as_str() {
                "on" => true,
                "off" => false,
                _ => bail!("usage: autonomous on|off"),
            };
            next.save(config_path)?;
            vec![status(format!("Autonomous collection: {}", words[1]))]
        }
        "workflow" if words.len() >= 2 => match words[1].as_str() {
            "list" if words.len() == 2 => {
                let steps = config.prepared_workflow.iter().enumerate()
                    .map(|(index, step)| format!("{}. {}", index + 1, step))
                    .collect::<Vec<_>>().join("\n");
                vec![Event::new(
                    "config", "workflow.list",
                    format!("{} prepared step(s) configured", config.prepared_workflow.len()),
                    None, Severity::Info, SourceKind::Live,
                ).with_evidence("steps", steps, "config.toml")]
            }
            "add" if words.len() >= 3 => {
                let step = words[2..].join(" ");
                if step.trim().is_empty() {
                    bail!("prepared step cannot be empty");
                }
                let mut next = config;
                next.prepared_workflow.push(step);
                next.save(config_path)?;
                vec![status(format!("Prepared step {} added", next.prepared_workflow.len()))]
            }
            "remove" if words.len() == 3 => {
                let index: usize = words[2].parse().context("prepared step index must be a number")?;
                let mut next = config;
                if index == 0 || index > next.prepared_workflow.len() {
                    bail!("prepared step index is outside the configured workflow");
                }
                next.prepared_workflow.remove(index - 1);
                next.save(config_path)?;
                vec![status(format!("Prepared step {index} removed"))]
            }
            "clear" if words.len() == 2 => {
                let mut next = config;
                let count = next.prepared_workflow.len();
                next.prepared_workflow.clear();
                next.save(config_path)?;
                vec![status(format!("{count} prepared step(s) removed"))]
            }
            _ => bail!("usage: workflow list, workflow add <text>, workflow remove <index>, or workflow clear"),
        },
        "retention" if words.len() == 1 => {
            vec![status(format!("Retention limit: {} events", config.retention_events))]
        }
        "retention" if words.len() == 3 && words[1] == "set" => {
            let count: usize = words[2].parse().context("retention count must be a number")?;
            let mut next = config;
            next.retention_events = count;
            next.save(config_path)?;
            vec![status(format!("Retention saved: {count} events; hub capacity changes on next launch"))]
        }
        "retention" => bail!("usage: retention, or retention set <100..100000>"),
        "config" if words.len() == 2 && words[1] == "reload" => {
            vec![status("Configuration reloaded")]
        }
        "export" if words.len() == 2 => {
            let count = hub.export_jsonl(Path::new(&words[1]))?;
            vec![status(format!("Exported {count} events to {}", words[1]))]
        }
        _ => bail!("unknown command or arguments; enter `help` for commands"),
    };
    for event in &output {
        hub.publish(event.clone());
    }
    Ok(output)
}

fn is_safe_local_assisted_command(line: &str) -> Result<bool> {
    let words = tokenize(line)?;
    Ok(match words.as_slice() {
        [command] => matches!(command.as_str(), "doctor" | "triage"),
        [command, action] => {
            matches!(
                (command.as_str(), action.as_str()),
                ("module", "list")
                    | ("indicator", "list")
                    | ("scope", "list")
                    | ("lan", "status")
                    | ("lan", "report")
                    | ("process", "top")
                    | ("traffic", "snapshot")
            ) || command == "binary"
        }
        [command, action, target] => {
            command == "process" && action == "inspect" && target == "self"
        }
        _ => false,
    })
}

fn is_scoped_assisted_command(line: &str) -> Result<bool> {
    let words = tokenize(line)?;
    Ok(match words.as_slice() {
        [command, action] if command == "lan" && action == "survey" => true,
        [command, action, _cidr] if command == "lan" && action == "survey" => true,
        [command, _target] => matches!(command.as_str(), "scan" | "investigate" | "http"),
        [command, _target, _ports] => matches!(command.as_str(), "scan" | "investigate"),
        _ => false,
    })
}

fn triage_snapshot(events: &[Event]) -> Event {
    let observations = events
        .iter()
        .filter(|event| matches!(event.source, SourceKind::Live | SourceKind::File))
        .filter(|event| {
            matches!(
                event.module.as_str(),
                "host"
                    | "process"
                    | "binary"
                    | "pcap"
                    | "tcp"
                    | "http"
                    | "lan"
                    | "traffic"
                    | "investigation"
            )
        })
        .collect::<Vec<_>>();
    let mut by_module = BTreeMap::<&str, usize>::new();
    let mut by_severity = BTreeMap::<Severity, usize>::new();
    for event in &observations {
        *by_module.entry(&event.module).or_default() += 1;
        *by_severity.entry(event.severity).or_default() += 1;
    }
    let mut seen = HashSet::new();
    let recent_subjects = observations
        .iter()
        .rev()
        .filter_map(|event| event.subject.as_deref())
        .filter(|subject| seen.insert(*subject))
        .take(5)
        .collect::<Vec<_>>()
        .join("\n");
    let recent_ids = observations
        .iter()
        .rev()
        .take(5)
        .map(|event| event.id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let indicator_matches = events
        .iter()
        .filter(|event| event.module == "detection" && event.kind == "indicator.match")
        .count();
    let subject_links = events
        .iter()
        .filter(|event| event.module == "correlation" && event.kind == "subject.link")
        .count();
    let modules = by_module
        .iter()
        .map(|(module, count)| format!("{module}: {count}"))
        .collect::<Vec<_>>()
        .join(", ");
    let severities = by_severity
        .iter()
        .map(|(severity, count)| format!("{severity:?}: {count}"))
        .collect::<Vec<_>>()
        .join(", ");
    Event::new(
        "investigation",
        "investigation.triage",
        format!(
            "Retained snapshot: {} observations across {} modules; {indicator_matches} indicator matches",
            observations.len(),
            by_module.len()
        ),
        None,
        Severity::Info,
        SourceKind::Derived,
    )
    .with_evidence("modules", modules, "retained_observations")
    .with_evidence("severity_counts", severities, "retained_observations")
    .with_evidence("indicator_matches", indicator_matches.to_string(), "retained_events")
    .with_evidence("subject_links", subject_links.to_string(), "retained_events")
    .with_evidence("recent_subjects", recent_subjects, "retained_observations")
    .with_evidence("recent_observation_ids", recent_ids, "retained_observations")
}

fn lan_report(events: &[Event], expected_survey_id: Option<&str>) -> Result<Event> {
    let Some(last_index) = events
        .iter()
        .rposition(|event| event.module == "lan" && event.kind == "lan.survey_complete")
    else {
        if expected_survey_id.is_some() {
            bail!("current LAN survey is no longer retained; run the survey again");
        }
        return Ok(Event::new(
            "investigation",
            "lan.report",
            "No local network survey results retained",
            None,
            Severity::Info,
            SourceKind::Derived,
        ));
    };
    let prior_index = events[..last_index]
        .iter()
        .rposition(|event| event.module == "lan" && event.kind == "lan.survey_complete");
    let survey = &events[last_index];
    if expected_survey_id.is_some_and(|expected| expected != survey.id.as_str()) {
        bail!("current LAN survey is no longer retained; run the survey again");
    }
    let results = &events[prior_index.map_or(0, |index| index + 1)..last_index];
    let hosts = results
        .iter()
        .filter(|event| event.module == "lan" && event.kind == "lan.host")
        .collect::<Vec<_>>();
    let open_endpoints = results
        .iter()
        .filter(|event| event.module == "lan" && event.kind == "lan.tcp_open")
        .collect::<Vec<_>>();
    let host_list = hosts
        .iter()
        .filter_map(|event| event.subject.as_deref())
        .take(32)
        .collect::<Vec<_>>()
        .join(", ");
    let endpoint_list = open_endpoints
        .iter()
        .filter_map(|event| event.evidence.iter().find(|item| item.label == "endpoint"))
        .map(|item| item.value.as_str())
        .take(32)
        .collect::<Vec<_>>()
        .join(", ");
    let reported_hosts = survey
        .evidence
        .iter()
        .find(|item| item.label == "responded_hosts")
        .map(|item| item.value.as_str())
        .unwrap_or("unknown");
    let reported_endpoints = survey
        .evidence
        .iter()
        .find(|item| item.label == "open_endpoints")
        .map(|item| item.value.as_str())
        .unwrap_or("unknown");
    let web_summary = events[last_index + 1..]
        .iter()
        .find(|event| event.module == "lan" && event.kind == "lan.web_followup_complete");
    let web_responses = web_summary
        .and_then(|event| event.evidence.iter().find(|item| item.label == "responses"))
        .map(|item| item.value.as_str());
    let web_attempted = web_summary
        .and_then(|event| {
            event
                .evidence
                .iter()
                .find(|item| item.label == "attempted_endpoints")
        })
        .map(|item| item.value.as_str());
    let survey_segment = survey.subject.as_deref().unwrap_or("unknown segment");
    let survey_time = survey.timestamp.to_rfc3339();
    let summary = match (web_responses, web_attempted) {
        (Some(responses), Some(attempted)) => format!(
            "Latest retained survey of {survey_segment} at {survey_time}: {reported_hosts} responsive hosts, {reported_endpoints} open TCP endpoints, {responses}/{attempted} web responses"
        ),
        _ => format!(
            "Latest retained survey of {survey_segment} at {survey_time}: {reported_hosts} responsive hosts, {reported_endpoints} open TCP endpoints"
        ),
    };
    Ok(Event::new(
        "investigation",
        "lan.report",
        summary,
        survey.subject.clone(),
        Severity::Info,
        SourceKind::Derived,
    )
    .with_evidence("survey_event_id", &survey.id, "retained_survey")
    .with_evidence("responsive_hosts", reported_hosts, "survey_summary")
    .with_evidence("open_endpoints", reported_endpoints, "survey_summary")
    .with_evidence("hosts_first_32", host_list, "retained_survey")
    .with_evidence("endpoints_first_32", endpoint_list, "retained_survey")
    .with_evidence(
        "web_responses",
        web_responses.unwrap_or("unknown"),
        "web_followup",
    )
    .with_evidence(
        "web_attempted",
        web_attempted.unwrap_or("unknown"),
        "web_followup",
    ))
}

pub fn status(summary: impl Into<String>) -> Event {
    Event::new(
        "command",
        "command.result",
        summary,
        None,
        Severity::Info,
        SourceKind::Live,
    )
}

fn follow_up_error(target: &str, url: &str, endpoint: SocketAddr, error: &anyhow::Error) -> Event {
    Event::new(
        "investigation",
        "follow_up.error",
        format!("HTTP follow-up on {url} via {endpoint}: {error}"),
        Some(target.to_string()),
        Severity::Low,
        SourceKind::Live,
    )
    .with_evidence("url", url, "configured_scope")
    .with_evidence("resolved_endpoint", endpoint.to_string(), "tcp_scan")
}

fn follow_up_url(target: &str, endpoint: SocketAddr) -> Result<String> {
    let target = normalize_target(target)?;
    let host = match target.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{target}]"),
        _ => target,
    };
    let scheme = if matches!(endpoint.port(), 443 | 8443) {
        "https"
    } else {
        "http"
    };
    Ok(format!("{scheme}://{host}:{}/", endpoint.port()))
}

fn canonicalize_indicators(indicators: &[Indicator]) -> Result<Vec<Indicator>> {
    let mut normalized = Vec::<Indicator>::with_capacity(indicators.len());
    for raw in indicators {
        let indicator = Indicator::parse(raw.kind.as_str(), &raw.value, &raw.label)?;
        if let Some(existing) = normalized
            .iter_mut()
            .find(|existing| existing.kind == indicator.kind && existing.value == indicator.value)
        {
            *existing = indicator;
        } else {
            normalized.push(indicator);
        }
    }
    Ok(normalized)
}

pub fn parse_ports(input: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in input.split(',') {
        if let Some((first, last)) = part.split_once('-') {
            let first: u16 = first.parse().context("invalid first port")?;
            let last: u16 = last.parse().context("invalid last port")?;
            if first == 0 || last < first || last - first > 127 {
                bail!("port range must contain 1 to 128 valid ports");
            }
            ports.extend(first..=last);
        } else {
            let port: u16 = part.parse().context("invalid port")?;
            if port == 0 {
                bail!("port zero is not supported");
            }
            ports.push(port);
        }
        if ports.len() > 128 {
            bail!("at most 128 ports can be scanned per command");
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

pub fn tokenize(input: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;
    for ch in input.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            started = true;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            escaped = true;
            started = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                started = true;
            }
            ch if ch.is_whitespace() => {
                if started {
                    out.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            _ => {
                current.push(ch);
                started = true;
            }
        }
    }
    if escaped || quote.is_some() {
        bail!("unfinished escape or quote in command");
    }
    if started {
        out.push(current);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::IndicatorKind;
    use tokio::net::TcpListener;

    #[test]
    fn quotes_paths_without_running_a_shell() {
        assert_eq!(
            tokenize("binary '/tmp/a b' --x").unwrap(),
            vec!["binary", "/tmp/a b", "--x"]
        );
        assert!(tokenize("binary 'bad").is_err());
    }

    #[test]
    fn ports_are_bounded_and_deduplicated() {
        assert_eq!(
            parse_ports("443,80,80,81-82").unwrap(),
            vec![80, 81, 82, 443]
        );
        assert!(parse_ports("1-200").is_err());
        assert!(parse_ports("0").is_err());
    }

    #[test]
    fn follow_up_url_brackets_ipv6_exactly_once() {
        let endpoint = "[::1]:8080".parse().unwrap();
        assert_eq!(
            follow_up_url("[::1]", endpoint).unwrap(),
            "http://[::1]:8080/"
        );
        assert_eq!(
            follow_up_url("::1", endpoint).unwrap(),
            "http://[::1]:8080/"
        );
        let tls_endpoint = "[::1]:8443".parse().unwrap();
        assert_eq!(
            follow_up_url("[::1]", tls_endpoint).unwrap(),
            "https://[::1]:8443/"
        );
    }

    #[tokio::test]
    async fn bracketed_ipv6_scope_allows_loopback_scan_when_available() {
        let Ok(listener) = TcpListener::bind("[::1]:0").await else {
            return;
        };
        let port = listener.local_addr().unwrap().port();
        let path = std::env::temp_dir().join(format!(
            "spectre-ipv6-command-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let hub = EventHub::new(100);
        execute_line("scope add [::1]", &hub, &path).await.unwrap();
        let events = execute_line(&format!("scan [::1] {port}"), &hub, &path)
            .await
            .unwrap();
        assert!(
            events
                .iter()
                .any(|event| event.kind == "tcp_open" && event.subject.as_deref() == Some("::1"))
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn indicator_commands_canonicalize_raw_toml_entries() {
        let path = std::env::temp_dir().join(format!(
            "spectre-indicator-command-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let raw = Indicator {
            kind: IndicatorKind::Domain,
            value: "EXAMPLE.ORG.".into(),
            label: "old label".into(),
        };
        let mut config = Config {
            indicators: vec![raw.clone()],
            ..Config::default()
        };
        config.save(&path).unwrap();
        let hub = EventHub::new(100);
        let listed = execute_line("indicator list", &hub, &path).await.unwrap();
        assert!(listed[0].evidence.iter().any(
            |item| item.label == "indicators" && item.value == "domain example.org  old label"
        ));

        execute_line("indicator add domain example.org replacement", &hub, &path)
            .await
            .unwrap();
        let saved = Config::load(&path).unwrap();
        assert_eq!(saved.indicators.len(), 1);
        assert_eq!(saved.indicators[0].value, "example.org");
        assert_eq!(saved.indicators[0].label, "replacement");

        config.indicators = vec![raw];
        config.save(&path).unwrap();
        execute_line("indicator remove domain example.org", &hub, &path)
            .await
            .unwrap();
        assert!(Config::load(&path).unwrap().indicators.is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn command_scope_and_prepared_provenance() {
        let path = std::env::temp_dir().join(format!(
            "spectre-command-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let hub = EventHub::new(100);
        let denied = execute_line("scan 127.0.0.1 9", &hub, &path)
            .await
            .unwrap_err();
        assert!(denied.to_string().contains("outside configured scope"));
        execute_line("scope add 127.0.0.1", &hub, &path)
            .await
            .unwrap();
        let mut config = Config::load(&path).unwrap();
        assert!(config.target_allowed("127.0.0.1"));
        config.prepared_workflow = vec!["binary /tmp/example".into()];
        config.save(&path).unwrap();
        assert!(
            execute_workspace_request(
                WorkspaceRequest::Command("present 1 \"binary /tmp/example\"".into()),
                &hub,
                &path,
            )
            .await
            .is_err()
        );
        assert!(
            !hub.snapshot()
                .iter()
                .any(|event| event.kind == "prepared.input")
        );
        let event = execute_workspace_request(
            WorkspaceRequest::AssistedCompletion {
                index: 1,
                text: "binary /tmp/example".into(),
            },
            &hub,
            &path,
        )
        .await
        .unwrap()
        .remove(0);
        assert_eq!(event.source, SourceKind::Prepared);
        assert_eq!(
            event
                .evidence
                .iter()
                .find(|e| e.label == "input")
                .unwrap()
                .value,
            "binary /tmp/example"
        );
        assert!(
            execute_workspace_request(
                WorkspaceRequest::AssistedCompletion {
                    index: 1,
                    text: "scan 127.0.0.1".into(),
                },
                &hub,
                &path,
            )
            .await
            .is_err()
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn built_in_assisted_step_runs_local_work_with_separate_provenance() {
        let path = std::env::temp_dir().join(format!(
            "spectre-assisted-command-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Config::default().save(&path).unwrap();
        let hub = EventHub::new(100);
        let output = execute_workspace_request(
            WorkspaceRequest::AssistedStep {
                scenario_id: "local-research".into(),
                index: 1,
                text: "doctor".into(),
            },
            &hub,
            &path,
        )
        .await
        .unwrap();
        assert_eq!(output[0].kind, "prepared.input");
        assert_eq!(output[0].source, SourceKind::Prepared);
        assert!(output.iter().any(|event| event.kind == "command.doctor"));
        let action = output
            .iter()
            .find(|event| event.kind == "assisted.action")
            .unwrap();
        let prepared_id = action
            .evidence
            .iter()
            .find(|item| item.label == "prepared_event_id")
            .map(|item| item.value.as_str())
            .unwrap();
        let result_ids = action
            .evidence
            .iter()
            .find(|item| item.label == "result_event_ids")
            .map(|item| item.value.as_str())
            .unwrap();
        let referenced = std::iter::once(prepared_id)
            .chain(result_ids.split(',').filter(|id| !id.is_empty()))
            .collect::<Vec<_>>();
        assert_eq!(referenced.len(), 2);
        assert!(referenced.iter().all(|id| {
            output
                .iter()
                .any(|event| event.id == *id && event.kind != "assisted.action")
        }));
        assert_eq!(output.last().unwrap().kind, "assisted.step.complete");
        let rejected = execute_workspace_request(
            WorkspaceRequest::AssistedStep {
                scenario_id: "local-research".into(),
                index: 1,
                text: "scan 127.0.0.1 22".into(),
            },
            &hub,
            &path,
        )
        .await
        .unwrap();
        assert_eq!(rejected[0].kind, "assisted.step.error");
        let rejected = execute_workspace_request(
            WorkspaceRequest::AssistedRun {
                scenario_id: "local-research".into(),
                index: 1,
                text: "doctor".into(),
            },
            &hub,
            &path,
        )
        .await
        .unwrap();
        assert_eq!(rejected[0].kind, "assisted.run.error");
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn network_assisted_reveal_does_not_start_a_scan() {
        let path = std::env::temp_dir().join(format!(
            "spectre-assisted-network-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut config = Config {
            allowed_targets: vec!["127.0.0.1".into()],
            ..Config::default()
        };
        config.save(&path).unwrap();
        let hub = EventHub::new(100);
        let scenario = assisted::scenarios(&config)
            .into_iter()
            .find(|scenario| scenario.id == "scoped-network:127.0.0.1")
            .unwrap();
        let step = scenario.steps[1].input.clone();
        let output = execute_workspace_request(
            WorkspaceRequest::AssistedStep {
                scenario_id: scenario.id.clone(),
                index: 2,
                text: step.clone(),
            },
            &hub,
            &path,
        )
        .await
        .unwrap();
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].source, SourceKind::Prepared);
        assert_eq!(output[1].kind, "assisted.step.complete");
        assert!(hub.snapshot().iter().all(|event| event.module != "tcp"));

        let changed = execute_workspace_request(
            WorkspaceRequest::AssistedRun {
                scenario_id: scenario.id.clone(),
                index: 2,
                text: "scan 192.0.2.1 22".into(),
            },
            &hub,
            &path,
        )
        .await
        .unwrap();
        assert_eq!(changed[0].kind, "assisted.run.error");
        assert!(hub.snapshot().iter().all(|event| event.module != "tcp"));

        config.allowed_targets.clear();
        config.save(&path).unwrap();
        let denied = execute_workspace_request(
            WorkspaceRequest::AssistedRun {
                scenario_id: scenario.id,
                index: 2,
                text: step,
            },
            &hub,
            &path,
        )
        .await
        .unwrap();
        assert_eq!(denied[0].kind, "assisted.run.error");
        assert!(hub.snapshot().iter().all(|event| event.module != "tcp"));
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn full_local_assisted_session_runs_all_stages_with_one_request() {
        let path = std::env::temp_dir().join(format!(
            "spectre-assisted-full-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Config::default().save(&path).unwrap();
        let hub = EventHub::new(2_000);
        let output = execute_workspace_request(
            WorkspaceRequest::AssistedRunSession {
                scenario_id: "local-research".into(),
            },
            &hub,
            &path,
        )
        .await
        .unwrap();
        assert_eq!(output[0].kind, "assisted.session.start");
        assert_eq!(
            output
                .iter()
                .filter(|event| event.kind == "assisted.session.stage")
                .count(),
            7
        );
        assert_eq!(output.last().unwrap().kind, "assisted.session.complete");
        assert!(output.iter().any(|event| event.kind == "command.doctor"));
        assert!(
            output
                .iter()
                .any(|event| event.kind == "investigation.triage")
        );
        let binary_stage = output
            .iter()
            .find(|event| {
                event.kind == "assisted.session.stage"
                    && event
                        .evidence
                        .iter()
                        .any(|item| item.label == "step_index" && item.value == "5")
            })
            .unwrap();
        assert!(binary_stage.evidence.iter().any(|item| {
            item.label == "status" && matches!(item.value.as_str(), "complete" | "error")
        }));
        let complete = output.last().unwrap();
        let succeeded: usize = complete
            .evidence
            .iter()
            .find(|item| item.label == "succeeded")
            .unwrap()
            .value
            .parse()
            .unwrap();
        let failed: usize = complete
            .evidence
            .iter()
            .find(|item| item.label == "failed")
            .unwrap()
            .value
            .parse()
            .unwrap();
        assert_eq!(succeeded + failed, 7);
        assert!(output.iter().all(|event| event.kind != "prepared.input"));
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn process_assisted_session_inspects_live_processes_with_one_request() {
        let path = std::env::temp_dir().join(format!(
            "spectre-process-session-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Config::default().save(&path).unwrap();
        let hub = EventHub::new(2_000);
        let output = execute_workspace_request(
            WorkspaceRequest::AssistedRunSession {
                scenario_id: "process-investigation".into(),
            },
            &hub,
            &path,
        )
        .await
        .unwrap();
        assert!(
            output
                .iter()
                .any(|event| event.kind == "process.top_summary")
        );
        assert!(output.iter().any(|event| event.kind == "process.inspect"));
        assert_eq!(
            output
                .iter()
                .filter(|event| event.kind == "assisted.session.stage")
                .count(),
            3
        );
        assert_eq!(output.last().unwrap().kind, "assisted.session.complete");
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn full_default_session_respects_lan_toggle_and_runs_other_domains() {
        let path = std::env::temp_dir().join(format!(
            "spectre-system-session-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config = Config {
            lan_assessment_enabled: false,
            ..Config::default()
        };
        config.save(&path).unwrap();
        let hub = EventHub::new(2_000);
        let output = execute_workspace_request(
            WorkspaceRequest::AssistedRunSession {
                scenario_id: "system-network".into(),
            },
            &hub,
            &path,
        )
        .await
        .unwrap();
        assert_eq!(
            output
                .iter()
                .filter(|event| event.kind == "assisted.session.stage")
                .count(),
            8
        );
        assert!(output.iter().any(|event| event.kind == "process.inspect"));
        assert!(output.iter().any(|event| event.kind == "traffic.snapshot"));
        assert!(output.iter().all(|event| event.module != "lan"));
        assert_eq!(output.last().unwrap().kind, "assisted.session.complete");
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn live_follow_up_refreshes_local_evidence_and_respects_lan_off() {
        let path = std::env::temp_dir().join(format!(
            "spectre-live-pulse-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Config {
            lan_assessment_enabled: false,
            ..Config::default()
        }
        .save(&path)
        .unwrap();
        let hub = EventHub::new(2_000);
        let output = execute_workspace_request(
            WorkspaceRequest::AssistedLivePulse {
                cycle: 1,
                include_lan: true,
            },
            &hub,
            &path,
        )
        .await
        .unwrap();
        assert!(output.iter().any(|event| event.kind == "traffic.snapshot"));
        assert!(
            output
                .iter()
                .any(|event| event.kind == "process.top_summary")
        );
        assert!(
            output
                .iter()
                .any(|event| event.kind == "investigation.triage")
        );
        assert!(output.iter().all(|event| event.module != "lan"));
        let complete = output.last().unwrap();
        assert_eq!(complete.kind, "assisted.watch.complete");
        assert!(
            complete
                .evidence
                .iter()
                .any(|item| { item.label == "lan_enabled" && item.value == "false" })
        );
        assert!(
            complete
                .evidence
                .iter()
                .any(|item| { item.label == "failed" && item.value == "0" })
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn triage_counts_only_retained_observations() {
        let events = vec![
            Event::new(
                "host",
                "host.sample",
                "sample",
                None,
                Severity::Info,
                SourceKind::Live,
            ),
            Event::new(
                "binary",
                "binary.format",
                "Mach-O",
                Some("/bin/ls".into()),
                Severity::Info,
                SourceKind::File,
            ),
            Event::new(
                "presentation",
                "prepared.input",
                "typed",
                None,
                Severity::Info,
                SourceKind::Prepared,
            ),
        ];
        let summary = triage_snapshot(&events);
        assert_eq!(summary.source, SourceKind::Derived);
        assert!(summary.summary.contains("2 observations across 2 modules"));
        assert!(
            summary
                .evidence
                .iter()
                .any(|item| { item.label == "recent_subjects" && item.value == "/bin/ls" })
        );
    }

    #[test]
    fn lan_report_uses_survey_totals_and_labels_retained_details() {
        let host = Event::new(
            "lan",
            "lan.host",
            "host answered",
            Some("192.168.1.2".into()),
            Severity::Info,
            SourceKind::Live,
        );
        let endpoint = Event::new(
            "lan",
            "lan.tcp_open",
            "open endpoint",
            Some("192.168.1.2".into()),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("endpoint", "192.168.1.2:80", "tcp_connect");
        let completed = Event::new(
            "lan",
            "lan.survey_complete",
            "survey complete",
            Some("192.168.1.0/24".into()),
            Severity::Info,
            SourceKind::Live,
        )
        .with_evidence("responded_hosts", "3", "tcp_connect")
        .with_evidence("open_endpoints", "4", "tcp_connect");
        let report = lan_report(&[host, endpoint, completed.clone()], Some(&completed.id)).unwrap();
        assert_eq!(report.kind, "lan.report");
        assert!(report.summary.contains("3 responsive hosts, 4 open"));
        assert!(
            report
                .evidence
                .iter()
                .any(|item| { item.label == "survey_event_id" && item.value == completed.id })
        );
        assert!(
            report.evidence.iter().any(|item| {
                item.label == "endpoints_first_32" && item.value == "192.168.1.2:80"
            })
        );
        let stale = lan_report(&[completed], Some("later-survey-id")).unwrap_err();
        assert!(stale.to_string().contains("no longer retained"));
    }

    #[tokio::test]
    async fn lan_toggle_controls_survey_without_network_traffic() {
        let path = std::env::temp_dir().join(format!(
            "spectre-lan-toggle-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Config::default().save(&path).unwrap();
        let hub = EventHub::new(100);
        let off = execute_line("lan off", &hub, &path).await.unwrap();
        assert_eq!(off[0].kind, "config.lan_assessment");
        assert!(!Config::load(&path).unwrap().lan_assessment_enabled);
        let disabled = execute_line("lan survey", &hub, &path).await.unwrap_err();
        assert!(disabled.to_string().contains("off"));
        assert!(hub.snapshot().iter().all(|event| event.module != "lan"));
        execute_line("lan on", &hub, &path).await.unwrap();
        assert!(Config::load(&path).unwrap().lan_assessment_enabled);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn workflow_and_retention_commands_validate_and_save() {
        let path = std::env::temp_dir().join(format!(
            "spectre-workflow-command-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let hub = EventHub::new(100);
        execute_line("workflow add 'binary /bin/ls'", &hub, &path)
            .await
            .unwrap();
        execute_line("workflow add 'pcap /tmp/capture.pcap'", &hub, &path)
            .await
            .unwrap();
        let listed = execute_line("workflow list", &hub, &path).await.unwrap();
        assert_eq!(listed[0].kind, "workflow.list");
        assert!(
            listed[0]
                .evidence
                .iter()
                .any(|item| item.value.contains("1. binary /bin/ls"))
        );
        assert!(
            execute_line("workflow remove 0", &hub, &path)
                .await
                .is_err()
        );
        execute_line("workflow remove 1", &hub, &path)
            .await
            .unwrap();
        assert_eq!(
            Config::load(&path).unwrap().prepared_workflow,
            vec!["pcap /tmp/capture.pcap"]
        );
        assert!(execute_line("retention set 99", &hub, &path).await.is_err());
        execute_line("retention set 500", &hub, &path)
            .await
            .unwrap();
        assert_eq!(Config::load(&path).unwrap().retention_events, 500);
        execute_line("workflow clear", &hub, &path).await.unwrap();
        assert!(Config::load(&path).unwrap().prepared_workflow.is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_http_follow_up_retains_attempted_endpoint() {
        let endpoint: SocketAddr = "192.0.2.10:443".parse().unwrap();
        let event = follow_up_error(
            "example.org",
            "https://example.org:443/",
            endpoint,
            &anyhow::anyhow!("TLS handshake failed"),
        );
        assert_eq!(event.subject.as_deref(), Some("example.org"));
        assert_eq!(event.kind, "follow_up.error");
        assert!(event.evidence.iter().any(|item| {
            item.label == "resolved_endpoint" && item.value == endpoint.to_string()
        }));
    }
}
