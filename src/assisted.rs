use std::{
    collections::HashSet,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

use crate::{
    analysis::binary::MAX_BINARY_BYTES,
    config::{Config, normalize_target},
    network::lan,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scenario {
    pub id: String,
    pub title: String,
    pub summary: String,
    pub steps: Vec<ScenarioStep>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioStep {
    pub phase: String,
    pub context: String,
    pub input: String,
    pub execution: Execution,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Execution {
    /// A local, read-only operation that can use the existing command worker.
    Local,
    /// An operation that needs a separate, explicit run action and scope check.
    Explicit,
    /// Prepared text only. Revealing this text must never run it.
    PresentationOnly,
}

/// Built-in sessions are available even when no prepared text has been configured.
/// The scenarios describe actions; constructing them performs no analysis or I/O
/// beyond resolving the current executable and checking candidate file sizes.
pub fn scenarios(config: &Config) -> Vec<Scenario> {
    let mut available = vec![system_network(config), local_research()];
    if config.lan_assessment_enabled {
        available.push(local_network());
    }
    available.push(process_investigation());
    let mut seen_targets = HashSet::new();
    for configured in &config.allowed_targets {
        if let Ok(target) = normalize_target(configured)
            && seen_targets.insert(target.clone())
        {
            available.push(scoped_network(&target));
        }
    }

    if !config.prepared_workflow.is_empty() {
        available.push(custom(&config.prepared_workflow));
    }

    available
}

fn system_network(config: &Config) -> Scenario {
    let local = local_research();
    let process = process_investigation();
    let (executable, _) = choose_binary_path(std::env::current_exe().ok(), platform_executable());
    let mut steps = vec![
        local.steps[0].clone(),
        local.steps[1].clone(),
        local.steps[2].clone(),
        step(
            "Live packet window",
            "Capture real packets from the current interface and decode flows, DNS, HTTP hosts, and TLS names.",
            "capture live auto 4 256 1536 \"ip or ip6\"",
            Execution::Explicit,
        ),
        process.steps[0].clone(),
        process.steps[1].clone(),
        step(
            "Process resources",
            "Inspect SPECTRE's open files, descriptors, and sockets while this session is running.",
            "runtime resources self",
            Execution::Local,
        ),
        step(
            "Call-stack sample",
            "Sample the running SPECTRE process and identify active stack frames.",
            "runtime sample self 1",
            Execution::Local,
        ),
        local.steps[4].clone(),
        step(
            "Disassembly",
            "Decode instructions from an executable section of the inspected binary.",
            format!(
                "disasm {} 96",
                quote_argument(&executable.to_string_lossy())
            ),
            Execution::Local,
        ),
        step(
            "Threat intelligence",
            "Enrich observed hashes and, when API keys are set, public network peers using external providers.",
            "intel enrich recent",
            Execution::Explicit,
        ),
        local.steps[5].clone(),
    ];
    let summary = if config.lan_assessment_enabled {
        let network = local_network();
        let network_summary = network.summary.clone();
        steps[0].context = format!("Check platform capabilities. {network_summary}");
        steps.extend(network.steps.into_iter().take(3));
        format!(
            "Run live packets, processes, call stacks, disassembly, intelligence, and network analysis. {network_summary}"
        )
    } else {
        "Run live packets, processes, call stacks, disassembly, and intelligence; LAN assessment is off."
            .to_owned()
    };
    steps.push(step(
        "Final triage",
        "Review the actual observations from the complete session.",
        "triage",
        Execution::Local,
    ));
    Scenario {
        id: "system-network".to_owned(),
        title: "System and network".to_owned(),
        summary,
        steps,
    }
}

fn local_network() -> Scenario {
    let detected = lan::detect_lan().ok();
    let (summary, survey_input, survey_context) = match detected {
        Some(scope) => (
            format!(
                "Survey the real {} segment on {} ({}).",
                scope.cidr, scope.interface, scope.local_ip
            ),
            format!("lan survey {}", quote_argument(&scope.cidr)),
            format!(
                "Probe the currently detected {} segment for TCP responses and open services.",
                scope.cidr
            ),
        ),
        None => (
            "Detect the active private IPv4 segment, then survey it when available.".to_owned(),
            "lan survey".to_owned(),
            "Probe the current private IPv4 segment when one is available.".to_owned(),
        ),
    };
    Scenario {
        id: "local-network".to_owned(),
        title: "Local network".to_owned(),
        summary,
        steps: vec![
            step(
                "Network context",
                "Identify the active interface and exact IPv4 segment.",
                "lan status",
                Execution::Local,
            ),
            step(
                "Host and service survey",
                survey_context,
                survey_input,
                Execution::Explicit,
            ),
            step(
                "Survey review",
                "Summarize retained hosts and open endpoints from the latest survey.",
                "lan report",
                Execution::Local,
            ),
            step(
                "Final triage",
                "Review all retained local and network observations together.",
                "triage",
                Execution::Local,
            ),
        ],
    }
}

fn process_investigation() -> Scenario {
    Scenario {
        id: "process-investigation".to_owned(),
        title: "Process investigation".to_owned(),
        summary: "Inspect the live process inventory and the current SPECTRE process.".to_owned(),
        steps: vec![
            step(
                "Process inventory",
                "Review the processes using the most resident memory now.",
                "process top",
                Execution::Local,
            ),
            step(
                "Process detail",
                "Inspect SPECTRE's live process identity, executable, parent, and memory.",
                "process inspect self",
                Execution::Local,
            ),
            step(
                "Evidence review",
                "Summarize the retained process and other observations.",
                "triage",
                Execution::Local,
            ),
        ],
    }
}

fn local_research() -> Scenario {
    let (executable, current_process) =
        choose_binary_path(std::env::current_exe().ok(), platform_executable());
    let binary_context = if current_process {
        format!(
            "Inspect the SPECTRE executable running this session: {}.",
            executable.display()
        )
    } else {
        format!(
            "Inspect a local platform executable: {}.",
            executable.display()
        )
    };

    Scenario {
        id: "local-research".to_owned(),
        title: "Local research".to_owned(),
        summary:
            "Follow live host and process observations into a local binary and evidence review."
                .to_owned(),
        steps: vec![
            step(
                "Environment",
                "Check the platform and built-in analysis capabilities.",
                "doctor",
                Execution::Local,
            ),
            step(
                "Collection",
                "Review the modules collecting local observations.",
                "module list",
                Execution::Local,
            ),
            step(
                "Interface traffic",
                "Read the current real counters from active network interfaces.",
                "traffic snapshot",
                Execution::Local,
            ),
            step(
                "Initial triage",
                "Summarize the observations collected so far.",
                "triage",
                Execution::Local,
            ),
            step(
                "Binary inspection",
                binary_context,
                format!("binary {}", quote_argument(&executable.to_string_lossy())),
                Execution::Local,
            ),
            step(
                "Indicators",
                "Review any exact-match indicators configured for this session.",
                "indicator list",
                Execution::Local,
            ),
            step(
                "Final review",
                "Revisit the event summary after the binary inspection.",
                "triage",
                Execution::Local,
            ),
        ],
    }
}

fn fits_binary_budget(path: &Path) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= MAX_BINARY_BYTES)
}

fn choose_binary_path(current: Option<PathBuf>, fallback: Option<PathBuf>) -> (PathBuf, bool) {
    match current {
        Some(path) if fits_binary_budget(&path) => (path, true),
        Some(path) => match fallback.filter(|candidate| fits_binary_budget(candidate)) {
            Some(candidate) => (candidate, false),
            None => (path, true),
        },
        None => (fallback.unwrap_or_else(|| PathBuf::from("spectre")), false),
    }
}

#[cfg(unix)]
fn platform_executable() -> Option<PathBuf> {
    Some(PathBuf::from("/bin/ls"))
}

#[cfg(windows)]
fn platform_executable() -> Option<PathBuf> {
    std::env::var_os("SystemRoot").map(|root| PathBuf::from(root).join("System32").join("cmd.exe"))
}

#[cfg(not(any(unix, windows)))]
fn platform_executable() -> Option<PathBuf> {
    None
}

fn scoped_network(target: &str) -> Scenario {
    let quoted_target = quote_argument(target);
    let web_step = if target.parse::<IpAddr>().is_ok() {
        step(
            "Indicators",
            "Review exact-match indicators alongside the scoped network results.",
            "indicator list",
            Execution::Local,
        )
    } else {
        step(
            "HTTP response",
            "Inspect one HTTPS response from the configured hostname.",
            format!("http {}", quote_argument(&format!("https://{target}/"))),
            Execution::Explicit,
        )
    };

    Scenario {
        id: format!("scoped-network:{target}"),
        title: "Scoped network review".to_owned(),
        summary: format!(
            "Inspect only the configured target {target} and review the resulting evidence."
        ),
        steps: vec![
            step(
                "Scope",
                "Confirm the exact target configured for active assessment.",
                "scope list",
                Execution::Local,
            ),
            step(
                "Port check",
                "Check a bounded set of common service ports on this target.",
                format!("scan {quoted_target} 22,80,443,8080,8443"),
                Execution::Explicit,
            ),
            step(
                "Investigation",
                "Follow observed web ports with response inspection.",
                format!("investigate {quoted_target} 22,80,443,8080,8443"),
                Execution::Explicit,
            ),
            web_step,
            step(
                "Review",
                "Summarize the actual observations from this session.",
                "triage",
                Execution::Local,
            ),
        ],
    }
}

fn custom(inputs: &[String]) -> Scenario {
    Scenario {
        id: "custom".to_owned(),
        title: "Custom prepared sequence".to_owned(),
        summary: "Present your saved sequence without running its text.".to_owned(),
        steps: inputs
            .iter()
            .enumerate()
            .map(|(index, input)| {
                step(
                    format!("Prepared step {}", index + 1),
                    "Reveal the saved text; this step does not execute it.",
                    input.clone(),
                    Execution::PresentationOnly,
                )
            })
            .collect(),
    }
}

fn step(
    phase: impl Into<String>,
    context: impl Into<String>,
    input: impl Into<String>,
    execution: Execution,
) -> ScenarioStep {
    ScenarioStep {
        phase: phase.into(),
        context: context.into(),
        input: input.into(),
        execution,
    }
}

fn quote_argument(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::{
        Execution, choose_binary_path, fits_binary_budget, platform_executable, scenarios,
    };
    use crate::analysis::binary::MAX_BINARY_BYTES;
    use crate::{command::tokenize, config::Config};
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn local_research_is_ready_without_configuration() {
        let available = scenarios(&Config::default());
        assert_eq!(available.len(), 4);
        let local = &available[1];
        assert_eq!(local.id, "local-research");
        assert_eq!(local.steps.len(), 7);
        assert!(
            local
                .steps
                .iter()
                .all(|step| step.execution == Execution::Local)
        );
        assert_eq!(local.steps[0].input, "doctor");
        assert_eq!(local.steps[2].input, "traffic snapshot");
        let binary = tokenize(&local.steps[4].input).unwrap();
        assert_eq!(binary[0], "binary");
        let selected = PathBuf::from(&binary[1]);
        let current = std::env::current_exe().unwrap();
        if fits_binary_budget(&current) {
            assert_eq!(selected, current);
            assert!(local.steps[4].context.contains("SPECTRE executable"));
        } else if let Some(fallback) = platform_executable().filter(|path| fits_binary_budget(path))
        {
            assert_eq!(selected, fallback);
            assert!(local.steps[4].context.contains("platform executable"));
        } else {
            assert_eq!(selected, current);
        }
        assert!(
            local.steps[4]
                .context
                .contains(&selected.to_string_lossy().to_string())
        );
    }

    #[test]
    fn oversized_executable_uses_small_platform_candidate() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("spectre-assisted-{}-{nonce}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let oversized = directory.join("oversized");
        let small = directory.join("small");
        fs::File::create(&oversized)
            .unwrap()
            .set_len(MAX_BINARY_BYTES + 1)
            .unwrap();
        fs::write(&small, b"local executable fixture").unwrap();

        assert_eq!(
            choose_binary_path(Some(oversized.clone()), Some(small.clone())),
            (small.clone(), false)
        );
        assert_eq!(
            choose_binary_path(Some(oversized.clone()), None),
            (oversized.clone(), true)
        );

        fs::remove_file(oversized).unwrap();
        fs::remove_file(small).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn custom_sequence_is_presentation_only() {
        let config = Config {
            prepared_workflow: vec!["first".into(), "scan example.org 443".into()],
            ..Config::default()
        };
        let available = scenarios(&config);
        assert_eq!(available.len(), 5);
        assert_eq!(available[4].id, "custom");
        assert!(
            available[4]
                .steps
                .iter()
                .all(|step| step.execution == Execution::PresentationOnly)
        );
    }

    #[test]
    fn local_network_scenario_is_ready_and_can_be_disabled() {
        let mut config = Config::default();
        let available = scenarios(&config);
        let network = available
            .iter()
            .find(|scenario| scenario.id == "local-network")
            .unwrap();
        assert_eq!(network.steps.len(), 4);
        assert_eq!(network.steps[0].input, "lan status");
        assert_eq!(network.steps[1].execution, Execution::Explicit);
        assert!(network.steps[1].input.starts_with("lan survey"));
        assert_eq!(network.steps[2].input, "lan report");
        assert_eq!(network.steps[3].input, "triage");
        config.lan_assessment_enabled = false;
        assert!(
            scenarios(&config)
                .iter()
                .all(|scenario| scenario.id != "local-network")
        );
    }

    #[test]
    fn first_scenario_runs_all_available_local_domains_in_one_session() {
        let mut config = Config::default();
        let available = scenarios(&config);
        let survey = &available[0];
        assert_eq!(survey.id, "system-network");
        assert_eq!(survey.steps.len(), 16);
        let inputs = survey
            .steps
            .iter()
            .map(|step| step.input.as_str())
            .collect::<Vec<_>>();
        assert_eq!(inputs[0], "doctor");
        assert!(inputs.contains(&"traffic snapshot"));
        assert!(inputs.contains(&"process top"));
        assert!(inputs.contains(&"process inspect self"));
        assert!(inputs.contains(&"runtime resources self"));
        assert!(inputs.contains(&"runtime sample self 1"));
        assert!(
            inputs
                .iter()
                .any(|input| input.starts_with("capture live "))
        );
        assert!(inputs.iter().any(|input| input.starts_with("binary ")));
        assert!(inputs.iter().any(|input| input.starts_with("disasm ")));
        assert!(inputs.contains(&"intel enrich recent"));
        assert!(inputs.iter().any(|input| input.starts_with("lan survey")));
        assert_eq!(inputs.last(), Some(&"triage"));

        config.lan_assessment_enabled = false;
        let disabled = scenarios(&config);
        assert_eq!(disabled[0].steps.len(), 13);
        assert!(
            disabled[0]
                .steps
                .iter()
                .all(|step| !step.input.starts_with("lan "))
        );
    }

    #[test]
    fn process_investigation_is_ready_without_configuration() {
        let available = scenarios(&Config::default());
        let process = available
            .iter()
            .find(|scenario| scenario.id == "process-investigation")
            .unwrap();
        assert_eq!(process.steps.len(), 3);
        assert_eq!(process.steps[0].input, "process top");
        assert_eq!(process.steps[1].input, "process inspect self");
        assert_eq!(process.steps[2].input, "triage");
        assert!(
            process
                .steps
                .iter()
                .all(|step| step.execution == Execution::Local)
        );
    }

    #[test]
    fn network_session_requires_a_scoped_target() {
        let mut config = Config::default();
        assert!(
            !scenarios(&config)
                .iter()
                .any(|scenario| scenario.id.starts_with("scoped-network:"))
        );

        config.allowed_targets = vec!["example.org".into()];
        let available = scenarios(&config);
        let network = available
            .iter()
            .find(|scenario| scenario.id == "scoped-network:example.org")
            .unwrap();
        assert_eq!(network.steps.len(), 5);
        assert_eq!(network.steps[0].input, "scope list");
        assert_eq!(
            network.steps[1].input,
            "scan \"example.org\" 22,80,443,8080,8443"
        );
        assert_eq!(
            network.steps[2].input,
            "investigate \"example.org\" 22,80,443,8080,8443"
        );
        assert_eq!(network.steps[1].execution, Execution::Explicit);
        assert_eq!(network.steps[2].execution, Execution::Explicit);
        assert_eq!(network.steps[3].execution, Execution::Explicit);
        assert_eq!(network.steps[3].input, "http \"https://example.org/\"");
        assert_eq!(network.steps[4].input, "triage");

        config.allowed_targets = vec!["127.0.0.1".into()];
        let available = scenarios(&config);
        let network = available
            .iter()
            .find(|scenario| scenario.id == "scoped-network:127.0.0.1")
            .unwrap();
        assert_eq!(network.steps.len(), 5);
        assert_eq!(network.steps[3].input, "indicator list");
    }

    #[test]
    fn each_normalized_target_gets_one_scenario_in_config_order() {
        let config = Config {
            allowed_targets: vec![
                "Example.ORG".into(),
                "example.org".into(),
                "127.0.0.1".into(),
                "[::1]".into(),
                "::1".into(),
            ],
            prepared_workflow: vec!["Review evidence".into()],
            ..Config::default()
        };
        let available = scenarios(&config);
        let ids = available
            .iter()
            .map(|scenario| scenario.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "system-network",
                "local-research",
                "local-network",
                "process-investigation",
                "scoped-network:example.org",
                "scoped-network:127.0.0.1",
                "scoped-network:::1",
                "custom",
            ]
        );
        assert_eq!(
            available[6].steps[1].input,
            "scan \"::1\" 22,80,443,8080,8443"
        );
        assert_eq!(available[6].steps[3].input, "indicator list");
    }
}
