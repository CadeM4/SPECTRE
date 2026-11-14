use std::{collections::HashSet, net::IpAddr};

use crate::config::{Config, normalize_target};

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
/// beyond resolving the current executable path.
pub fn scenarios(config: &Config) -> Vec<Scenario> {
    let mut available = vec![local_research()];
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

fn local_research() -> Scenario {
    let executable = std::env::current_exe()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/bin/ls".to_owned());

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
                "Initial triage",
                "Summarize the observations collected so far.",
                "triage",
                Execution::Local,
            ),
            step(
                "Binary inspection",
                "Inspect the real executable running this SPECTRE session.",
                format!("binary {}", quote_argument(&executable)),
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
    use super::{Execution, scenarios};
    use crate::{command::tokenize, config::Config};

    #[test]
    fn local_research_is_ready_without_configuration() {
        let available = scenarios(&Config::default());
        assert_eq!(available.len(), 1);
        let local = &available[0];
        assert_eq!(local.id, "local-research");
        assert_eq!(local.steps.len(), 6);
        assert!(
            local
                .steps
                .iter()
                .all(|step| step.execution == Execution::Local)
        );
        assert_eq!(local.steps[0].input, "doctor");
        let binary = tokenize(&local.steps[3].input).unwrap();
        assert_eq!(binary[0], "binary");
        assert_eq!(
            binary[1],
            std::env::current_exe().unwrap().to_string_lossy()
        );
    }

    #[test]
    fn custom_sequence_is_presentation_only() {
        let config = Config {
            prepared_workflow: vec!["first".into(), "scan example.org 443".into()],
            ..Config::default()
        };
        let available = scenarios(&config);
        assert_eq!(available.len(), 2);
        assert_eq!(available[1].id, "custom");
        assert!(
            available[1]
                .steps
                .iter()
                .all(|step| step.execution == Execution::PresentationOnly)
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
                "local-research",
                "scoped-network:example.org",
                "scoped-network:127.0.0.1",
                "scoped-network:::1",
                "custom",
            ]
        );
        assert_eq!(
            available[3].steps[1].input,
            "scan \"::1\" 22,80,443,8080,8443"
        );
        assert_eq!(available[3].steps[3].input, "indicator list");
    }
}
