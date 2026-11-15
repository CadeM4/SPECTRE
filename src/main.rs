use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use spectre::{
    capability, command,
    config::Config,
    engine::EventHub,
    model::{Event, Severity, SourceKind},
    tui,
};
use std::{io::IsTerminal, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "spectre",
    version,
    about = "Terminal intelligence and security research environment",
    author = "Cade Masterson"
)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true, help = "Emit complete events or report as JSON")]
    json: bool,
    #[command(subcommand)]
    command: Option<Action>,
}

#[derive(Subcommand)]
enum Action {
    /// Launch the terminal workspace
    Launch,
    /// Inspect platform and optional tooling
    Doctor,
    /// Show version and project attribution
    Version,
    /// Inspect a binary or packet capture
    Analyze {
        #[command(subcommand)]
        target: AnalyzeTarget,
    },
    /// Connect to bounded TCP ports on a scoped target
    Scan {
        target: String,
        #[arg(long)]
        ports: Option<String>,
    },
    /// Run a scoped TCP assessment with HTTP follow-up on observed web ports
    Investigate {
        target: String,
        #[arg(long)]
        ports: Option<String>,
    },
    /// Inspect response security properties on a scoped URL
    Http { url: String },
    /// Inspect live processes without changing them
    Process {
        #[command(subcommand)]
        action: ProcessAction,
    },
    /// Read current network interface counters without capturing packets
    Traffic {
        #[command(subcommand)]
        action: TrafficAction,
    },
    /// Inspect or survey the active private IPv4 network
    Lan {
        #[command(subcommand)]
        action: LanAction,
    },
    /// Manage exact-match authorized targets
    Scope {
        #[command(subcommand)]
        action: ScopeAction,
    },
    /// List or select an operating profile
    Profiles { name: Option<String> },
    /// List or select a terminal theme
    Themes { name: Option<String> },
    /// List or change autonomous modules
    Modules {
        #[command(subcommand)]
        action: Option<ModuleAction>,
    },
    /// Manage exact-match local detection indicators
    Indicators {
        #[command(subcommand)]
        action: Option<IndicatorAction>,
    },
    /// Show or create the configuration file
    Configure {
        #[arg(long)]
        init: bool,
    },
}

#[derive(Subcommand)]
enum AnalyzeTarget {
    Binary { path: PathBuf },
    Pcap { path: PathBuf },
}

#[derive(Subcommand)]
enum ScopeAction {
    Add { target: String },
    Remove { target: String },
    List,
}

#[derive(Subcommand)]
enum LanAction {
    /// Show the active interface and exact survey segment without sending packets
    Status,
    /// Enable local-network assisted assessment
    On,
    /// Disable local-network assisted assessment
    Off,
    /// Probe the active private IPv4 segment for TCP responses and open services
    Survey,
}

#[derive(Subcommand)]
enum ProcessAction {
    /// Show processes using the most resident memory
    Top {
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// Inspect a numeric PID or the current SPECTRE process
    Inspect { pid: String },
}

#[derive(Subcommand)]
enum TrafficAction {
    /// Show current per-interface byte counters
    Snapshot,
}

#[derive(Subcommand)]
enum ModuleAction {
    Enable { name: String },
    Disable { name: String },
}

#[derive(Subcommand)]
enum IndicatorAction {
    Add {
        kind: String,
        value: String,
        label: Option<String>,
    },
    Remove {
        kind: String,
        value: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cli {
        config,
        json,
        command,
    } = Cli::parse();
    let config_path = config.unwrap_or_else(Config::path);
    match command.unwrap_or(Action::Launch) {
        Action::Version => {
            println!("SPECTRE {}", env!("CARGO_PKG_VERSION"));
            println!("Created by Cade Masterson");
        }
        Action::Doctor => {
            let report = capability::inspect();
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("SPECTRE  {} / {}", report.os, report.arch);
                println!(
                    "Terminal: {}",
                    if report.terminal {
                        "available"
                    } else {
                        "not attached"
                    }
                );
                println!("Recommended profile: {}", report.recommended_profile);
                for module in report.modules {
                    println!("  {:<12} {}", module.name, module.detail);
                }
                for tool in report.tools {
                    println!(
                        "  {:<12} {}",
                        tool.name,
                        tool.path
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "not found".into())
                    );
                }
            }
        }
        Action::Configure { init } => {
            let config = Config::load_or_default(&config_path)?;
            if init || !config_path.exists() {
                config.save(&config_path)?;
            }
            println!("{}", config_path.display());
            println!("{}", toml::to_string_pretty(&config)?);
        }
        Action::Launch => {
            if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
                bail!(
                    "launch needs an interactive terminal; use `spectre doctor` or a headless analysis command here"
                );
            }
            let config = Config::load_or_default(&config_path)?;
            if !config_path.exists() {
                config.save(&config_path)?;
            }
            let hub = EventHub::new(config.retention_events);
            hub.set_correlation_enabled(
                config
                    .enabled_modules
                    .iter()
                    .any(|module| module == "correlation"),
            );
            hub.set_indicators(config.indicators.clone());
            let (config_tx, config_rx) = tokio::sync::watch::channel(config.clone());
            let event_rx = hub.subscribe();
            let autonomous = spectre::engine::spawn_autonomous(hub.clone(), config_rx);
            let (command_tx, mut command_rx) =
                tokio::sync::mpsc::channel::<command::WorkspaceRequest>(64);
            let worker_hub = hub.clone();
            let worker_path = config_path.clone();
            let worker = tokio::spawn(async move {
                while let Some(request) = command_rx.recv().await {
                    if let Err(error) =
                        command::execute_workspace_request(request, &worker_hub, &worker_path).await
                    {
                        worker_hub.publish(Event::new(
                            "command",
                            "command.error",
                            error.to_string(),
                            None,
                            Severity::Low,
                            SourceKind::Live,
                        ));
                    }
                    if let Ok(next) = Config::load_or_default(&worker_path) {
                        worker_hub.set_correlation_enabled(
                            next.enabled_modules
                                .iter()
                                .any(|module| module == "correlation"),
                        );
                        worker_hub.set_indicators(next.indicators.clone());
                        config_tx.send_replace(next);
                    }
                }
            });
            let result = tui::run_tui(config, config_path, event_rx, command_tx);
            autonomous.abort();
            worker.abort();
            result?;
        }
        action => {
            let line = match action {
                Action::Analyze {
                    target: AnalyzeTarget::Binary { path },
                } => format!("binary {}", quote(path.to_string_lossy().as_ref())),
                Action::Analyze {
                    target: AnalyzeTarget::Pcap { path },
                } => format!("pcap {}", quote(path.to_string_lossy().as_ref())),
                Action::Scan { target, ports } => format!(
                    "scan {} {}",
                    quote(&target),
                    ports.unwrap_or_else(|| {
                        "21,22,25,53,80,110,143,443,445,3389,5432,6379,8080,8443".into()
                    })
                ),
                Action::Investigate { target, ports } => format!(
                    "investigate {} {}",
                    quote(&target),
                    ports.unwrap_or_else(|| "22,80,443,8080,8443".into())
                ),
                Action::Http { url } => format!("http {}", quote(&url)),
                Action::Process { action } => match action {
                    ProcessAction::Top { limit } => format!("process top {limit}"),
                    ProcessAction::Inspect { pid } => format!("process inspect {}", quote(&pid)),
                },
                Action::Traffic {
                    action: TrafficAction::Snapshot,
                } => "traffic snapshot".into(),
                Action::Lan { action } => match action {
                    LanAction::Status => "lan status".into(),
                    LanAction::On => "lan on".into(),
                    LanAction::Off => "lan off".into(),
                    LanAction::Survey => "lan survey".into(),
                },
                Action::Scope {
                    action: ScopeAction::Add { target },
                } => format!("scope add {}", quote(&target)),
                Action::Scope {
                    action: ScopeAction::Remove { target },
                } => format!("scope remove {}", quote(&target)),
                Action::Scope {
                    action: ScopeAction::List,
                } => "scope list".into(),
                Action::Profiles { name } => {
                    format!("profile {}", name.unwrap_or_else(|| "list".into()))
                }
                Action::Themes { name } => {
                    format!("theme {}", name.unwrap_or_else(|| "list".into()))
                }
                Action::Modules { action: None } => "module list".into(),
                Action::Modules {
                    action: Some(ModuleAction::Enable { name }),
                } => format!("module enable {}", quote(&name)),
                Action::Modules {
                    action: Some(ModuleAction::Disable { name }),
                } => format!("module disable {}", quote(&name)),
                Action::Indicators { action: None } => "indicator list".into(),
                Action::Indicators {
                    action: Some(IndicatorAction::Add { kind, value, label }),
                } => {
                    let base = format!("indicator add {} {}", quote(&kind), quote(&value));
                    if let Some(label) = label {
                        format!("{base} {}", quote(&label))
                    } else {
                        base
                    }
                }
                Action::Indicators {
                    action: Some(IndicatorAction::Remove { kind, value }),
                } => {
                    format!("indicator remove {} {}", quote(&kind), quote(&value))
                }
                _ => unreachable!(),
            };
            let hub = EventHub::new(2_000);
            command::execute_line(&line, &hub, &config_path)
                .await
                .context("analysis failed")?;
            for event in hub.snapshot() {
                if json {
                    println!("{}", serde_json::to_string(&event)?);
                } else {
                    print_human_event(&event);
                }
            }
        }
    }
    Ok(())
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn print_human_event(event: &Event) {
    println!(
        "{}Z  {:<12} {:<22} {}",
        event.timestamp.format("%Y-%m-%d %H:%M:%S"),
        event.module,
        event.kind,
        event.summary
    );
    for evidence in &event.evidence {
        let lines = evidence.value.lines().collect::<Vec<_>>();
        if lines.len() > 1 {
            println!("    {} [{}]:", evidence.label, evidence.origin);
            for line in lines.iter().take(5) {
                println!("      {}", shorten(line, 180));
            }
            if lines.len() > 5 {
                println!(
                    "      … {} more lines; use --json for complete evidence",
                    lines.len() - 5
                );
            }
        } else {
            println!(
                "    {}: {} [{}]",
                evidence.label,
                shorten(&evidence.value, 180),
                evidence.origin
            );
        }
    }
}

fn shorten(value: &str, limit: usize) -> String {
    let mut chars = value.chars();
    let prefix = chars.by_ref().take(limit).collect::<String>();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}
