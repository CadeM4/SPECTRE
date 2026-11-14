use crate::config::Config;
use serde::Serialize;
use std::{env, io::IsTerminal, path::PathBuf};

#[derive(Debug, Serialize)]
pub struct CapabilityReport {
    pub os: String,
    pub arch: String,
    pub terminal: bool,
    pub recommended_profile: String,
    pub tools: Vec<ToolCapability>,
    pub modules: Vec<ModuleCapability>,
}

#[derive(Debug, Serialize)]
pub struct ToolCapability {
    pub name: String,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct ModuleCapability {
    pub name: String,
    pub available: bool,
    pub detail: String,
}

pub fn inspect() -> CapabilityReport {
    let tools = [
        "tshark",
        "tcpdump",
        "nmap",
        "ghidraRun",
        "gdb",
        "lldb",
        "frida",
    ]
    .into_iter()
    .map(|name| ToolCapability {
        name: name.into(),
        path: find_tool(name),
    })
    .collect();
    CapabilityReport {
        os: env::consts::OS.into(),
        arch: env::consts::ARCH.into(),
        terminal: std::io::stdout().is_terminal(),
        recommended_profile: Config::recommended().profile,
        tools,
        modules: vec![
            ModuleCapability {
                name: "host".into(),
                available: true,
                detail: "local CPU and memory observations".into(),
            },
            ModuleCapability {
                name: "process".into(),
                available: true,
                detail: "local process inventory and changes; OS access rules apply".into(),
            },
            ModuleCapability {
                name: "binary".into(),
                available: true,
                detail: "offline PE, ELF, and Mach-O inspection".into(),
            },
            ModuleCapability {
                name: "pcap".into(),
                available: true,
                detail: "offline classic PCAP inspection".into(),
            },
            ModuleCapability {
                name: "tcp".into(),
                available: true,
                detail: "explicitly scoped TCP connect assessment".into(),
            },
            ModuleCapability {
                name: "http".into(),
                available: true,
                detail: "explicitly scoped HTTP response assessment".into(),
            },
        ],
    }
}

fn find_tool(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    let candidates: Vec<String> = if cfg!(windows) {
        vec![name.into(), format!("{name}.exe"), format!("{name}.cmd")]
    } else {
        vec![name.into()]
    };
    for directory in env::split_paths(&path) {
        for candidate in &candidates {
            let entry = directory.join(candidate);
            if entry.is_file() {
                return Some(entry);
            }
        }
    }
    None
}
