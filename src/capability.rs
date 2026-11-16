use crate::{config::Config, network::lan};
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
    let lan = lan::detect_lan();
    let tools: Vec<ToolCapability> = [
        "tshark",
        "tcpdump",
        "nmap",
        "ghidraRun",
        "gdb",
        "lldb",
        "frida",
        "frida-trace",
        "objdump",
        "llvm-objdump",
        "sample",
        "lsof",
    ]
    .into_iter()
    .map(|name| ToolCapability {
        name: name.into(),
        path: find_tool(name),
    })
    .collect();
    let has_tool = |name: &str| {
        tools
            .iter()
            .any(|tool| tool.name == name && tool.path.is_some())
    };
    let live_capture = cfg!(any(target_os = "macos", target_os = "linux")) && has_tool("tcpdump");
    let disasm = has_tool("objdump") || has_tool("llvm-objdump");
    let sample = cfg!(target_os = "macos") && has_tool("sample");
    let resources = has_tool("lsof");
    let trace = cfg!(unix) && has_tool("frida-trace");
    let vt_key = key_configured("SPECTRE_VT_API_KEY");
    let abuse_key = key_configured("SPECTRE_ABUSEIPDB_API_KEY");
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
                detail: "live inventory, top processes, PID inspection, and starts; OS access rules apply".into(),
            },
            ModuleCapability {
                name: "traffic".into(),
                available: true,
                detail: "passive per-interface byte and packet counters; live packet capture is a separate explicit action".into(),
            },
            ModuleCapability {
                name: "capture".into(),
                available: live_capture,
                detail: if live_capture {
                    "live bounded packet capture via tcpdump on a selected interface; capture-device permission is checked when run"
                } else {
                    "requires macOS or Linux and tcpdump; capture-device permission is checked when run"
                }
                .into(),
            },
            ModuleCapability {
                name: "lan".into(),
                available: lan.is_ok(),
                detail: lan.map_or_else(
                    |error| format!("no physical private IPv4 segment detected: {error}"),
                    |scope| format!("active {} on {}; survey starts only on request", scope.cidr, scope.interface),
                ),
            },
            ModuleCapability {
                name: "binary".into(),
                available: true,
                detail: "offline PE, ELF, and Mach-O inspection".into(),
            },
            ModuleCapability {
                name: "disasm".into(),
                available: disasm,
                detail: if disasm {
                    "offline bounded instruction disassembly via objdump; the target is never executed"
                } else {
                    "requires objdump or llvm-objdump for offline instruction disassembly"
                }
                .into(),
            },
            ModuleCapability {
                name: "runtime_sample".into(),
                available: sample,
                detail: if sample {
                    "on-demand process stack sample; attaching to another PID may require OS permission"
                } else {
                    "requires macOS and the sample tool for process stack sampling"
                }
                .into(),
            },
            ModuleCapability {
                name: "runtime_resources".into(),
                available: resources,
                detail: if resources {
                    "on-demand process open-file and socket inventory via lsof; OS access rules apply"
                } else {
                    "requires lsof for process open-file and socket inventory"
                }
                .into(),
            },
            ModuleCapability {
                name: "runtime_trace".into(),
                available: trace,
                detail: if !cfg!(unix) {
                    "function tracing currently requires macOS or Linux"
                } else if trace {
                    "optional on-demand function trace via frida-trace; process-attach permission is required"
                } else {
                    "install frida-tools to enable optional on-demand function tracing"
                }
                .into(),
            },
            ModuleCapability {
                name: "intel_cisa_kev".into(),
                available: true,
                detail: "keyless CISA Known Exploited Vulnerabilities lookup for CVEs; remote service checked only when queried".into(),
            },
            ModuleCapability {
                name: "intel_circl".into(),
                available: true,
                detail: "keyless CIRCL hashlookup for file hashes; remote service checked only when queried".into(),
            },
            ModuleCapability {
                name: "intel_virustotal".into(),
                available: vt_key,
                detail: if vt_key {
                    "VirusTotal key configured for explicit IP, domain, and hash lookups; remote service not yet checked"
                } else {
                    "set SPECTRE_VT_API_KEY for explicit IP, domain, and hash lookups"
                }
                .into(),
            },
            ModuleCapability {
                name: "intel_abuseipdb".into(),
                available: abuse_key,
                detail: if abuse_key {
                    "AbuseIPDB key configured for explicit IP lookups; remote service not yet checked"
                } else {
                    "set SPECTRE_ABUSEIPDB_API_KEY for explicit IP lookups"
                }
                .into(),
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
    let standard_paths: &[&str] = match name {
        "tcpdump" => &["/usr/sbin/tcpdump", "/usr/bin/tcpdump"],
        "objdump" => &["/usr/bin/objdump"],
        "sample" => &["/usr/bin/sample"],
        "lsof" => &["/usr/sbin/lsof", "/usr/bin/lsof"],
        _ => &[],
    };
    for path in standard_paths {
        let entry = PathBuf::from(path);
        if entry.is_file() {
            return Some(entry);
        }
    }
    let candidates: Vec<String> = if cfg!(windows) {
        vec![name.into(), format!("{name}.exe"), format!("{name}.cmd")]
    } else {
        vec![name.into()]
    };
    if let Some(path) = env::var_os("PATH") {
        for directory in env::split_paths(&path) {
            for candidate in &candidates {
                let entry = directory.join(candidate);
                if entry.is_file() {
                    return Some(entry);
                }
            }
        }
    }
    if let Some(home) = dirs::home_dir() {
        for candidate in candidates {
            let entry = home.join(".local/bin").join(candidate);
            if entry.is_file() {
                return Some(entry);
            }
        }
    }
    None
}

fn key_configured(name: &str) -> bool {
    env::var(name).is_ok_and(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::inspect;

    #[test]
    fn doctor_reports_new_capabilities_with_matching_tool_state() {
        let report = inspect();
        let tool_present = |name: &str| {
            report
                .tools
                .iter()
                .any(|tool| tool.name == name && tool.path.is_some())
        };
        let module = |name: &str| {
            report
                .modules
                .iter()
                .find(|module| module.name == name)
                .unwrap_or_else(|| panic!("missing {name} doctor module"))
        };
        assert_eq!(
            module("disasm").available,
            tool_present("objdump") || tool_present("llvm-objdump")
        );
        assert_eq!(module("runtime_resources").available, tool_present("lsof"));
        assert_eq!(
            module("runtime_trace").available,
            cfg!(unix) && tool_present("frida-trace")
        );
        if !cfg!(unix) {
            assert!(module("runtime_trace").detail.contains("macOS or Linux"));
        }
        assert_eq!(
            module("runtime_sample").available,
            cfg!(target_os = "macos") && tool_present("sample")
        );
        assert_eq!(
            module("capture").available,
            cfg!(any(target_os = "macos", target_os = "linux")) && tool_present("tcpdump")
        );
        assert!(module("intel_cisa_kev").available);
        assert!(module("intel_circl").available);
    }

    #[test]
    fn doctor_distinguishes_key_presence_from_keyless_sources() {
        let report = inspect();
        let module = |name: &str| {
            report
                .modules
                .iter()
                .find(|module| module.name == name)
                .unwrap_or_else(|| panic!("missing {name} doctor module"))
        };
        assert_eq!(
            module("intel_virustotal").available,
            super::key_configured("SPECTRE_VT_API_KEY")
        );
        assert_eq!(
            module("intel_abuseipdb").available,
            super::key_configured("SPECTRE_ABUSEIPDB_API_KEY")
        );
        assert!(module("intel_cisa_kev").detail.contains("keyless"));
        assert!(module("intel_circl").detail.contains("keyless"));
    }
}
