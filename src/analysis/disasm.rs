//! Bounded, offline disassembly of executable sections using a local objdump.
//! The target file is parsed and handed to the disassembler as a path; it is
//! never launched as a process.

use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use object::{
    Architecture, FileKind, Object, ObjectSection, SectionKind, SubArchitecture,
    read::macho::{FatArch, MachOFatFile32, MachOFatFile64},
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    time::timeout,
};

use crate::{
    analysis::binary::MAX_BINARY_BYTES,
    model::{Event, Severity, SourceKind},
};

const MAX_INSTRUCTIONS: usize = 256;
const MAX_TOOL_OUTPUT: usize = 256 * 1024;
const MAX_TOOL_ERROR: usize = 8 * 1024;
const TOOL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
struct TargetSection {
    name: String,
    address: u64,
    size: u64,
    architecture: Architecture,
    format: String,
    macho_arch: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Instruction {
    address: u64,
    mnemonic: String,
    operands: String,
}

/// Return real instructions from the first executable section of a local
/// PE, ELF, or Mach-O file. A universal Mach-O selects the host architecture
/// when it exists. The result and child-process output are strictly bounded.
pub async fn disassemble_binary(path: &Path, max_instructions: usize) -> Result<Vec<Event>> {
    if !(1..=MAX_INSTRUCTIONS).contains(&max_instructions) {
        bail!("disassembly instruction limit must be between 1 and {MAX_INSTRUCTIONS}");
    }
    let canonical =
        fs::canonicalize(path).with_context(|| format!("resolve {}", path.display()))?;
    let metadata =
        fs::metadata(&canonical).with_context(|| format!("stat {}", canonical.display()))?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", canonical.display());
    }
    if metadata.len() > MAX_BINARY_BYTES {
        bail!(
            "{} is {} bytes; disassembly is limited to {} bytes",
            canonical.display(),
            metadata.len(),
            MAX_BINARY_BYTES
        );
    }
    let mut data = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(&canonical)
        .with_context(|| format!("open {}", canonical.display()))?
        .take(MAX_BINARY_BYTES + 1)
        .read_to_end(&mut data)
        .with_context(|| format!("read {}", canonical.display()))?;
    if data.len() as u64 > MAX_BINARY_BYTES {
        bail!(
            "{} grew beyond the disassembly size limit",
            canonical.display()
        );
    }
    let section = select_section(&data)
        .with_context(|| format!("select executable section in {}", canonical.display()))?;
    let tool = find_objdump()
        .context("no local objdump found; install Xcode Command Line Tools or LLVM/binutils")?;
    let (stdout, stderr, capped) = run_objdump(&tool, &canonical, &section).await?;
    let text = String::from_utf8_lossy(&stdout);
    let section_end = section.address.saturating_add(section.size);
    let instructions = parse_instructions(
        &text,
        max_instructions,
        Some((section.address, section_end)),
    );
    if instructions.is_empty() {
        let explanation = stderr
            .lines()
            .next()
            .unwrap_or("no instruction text was emitted");
        bail!("disassembler returned no instructions: {explanation}");
    }
    let subject = canonical.display().to_string();
    let hash = format!("{:x}", Sha256::digest(&data));
    let first = instructions
        .first()
        .expect("nonempty instruction list")
        .address;
    let last = instructions
        .last()
        .expect("nonempty instruction list")
        .address;
    let calls = instructions
        .iter()
        .filter(|instruction| flow_class(&instruction.mnemonic) == "call")
        .count();
    let branches = instructions
        .iter()
        .filter(|instruction| flow_class(&instruction.mnemonic) == "branch")
        .count();
    let returns = instructions
        .iter()
        .filter(|instruction| flow_class(&instruction.mnemonic) == "return")
        .count();
    let mut events = vec![
        Event::new(
            "disasm",
            "disasm.summary",
            format!(
                "{} {:?}: {} instructions from {} (0x{first:x}–0x{last:x})",
                section.format,
                section.architecture,
                instructions.len(),
                section.name,
            ),
            Some(subject.clone()),
            Severity::Info,
            SourceKind::File,
        )
        .with_evidence("sha256", hash, &subject)
        .with_evidence("section", &section.name, &subject)
        .with_evidence(
            "section_address",
            format!("0x{:x}", section.address),
            &subject,
        )
        .with_evidence("section_size", section.size.to_string(), &subject)
        .with_evidence(
            "architecture",
            format!("{:?}", section.architecture),
            &subject,
        )
        .with_evidence("tool", tool.display().to_string(), "local_disassembler")
        .with_evidence(
            "instructions_retained",
            instructions.len().to_string(),
            "bounded_tool_output",
        )
        .with_evidence(
            "tool_output_capped",
            capped.to_string(),
            "bounded_tool_output",
        )
        .with_evidence("calls", calls.to_string(), "decoded_instructions")
        .with_evidence("branches", branches.to_string(), "decoded_instructions")
        .with_evidence("returns", returns.to_string(), "decoded_instructions"),
    ];
    for instruction in instructions {
        let flow = flow_class(&instruction.mnemonic);
        let summary = if instruction.operands.is_empty() {
            format!("0x{:x}  {}", instruction.address, instruction.mnemonic)
        } else {
            format!(
                "0x{:x}  {} {}",
                instruction.address, instruction.mnemonic, instruction.operands
            )
        };
        events.push(
            Event::new(
                "disasm",
                "disasm.instruction",
                summary,
                Some(subject.clone()),
                Severity::Info,
                SourceKind::File,
            )
            .with_evidence("address", format!("0x{:x}", instruction.address), &subject)
            .with_evidence("mnemonic", instruction.mnemonic, &subject)
            .with_evidence("operands", instruction.operands, &subject)
            .with_evidence("flow", flow, "instruction_classification")
            .with_evidence("section", &section.name, &subject),
        );
    }
    Ok(events)
}

fn select_section(data: &[u8]) -> Result<TargetSection> {
    match FileKind::parse(data).context("identify binary format")? {
        FileKind::MachOFat32 => {
            let fat = MachOFatFile32::parse(data).context("parse universal Mach-O")?;
            select_fat_section(fat.arches(), data)
        }
        FileKind::MachOFat64 => {
            let fat = MachOFatFile64::parse(data).context("parse universal Mach-O")?;
            select_fat_section(fat.arches(), data)
        }
        _ => select_object_section(data, None),
    }
}

fn select_fat_section<A: FatArch>(arches: &[A], data: &[u8]) -> Result<TargetSection> {
    let preferred = host_architecture();
    let arch = arches
        .iter()
        .find(|arch| arch.architecture() == preferred)
        .or_else(|| {
            arches.iter().find(|arch| {
                matches!(
                    arch.architecture(),
                    Architecture::Aarch64 | Architecture::X86_64 | Architecture::I386
                )
            })
        })
        .context("universal Mach-O has no supported architecture slice")?;
    let slice = arch.data(data).context("read universal Mach-O slice")?;
    let macho_arch = macho_arch_name(arch.architecture(), arch.cpusubtype());
    select_object_section(slice, macho_arch)
}

fn select_object_section(data: &[u8], fat_arch: Option<&'static str>) -> Result<TargetSection> {
    let file = object::File::parse(data).context("parse object file")?;
    let text = file
        .sections()
        .find(|section| section.kind() == SectionKind::Text && section.size() > 0)
        .context("no nonempty executable text section found")?;
    let name = text.name().unwrap_or("<text>").to_owned();
    let architecture = file.architecture();
    let macho_arch = if file.format() == object::BinaryFormat::MachO {
        fat_arch.or_else(|| match (architecture, file.sub_architecture()) {
            (Architecture::Aarch64, Some(SubArchitecture::Arm64E)) => Some("arm64e"),
            (Architecture::Aarch64, _) => Some("arm64"),
            (Architecture::X86_64, _) => Some("x86_64"),
            (Architecture::I386, _) => Some("i386"),
            _ => None,
        })
    } else {
        None
    };
    Ok(TargetSection {
        name,
        address: text.address(),
        size: text.size(),
        architecture,
        format: format!("{:?}", file.format()),
        macho_arch,
    })
}

fn host_architecture() -> Architecture {
    if cfg!(target_arch = "aarch64") {
        Architecture::Aarch64
    } else if cfg!(target_arch = "x86_64") {
        Architecture::X86_64
    } else if cfg!(target_arch = "x86") {
        Architecture::I386
    } else {
        Architecture::Unknown
    }
}

fn macho_arch_name(
    architecture: Architecture,
    subtype: object::macho::CpuSubtype,
) -> Option<&'static str> {
    match architecture {
        Architecture::Aarch64 if subtype.id() == object::macho::CPU_SUBTYPE_ARM64E => {
            Some("arm64e")
        }
        Architecture::Aarch64 => Some("arm64"),
        Architecture::X86_64 => Some("x86_64"),
        Architecture::I386 => Some("i386"),
        _ => None,
    }
}

fn find_objdump() -> Option<PathBuf> {
    #[cfg(not(windows))]
    {
        let system = PathBuf::from("/usr/bin/objdump");
        if system.is_file() {
            return Some(system);
        }
    }
    let path = env::var_os("PATH")?;
    let names: &[&str] = if cfg!(windows) {
        &["llvm-objdump.exe", "objdump.exe"]
    } else {
        &["llvm-objdump", "objdump"]
    };
    for directory in env::split_paths(&path) {
        for name in names {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

async fn run_objdump(
    tool: &Path,
    path: &Path,
    section: &TargetSection,
) -> Result<(Vec<u8>, String, bool)> {
    let mut command = Command::new(tool);
    command.arg("-d");
    if section.format == "MachO" && cfg!(target_os = "macos") {
        command.arg("--macho");
        if let Some(arch) = section.macho_arch {
            command.arg(format!("--arch={arch}"));
        }
    }
    command.arg(path);
    command
        .env("LC_ALL", "C")
        .env("TERM", "dumb")
        .env("DEBUGINFOD_URLS", "");
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .with_context(|| format!("start {}", tool.display()))?;
    let stdout = child
        .stdout
        .take()
        .context("disassembler stdout unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("disassembler stderr unavailable")?;
    let error_task = tokio::spawn(async move { read_limited(stderr, MAX_TOOL_ERROR).await });
    let output = match timeout(TOOL_TIMEOUT, read_limited(stdout, MAX_TOOL_OUTPUT)).await {
        Ok(result) => result.context("read disassembler stdout")?,
        Err(_) => {
            let _ = child.kill().await;
            error_task.abort();
            bail!("disassembler exceeded the ten-second time limit");
        }
    };
    let capped = output.len() > MAX_TOOL_OUTPUT;
    if capped {
        let _ = child.kill().await;
    }
    let stderr = match timeout(Duration::from_secs(2), error_task).await {
        Ok(Ok(Ok(bytes))) => String::from_utf8_lossy(&bytes).into_owned(),
        _ => String::new(),
    };
    if !capped {
        let status = timeout(Duration::from_secs(2), child.wait())
            .await
            .context("disassembler did not exit after writing output")?
            .context("wait for disassembler")?;
        if !status.success() {
            let reason = stderr.lines().next().unwrap_or("unknown error");
            bail!("disassembler failed: {reason}");
        }
    }
    Ok((output, stderr, capped))
}

async fn read_limited<R: AsyncRead + Unpin>(reader: R, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    Ok(bytes)
}

fn parse_instructions(
    output: &str,
    limit: usize,
    address_range: Option<(u64, u64)>,
) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    for line in output.lines() {
        let Some((raw_address, rest)) = line.trim_start().split_once(':') else {
            continue;
        };
        if raw_address.is_empty()
            || raw_address.len() > 16
            || !raw_address.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            continue;
        }
        let Ok(address) = u64::from_str_radix(raw_address, 16) else {
            continue;
        };
        if address_range.is_some_and(|(start, end)| address < start || address >= end) {
            continue;
        }
        let mut words = rest.split_whitespace().peekable();
        while let Some(word) = words.peek() {
            let raw_byte = (word.len() == 2 || word.len() == 8)
                && word.bytes().all(|byte| byte.is_ascii_hexdigit());
            if raw_byte {
                words.next();
            } else {
                break;
            }
        }
        let Some(mnemonic) = words.next() else {
            continue;
        };
        if mnemonic == "..." || mnemonic.starts_with('<') {
            continue;
        }
        let operands = words.collect::<Vec<_>>().join(" ");
        instructions.push(Instruction {
            address,
            mnemonic: mnemonic.to_owned(),
            operands,
        });
        if instructions.len() >= limit {
            break;
        }
    }
    instructions
}

fn flow_class(mnemonic: &str) -> &'static str {
    let mnemonic = mnemonic.to_ascii_lowercase();
    if mnemonic.starts_with("ret") || mnemonic == "iret" || mnemonic == "eret" {
        "return"
    } else if matches!(
        mnemonic.as_str(),
        "call" | "callq" | "bl" | "blr" | "jal" | "jalr" | "jsr"
    ) {
        "call"
    } else if mnemonic.starts_with('j')
        || mnemonic == "b"
        || mnemonic.starts_with("b.")
        || matches!(mnemonic.as_str(), "br" | "cbz" | "cbnz" | "tbz" | "tbnz")
    {
        "branch"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_llvm_and_gnu_instruction_lines_without_headers() {
        let llvm = "/bin/ls:\n(__TEXT,__text) section\n100000700:\t00 a0 01 91\tadd\tx0, x0, #0x68\n100000704:\tc0 03 5f d6\tret\n";
        assert_eq!(
            parse_instructions(llvm, 2, None),
            vec![
                Instruction {
                    address: 0x100000700,
                    mnemonic: "add".into(),
                    operands: "x0, x0, #0x68".into()
                },
                Instruction {
                    address: 0x100000704,
                    mnemonic: "ret".into(),
                    operands: String::new()
                },
            ]
        );
        let gnu = "0000000000401000 <_start>:\n  401000:\t55\tpush   %rbp\n  401001:\te8 00 00 00 00\tcallq  401006 <foo>\n  401002:\t90\tnop\n";
        let parsed = parse_instructions(gnu, 8, Some((0x401000, 0x401002)));
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].mnemonic, "push");
        assert_eq!(parsed[1].operands, "401006 <foo>");
        let relocatable = "(__TEXT,__text) section\n0:\t1f 20 03 d5\tnop\n4:\tc0 03 5f d6\tret\n";
        let parsed = parse_instructions(relocatable, 8, Some((0, 8)));
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].address, 0);
        assert_eq!(parsed[1].mnemonic, "ret");
    }

    #[test]
    fn classifies_observed_control_flow_without_claiming_intent() {
        assert_eq!(flow_class("bl"), "call");
        assert_eq!(flow_class("b.eq"), "branch");
        assert_eq!(flow_class("ret"), "return");
        assert_eq!(flow_class("mov"), "other");
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn disassembles_real_macho_without_executing_it() {
        let events = disassemble_binary(Path::new("/bin/ls"), 24).await.unwrap();
        assert_eq!(events[0].kind, "disasm.summary");
        if cfg!(target_arch = "aarch64") {
            assert!(events[0].summary.contains("Aarch64"));
        }
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "disasm.instruction")
                .count(),
            24
        );
        assert!(
            events[0]
                .evidence
                .iter()
                .any(|item| item.label == "sha256" && item.value.len() == 64)
        );
        assert!(
            events
                .iter()
                .skip(1)
                .all(|event| event.source == SourceKind::File)
        );
    }
}
