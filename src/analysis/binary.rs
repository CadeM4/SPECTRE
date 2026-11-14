use std::{collections::BTreeSet, fs, io::Read, path::Path};

use anyhow::{Context, Result, bail};
use object::{
    FileKind, Object, ObjectSection, ObjectSymbol,
    read::{
        NameOrOrdinal,
        macho::{FatArch, MachOFatFile32, MachOFatFile64},
    },
};
use sha2::{Digest, Sha256};

use crate::model::{Event, Severity, SourceKind};

const MAX_BINARY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SECTIONS: usize = 128;
const MAX_IMPORTS: usize = 256;
const MAX_IMPORT_INSPECTION: usize = 8192;
const MAX_STRINGS: usize = 64;

/// Static inspection only. A size limit bounds parsing and the amount of retained evidence.
pub fn analyze_binary(path: &Path) -> Result<Vec<Event>> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if metadata.len() > MAX_BINARY_BYTES {
        bail!(
            "{} is {} bytes; binary inspection is limited to {} bytes",
            path.display(),
            metadata.len(),
            MAX_BINARY_BYTES
        );
    }

    let mut data = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .take(MAX_BINARY_BYTES + 1)
        .read_to_end(&mut data)
        .with_context(|| format!("read {}", path.display()))?;
    if data.len() as u64 > MAX_BINARY_BYTES {
        bail!(
            "{} grew beyond the binary inspection limit while reading",
            path.display()
        );
    }
    let subject = path.display().to_string();
    let hash = format!("{:x}", Sha256::digest(&data));
    match FileKind::parse(data.as_slice())
        .with_context(|| format!("identify executable or object file {}", path.display()))?
    {
        FileKind::MachOFat32 => analyze_fat32(&data, &subject, &hash),
        FileKind::MachOFat64 => analyze_fat64(&data, &subject, &hash),
        _ => analyze_object(&data, &subject, &hash),
    }
}

fn analyze_fat32(data: &[u8], subject: &str, hash: &str) -> Result<Vec<Event>> {
    let fat = MachOFatFile32::parse(data).context("parse universal Mach-O header")?;
    let mut events = vec![fat_identity(subject, hash, fat.arches().len())];
    for arch in fat.arches().iter().take(16) {
        let slice = arch
            .data(data)
            .context("read universal Mach-O architecture slice")?;
        let slice_subject = format!("{subject}#{:?}", arch.architecture());
        let slice_hash = format!("{:x}", Sha256::digest(slice));
        events.extend(analyze_object(slice, &slice_subject, &slice_hash)?);
    }
    Ok(events)
}

fn analyze_fat64(data: &[u8], subject: &str, hash: &str) -> Result<Vec<Event>> {
    let fat = MachOFatFile64::parse(data).context("parse universal Mach-O header")?;
    let mut events = vec![fat_identity(subject, hash, fat.arches().len())];
    for arch in fat.arches().iter().take(16) {
        let slice = arch
            .data(data)
            .context("read universal Mach-O architecture slice")?;
        let slice_subject = format!("{subject}#{:?}", arch.architecture());
        let slice_hash = format!("{:x}", Sha256::digest(slice));
        events.extend(analyze_object(slice, &slice_subject, &slice_hash)?);
    }
    Ok(events)
}

fn fat_identity(subject: &str, hash: &str, count: usize) -> Event {
    Event::new(
        "binary",
        "binary.container",
        format!(
            "Universal Mach-O with {count} architecture slice(s); first {} inspected",
            count.min(16)
        ),
        Some(subject.to_owned()),
        Severity::Info,
        SourceKind::File,
    )
    .with_evidence("sha256", hash, subject)
}

fn analyze_object(data: &[u8], subject: &str, hash: &str) -> Result<Vec<Event>> {
    let file = object::File::parse(data)
        .with_context(|| format!("parse executable or object file {subject}"))?;
    let subject = subject.to_owned();
    let format = format!("{:?}", file.format());
    let architecture = format!("{:?}", file.architecture());
    let width = if file.is_64() { 64 } else { 32 };
    let endian = if file.is_little_endian() {
        "little"
    } else {
        "big"
    };

    let mut events = vec![
        Event::new(
            "binary",
            "binary.identity",
            format!("{format} {architecture}, {width}-bit, {} bytes", data.len()),
            Some(subject.clone()),
            Severity::Info,
            SourceKind::File,
        )
        .with_evidence("sha256", hash, &subject)
        .with_evidence("entry_point", format!("0x{:x}", file.entry()), &subject)
        .with_evidence("endianness", endian, &subject),
    ];

    let mut section_count = 0usize;
    let mut high_entropy = 0usize;
    for section in file.sections().take(MAX_SECTIONS) {
        section_count += 1;
        let name = sanitize(section.name().unwrap_or("<unnamed>"));
        let size = section.size();
        let entropy = section.data().ok().map(shannon_entropy);
        let mut event = Event::new(
            "binary",
            "binary.section",
            format!("{name}: {} bytes at 0x{:x}", size, section.address()),
            Some(subject.clone()),
            Severity::Info,
            SourceKind::File,
        )
        .with_evidence("section", &name, &subject)
        .with_evidence("size", size.to_string(), &subject);
        if let Some(bits) = entropy {
            event = event.with_evidence("entropy_bits_per_byte", format!("{bits:.3}"), &subject);
            if size >= 4096 && bits >= 7.2 {
                high_entropy += 1;
            }
        }
        events.push(event);
    }
    if high_entropy > 0 {
        events.push(Event::new(
            "binary",
            "binary.entropy_observation",
            format!("{high_entropy} section(s) have entropy of at least 7.2 bits per byte"),
            Some(subject.clone()),
            Severity::Low,
            SourceKind::File,
        )
        .with_evidence("interpretation", "High entropy can reflect compression, encryption, or ordinary binary data; inspect sections before drawing a conclusion.", &subject));
    }
    events.push(Event::new(
        "binary",
        "binary.section_summary",
        format!("Inspected {section_count} sections"),
        Some(subject.clone()),
        Severity::Info,
        SourceKind::File,
    ));

    match file.imports() {
        Ok(imports) => {
            let mut total = 0usize;
            let mut errors = 0usize;
            let mut samples = Vec::new();
            for entry in imports.take(MAX_IMPORT_INSPECTION) {
                match entry {
                    Ok(import) => {
                        total += 1;
                        if samples.len() < MAX_IMPORTS {
                            let lib = sanitize_bytes(import.library());
                            let name = match import.name() {
                                NameOrOrdinal::Name(name) => sanitize_bytes(name),
                                NameOrOrdinal::Ordinal(ordinal) => format!("#{ordinal}"),
                            };
                            samples.push(format!("{lib}!{name}"));
                        }
                    }
                    Err(_) => errors += 1,
                }
            }
            if total > 0 {
                events.push(
                    Event::new(
                        "binary",
                        "binary.imports",
                        format!("{total} imports inspected; {} retained", samples.len()),
                        Some(subject.clone()),
                        Severity::Info,
                        SourceKind::File,
                    )
                    .with_evidence("imports", samples.join("\n"), &subject),
                );
            }
            if errors > 0 {
                events.push(Event::new(
                    "binary",
                    "binary.partial_analysis",
                    format!("{errors} import entries could not be decoded"),
                    Some(subject.clone()),
                    Severity::Info,
                    SourceKind::File,
                ));
            }
        }
        Err(error) => events.push(Event::new(
            "binary",
            "binary.partial_analysis",
            format!("Imports unavailable: {error}"),
            Some(subject.clone()),
            Severity::Info,
            SourceKind::File,
        )),
    }

    if let Ok(libraries) = file.import_libraries() {
        let names = libraries
            .take(128)
            .filter_map(Result::ok)
            .map(|library| sanitize_bytes(library.name()))
            .collect::<Vec<_>>();
        if !names.is_empty() {
            events.push(
                Event::new(
                    "binary",
                    "binary.dependencies",
                    format!("{} linked libraries retained", names.len()),
                    Some(subject.clone()),
                    Severity::Info,
                    SourceKind::File,
                )
                .with_evidence("libraries", names.join("\n"), &subject),
            );
        }
    }

    if let Ok(exports) = file.exports() {
        let names = exports
            .take(MAX_IMPORTS)
            .filter_map(Result::ok)
            .map(|export| match export.name() {
                NameOrOrdinal::Name(name) => sanitize_bytes(name),
                NameOrOrdinal::Ordinal(ordinal) => format!("#{ordinal}"),
            })
            .collect::<Vec<_>>();
        if !names.is_empty() {
            events.push(
                Event::new(
                    "binary",
                    "binary.exports",
                    format!("{} exports retained", names.len()),
                    Some(subject.clone()),
                    Severity::Info,
                    SourceKind::File,
                )
                .with_evidence("exports", names.join("\n"), &subject),
            );
        }
    }

    let mut symbols = BTreeSet::new();
    for symbol in file.symbols().take(4096) {
        if let Ok(name) = symbol.name()
            && !name.is_empty()
            && !name.starts_with('.')
        {
            symbols.insert(sanitize(name));
            if symbols.len() >= 64 {
                break;
            }
        }
    }
    if !symbols.is_empty() {
        events.push(
            Event::new(
                "binary",
                "binary.symbols",
                format!("{} named symbols retained", symbols.len()),
                Some(subject.clone()),
                Severity::Info,
                SourceKind::File,
            )
            .with_evidence(
                "symbols",
                symbols.into_iter().collect::<Vec<_>>().join("\n"),
                &subject,
            ),
        );
    }

    let strings = extract_strings(data, MAX_STRINGS);
    if !strings.is_empty() {
        events.push(
            Event::new(
                "binary",
                "binary.strings",
                format!("{} printable strings retained", strings.len()),
                Some(subject.clone()),
                Severity::Info,
                SourceKind::File,
            )
            .with_evidence("strings", strings.join("\n"), &subject),
        );
    }

    Ok(events)
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let total = bytes.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

fn extract_strings(data: &[u8], limit: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut start = None;
    for (index, byte) in data.iter().enumerate() {
        if (0x20..=0x7e).contains(byte) {
            start.get_or_insert(index);
            continue;
        }
        if let Some(begin) = start.take()
            && index - begin >= 8
        {
            let sample = &data[begin..index.min(begin + 160)];
            result.push(String::from_utf8_lossy(sample).into_owned());
            if result.len() >= limit {
                break;
            }
        }
    }
    if result.len() < limit
        && let Some(begin) = start
        && data.len() - begin >= 8
    {
        result
            .push(String::from_utf8_lossy(&data[begin..data.len().min(begin + 160)]).into_owned());
    }
    result
}

fn sanitize_bytes(value: &[u8]) -> String {
    sanitize(&String::from_utf8_lossy(&value[..value.len().min(160)]))
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .take(160)
        .map(|character| {
            if character.is_control() {
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
    fn entropy_boundaries() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[7; 1024]), 0.0);
        assert!((shannon_entropy(&[0, 1]) - 1.0).abs() < 1e-9);
        assert!((shannon_entropy(&(0u8..=255).collect::<Vec<_>>()) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn strings_are_bounded_and_printable() {
        let values = extract_strings(b"x\0first_long_string\0second_long_string\0", 1);
        assert_eq!(values, vec!["first_long_string"]);
    }

    #[test]
    fn inspects_real_executable_with_provenance() {
        let path = std::env::current_exe().unwrap();
        let expected_hash = format!("{:x}", Sha256::digest(fs::read(&path).unwrap()));
        let events = analyze_binary(&path).unwrap();
        assert!(events.iter().any(|event| event.kind == "binary.identity"));
        assert!(events.iter().flat_map(|event| &event.evidence).any(|item| {
            item.label == "sha256"
                && item.value == expected_hash
                && item.origin == path.display().to_string()
        }));
        assert!(events.iter().any(|event| event.kind == "binary.section"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inspects_universal_macho_slice() {
        let thin = fs::read(std::env::current_exe().unwrap()).unwrap();
        let cputype: u32 = if cfg!(target_arch = "aarch64") {
            0x0100_000c
        } else {
            0x0100_0007
        };
        let mut fat = Vec::new();
        fat.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
        fat.extend_from_slice(&1u32.to_be_bytes());
        fat.extend_from_slice(&cputype.to_be_bytes());
        fat.extend_from_slice(&0u32.to_be_bytes());
        fat.extend_from_slice(&28u32.to_be_bytes());
        fat.extend_from_slice(&(thin.len() as u32).to_be_bytes());
        fat.extend_from_slice(&0u32.to_be_bytes());
        fat.extend_from_slice(&thin);
        let path = std::env::temp_dir().join(format!("spectre-fat-test-{}", std::process::id()));
        fs::write(&path, fat).unwrap();
        let events = analyze_binary(&path).unwrap();
        fs::remove_file(path).unwrap();
        assert!(events.iter().any(|event| event.kind == "binary.container"));
        assert!(events.iter().any(|event| event.kind == "binary.identity"));
    }
}
