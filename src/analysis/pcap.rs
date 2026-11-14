use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::model::{Event, Severity, SourceKind};

const MAX_PCAP_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PACKET_BYTES: usize = 4 * 1024 * 1024;
const MAX_PACKETS: u64 = 200_000;
const MAX_FLOWS: usize = 16_384;
const MAX_REPORTED_FLOWS: usize = 128;
const MAX_NAMES: usize = 128;

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, bytes: &[u8]) -> u16 {
        let value = [bytes[0], bytes[1]];
        match self {
            Self::Little => u16::from_le_bytes(value),
            Self::Big => u16::from_be_bytes(value),
        }
    }

    fn u32(self, bytes: &[u8]) -> u32 {
        let value = [bytes[0], bytes[1], bytes[2], bytes[3]];
        match self {
            Self::Little => u32::from_le_bytes(value),
            Self::Big => u32::from_be_bytes(value),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FlowKey {
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
}

impl FlowKey {
    fn label(&self) -> String {
        format!(
            "{}:{} → {}:{} ({})",
            self.src,
            self.src_port,
            self.dst,
            self.dst_port,
            protocol_name(self.protocol)
        )
    }
}

#[derive(Clone, Default)]
struct FlowStats {
    packets: u64,
    captured_bytes: u64,
    first: Option<DateTime<Utc>>,
    last: Option<DateTime<Utc>>,
    tcp_syns: u64,
}

#[derive(Clone, Default)]
struct NameStats {
    count: u64,
    first: Option<DateTime<Utc>>,
    last: Option<DateTime<Utc>>,
}

fn observe_name(names: &mut BTreeMap<String, NameStats>, name: String, timestamp: DateTime<Utc>) {
    if names.len() >= MAX_NAMES && !names.contains_key(&name) {
        return;
    }
    let stats = names.entry(name).or_default();
    stats.count += 1;
    if stats.first.is_none() {
        stats.first = Some(timestamp);
    }
    stats.last = Some(timestamp);
}

fn name_event(
    kind: &str,
    description: &str,
    name: String,
    stats: NameStats,
    capture: &str,
) -> Event {
    let mut event = Event::new(
        "pcap",
        kind,
        format!("{description} {name} observed {} time(s)", stats.count),
        Some(name),
        Severity::Info,
        SourceKind::File,
    )
    .with_evidence("capture", capture, capture);
    if let Some(ts) = stats.first {
        event = event.with_evidence("first_packet_utc", ts.to_rfc3339(), capture);
    }
    if let Some(ts) = stats.last {
        event.timestamp = ts;
        event = event.with_evidence("last_packet_utc", ts.to_rfc3339(), capture);
    }
    event
}

struct IpPacket<'a> {
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    payload: &'a [u8],
}

/// Parse a classic PCAP capture without running external tools or opening the network.
pub fn analyze_pcap(path: &Path) -> Result<Vec<Event>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?;
    if metadata.len() > MAX_PCAP_BYTES {
        bail!(
            "{} is {} bytes; PCAP inspection is limited to {} bytes",
            path.display(),
            metadata.len(),
            MAX_PCAP_BYTES
        );
    }
    let subject = path.display().to_string();
    let mut reader = BufReader::new(file);
    let mut header = [0u8; 24];
    reader
        .read_exact(&mut header)
        .context("read PCAP global header")?;
    let (endian, nanoseconds) = match &header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, true),
        [0x0a, 0x0d, 0x0d, 0x0a] => {
            bail!("PCAPNG is not supported yet; export a classic PCAP capture")
        }
        _ => bail!("{} does not have a classic PCAP header", path.display()),
    };
    let major = endian.u16(&header[4..6]);
    if major != 2 {
        bail!("unsupported PCAP major version {major}");
    }
    let snaplen = endian.u32(&header[16..20]) as usize;
    let linktype = endian.u32(&header[20..24]) & 0xffff;
    if !matches!(linktype, 1 | 101 | 113 | 276) {
        bail!(
            "unsupported PCAP link type {linktype}; supported: Ethernet, raw IP, Linux cooked v1/v2"
        );
    }

    let mut hasher = Sha256::new();
    hasher.update(header);
    let mut packet_count = 0u64;
    let mut captured_bytes = 0u64;
    let mut decoded_packets = 0u64;
    let mut flows: BTreeMap<FlowKey, FlowStats> = BTreeMap::new();
    let mut dns_queries: BTreeMap<String, NameStats> = BTreeMap::new();
    let mut tls_names: BTreeMap<String, NameStats> = BTreeMap::new();
    let mut http_hosts: BTreeMap<String, NameStats> = BTreeMap::new();
    let mut first_time = None;
    let mut last_time = None;

    loop {
        let mut packet_header = [0u8; 16];
        if reader
            .read(&mut packet_header[..1])
            .context("read packet header")?
            == 0
        {
            break;
        }
        reader
            .read_exact(&mut packet_header[1..])
            .context("truncated PCAP packet header")?;
        let included = endian.u32(&packet_header[8..12]) as usize;
        if included > MAX_PACKET_BYTES || (snaplen > 0 && included > snaplen) {
            bail!(
                "packet {} has invalid captured length {included}",
                packet_count + 1
            );
        }
        let mut frame = vec![0u8; included];
        reader
            .read_exact(&mut frame)
            .context("truncated PCAP packet payload")?;
        hasher.update(packet_header);
        hasher.update(&frame);
        packet_count += 1;
        captured_bytes += included as u64;
        if packet_count > MAX_PACKETS {
            bail!("capture exceeds the {} packet analysis limit", MAX_PACKETS);
        }

        let seconds = endian.u32(&packet_header[0..4]) as i64;
        let fraction = endian.u32(&packet_header[4..8]);
        let fractional_limit = if nanoseconds {
            1_000_000_000
        } else {
            1_000_000
        };
        if fraction >= fractional_limit {
            bail!(
                "packet {} has invalid timestamp fraction {fraction}",
                packet_count
            );
        }
        let nanos = if nanoseconds {
            fraction
        } else {
            fraction * 1000
        };
        let timestamp = DateTime::<Utc>::from_timestamp(seconds, nanos);
        if first_time.is_none() {
            first_time = timestamp;
        }
        last_time = timestamp;

        let Some(packet) = decode_ip(linktype, &frame) else {
            continue;
        };
        decoded_packets += 1;
        let (src_port, dst_port, application, syn) = match packet.protocol {
            6 if packet.payload.len() >= 20 => {
                let offset = ((packet.payload[12] >> 4) as usize) * 4;
                if offset < 20 || offset > packet.payload.len() {
                    continue;
                }
                (
                    u16::from_be_bytes([packet.payload[0], packet.payload[1]]),
                    u16::from_be_bytes([packet.payload[2], packet.payload[3]]),
                    &packet.payload[offset..],
                    packet.payload[13] & 0x02 != 0 && packet.payload[13] & 0x10 == 0,
                )
            }
            17 if packet.payload.len() >= 8 => {
                let length = u16::from_be_bytes([packet.payload[4], packet.payload[5]]) as usize;
                if length < 8 {
                    continue;
                }
                let end = length.min(packet.payload.len());
                (
                    u16::from_be_bytes([packet.payload[0], packet.payload[1]]),
                    u16::from_be_bytes([packet.payload[2], packet.payload[3]]),
                    &packet.payload[8..end],
                    false,
                )
            }
            _ => (0, 0, &[][..], false),
        };
        let key = FlowKey {
            src: packet.src,
            dst: packet.dst,
            protocol: packet.protocol,
            src_port,
            dst_port,
        };
        if let Some(stats) = flows.get_mut(&key) {
            stats.packets += 1;
            stats.captured_bytes += included as u64;
            stats.last = timestamp;
            stats.tcp_syns += u64::from(syn);
        } else if flows.len() < MAX_FLOWS {
            flows.insert(
                key,
                FlowStats {
                    packets: 1,
                    captured_bytes: included as u64,
                    first: timestamp,
                    last: timestamp,
                    tcp_syns: u64::from(syn),
                },
            );
        }
        if packet.protocol == 17 && (src_port == 53 || dst_port == 53) {
            for name in dns_question_names(application).into_iter().take(8) {
                if let Some(ts) = timestamp {
                    observe_name(&mut dns_queries, name, ts);
                }
            }
        }
        if packet.protocol == 6 {
            if let Some(name) = tls_client_hello_sni(application)
                && let Some(ts) = timestamp
            {
                observe_name(&mut tls_names, name, ts);
            }
            if let Some(host) = http_host(application)
                && let Some(ts) = timestamp
            {
                observe_name(&mut http_hosts, host, ts);
            }
        }
    }

    let mut events = Vec::new();
    let mut summary = Event::new(
        "pcap",
        "pcap.summary",
        format!(
            "{packet_count} packets, {captured_bytes} captured bytes, {decoded_packets} IP packets, {} flows",
            flows.len()
        ),
        Some(subject.clone()),
        Severity::Info,
        SourceKind::File,
    )
    .with_evidence("sha256", format!("{:x}", hasher.finalize()), &subject)
    .with_evidence("link_type", linktype.to_string(), &subject)
    .with_evidence("snaplen", snaplen.to_string(), &subject);
    if let Some(ts) = first_time {
        summary = summary.with_evidence("first_packet_utc", ts.to_rfc3339(), &subject);
    }
    if let Some(ts) = last_time {
        summary = summary.with_evidence("last_packet_utc", ts.to_rfc3339(), &subject);
        summary.timestamp = ts;
    }
    events.push(summary);

    let mut ranked = flows.into_iter().collect::<Vec<_>>();
    ranked.sort_by_key(|a| std::cmp::Reverse(a.1.captured_bytes));
    for (key, stats) in ranked.into_iter().take(MAX_REPORTED_FLOWS) {
        let mut event = Event::new(
            "pcap",
            "pcap.flow",
            format!(
                "{} packets, {} bytes: {}",
                stats.packets,
                stats.captured_bytes,
                key.label()
            ),
            Some(key.label()),
            Severity::Info,
            SourceKind::File,
        )
        .with_evidence("capture", &subject, &subject)
        .with_evidence("src_ip", key.src.to_string(), &subject)
        .with_evidence("dst_ip", key.dst.to_string(), &subject)
        .with_evidence("tcp_syn_without_ack", stats.tcp_syns.to_string(), &subject);
        if let Some(ts) = stats.first {
            event = event.with_evidence("first_packet_utc", ts.to_rfc3339(), &subject);
        }
        if let Some(ts) = stats.last {
            event.timestamp = ts;
            event = event.with_evidence("last_packet_utc", ts.to_rfc3339(), &subject);
        }
        events.push(event);
    }
    for (name, stats) in dns_queries {
        events.push(name_event(
            "pcap.dns_question",
            "DNS question",
            name,
            stats,
            &subject,
        ));
    }
    for (name, stats) in tls_names {
        events.push(name_event(
            "pcap.tls_sni",
            "TLS ClientHello SNI",
            name,
            stats,
            &subject,
        ));
    }
    for (name, stats) in http_hosts {
        events.push(name_event(
            "pcap.http_host",
            "HTTP Host",
            name,
            stats,
            &subject,
        ));
    }
    Ok(events)
}

fn protocol_name(number: u8) -> &'static str {
    match number {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "IP",
    }
}

fn decode_ip(linktype: u32, frame: &[u8]) -> Option<IpPacket<'_>> {
    let payload = match linktype {
        1 => {
            if frame.len() < 14 {
                return None;
            }
            let mut offset = 14;
            let mut kind = u16::from_be_bytes([frame[12], frame[13]]);
            for _ in 0..2 {
                if !matches!(kind, 0x8100 | 0x88a8 | 0x9100) {
                    break;
                }
                if frame.len() < offset + 4 {
                    return None;
                }
                kind = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
                offset += 4;
            }
            if !matches!(kind, 0x0800 | 0x86dd) {
                return None;
            }
            frame.get(offset..)?
        }
        101 => frame,
        113 => {
            if frame.len() < 16 {
                return None;
            }
            let kind = u16::from_be_bytes([frame[14], frame[15]]);
            if !matches!(kind, 0x0800 | 0x86dd) {
                return None;
            }
            &frame[16..]
        }
        276 => {
            if frame.len() < 20 {
                return None;
            }
            let kind = u16::from_be_bytes([frame[0], frame[1]]);
            if !matches!(kind, 0x0800 | 0x86dd) {
                return None;
            }
            &frame[20..]
        }
        _ => return None,
    };
    match payload.first()? >> 4 {
        4 => decode_ipv4(payload),
        6 => decode_ipv6(payload),
        _ => None,
    }
}

fn decode_ipv4(packet: &[u8]) -> Option<IpPacket<'_>> {
    if packet.len() < 20 {
        return None;
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if header_len < 20 || total_len < header_len || packet.len() < total_len {
        return None;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    let protocol = packet[9];
    let transport = if fragment & 0x1fff == 0 {
        &packet[header_len..total_len]
    } else {
        &[][..]
    };
    Some(IpPacket {
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).into(),
        dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).into(),
        protocol,
        payload: transport,
    })
}

fn decode_ipv6(packet: &[u8]) -> Option<IpPacket<'_>> {
    if packet.len() < 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let end = 40usize.checked_add(payload_len)?;
    if packet.len() < end {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
    let mut next = packet[6];
    let mut offset = 40;
    for _ in 0..8 {
        let length = match next {
            0 | 43 | 60 => {
                if offset + 2 > end {
                    return None;
                }
                (packet[offset + 1] as usize + 1) * 8
            }
            44 => 8,
            51 => {
                if offset + 2 > end {
                    return None;
                }
                (packet[offset + 1] as usize + 2) * 4
            }
            _ => break,
        };
        if offset + length > end {
            return None;
        }
        let following = packet[offset];
        if next == 44 && packet[offset + 2] & 0xf8 != 0 {
            return Some(IpPacket {
                src: src.into(),
                dst: dst.into(),
                protocol: following,
                payload: &[],
            });
        }
        next = following;
        offset += length;
    }
    Some(IpPacket {
        src: src.into(),
        dst: dst.into(),
        protocol: next,
        payload: &packet[offset..end],
    })
}

fn dns_question_names(packet: &[u8]) -> Vec<String> {
    if packet.len() < 12 {
        return Vec::new();
    }
    let count = u16::from_be_bytes([packet[4], packet[5]]).min(8) as usize;
    let mut offset = 12;
    let mut names = Vec::new();
    for _ in 0..count {
        let Some((name, next)) = dns_name(packet, offset, 0) else {
            break;
        };
        if next + 4 > packet.len() {
            break;
        }
        let qtype = u16::from_be_bytes([packet[next], packet[next + 1]]);
        if !name.is_empty() {
            names.push(format!("{name} [{}]", dns_type(qtype)));
        }
        offset = next + 4;
    }
    names
}

fn dns_type(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        5 => "CNAME".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        _ => qtype.to_string(),
    }
}

fn dns_name(packet: &[u8], start: usize, depth: u8) -> Option<(String, usize)> {
    if depth > 8 {
        return None;
    }
    let mut offset = start;
    let mut labels = Vec::new();
    let mut encoded_len = 0usize;
    loop {
        let length = *packet.get(offset)?;
        offset += 1;
        if length == 0 {
            break;
        }
        if length & 0xc0 == 0xc0 {
            let next = *packet.get(offset)?;
            offset += 1;
            let pointer = (((length as usize) & 0x3f) << 8) | next as usize;
            let (suffix, _) = dns_name(packet, pointer, depth + 1)?;
            labels.push(suffix);
            break;
        }
        if length > 63 || length & 0xc0 != 0 {
            return None;
        }
        let end = offset.checked_add(length as usize)?;
        let label = packet.get(offset..end)?;
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).into_owned());
        encoded_len += length as usize + 1;
        if encoded_len > 255 {
            return None;
        }
        offset = end;
    }
    Some((labels.join(".").to_ascii_lowercase(), offset))
}

fn tls_client_hello_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 9 || payload[0] != 22 || payload[1] != 3 {
        return None;
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if record_len + 5 > payload.len() || payload[5] != 1 {
        return None;
    }
    let hello_len =
        ((payload[6] as usize) << 16) | ((payload[7] as usize) << 8) | payload[8] as usize;
    let end = 9usize.checked_add(hello_len)?;
    if end > record_len + 5 || end > payload.len() {
        return None;
    }
    let mut cursor = 9usize.checked_add(2 + 32)?;
    cursor = cursor.checked_add(*payload.get(cursor)? as usize + 1)?;
    cursor = cursor.checked_add(2 + be_u16(payload, cursor)? as usize)?;
    cursor = cursor.checked_add(1 + *payload.get(cursor)? as usize)?;
    let extensions_len = be_u16(payload, cursor)? as usize;
    cursor += 2;
    let ext_end = cursor.checked_add(extensions_len)?;
    if ext_end > end {
        return None;
    }
    while cursor + 4 <= ext_end {
        let kind = be_u16(payload, cursor)?;
        let length = be_u16(payload, cursor + 2)? as usize;
        cursor += 4;
        let next = cursor.checked_add(length)?;
        if next > ext_end {
            return None;
        }
        if kind == 0 && length >= 5 {
            let list_len = be_u16(payload, cursor)? as usize;
            if list_len + 2 <= length {
                let mut name_cursor = cursor + 2;
                let list_end = name_cursor + list_len;
                while name_cursor + 3 <= list_end {
                    let name_type = payload[name_cursor];
                    let name_len = be_u16(payload, name_cursor + 1)? as usize;
                    name_cursor += 3;
                    if name_cursor + name_len > list_end {
                        return None;
                    }
                    if name_type == 0 {
                        let name = &payload[name_cursor..name_cursor + name_len];
                        if !name.is_empty()
                            && name.iter().all(|b| {
                                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
                            })
                        {
                            return Some(String::from_utf8_lossy(name).to_ascii_lowercase());
                        }
                    }
                    name_cursor += name_len;
                }
            }
        }
        cursor = next;
    }
    None
}

fn be_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn http_host(payload: &[u8]) -> Option<String> {
    let sample = payload.get(..payload.len().min(4096))?;
    let first_line_end = sample.windows(2).position(|part| part == b"\r\n")?;
    let request = &sample[..first_line_end];
    if ![
        b"GET ".as_slice(),
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
    ]
    .iter()
    .any(|method| request.starts_with(method))
    {
        return None;
    }
    for line in sample[first_line_end + 2..].split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        if line.len() > 5 && line[..5].eq_ignore_ascii_case(b"Host:") {
            let host = line[5..]
                .iter()
                .copied()
                .skip_while(|b| *b == b' ')
                .collect::<Vec<_>>();
            if !host.is_empty()
                && host
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
            {
                return Some(String::from_utf8_lossy(&host).to_ascii_lowercase());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_dns_question() {
        let packet = [
            0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
            b'o', b'r', b'g', 0, 0, 1, 0, 1,
        ];
        assert_eq!(dns_question_names(&packet), vec!["example.org [A]"]);
    }

    #[test]
    fn rejects_dns_pointer_cycle() {
        let packet = [0xc0, 0x00];
        assert!(dns_name(&packet, 0, 0).is_none());
    }

    #[test]
    fn parses_http_host() {
        assert_eq!(
            http_host(b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"),
            Some("example.org".into())
        );
        assert_eq!(http_host(b"HTTP/1.1 200 OK\r\nHost: example.org\r\n"), None);
    }

    #[test]
    fn parses_single_segment_tls_client_hello_sni() {
        let name = b"example.org";
        let mut extension = Vec::new();
        extension.extend_from_slice(&0u16.to_be_bytes());
        extension.extend_from_slice(&((5 + name.len()) as u16).to_be_bytes());
        extension.extend_from_slice(&((3 + name.len()) as u16).to_be_bytes());
        extension.push(0);
        extension.extend_from_slice(&(name.len() as u16).to_be_bytes());
        extension.extend_from_slice(name);
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.extend_from_slice(&[1, 0]);
        hello.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extension);
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&((hello.len() + 4) as u16).to_be_bytes());
        record.push(1);
        record.extend_from_slice(&[0, 0, hello.len() as u8]);
        record.extend_from_slice(&hello);
        assert_eq!(tls_client_hello_sni(&record), Some("example.org".into()));
    }

    #[test]
    fn reads_classic_pcap_and_aggregates_flow() {
        let path =
            std::env::temp_dir().join(format!("spectre-pcap-test-{}.pcap", std::process::id()));
        let mut file = File::create(&path).unwrap();
        file.write_all(&[
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ])
        .unwrap();
        let mut frame = vec![0u8; 14 + 20 + 8 + 29];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = &mut frame[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(57u16).to_be_bytes());
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[192, 0, 2, 53]);
        ip[20..22].copy_from_slice(&50000u16.to_be_bytes());
        ip[22..24].copy_from_slice(&53u16.to_be_bytes());
        ip[24..26].copy_from_slice(&37u16.to_be_bytes());
        ip[28..].copy_from_slice(&[
            0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
            b'o', b'r', b'g', 0, 0, 1, 0, 1,
        ]);
        file.write_all(&1u32.to_le_bytes()).unwrap();
        file.write_all(&0u32.to_le_bytes()).unwrap();
        file.write_all(&(frame.len() as u32).to_le_bytes()).unwrap();
        file.write_all(&(frame.len() as u32).to_le_bytes()).unwrap();
        file.write_all(&frame).unwrap();
        drop(file);
        let expected_hash = format!("{:x}", Sha256::digest(std::fs::read(&path).unwrap()));
        let events = analyze_pcap(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let summary = events
            .iter()
            .find(|event| event.kind == "pcap.summary")
            .unwrap();
        assert!(
            summary
                .evidence
                .iter()
                .any(|item| item.label == "sha256" && item.value == expected_hash)
        );
        assert!(events.iter().any(|event| event.kind == "pcap.flow"));
        let dns = events
            .iter()
            .find(|event| event.kind == "pcap.dns_question")
            .unwrap();
        assert!(dns.summary.contains("example.org"));
        assert_eq!(
            dns.timestamp,
            DateTime::<Utc>::from_timestamp(1, 0).unwrap()
        );
        assert!(dns.evidence.iter().any(|item| {
            item.label == "last_packet_utc" && item.value == "1970-01-01T00:00:01+00:00"
        }));
    }

    #[test]
    fn truncated_capture_is_an_error() {
        let path = std::env::temp_dir().join(format!(
            "spectre-pcap-truncated-{}.pcap",
            std::process::id()
        ));
        let mut file = File::create(&path).unwrap();
        file.write_all(&[
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ])
        .unwrap();
        file.write_all(&0u32.to_le_bytes()).unwrap();
        file.write_all(&0u32.to_le_bytes()).unwrap();
        file.write_all(&8u32.to_le_bytes()).unwrap();
        file.write_all(&8u32.to_le_bytes()).unwrap();
        file.write_all(&[0u8; 4]).unwrap();
        drop(file);
        let error = analyze_pcap(&path).unwrap_err();
        std::fs::remove_file(path).unwrap();
        assert!(format!("{error:#}").contains("truncated PCAP packet payload"));
    }
}
