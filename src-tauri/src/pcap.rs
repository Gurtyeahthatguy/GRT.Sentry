//! Reading a capture the user already saved, in pcap or pcapng.
//!
//! GRT Sentry never captures traffic. Given a file someone recorded with
//! tcpdump or Wireshark, it lists who talked to whom and compares every
//! address with the user's indicators. Only headers are read: the file is
//! taken a block at a time and payloads are never kept.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::Serialize;

use crate::indicators::Indicators;
use crate::state::{Action, Finding, Issue, IssueKind, IssueTarget, Severity};

/// A block bigger than this is a damaged file, not a packet.
const MAX_BLOCK: usize = 1 << 20;
const MAX_PACKETS: u64 = 50_000_000;
const MAX_FLOWS: usize = 200_000;
/// Flows the interface lists, biggest first.
const FLOWS_SHOWN: usize = 500;

/// Every packet between two endpoints on one protocol and port.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Flow {
    pub from: String,
    pub to: String,
    pub protocol: String,
    /// The lower of the two ports, which is usually the service.
    pub port: Option<u16>,
    pub packets: u64,
    pub bytes: u64,
    pub first: i64,
    pub last: i64,
    /// What the indicators say about one of the two addresses, and which.
    pub indicator: Option<String>,
    pub flagged: Option<String>,
}

#[derive(Serialize, Debug, Default)]
pub struct Capture {
    pub packets: u64,
    /// Packets that were not IP, or too short to read.
    pub other: u64,
    pub flow_count: usize,
    pub flows: Vec<Flow>,
    /// Set when a limit stopped the reading or the file was damaged.
    pub note: Option<String>,
}

#[derive(Hash, PartialEq, Eq, Clone)]
struct Key {
    a: IpAddr,
    b: IpAddr,
    protocol: u8,
    port: Option<u16>,
}

struct Packet<'a> {
    link: u32,
    time: i64,
    data: &'a [u8],
    length: u64,
}

pub fn read(path: &Path, indicators: &Indicators) -> Result<Capture, String> {
    let file = File::open(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut capture = Capture::default();
    let mut flows: HashMap<Key, Flow> = HashMap::new();

    let mut add = |packet: Packet, capture: &mut Capture| {
        capture.packets += 1;
        let Some((key, from, to)) = parse(packet.link, packet.data) else {
            capture.other += 1;
            return;
        };
        if let Some(flow) = flows.get_mut(&key) {
            flow.packets += 1;
            flow.bytes += packet.length;
            flow.first = flow.first.min(packet.time);
            flow.last = flow.last.max(packet.time);
        } else if flows.len() < MAX_FLOWS {
            let hit = [from, to].into_iter().find_map(|ip| indicators.match_ip(&ip).map(|note| (ip.to_string(), note)));
            let (flagged, indicator) = hit.map(|(ip, note)| (Some(ip), Some(note))).unwrap_or_default();
            flows.insert(
                key.clone(),
                Flow {
                    from: from.to_string(),
                    to: to.to_string(),
                    protocol: protocol_name(key.protocol),
                    port: key.port,
                    packets: 1,
                    bytes: packet.length,
                    first: packet.time,
                    last: packet.time,
                    indicator,
                    flagged,
                },
            );
        } else if capture.note.is_none() {
            capture.note = Some(format!("The capture holds more than {MAX_FLOWS} conversations; the rest were counted but not listed."));
        }
    };

    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic).map_err(|_| "The file is too short to be a capture.".to_string())?;
    let damaged = match magic {
        [0x0a, 0x0d, 0x0d, 0x0a] => read_pcapng(&mut reader, &mut capture, &mut add),
        _ => read_pcap(&mut reader, magic, &mut capture, &mut add)?,
    };
    if damaged && capture.note.is_none() {
        capture.note = Some("The file ends in the middle of a packet or is damaged; what came before was read.".to_string());
    }
    if capture.packets >= MAX_PACKETS {
        capture.note = Some(format!("Only the first {MAX_PACKETS} packets were read."));
    }

    let mut list: Vec<Flow> = flows.into_values().collect();
    capture.flow_count = list.len();
    // What matches an indicator comes first, then the biggest.
    list.sort_by(|x, y| y.indicator.is_some().cmp(&x.indicator.is_some()).then(y.bytes.cmp(&x.bytes)));
    list.truncate(FLOWS_SHOWN);
    capture.flows = list;
    Ok(capture)
}

fn read_exact(reader: &mut impl Read, length: usize) -> Option<Vec<u8>> {
    if length > MAX_BLOCK {
        return None;
    }
    let mut buffer = vec![0u8; length];
    reader.read_exact(&mut buffer).ok()?;
    Some(buffer)
}

/// The classic format. Returns whether it stopped on damage.
fn read_pcap(
    reader: &mut impl Read,
    magic: [u8; 4],
    capture: &mut Capture,
    add: &mut impl FnMut(Packet, &mut Capture),
) -> Result<bool, String> {
    let (big, nanos) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
        _ => return Err("This is not a pcap or pcapng capture.".to_string()),
    };
    let _ = nanos;
    let u32_at = |b: &[u8], at: usize| {
        let bytes = [b[at], b[at + 1], b[at + 2], b[at + 3]];
        if big { u32::from_be_bytes(bytes) } else { u32::from_le_bytes(bytes) }
    };
    let Some(header) = read_exact(reader, 20) else { return Ok(true) };
    let link = u32_at(&header, 16) & 0x0fff_ffff;

    while capture.packets < MAX_PACKETS {
        let mut record = [0u8; 16];
        match reader.read_exact(&mut record) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(_) => return Ok(true),
        }
        let time = u32_at(&record, 0) as i64;
        let included = u32_at(&record, 8) as usize;
        let length = u32_at(&record, 12) as u64;
        let Some(data) = read_exact(reader, included) else { return Ok(true) };
        add(Packet { link, time, data: &data, length }, capture);
    }
    Ok(false)
}

/// The newer format, a sequence of blocks. Returns whether it stopped on damage.
fn read_pcapng(reader: &mut impl Read, capture: &mut Capture, add: &mut impl FnMut(Packet, &mut Capture)) -> bool {
    // The section header gives the byte order; its type was already read.
    let mut big = false;
    let mut links: Vec<(u32, u64)> = Vec::new();
    let mut pending_type: Option<u32> = Some(0x0a0d_0d0a);

    while capture.packets < MAX_PACKETS {
        let block_type = match pending_type.take() {
            Some(t) => t,
            None => {
                let mut raw = [0u8; 4];
                match reader.read_exact(&mut raw) {
                    Ok(()) => {}
                    Err(_) => return false,
                }
                if big { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) }
            }
        };
        let mut raw_length = [0u8; 4];
        if reader.read_exact(&mut raw_length).is_err() {
            return true;
        }

        if block_type == 0x0a0d_0d0a {
            let mut order = [0u8; 4];
            if reader.read_exact(&mut order).is_err() {
                return true;
            }
            big = order == [0x1a, 0x2b, 0x3c, 0x4d];
            links.clear();
            let total = if big { u32::from_be_bytes(raw_length) } else { u32::from_le_bytes(raw_length) } as usize;
            if total < 12 || read_exact(reader, total - 12).is_none() {
                return true;
            }
            continue;
        }

        let total = if big { u32::from_be_bytes(raw_length) } else { u32::from_le_bytes(raw_length) } as usize;
        if total < 12 || total % 4 != 0 {
            return true;
        }
        let Some(body) = read_exact(reader, total - 8) else { return true };
        let body = &body[..body.len() - 4];
        let u16_at = |at: usize| body.get(at..at + 2).map(|b| if big { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) });
        let u32_at = |at: usize| {
            body.get(at..at + 4).map(|b| {
                let bytes = [b[0], b[1], b[2], b[3]];
                if big { u32::from_be_bytes(bytes) } else { u32::from_le_bytes(bytes) }
            })
        };

        match block_type {
            // Interface description: the link type, and the clock's resolution.
            1 => {
                let link = u16_at(0).unwrap_or(0) as u32;
                links.push((link, interface_resolution(body, big)));
            }
            // Enhanced packet.
            6 => {
                let (Some(interface), Some(high), Some(low), Some(included), Some(length)) =
                    (u32_at(0), u32_at(4), u32_at(8), u32_at(12), u32_at(16))
                else {
                    return true;
                };
                let Some(&(link, per_second)) = links.get(interface as usize) else { continue };
                let Some(data) = body.get(20..20 + included as usize) else { return true };
                let ticks = ((high as u64) << 32) | low as u64;
                let time = (ticks / per_second.max(1)) as i64;
                add(Packet { link, time, data, length: length as u64 }, capture);
            }
            // Simple packet: no time, and always the first interface.
            3 => {
                let Some(length) = u32_at(0) else { return true };
                let Some(&(link, _)) = links.first() else { continue };
                let data = &body[4.min(body.len())..];
                let data = &data[..data.len().min(length as usize)];
                add(Packet { link, time: 0, data, length: length as u64 }, capture);
            }
            _ => {}
        }
    }
    false
}

/// Ticks per second, from the interface's `if_tsresol` option; microseconds by default.
fn interface_resolution(body: &[u8], big: bool) -> u64 {
    let mut at = 8;
    while at + 4 <= body.len() {
        let read16 = |i: usize| if big { u16::from_be_bytes([body[i], body[i + 1]]) } else { u16::from_le_bytes([body[i], body[i + 1]]) };
        let (code, length) = (read16(at), read16(at + 2) as usize);
        if code == 0 {
            break;
        }
        if code == 9 && length >= 1 {
            if let Some(&value) = body.get(at + 4) {
                let exponent = (value & 0x7f) as u32;
                return if value & 0x80 == 0 { 10u64.saturating_pow(exponent) } else { 1u64 << exponent.min(63) };
            }
        }
        at += 4 + length.div_ceil(4) * 4;
    }
    1_000_000
}

/// Where the IP header starts for a link type, and which version it is.
fn ip_payload(link: u32, data: &[u8]) -> Option<&[u8]> {
    match link {
        // Ethernet, with up to two VLAN tags.
        1 => {
            let mut at = 12;
            loop {
                let ethertype = u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]);
                match ethertype {
                    0x8100 | 0x88a8 => at += 4,
                    0x0800 | 0x86dd => return data.get(at + 2..),
                    _ => return None,
                }
            }
        }
        // BSD loopback: four bytes of address family, in either order.
        0 | 108 => data.get(4..),
        // Raw IP.
        101 | 228 | 229 | 12 | 14 => Some(data),
        // Linux cooked capture, both versions.
        113 => data.get(16..),
        276 => data.get(20..),
        _ => None,
    }
}

fn parse(link: u32, data: &[u8]) -> Option<(Key, IpAddr, IpAddr)> {
    let ip = ip_payload(link, data)?;
    let version = ip.first()? >> 4;
    let (from, to, protocol, rest): (IpAddr, IpAddr, u8, Option<&[u8]>) = match version {
        4 => {
            let header = ((ip.first()? & 0x0f) as usize) * 4;
            let from = Ipv4Addr::new(*ip.get(12)?, ip[13], ip[14], ip[15]);
            let to = Ipv4Addr::new(*ip.get(16)?, *ip.get(17)?, *ip.get(18)?, *ip.get(19)?);
            let fragment = u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]) & 0x1fff;
            let rest = if fragment == 0 { ip.get(header..) } else { None };
            (from.into(), to.into(), *ip.get(9)?, rest)
        }
        6 => {
            let from: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
            let to: [u8; 16] = ip.get(24..40)?.try_into().ok()?;
            let (mut next, mut at) = (*ip.get(6)?, 40usize);
            // Hop-by-hop, routing, fragment and destination options.
            while matches!(next, 0 | 43 | 44 | 60) {
                let length = if next == 44 { 8 } else { (*ip.get(at + 1)? as usize + 1) * 8 };
                next = *ip.get(at)?;
                at += length;
            }
            (Ipv6Addr::from(from).into(), Ipv6Addr::from(to).into(), next, ip.get(at..))
        }
        _ => return None,
    };
    let port = match (protocol, rest) {
        (6 | 17, Some(ports)) if ports.len() >= 4 => {
            let source = u16::from_be_bytes([ports[0], ports[1]]);
            let destination = u16::from_be_bytes([ports[2], ports[3]]);
            Some(source.min(destination))
        }
        _ => None,
    };
    // One flow for both directions.
    let (a, b) = if from <= to { (from, to) } else { (to, from) };
    Some((Key { a, b, protocol, port }, from, to))
}

fn protocol_name(number: u8) -> String {
    match number {
        6 => "tcp".into(),
        17 => "udp".into(),
        1 => "icmp".into(),
        58 => "icmpv6".into(),
        other => format!("ip protocol {other}"),
    }
}

/// An issue for every address in the capture that the indicators list.
pub fn findings(capture: &Capture, name: &str) -> Vec<Finding> {
    let mut by_address: HashMap<String, (String, u64)> = HashMap::new();
    for flow in &capture.flows {
        let (Some(address), Some(note)) = (&flow.flagged, &flow.indicator) else { continue };
        by_address.entry(address.clone()).or_insert((note.clone(), 0)).1 += flow.packets;
    }
    by_address
        .into_iter()
        .map(|(address, (note, packets))| {
            Finding::new(
                Issue {
                    kind: IssueKind::SuspiciousConnection,
                    severity: Severity::Critical,
                    title: format!("The capture {name} talks to {address}, from your indicators"),
                    location: address.clone(),
                    detail: Some(format!(
                        "{packets} packets in the capture went to or came from {address}. Your indicators file lists it: {note}"
                    )),
                    actions: vec![Action::new("block_ip", "Block address", true), Action::ignore()],
                    ..Default::default()
                },
                IssueTarget::Connection { ip: address, pid: None, process: None },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp(from: [u8; 4], to: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend([0x08, 0x00]);
        let mut ip = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
        ip.extend(from);
        ip.extend(to);
        ip.extend(sport.to_be_bytes());
        ip.extend(dport.to_be_bytes());
        ip.extend([0u8; 16]);
        frame.extend(ip);
        frame
    }

    fn classic(packets: &[Vec<u8>]) -> Vec<u8> {
        let mut file = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        file.extend([0u8; 8]);
        file.extend(65535u32.to_le_bytes());
        file.extend(1u32.to_le_bytes());
        for (n, packet) in packets.iter().enumerate() {
            file.extend((1_787_000_000u32 + n as u32).to_le_bytes());
            file.extend(0u32.to_le_bytes());
            file.extend((packet.len() as u32).to_le_bytes());
            file.extend((packet.len() as u32).to_le_bytes());
            file.extend(packet);
        }
        file
    }

    fn pcapng(packets: &[Vec<u8>]) -> Vec<u8> {
        let block = |kind: u32, body: Vec<u8>| {
            let mut body = body;
            while body.len() % 4 != 0 {
                body.push(0);
            }
            let total = (body.len() + 12) as u32;
            let mut out = kind.to_le_bytes().to_vec();
            out.extend(total.to_le_bytes());
            out.extend(body);
            out.extend(total.to_le_bytes());
            out
        };
        let mut section = vec![0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0];
        section.extend((-1i64).to_le_bytes());
        let mut file = block(0x0a0d_0d0a, section);
        let mut interface = vec![1, 0, 0, 0];
        interface.extend(0u32.to_le_bytes());
        file.extend(block(1, interface));
        for packet in packets {
            let micros: u64 = 1_787_000_000 * 1_000_000;
            let mut body = 0u32.to_le_bytes().to_vec();
            body.extend(((micros >> 32) as u32).to_le_bytes());
            body.extend((micros as u32).to_le_bytes());
            body.extend((packet.len() as u32).to_le_bytes());
            body.extend((packet.len() as u32).to_le_bytes());
            body.extend(packet);
            file.extend(block(6, body));
        }
        file
    }

    fn indicators() -> Indicators {
        Indicators::parse("203.0.113.66 known command server\n")
    }

    fn sample() -> Vec<Vec<u8>> {
        vec![
            ipv4_tcp([192, 168, 1, 20], [203, 0, 113, 66], 50000, 443),
            ipv4_tcp([203, 0, 113, 66], [192, 168, 1, 20], 443, 50000),
            ipv4_tcp([192, 168, 1, 20], [198, 51, 100, 1], 50001, 80),
            vec![0u8; 20],
        ]
    }

    fn read_bytes(bytes: Vec<u8>) -> Capture {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.pcap");
        std::fs::write(&path, bytes).unwrap();
        read(&path, &indicators()).unwrap()
    }

    #[test]
    fn both_formats_give_the_same_conversations() {
        for capture in [read_bytes(classic(&sample())), read_bytes(pcapng(&sample()))] {
            assert_eq!(capture.packets, 4);
            assert_eq!(capture.other, 1, "the frame that is not IP is counted apart");
            assert_eq!(capture.flow_count, 2, "both directions are one conversation");
            let first = &capture.flows[0];
            assert!(first.indicator.as_deref().is_some_and(|n| n.contains("command server")));
            assert_eq!(first.packets, 2);
            assert_eq!(first.port, Some(443));
            assert_eq!(first.first, 1_787_000_000);
            assert!(capture.note.is_none());
        }
    }

    #[test]
    fn an_address_from_the_indicators_becomes_one_issue() {
        let capture = read_bytes(classic(&sample()));
        let found = findings(&capture, "c.pcap");
        assert_eq!(found.len(), 1, "the local side of the conversation is not reported");
        assert_eq!(found[0].issue.location, "203.0.113.66");
        assert_eq!(found[0].issue.severity, Severity::Critical);
    }

    #[test]
    fn a_cut_file_keeps_what_came_before() {
        let mut bytes = classic(&sample());
        bytes.truncate(bytes.len() - 10);
        let capture = read_bytes(bytes);
        assert_eq!(capture.packets, 3);
        assert!(capture.note.is_some());
    }

    #[test]
    fn something_that_is_not_a_capture_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.pcap");
        std::fs::write(&path, b"hello there").unwrap();
        assert!(read(&path, &indicators()).unwrap_err().contains("not a pcap"));
    }
}
