//! Minimal DNS wire-format reader/writer.
//!
//! Shared by the mDNS responder-discovery and the reverse-DNS/DNS-timing probes.
//! Only the record types this app actually consumes are decoded (A, PTR, SRV,
//! TXT); anything else is skipped by length so an unknown record never derails
//! parsing of the rest of the packet.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_ANY: u16 = 255;
pub const CLASS_IN: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Ptr(String),
    Txt(Vec<String>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Other,
}

#[derive(Debug, Clone)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub data: RData,
}

#[derive(Debug, Clone, Default)]
pub struct Message {
    pub id: u16,
    pub questions: Vec<(String, u16)>,
    pub records: Vec<Record>,
    /// True when the RCODE indicates the server refused or failed the query.
    pub rcode: u8,
}

/* -------------------------------------------------------------------- writer */

pub fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        // Labels are length-prefixed with a single byte, so 63 is the hard cap.
        let len = bytes.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
}

pub fn build_query(id: u16, name: &str, rtype: u16, recursion: bool) -> Vec<u8> {
    build_query_with_class(id, name, rtype, CLASS_IN, recursion)
}

/// mDNS "QU" bit — the top bit of the question's class field asks responders to
/// reply **unicast** to our source port instead of to the multicast group.
///
/// This matters because port 5353 is usually already held by a system responder
/// (avahi, mDNSResponder, Bonjour) and often by browsers too. When we cannot own
/// that port, multicast answers are not reliably delivered to us, and a
/// multicast-only query sees almost nothing. Asking for a unicast reply makes
/// discovery work from an ephemeral port.
pub const UNICAST_RESPONSE: u16 = 0x8000;

pub fn build_mdns_query(name: &str, rtype: u16) -> Vec<u8> {
    build_query_with_class(0, name, rtype, UNICAST_RESPONSE | CLASS_IN, false)
}

pub fn build_query_with_class(
    id: u16,
    name: &str,
    rtype: u16,
    qclass: u16,
    recursion: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    let flags: u16 = if recursion { 0x0100 } else { 0x0000 };
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(name, &mut out);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&qclass.to_be_bytes());
    out
}

/* -------------------------------------------------------------------- reader */

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn u8(&mut self) -> Option<u8> {
        let value = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(value)
    }

    fn u16(&mut self) -> Option<u16> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Some((hi << 8) | lo)
    }

    fn u32(&mut self) -> Option<u32> {
        let a = self.u16()? as u32;
        let b = self.u16()? as u32;
        Some((a << 16) | b)
    }

    fn slice(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let out = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    /// Decodes a possibly-compressed name.
    ///
    /// Compression pointers can legally point backwards, and a malformed packet
    /// can make them point in a loop — a hard-capped jump budget is what keeps a
    /// hostile or corrupt response from hanging the scan.
    fn name(&mut self) -> Option<String> {
        let mut labels: Vec<String> = Vec::new();
        let mut jumps = 0;
        let mut pos = self.pos;
        let mut advanced = false;

        loop {
            let len = *self.buf.get(pos)? as usize;

            if len == 0 {
                pos += 1;
                if !advanced {
                    self.pos = pos;
                }
                break;
            }

            if len & 0xC0 == 0xC0 {
                let lo = *self.buf.get(pos + 1)? as usize;
                let target = ((len & 0x3F) << 8) | lo;

                if !advanced {
                    self.pos = pos + 2;
                    advanced = true;
                }

                jumps += 1;
                if jumps > 16 {
                    return None;
                }
                pos = target;
                continue;
            }

            let start = pos + 1;
            let end = start.checked_add(len)?;
            let label = self.buf.get(start..end)?;
            labels.push(String::from_utf8_lossy(label).into_owned());
            pos = end;

            if !advanced {
                self.pos = pos;
            }
        }

        Some(labels.join("."))
    }
}

pub fn parse(buf: &[u8]) -> Option<Message> {
    let mut reader = Reader::new(buf);

    let id = reader.u16()?;
    let flags = reader.u16()?;
    let qdcount = reader.u16()?;
    let ancount = reader.u16()?;
    let nscount = reader.u16()?;
    let arcount = reader.u16()?;

    let mut message = Message {
        id,
        rcode: (flags & 0x000F) as u8,
        ..Default::default()
    };

    for _ in 0..qdcount {
        let name = reader.name()?;
        let rtype = reader.u16()?;
        let _class = reader.u16()?;
        message.questions.push((name, rtype));
    }

    // Answers, authorities and additionals are all treated the same: mDNS
    // responders routinely put the SRV/TXT/A records we need in additionals.
    let total = ancount as usize + nscount as usize + arcount as usize;

    for _ in 0..total {
        let Some(name) = reader.name() else { break };
        let Some(rtype) = reader.u16() else { break };
        let Some(_class) = reader.u16() else { break };
        let Some(_ttl) = reader.u32() else { break };
        let Some(rdlen) = reader.u16() else { break };

        let rdata_start = reader.pos;
        let Some(rdata) = reader.slice(rdlen as usize) else {
            break;
        };

        let data = match rtype {
            TYPE_A if rdata.len() >= 4 => {
                RData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))
            }
            TYPE_PTR => {
                // Names inside RDATA may use compression relative to the whole packet.
                let mut sub = Reader {
                    buf,
                    pos: rdata_start,
                };
                match sub.name() {
                    Some(name) => RData::Ptr(name),
                    None => RData::Other,
                }
            }
            TYPE_SRV if rdata.len() >= 6 => {
                let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
                let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
                let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                let mut sub = Reader {
                    buf,
                    pos: rdata_start + 6,
                };
                let target = sub.name().unwrap_or_default();
                RData::Srv {
                    priority,
                    weight,
                    port,
                    target,
                }
            }
            TYPE_TXT => {
                let mut strings = Vec::new();
                let mut offset = 0;
                while offset < rdata.len() {
                    let len = rdata[offset] as usize;
                    offset += 1;
                    if offset + len > rdata.len() {
                        break;
                    }
                    strings
                        .push(String::from_utf8_lossy(&rdata[offset..offset + len]).into_owned());
                    offset += len;
                }
                RData::Txt(strings)
            }
            _ => RData::Other,
        };

        message.records.push(Record { name, rtype, data });
    }

    Some(message)
}

/// Splits DNS-SD TXT strings into key/value pairs. A string with no `=` is a
/// valueless flag, which the spec permits.
pub fn txt_to_map(strings: &[String]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for entry in strings {
        match entry.split_once('=') {
            Some((key, value)) => {
                map.insert(key.trim().to_string(), value.to_string());
            }
            None => {
                let key = entry.trim();
                if !key.is_empty() {
                    map.insert(key.to_string(), String::new());
                }
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_query() {
        let query = build_query(0x1234, "example.com", TYPE_A, true);
        let parsed = parse(&query).expect("query should parse");
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].0, "example.com");
        assert_eq!(parsed.questions[0].1, TYPE_A);
    }

    #[test]
    fn decodes_compressed_names() {
        // Header + question "a.local" then an A record whose name is a pointer to it.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u16.to_be_bytes()); // id
        buf.extend_from_slice(&0x8400u16.to_be_bytes()); // flags: response, AA
        buf.extend_from_slice(&1u16.to_be_bytes()); // qd
        buf.extend_from_slice(&1u16.to_be_bytes()); // an
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        let name_offset = buf.len();
        encode_name("a.local", &mut buf);
        buf.extend_from_slice(&TYPE_A.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());

        // Answer: pointer to the question name.
        buf.push(0xC0);
        buf.push(name_offset as u8);
        buf.extend_from_slice(&TYPE_A.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&120u32.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[10, 0, 3, 22]);

        let parsed = parse(&buf).expect("should parse");
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].name, "a.local");
        assert_eq!(
            parsed.records[0].data,
            RData::A(Ipv4Addr::new(10, 0, 3, 22))
        );
    }

    #[test]
    fn a_compression_loop_terminates_instead_of_hanging() {
        // A pointer that points at itself must be rejected, not looped on.
        let mut buf = vec![0u8; 12];
        buf[4] = 0; // qdcount hi
        buf[5] = 1; // qdcount lo
        let offset = buf.len();
        buf.push(0xC0);
        buf.push(offset as u8); // points to itself
        buf.extend_from_slice(&TYPE_A.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());

        // Must return rather than spin forever.
        let _ = parse(&buf);
    }

    #[test]
    fn parses_txt_key_value_pairs_and_bare_flags() {
        let strings = vec![
            "platform=ESP32".to_string(),
            "board=esp32dev".to_string(),
            "flag".to_string(),
            "empty=".to_string(),
        ];
        let map = txt_to_map(&strings);
        assert_eq!(map.get("platform").unwrap(), "ESP32");
        assert_eq!(map.get("board").unwrap(), "esp32dev");
        assert_eq!(map.get("flag").unwrap(), "");
        assert_eq!(map.get("empty").unwrap(), "");
    }

    #[test]
    fn truncated_packets_do_not_panic() {
        for len in 0..12 {
            let _ = parse(&vec![0u8; len]);
        }
        let _ = parse(&[0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, b'a']);
    }
}
