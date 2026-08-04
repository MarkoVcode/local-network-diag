//! NetBIOS node-status query (UDP/137).
//!
//! Windows machines, Samba servers and many NAS boxes answer this with their
//! machine name, workgroup and adapter MAC — often the only friendly name for a
//! device that publishes no mDNS.

use crate::types::NetbiosResult;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;

/// NetBIOS "first-level encoding": each byte of the 16-byte name becomes two
/// bytes, one per nibble, offset from 'A'. The wildcard name `*` padded with
/// NULs encodes to `CKAAAA...`.
fn encode_netbios_name(name: &str) -> Vec<u8> {
    let mut padded = [0u8; 16];
    for (i, byte) in name.bytes().take(16).enumerate() {
        padded[i] = byte;
    }

    let mut out = Vec::with_capacity(34);
    out.push(32);
    for byte in padded {
        out.push(b'A' + (byte >> 4));
        out.push(b'A' + (byte & 0x0F));
    }
    out.push(0);
    out
}

fn build_query(transaction_id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(50);
    out.extend_from_slice(&transaction_id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // flags: standard query
    out.extend_from_slice(&1u16.to_be_bytes()); // questions
    out.extend_from_slice(&0u16.to_be_bytes()); // answers
    out.extend_from_slice(&0u16.to_be_bytes()); // authority
    out.extend_from_slice(&0u16.to_be_bytes()); // additional
    out.extend_from_slice(&encode_netbios_name("*"));
    out.extend_from_slice(&0x0021u16.to_be_bytes()); // NBSTAT
    out.extend_from_slice(&0x0001u16.to_be_bytes()); // class IN
    out
}

/// NetBIOS suffixes: 0x00 workstation, 0x20 file server, 0x1e browser group.
pub(crate) fn parse_response(buf: &[u8]) -> Option<NetbiosResult> {
    // 12-byte header + 34-byte encoded question name + 4 bytes type/class,
    // then the answer RR header: 34-byte name + type + class + ttl + rdlength.
    let mut offset = 12 + 34 + 4 + 34 + 2 + 2 + 4 + 2;

    let count = *buf.get(offset)? as usize;
    offset += 1;

    let mut names = Vec::new();
    let mut workgroup = None;

    for _ in 0..count {
        let entry = buf.get(offset..offset + 18)?;
        let raw = String::from_utf8_lossy(&entry[..15]).trim().to_string();
        let suffix = entry[15];
        let flags = u16::from_be_bytes([entry[16], entry[17]]);
        let is_group = flags & 0x8000 != 0;
        offset += 18;

        if raw.is_empty() || raw.contains(' ') || !raw.is_ascii() {
            continue;
        }

        if is_group {
            if workgroup.is_none() && (suffix == 0x00 || suffix == 0x1e) {
                workgroup = Some(raw);
            }
        } else if (suffix == 0x00 || suffix == 0x20) && !names.contains(&raw) {
            names.push(raw);
        }
    }

    // The adapter MAC trails the name list.
    let mac = buf.get(offset..offset + 6).and_then(|bytes| {
        if bytes.iter().all(|b| *b == 0) {
            return None;
        }
        let text = bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        if crate::netutil::is_meaningless_mac(&text) {
            None
        } else {
            Some(text)
        }
    });

    if names.is_empty() && workgroup.is_none() {
        return None;
    }

    Some(NetbiosResult {
        names,
        workgroup,
        mac,
    })
}

async fn query_host(ip: Ipv4Addr, timeout: Duration) -> Option<NetbiosResult> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .await
        .ok()?;
    let query = build_query(rand_id());
    socket
        .send_to(&query, SocketAddrV4::new(ip, 137))
        .await
        .ok()?;

    let mut buf = vec![0u8; 2048];
    let (len, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_response(&buf[..len])
}

/// Small non-cryptographic id source — this is a transaction tag, not a secret,
/// and avoiding an rng dependency keeps the build lean.
fn rand_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos ^ (nanos >> 16)) as u16
}

pub async fn discover(
    ips: &[Ipv4Addr],
    concurrency: usize,
    timeout: Duration,
) -> Vec<(Ipv4Addr, NetbiosResult)> {
    use futures::stream::{self, StreamExt};

    stream::iter(ips.iter().copied())
        .map(|ip| async move { query_host(ip, timeout).await.map(|result| (ip, result)) })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|result| async move { result })
        .collect()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_wildcard_name_per_rfc1001() {
        let encoded = encode_netbios_name("*");
        assert_eq!(encoded[0], 32, "length prefix");
        assert_eq!(&encoded[1..3], b"CK", "'*' is 0x2A -> 'C','K'");
        assert!(
            encoded[3..33].iter().all(|b| *b == b'A'),
            "NUL padding encodes to 'A'"
        );
        assert_eq!(encoded[33], 0, "null terminator");
    }

    #[test]
    fn parses_a_node_status_response() {
        let mut buf = vec![0u8; 12 + 34 + 4 + 34 + 2 + 2 + 4 + 2];
        // Two names: a workstation and a group, then the adapter MAC.
        buf.push(2);

        let mut entry = |name: &str, suffix: u8, group: bool| {
            let mut padded = [b' '; 15];
            for (i, b) in name.bytes().take(15).enumerate() {
                padded[i] = b;
            }
            buf.extend_from_slice(&padded);
            buf.push(suffix);
            let flags: u16 = if group { 0x8000 } else { 0x0400 };
            buf.extend_from_slice(&flags.to_be_bytes());
        };

        entry("NAS01", 0x20, false);
        entry("WORKGROUP", 0x00, true);
        buf.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let result = parse_response(&buf).expect("should parse");
        assert_eq!(result.names, vec!["NAS01".to_string()]);
        assert_eq!(result.workgroup.as_deref(), Some("WORKGROUP"));
        assert_eq!(result.mac.as_deref(), Some("00:11:22:33:44:55"));
    }

    #[test]
    fn truncated_responses_return_none_instead_of_panicking() {
        for len in 0..100 {
            let _ = parse_response(&vec![0u8; len]);
        }
    }

    #[test]
    fn all_zero_adapter_mac_is_discarded() {
        let mut buf = vec![0u8; 12 + 34 + 4 + 34 + 2 + 2 + 4 + 2];
        buf.push(1);
        let mut padded = [b' '; 15];
        padded[..3].copy_from_slice(b"PC1");
        buf.extend_from_slice(&padded);
        buf.push(0x00);
        buf.extend_from_slice(&0x0400u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 6]);

        let result = parse_response(&buf).expect("should parse");
        assert!(result.mac.is_none(), "an all-zero MAC carries no identity");
    }
}
