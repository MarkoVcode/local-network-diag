//! DNS queries over UDP, used for resolver timing and reverse lookups.
//!
//! Written directly on the wire format rather than pulling in a resolver crate:
//! the engine needs to time a *specific* server rather than "whatever the system
//! resolver decides", which most high-level resolvers make awkward.

use super::dnsmsg::{self, RData};
use futures::stream::{self, StreamExt};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

pub struct QueryOutcome {
    pub answers: Vec<String>,
    pub elapsed: Duration,
    pub rcode: u8,
}

async fn query(
    server: IpAddr,
    name: &str,
    rtype: u16,
    timeout: Duration,
) -> Result<QueryOutcome, String> {
    let bind: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };

    let socket = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
    let id = (Instant::now().elapsed().subsec_nanos() as u16) ^ 0x5EED;
    let packet = dnsmsg::build_query(id, name, rtype, true);

    let started = Instant::now();
    socket
        .send_to(&packet, SocketAddr::new(server, 53))
        .await
        .map_err(|e| e.to_string())?;

    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| e.to_string())?;

    let elapsed = started.elapsed();
    let message = dnsmsg::parse(&buf[..len]).ok_or_else(|| "malformed response".to_string())?;

    let answers = message
        .records
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(addr) => Some(addr.to_string()),
            RData::Ptr(name) => Some(name.trim_end_matches('.').to_string()),
            _ => None,
        })
        .collect();

    Ok(QueryOutcome {
        answers,
        elapsed,
        rcode: message.rcode,
    })
}

pub async fn resolve_a(
    server: IpAddr,
    name: &str,
    timeout: Duration,
) -> Result<QueryOutcome, String> {
    query(server, name, dnsmsg::TYPE_A, timeout).await
}

/// Reverse lookup for one address against a specific server.
pub async fn reverse(server: IpAddr, ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let octets = ip.octets();
    let name = format!(
        "{}.{}.{}.{}.in-addr.arpa",
        octets[3], octets[2], octets[1], octets[0]
    );

    let outcome = query(server, &name, dnsmsg::TYPE_PTR, timeout).await.ok()?;
    outcome.answers.into_iter().next()
}

/// Reverse-resolves many addresses against the configured resolvers.
///
/// Home routers commonly answer PTR for their own DHCP clients, which is often
/// the only name available for a device that publishes no mDNS.
pub async fn reverse_lookup_many(
    ips: &[Ipv4Addr],
    servers: &[String],
    concurrency: usize,
    timeout: Duration,
) -> Vec<(Ipv4Addr, String)> {
    let resolvers: Vec<IpAddr> = servers
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();

    if resolvers.is_empty() {
        return Vec::new();
    }

    stream::iter(ips.iter().copied())
        .map(|ip| {
            let resolvers = resolvers.clone();
            async move {
                for server in resolvers {
                    if let Some(name) = reverse(server, ip, timeout).await {
                        if !name.is_empty() {
                            return Some((ip, name));
                        }
                    }
                }
                None
            }
        })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|result| async move { result })
        .collect()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn times_out_cleanly_against_a_blackhole_server() {
        // 192.0.2.0/24 is TEST-NET-1 and never routes anywhere.
        let result = resolve_a(
            "192.0.2.1".parse().unwrap(),
            "example.com",
            Duration::from_millis(300),
        )
        .await;
        assert!(
            result.is_err(),
            "an unreachable resolver must error rather than hang"
        );
    }
}
