//! TCP connect scanner.
//!
//! A full connect — not a half-open SYN scan — so every hit is unambiguous: the
//! service really accepted a connection. This also needs no elevated privileges
//! on any of the three target platforms, which is the whole point.

use crate::netutil::service_name;
use crate::types::PortInfo;
use futures::stream::{self, StreamExt};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    Open,
    /// The host actively refused — it is demonstrably up even if it ignores ICMP.
    Refused,
    Filtered,
}

pub async fn probe(ip: Ipv4Addr, port: u16, timeout: Duration) -> ProbeOutcome {
    let addr = SocketAddrV4::new(ip, port);
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            // Drop immediately; the banner phase reconnects for the ports it wants.
            drop(stream);
            ProbeOutcome::Open
        }
        Ok(Err(err)) => {
            if err.kind() == std::io::ErrorKind::ConnectionRefused {
                ProbeOutcome::Refused
            } else {
                ProbeOutcome::Filtered
            }
        }
        Err(_) => ProbeOutcome::Filtered,
    }
}

#[derive(Debug, Default)]
pub struct PortScanResult {
    pub open: HashMap<Ipv4Addr, Vec<PortInfo>>,
    pub refused_hosts: HashSet<Ipv4Addr>,
}

pub async fn scan<F>(
    ips: &[Ipv4Addr],
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
    mut on_progress: F,
) -> PortScanResult
where
    F: FnMut(u64, u64) + Send,
{
    let total = (ips.len() as u64) * (ports.len() as u64);
    let done = Arc::new(AtomicU64::new(0));

    let tasks: Vec<(Ipv4Addr, u16)> = ips
        .iter()
        .flat_map(|ip| ports.iter().map(move |port| (*ip, *port)))
        .collect();

    let counter = Arc::clone(&done);
    let results = stream::iter(tasks)
        .map(move |(ip, port)| {
            let counter = Arc::clone(&counter);
            async move {
                let outcome = probe(ip, port, timeout).await;
                let seen = counter.fetch_add(1, Ordering::Relaxed) + 1;
                (ip, port, outcome, seen)
            }
        })
        .buffer_unordered(concurrency.max(1))
        .collect::<Vec<_>>()
        .await;

    let mut out = PortScanResult::default();
    let mut last_reported = 0u64;

    for (ip, port, outcome, seen) in results {
        match outcome {
            ProbeOutcome::Open => {
                out.open.entry(ip).or_default().push(PortInfo {
                    port,
                    protocol: "tcp".into(),
                    service: service_name(port).map(|s| s.to_string()),
                    banner: None,
                });
            }
            ProbeOutcome::Refused => {
                out.refused_hosts.insert(ip);
            }
            ProbeOutcome::Filtered => {}
        }

        // Report at a coarse granularity: the UI cannot use 20k updates.
        if seen.saturating_sub(last_reported) >= 100 || seen == total {
            last_reported = seen;
            on_progress(seen, total);
        }
    }

    on_progress(total, total);

    for list in out.open.values_mut() {
        list.sort_by_key(|p| p.port);
    }

    out
}

/// Single-host scan backing the on-demand deep scan in the UI.
pub async fn scan_host(
    ip: Ipv4Addr,
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
) -> Vec<PortInfo> {
    let result = scan(&[ip], ports, concurrency, timeout, |_, _| {}).await;
    result.open.get(&ip).cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn detects_an_open_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let outcome = probe(Ipv4Addr::LOCALHOST, port, Duration::from_secs(2)).await;
        assert_eq!(outcome, ProbeOutcome::Open);
    }

    #[tokio::test]
    async fn reports_refused_separately_from_filtered() {
        // Binding then dropping frees the port, so connecting is actively refused.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let outcome = probe(Ipv4Addr::LOCALHOST, port, Duration::from_secs(2)).await;
        assert_eq!(
            outcome,
            ProbeOutcome::Refused,
            "a refused connection proves the host is up and must not be reported as filtered"
        );
    }

    #[tokio::test]
    async fn scan_collects_open_ports_and_reports_progress() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        let mut last = (0u64, 0u64);
        let result = scan(
            &[Ipv4Addr::LOCALHOST],
            &[port],
            16,
            Duration::from_secs(2),
            |done, total| last = (done, total),
        )
        .await;

        assert_eq!(result.open.get(&Ipv4Addr::LOCALHOST).unwrap()[0].port, port);
        assert_eq!(last, (1, 1), "progress must finish at 100%");
    }
}
