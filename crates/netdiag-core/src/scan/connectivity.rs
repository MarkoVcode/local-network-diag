//! Connectivity health.
//!
//! Separates the three places "the internet is slow" actually originates — the
//! local hop to the gateway, name resolution, and the path beyond — so the
//! symptom can be attributed rather than guessed at.

use crate::exec::run;
use crate::platform;
use crate::scan::dns;
use crate::types::{ConnectivityInfo, DnsTiming, LatencyStats, ProbeResult};
use std::net::IpAddr;
use std::time::Duration;

const WAN_TARGETS: &[(&str, &str)] = &[("1.1.1.1", "Cloudflare DNS"), ("8.8.8.8", "Google DNS")];

/// Parses the statistics block `ping` prints regardless of loss, on any platform.
pub(crate) fn parse_latency(
    target: &str,
    label: &str,
    output: &str,
    requested: u32,
) -> LatencyStats {
    let lower = output.to_ascii_lowercase();

    let sent = extract_before(&lower, " packets transmitted")
        .or_else(|| extract_after(&lower, "sent = "))
        .unwrap_or(requested);

    let received = extract_before(&lower, " received")
        .or_else(|| extract_after(&lower, "received = "))
        .unwrap_or(0);

    let loss_percent = if let Some(index) = lower.find("% packet loss") {
        lower[..index]
            .rsplit([' ', ','])
            .next()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or_else(|| default_loss(sent, received))
    } else if let Some(index) = lower.find("% loss") {
        lower[..index]
            .rsplit(['(', ' '])
            .next()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or_else(|| default_loss(sent, received))
    } else {
        default_loss(sent, received)
    };

    // Unix: "rtt min/avg/max/mdev = 1.2/1.3/1.4/0.1 ms"
    let (min_ms, avg_ms, max_ms, jitter_ms) = parse_unix_rtt(output)
        .unwrap_or_else(|| parse_windows_rtt(output).unwrap_or((None, None, None, None)));

    // Per-reply samples for the sparkline.
    let samples = collect_samples(output);

    LatencyStats {
        target: target.to_string(),
        label: label.to_string(),
        sent,
        received,
        loss_percent,
        min_ms,
        avg_ms,
        max_ms,
        jitter_ms,
        samples,
    }
}

fn default_loss(sent: u32, received: u32) -> f64 {
    if sent == 0 {
        100.0
    } else {
        ((sent.saturating_sub(received)) as f64 / sent as f64) * 100.0
    }
}

fn extract_before(text: &str, marker: &str) -> Option<u32> {
    let index = text.find(marker)?;
    text[..index].split_whitespace().last()?.parse().ok()
}

fn extract_after(text: &str, marker: &str) -> Option<u32> {
    let index = text.find(marker)? + marker.len();
    let digits: String = text[index..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

type RttTuple = (Option<f64>, Option<f64>, Option<f64>, Option<f64>);

fn parse_unix_rtt(output: &str) -> Option<RttTuple> {
    let index = output.find(" = ")?;
    let rest = &output[index + 3..];
    let numbers: Vec<f64> = rest
        .split_whitespace()
        .next()?
        .split('/')
        .filter_map(|n| n.parse::<f64>().ok())
        .collect();

    if numbers.len() < 3 {
        return None;
    }
    Some((
        Some(numbers[0]),
        Some(numbers[1]),
        Some(numbers[2]),
        numbers.get(3).copied(),
    ))
}

fn parse_windows_rtt(output: &str) -> Option<RttTuple> {
    let find = |marker: &str| -> Option<f64> {
        let index = output.find(marker)? + marker.len();
        let digits: String = output[index..]
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        digits.parse().ok()
    };

    let min = find("Minimum = ");
    let avg = find("Average = ");
    let max = find("Maximum = ");

    if min.is_none() && avg.is_none() {
        return None;
    }

    // Windows reports no deviation figure; derive spread as a jitter proxy so
    // the field is populated consistently across platforms.
    let jitter = match (min, max) {
        (Some(lo), Some(hi)) => Some(hi - lo),
        _ => None,
    };

    Some((min, avg, max, jitter))
}

fn collect_samples(output: &str) -> Vec<f64> {
    let mut samples = Vec::new();
    for marker in ["time=", "time<"] {
        let mut rest = output;
        while let Some(index) = rest.find(marker) {
            let after = &rest[index + marker.len()..];
            let digits: String = after
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if let Ok(value) = digits.parse::<f64>() {
                samples.push(value);
            }
            rest = after;
        }
    }
    samples
}

pub async fn measure_latency(target: &str, label: &str, count: u32) -> LatencyStats {
    let args = platform::ping_args(target, count, 2);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let timeout = Duration::from_secs((count as u64) * 2 + 8);

    let result = run("ping", &arg_refs, timeout).await;
    let output = if result.stdout.trim().is_empty() {
        result.stderr
    } else {
        result.stdout
    };

    parse_latency(target, label, &output, count)
}

async fn measure_dns(servers: &[String]) -> Vec<DnsTiming> {
    const QUERY: &str = "example.com";
    let mut results = Vec::new();

    for server in servers {
        let Ok(addr) = server.parse::<IpAddr>() else {
            continue;
        };

        match dns::resolve_a(addr, QUERY, Duration::from_secs(3)).await {
            Ok(outcome) => results.push(DnsTiming {
                server: server.clone(),
                query: QUERY.into(),
                ok: outcome.rcode == 0 && !outcome.answers.is_empty(),
                response_ms: Some(outcome.elapsed.as_millis() as u64),
                answers: outcome.answers,
                error: if outcome.rcode == 0 {
                    None
                } else {
                    Some(format!("DNS rcode {}", outcome.rcode))
                },
            }),
            Err(error) => results.push(DnsTiming {
                server: server.clone(),
                query: QUERY.into(),
                ok: false,
                response_ms: None,
                answers: Vec::new(),
                error: Some(error),
            }),
        }
    }

    results
}

/// Discovers the public IP without depending on a third-party HTTP service:
/// OpenDNS answers this special name with the querying source address.
async fn find_public_ip() -> Option<String> {
    let resolvers = ["208.67.222.222", "208.67.220.220"];
    for resolver in resolvers {
        let Ok(addr) = resolver.parse::<IpAddr>() else {
            continue;
        };
        if let Ok(outcome) = dns::resolve_a(addr, "myip.opendns.com", Duration::from_secs(3)).await
        {
            if let Some(ip) = outcome.answers.into_iter().next() {
                return Some(ip);
            }
        }
    }
    None
}

pub async fn collect(gateway_ip: Option<&str>, dns_servers: &[String]) -> ConnectivityInfo {
    let gateway_future = async {
        match gateway_ip {
            Some(ip) => Some(measure_latency(ip, "Gateway", 10).await),
            None => None,
        }
    };

    let wan_future = async {
        let mut stats = Vec::new();
        for (target, label) in WAN_TARGETS {
            stats.push(measure_latency(target, label, 5).await);
        }
        stats
    };

    let (gateway, wan, dns_timings, public_ip) = futures::join!(
        gateway_future,
        wan_future,
        measure_dns(dns_servers),
        find_public_ip()
    );

    let wan_reachable = wan.iter().any(|w| w.received > 0) || public_ip.is_some();

    // Trace outward only if the WAN answered; otherwise trace to the gateway so
    // the report shows exactly where the path stops.
    let trace_target = if wan_reachable {
        Some("1.1.1.1")
    } else {
        gateway_ip
    };
    let trace = match trace_target {
        Some(target) => platform::traceroute(target).await,
        None => ProbeResult::unavailable("no gateway or WAN target to trace"),
    };

    ConnectivityInfo {
        gateway,
        wan,
        dns: dns_timings,
        public_ip,
        wan_reachable,
        trace,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_ping_statistics() {
        let output = "PING 10.0.3.1 (10.0.3.1) 56(84) bytes of data.\n64 bytes from 10.0.3.1: icmp_seq=1 ttl=64 time=1.75 ms\n64 bytes from 10.0.3.1: icmp_seq=2 ttl=64 time=2.10 ms\n\n--- 10.0.3.1 ping statistics ---\n10 packets transmitted, 10 received, 0% packet loss, time 1805ms\nrtt min/avg/max/mdev = 1.234/2.208/3.001/0.962 ms\n";
        let stats = parse_latency("10.0.3.1", "Gateway", output, 10);

        assert_eq!(stats.sent, 10);
        assert_eq!(stats.received, 10);
        assert_eq!(stats.loss_percent, 0.0);
        assert_eq!(stats.min_ms, Some(1.234));
        assert_eq!(stats.avg_ms, Some(2.208));
        assert_eq!(stats.max_ms, Some(3.001));
        assert_eq!(stats.jitter_ms, Some(0.962));
        assert_eq!(stats.samples, vec![1.75, 2.10]);
    }

    #[test]
    fn parses_windows_ping_statistics() {
        let output = "\nPinging 10.0.3.1 with 32 bytes of data:\nReply from 10.0.3.1: bytes=32 time=2ms TTL=64\nReply from 10.0.3.1: bytes=32 time=3ms TTL=64\n\nPing statistics for 10.0.3.1:\n    Packets: Sent = 10, Received = 9, Lost = 1 (10% loss),\nApproximate round trip times in milli-seconds:\n    Minimum = 2ms, Maximum = 5ms, Average = 3ms\n";
        let stats = parse_latency("10.0.3.1", "Gateway", output, 10);

        assert_eq!(stats.sent, 10);
        assert_eq!(stats.received, 9);
        assert_eq!(stats.loss_percent, 10.0);
        assert_eq!(stats.min_ms, Some(2.0));
        assert_eq!(stats.avg_ms, Some(3.0));
        assert_eq!(stats.max_ms, Some(5.0));
        assert_eq!(stats.samples, vec![2.0, 3.0]);
    }

    #[test]
    fn reports_total_loss_when_nothing_replies() {
        let output = "5 packets transmitted, 0 received, 100% packet loss, time 4090ms\n";
        let stats = parse_latency("1.1.1.1", "WAN", output, 5);
        assert_eq!(stats.received, 0);
        assert_eq!(stats.loss_percent, 100.0);
        assert!(stats.avg_ms.is_none());
    }

    #[test]
    fn empty_output_degrades_to_total_loss_rather_than_panicking() {
        let stats = parse_latency("10.0.0.1", "Gateway", "", 5);
        assert_eq!(stats.received, 0);
        assert_eq!(stats.loss_percent, 100.0);
        assert!(stats.samples.is_empty());
    }

    #[tokio::test]
    async fn measures_loopback_latency_on_this_machine() {
        let stats = measure_latency("127.0.0.1", "Loopback", 2).await;
        assert!(stats.received > 0, "loopback must respond");
        assert_eq!(stats.loss_percent, 0.0);
    }
}
