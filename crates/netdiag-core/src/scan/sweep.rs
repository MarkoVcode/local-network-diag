//! Liveness sweep and MAC harvest.
//!
//! The engine has no elevated privileges on any platform, so a raw ARP scan is
//! off the table. The technique that makes MAC addresses available anyway:
//!
//! 1. ping each host — the system `ping` binary is setuid/capability-endowed
//!    (or, on Windows, uses the IP Helper API) so it works as an ordinary user;
//! 2. the kernel populates its ARP/neighbour cache as a side effect;
//! 3. read that cache back with the platform's own tool, which needs no
//!    privileges.
//!
//! Hosts that ignore ICMP are still picked up by the TCP phase, and pinging them
//! here is what puts their MAC in the cache regardless of whether they reply.

use crate::exec::run;
use crate::platform;
use futures::stream::{self, StreamExt};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct SweepResult {
    pub alive: HashMap<Ipv4Addr, Option<f64>>,
    pub neighbors: HashMap<Ipv4Addr, String>,
}

/// Extracts the round-trip time from `ping` output across all three platforms.
///
/// Linux/BSD summary: `rtt min/avg/max/mdev = 1.234/1.345/1.456/0.1 ms`
/// Windows:           `Average = 2ms` / `time=2ms` / `time<1ms`
pub(crate) fn parse_ping_rtt(output: &str) -> Option<f64> {
    // Unix summary line.
    if let Some(index) = output.find(" = ") {
        let rest = &output[index + 3..];
        let numbers: Vec<&str> = rest.split('/').collect();
        if numbers.len() >= 2 {
            if let Ok(avg) = numbers[1].trim().parse::<f64>() {
                return Some(avg);
            }
        }
    }

    // Windows "Average = 2ms".
    if let Some(index) = output.find("Average = ") {
        let rest = &output[index + 10..];
        let digits: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if let Ok(value) = digits.parse::<f64>() {
            return Some(value);
        }
    }

    // Per-reply "time=1.23 ms" / "time<1ms".
    for marker in ["time=", "time<"] {
        if let Some(index) = output.find(marker) {
            let rest = &output[index + marker.len()..];
            let digits: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if let Ok(value) = digits.parse::<f64>() {
                return Some(value);
            }
        }
    }

    None
}

/// Decides whether a ping reply actually happened.
///
/// Exit status alone is unreliable: Windows `ping` returns 0 even when every
/// reply is "Destination host unreachable", so the text is checked too.
pub(crate) fn ping_succeeded(exit_ok: bool, output: &str) -> bool {
    let lower = output.to_ascii_lowercase();

    if lower.contains("unreachable")
        || lower.contains("100% packet loss")
        || lower.contains("100.0% packet loss")
    {
        return false;
    }

    // Linux prints "1 received", macOS prints "1 packets received", Windows
    // prints "Received = 1".
    if let Some(count) = count_before(&lower, " received") {
        return count > 0;
    }
    if let Some(index) = lower.find("received = ") {
        let rest = &lower[index + 11..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(count) = digits.parse::<u32>() {
            return count > 0;
        }
    }

    exit_ok && (lower.contains("ttl=") || lower.contains("time="))
}

/// Reads the count preceding a marker, stepping over plain filler words.
///
/// The wording differs per platform: Linux says "1 received" but macOS says
/// "1 **packets** received". Taking the immediately preceding word works on
/// Linux and silently yields "packets" on macOS, which parses as no reply — so
/// every host would look dead there.
///
/// The scan is deliberately bounded: it steps over purely alphabetic words and
/// stops at anything else. Scanning back unconditionally would wander into
/// unrelated numbers — on Windows the text before " received" ends in
/// "Sent = 10," and continues into per-reply lines containing "bytes=32".
pub(crate) fn count_before(text: &str, marker: &str) -> Option<u32> {
    let index = text.find(marker)?;

    for token in text[..index].split_whitespace().rev() {
        if let Ok(count) = token.parse::<u32>() {
            return Some(count);
        }
        if !token.chars().all(|c| c.is_ascii_alphabetic()) {
            // Punctuation or a key=value pair: we have left the phrase.
            return None;
        }
    }

    None
}

async fn ping_host(ip: Ipv4Addr) -> (Ipv4Addr, bool, Option<f64>) {
    let args = platform::ping_args(&ip.to_string(), 1, 1);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = run("ping", &arg_refs, Duration::from_millis(2500)).await;

    let output = if result.stdout.trim().is_empty() {
        result.stderr.clone()
    } else {
        result.stdout.clone()
    };
    let alive = ping_succeeded(result.ok, &output);
    let rtt = if alive { parse_ping_rtt(&output) } else { None };

    (ip, alive, rtt)
}

pub async fn sweep<F>(ips: &[Ipv4Addr], concurrency: usize, mut on_progress: F) -> SweepResult
where
    F: FnMut(u64, u64) + Send,
{
    let total = ips.len() as u64;
    let counter = Arc::new(AtomicU64::new(0));

    let progress_counter = Arc::clone(&counter);
    let results = stream::iter(ips.iter().copied())
        .map(move |ip| {
            let counter = Arc::clone(&progress_counter);
            async move {
                let outcome = ping_host(ip).await;
                let seen = counter.fetch_add(1, Ordering::Relaxed) + 1;
                (outcome, seen)
            }
        })
        .buffer_unordered(concurrency.max(1))
        .collect::<Vec<_>>()
        .await;

    let mut sweep_result = SweepResult::default();
    let mut last_reported = 0u64;

    for ((ip, alive, rtt), seen) in results {
        if alive {
            sweep_result.alive.insert(ip, rtt);
        }
        if seen.saturating_sub(last_reported) >= 10 || seen == total {
            last_reported = seen;
            on_progress(seen, total);
        }
    }
    on_progress(total, total);

    // Give the kernel a moment to settle entries for hosts that replied last.
    tokio::time::sleep(Duration::from_millis(300)).await;
    sweep_result.neighbors = read_neighbors().await;

    sweep_result
}

pub async fn read_neighbors() -> HashMap<Ipv4Addr, String> {
    platform::neighbor_table()
        .await
        .into_iter()
        .map(|n| (n.ip, n.mac))
        .collect()
}

/// Re-reads the neighbour table after the TCP phase. Hosts that dropped our ICMP
/// but accepted a TCP connection will have appeared by then, so this second read
/// recovers MACs the first pass missed.
pub async fn refresh_neighbors(existing: &mut HashMap<Ipv4Addr, String>) {
    for (ip, mac) in read_neighbors().await {
        existing.insert(ip, mac);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_ping_summary() {
        let output = "PING 10.0.3.1 (10.0.3.1) 56(84) bytes of data.\n\n--- 10.0.3.1 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\nrtt min/avg/max/mdev = 1.755/1.755/1.755/0.000 ms\n";
        assert!(ping_succeeded(true, output));
        assert_eq!(parse_ping_rtt(output), Some(1.755));
    }

    #[test]
    fn parses_macos_ping_summary() {
        // macOS says "1 packets received" where Linux says "1 received". Reading
        // the word immediately before " received" yields "packets" here, which
        // parses as no reply — so every host would look dead on macOS.
        let output = "PING 127.0.0.1 (127.0.0.1): 56 data bytes\n\n--- 127.0.0.1 ping statistics ---\n1 packets transmitted, 1 packets received, 0.0% packet loss\nround-trip min/avg/max/stddev = 0.045/0.045/0.045/0.000 ms\n";
        assert!(
            ping_succeeded(true, output),
            "macOS's 'N packets received' wording must be recognised"
        );
        assert_eq!(parse_ping_rtt(output), Some(0.045));
    }

    #[test]
    fn macos_total_loss_is_not_alive() {
        let output = "--- 10.0.3.99 ping statistics ---\n1 packets transmitted, 0 packets received, 100.0% packet loss\n";
        assert!(!ping_succeeded(false, output));
    }

    #[test]
    fn count_before_skips_filler_words_but_stops_at_punctuation() {
        assert_eq!(count_before("1 received", " received"), Some(1));
        assert_eq!(count_before("3 packets received", " received"), Some(3));
        assert_eq!(count_before("0 packets received", " received"), Some(0));
        assert_eq!(count_before("no numbers here", " received"), None);

        // Windows: the preceding text ends in "Sent = 10," and earlier lines
        // contain "bytes=32". Neither may be mistaken for the received count.
        assert_eq!(
            count_before(
                "reply from 1.2.3.4: bytes=32 ttl=64\npackets: sent = 10, received = 9",
                " received"
            ),
            None,
            "must not wander past punctuation into unrelated numbers"
        );
    }

    #[test]
    fn parses_windows_ping_output() {
        let output = "\nPinging 10.0.3.1 with 32 bytes of data:\nReply from 10.0.3.1: bytes=32 time=2ms TTL=64\n\nPing statistics for 10.0.3.1:\n    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),\nApproximate round trip times in milli-seconds:\n    Minimum = 2ms, Maximum = 2ms, Average = 2ms\n";
        assert!(ping_succeeded(true, output));
        assert_eq!(parse_ping_rtt(output), Some(2.0));
    }

    #[test]
    fn windows_destination_unreachable_is_not_a_successful_reply() {
        // Windows ping exits 0 here, so exit status alone would be wrong.
        let output = "\nPinging 10.0.3.99 with 32 bytes of data:\nReply from 10.0.3.221: Destination host unreachable.\n\nPing statistics for 10.0.3.99:\n    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),\n";
        assert!(
            !ping_succeeded(true, output),
            "'Destination host unreachable' must not count as a live host"
        );
    }

    #[test]
    fn total_packet_loss_is_not_alive() {
        let output = "1 packets transmitted, 0 received, 100% packet loss, time 0ms\n";
        assert!(!ping_succeeded(false, output));
        assert_eq!(parse_ping_rtt(output), None);
    }

    #[test]
    fn handles_sub_millisecond_windows_replies() {
        let output = "Reply from 127.0.0.1: bytes=32 time<1ms TTL=128\n    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),\n";
        assert!(ping_succeeded(true, output));
        assert_eq!(parse_ping_rtt(output), Some(1.0));
    }

    #[tokio::test]
    async fn pings_loopback_successfully() {
        // Verifies the per-OS argument construction actually works on this host.
        let (ip, alive, _) = ping_host(Ipv4Addr::LOCALHOST).await;
        assert_eq!(ip, Ipv4Addr::LOCALHOST);
        assert!(alive, "loopback must always answer ICMP");
    }
}
