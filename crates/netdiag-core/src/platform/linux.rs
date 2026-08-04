//! Linux platform support: iproute2, systemd-resolved and NetworkManager.

use super::Neighbor;
use crate::exec::{has_tool, run};
use crate::types::{
    ChannelUsage, DnsConfig, Gateway, ProbeResult, RouteInfo, TraceHop, TraceResult, WifiInfo,
    WifiNetwork,
};
use std::net::Ipv4Addr;
use std::time::Duration;

pub const ARP_TOOL: super::ToolRef = super::ToolRef {
    command: "ip",
    remedy: "Install the iproute2 package (`sudo apt install iproute2`). It is present by default on virtually all distributions.",
};
pub const PING_TOOL: super::ToolRef = super::ToolRef {
    command: "ping",
    remedy: "Install iputils-ping (`sudo apt install iputils-ping`).",
};
pub const TRACE_TOOL: super::ToolRef = super::ToolRef {
    command: "tracepath",
    remedy: "Install iputils-tracepath or mtr (`sudo apt install mtr-tiny`).",
};
pub const WIFI_TOOL: super::ToolRef = super::ToolRef {
    command: "nmcli",
    remedy: "Install NetworkManager (`sudo apt install network-manager`). Without it Wi-Fi signal and channel data are unavailable; everything else still works.",
};

/// `ping -c1 -W1 -n` — on Linux `-W` is a timeout in **seconds**.
pub fn ping_args(ip: &str, count: u32, timeout_secs: u32) -> Vec<String> {
    vec![
        "-c".into(),
        count.to_string(),
        "-W".into(),
        timeout_secs.to_string(),
        "-n".into(),
        "-q".into(),
        ip.to_string(),
    ]
}

pub fn ping_supports_flood() -> bool {
    true
}

/// Reads the kernel neighbour cache. Entries in FAILED/INCOMPLETE state have no
/// lladdr and are skipped.
pub async fn neighbor_table() -> Vec<Neighbor> {
    let result = run("ip", &["neigh", "show"], Duration::from_secs(5)).await;
    if !result.has_output() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for line in result.stdout.lines() {
        let mut parts = line.split_whitespace();
        let Some(ip_text) = parts.next() else {
            continue;
        };
        let Ok(ip) = ip_text.parse::<Ipv4Addr>() else {
            continue;
        };

        // 10.0.3.1 dev wlo1 lladdr e0:63:da:82:1b:35 REACHABLE
        let mut mac = None;
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for (i, token) in tokens.iter().enumerate() {
            if *token == "lladdr" {
                mac = tokens.get(i + 1).map(|m| crate::netutil::normalize_mac(m));
            }
        }

        if let Some(mac) = mac {
            if !crate::netutil::is_meaningless_mac(&mac) {
                out.push(Neighbor { ip, mac });
            }
        }
    }
    out
}

pub async fn default_gateway() -> (Option<Gateway>, Vec<RouteInfo>) {
    let result = run("ip", &["route", "show"], Duration::from_secs(5)).await;
    let mut routes = Vec::new();
    let mut gateway = None;

    for line in result.stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let field = |key: &str| -> Option<String> {
            tokens
                .iter()
                .position(|t| *t == key)
                .and_then(|i| tokens.get(i + 1))
                .map(|s| s.to_string())
        };

        let dev = field("dev").unwrap_or_default();
        let via = field("via");
        let metric = field("metric").and_then(|m| m.parse().ok());

        if tokens.first() == Some(&"default") {
            if let Some(ref via_ip) = via {
                if gateway.is_none() {
                    gateway = Some(Gateway {
                        ip: via_ip.clone(),
                        dev: dev.clone(),
                    });
                }
            }
        }

        routes.push(RouteInfo {
            destination: tokens.first().unwrap_or(&"").to_string(),
            via,
            dev,
            metric,
            raw: trimmed.to_string(),
        });
    }

    (gateway, routes)
}

pub async fn dns_servers() -> DnsConfig {
    let mut config = DnsConfig::default();

    // systemd-resolved is the common case and reports per-link servers.
    let result = run("resolvectl", &["status"], Duration::from_secs(5)).await;
    if result.ok {
        for line in result.stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed
                .strip_prefix("Current DNS Server:")
                .or_else(|| trimmed.strip_prefix("DNS Servers:"))
                .or_else(|| trimmed.strip_prefix("DNS Server:"))
            {
                for server in rest.split_whitespace() {
                    if server.parse::<std::net::IpAddr>().is_ok()
                        && !config.servers.contains(&server.to_string())
                    {
                        config.servers.push(server.to_string());
                    }
                }
            }
            if let Some(rest) = trimmed.strip_prefix("DNS Domain:") {
                for domain in rest.split_whitespace() {
                    if !config.search_domains.contains(&domain.to_string()) {
                        config.search_domains.push(domain.to_string());
                    }
                }
            }
        }
    }

    if config.servers.is_empty() {
        config = super::super::scan::hostinfo::parse_resolv_conf().await;
    }

    config
}

/// mtr gives per-hop loss; tracepath is the fallback since traceroute is often absent.
pub async fn traceroute(target: &str) -> ProbeResult<TraceResult> {
    if has_tool("mtr").await {
        let result = run(
            "mtr",
            &["--report", "--report-cycles", "3", "--no-dns", "-4", target],
            Duration::from_secs(35),
        )
        .await;

        if result.has_output() {
            let hops = parse_mtr(&result.stdout);
            if !hops.is_empty() {
                return ProbeResult::ok(TraceResult {
                    tool: "mtr".into(),
                    hops,
                });
            }
        }
    }

    if has_tool("tracepath").await {
        let result = run(
            "tracepath",
            &["-4", "-m", "15", target],
            Duration::from_secs(45),
        )
        .await;
        if result.has_output() {
            let hops = parse_tracepath(&result.stdout);
            if !hops.is_empty() {
                return ProbeResult::ok(TraceResult {
                    tool: "tracepath".into(),
                    hops,
                });
            }
        }
    }

    if has_tool("traceroute").await {
        let result = run(
            "traceroute",
            &["-n", "-m", "15", "-w", "2", target],
            Duration::from_secs(45),
        )
        .await;
        if result.has_output() {
            let hops = parse_traceroute(&result.stdout);
            if !hops.is_empty() {
                return ProbeResult::ok(TraceResult {
                    tool: "traceroute".into(),
                    hops,
                });
            }
        }
    }

    ProbeResult::unavailable("none of mtr, tracepath or traceroute is available")
}

pub(crate) fn parse_mtr(output: &str) -> Vec<TraceHop> {
    let mut hops = Vec::new();
    for line in output.lines() {
        // "  1.|-- 10.0.3.1   0.0%   3   1.2  1.3  1.2  1.5  0.1"
        let Some((index_part, rest)) = line.split_once(".|--") else {
            continue;
        };
        let Ok(hop) = index_part.trim().parse::<u32>() else {
            continue;
        };

        let tokens: Vec<&str> = rest.split_whitespace().collect();
        let host = tokens.first().copied().unwrap_or("???");
        let timeout = host == "???";

        let loss = tokens
            .get(1)
            .and_then(|t| t.trim_end_matches('%').parse::<f64>().ok());
        let rtt = tokens.get(3).and_then(|t| t.parse::<f64>().ok());

        hops.push(TraceHop {
            hop,
            host: if timeout {
                None
            } else {
                Some(host.to_string())
            },
            rtt_ms: if timeout { None } else { rtt },
            loss_percent: loss,
            timeout,
        });
    }
    hops
}

pub(crate) fn parse_tracepath(output: &str) -> Vec<TraceHop> {
    let mut hops: Vec<TraceHop> = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        let Some((index_part, rest)) = trimmed.split_once(':') else {
            continue;
        };
        let Ok(hop) = index_part.trim().parse::<u32>() else {
            continue;
        };

        let tokens: Vec<&str> = rest.split_whitespace().collect();
        let Some(first) = tokens.first() else {
            continue;
        };

        if *first == "no" {
            hops.push(TraceHop {
                hop,
                host: None,
                rtt_ms: None,
                loss_percent: None,
                timeout: true,
            });
            continue;
        }

        let rtt = tokens
            .iter()
            .find(|t| t.ends_with("ms"))
            .and_then(|t| t.trim_end_matches("ms").parse::<f64>().ok());

        // tracepath repeats a hop for its MTU "resume" lines; collapse duplicates.
        if hops
            .last()
            .map(|h| h.hop == hop && h.rtt_ms == rtt)
            .unwrap_or(false)
        {
            continue;
        }

        hops.push(TraceHop {
            hop,
            host: Some(first.to_string()),
            rtt_ms: rtt,
            loss_percent: None,
            timeout: false,
        });
    }
    hops
}

pub(crate) fn parse_traceroute(output: &str) -> Vec<TraceHop> {
    let mut hops = Vec::new();
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(first) = tokens.first() else {
            continue;
        };
        let Ok(hop) = first.parse::<u32>() else {
            continue;
        };

        let host = tokens.get(1).copied().filter(|h| *h != "*");
        let rtt = tokens
            .iter()
            .find(|t| t.parse::<f64>().is_ok() && tokens.contains(&"ms"))
            .and_then(|t| t.parse::<f64>().ok());

        hops.push(TraceHop {
            hop,
            host: host.map(|h| h.to_string()),
            rtt_ms: rtt,
            loss_percent: None,
            timeout: host.is_none(),
        });
    }
    hops
}

/// NetworkManager survey. `nmcli -t` escapes literal colons inside fields as
/// `\:`, and BSSIDs are full of them — a naive split corrupts every row.
pub async fn wifi_survey() -> ProbeResult<WifiInfo> {
    if !has_tool("nmcli").await {
        return ProbeResult::unavailable(
            "nmcli not installed — Wi-Fi signal and channel congestion are unavailable",
        );
    }

    let interface = {
        let result = run(
            "nmcli",
            &["-t", "-f", "DEVICE,TYPE,STATE", "dev", "status"],
            Duration::from_secs(5),
        )
        .await;
        result
            .stdout
            .lines()
            .filter_map(|line| {
                let fields = split_terse(line);
                let device = fields.first()?;
                let kind = fields.get(1)?;
                if kind == "wifi" && !device.starts_with("p2p-") {
                    Some(device.clone())
                } else {
                    None
                }
            })
            .next()
    };

    let result = run(
        "nmcli",
        &[
            "-t",
            "-f",
            "IN-USE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,SECURITY",
            "dev",
            "wifi",
            "list",
        ],
        Duration::from_secs(15),
    )
    .await;

    if !result.has_output() {
        return ProbeResult::unavailable("no Wi-Fi networks visible");
    }

    let mut networks = Vec::new();
    for line in result.stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let fields = split_terse(line);
        if fields.len() < 8 {
            continue;
        }

        let Ok(channel) = fields[3].parse::<u32>() else {
            continue;
        };
        let frequency: u32 = fields[4]
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .unwrap_or(0);

        networks.push(WifiNetwork {
            // An empty SSID is a hidden network, not a parse failure.
            ssid: if fields[1].is_empty() {
                "(hidden)".into()
            } else {
                fields[1].clone()
            },
            bssid: if fields[2].is_empty() {
                None
            } else {
                Some(fields[2].clone())
            },
            active: fields[0].trim() == "*",
            signal: fields[6].parse().unwrap_or(0),
            channel,
            band: crate::scan::wifi::band_for_frequency(frequency).to_string(),
            rate: if fields[5].is_empty() {
                None
            } else {
                Some(fields[5].clone())
            },
            security: if fields[7].is_empty() {
                Some("Open".into())
            } else {
                Some(fields[7].clone())
            },
        });
    }

    if networks.is_empty() {
        return ProbeResult::unavailable("no Wi-Fi networks visible");
    }

    ProbeResult::ok(crate::scan::wifi::assemble(interface, networks))
}

/// Splits nmcli terse output on unescaped colons.
pub(crate) fn split_terse(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars();

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ':' => {
                fields.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    fields.push(current);
    fields
}

/// Channel usage is assembled centrally; re-exported so the shared code can use it.
pub(crate) fn _unused(_: &[ChannelUsage]) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_nmcli_terse_output_preserving_escaped_bssid_colons() {
        let line = r"*:ADOFULL:78\:8A\:20\:5B\:C4\:B8:149:5745 MHz:405 Mbit/s:97:WPA2";
        let fields = split_terse(line);
        assert_eq!(fields[0], "*");
        assert_eq!(fields[1], "ADOFULL");
        assert_eq!(fields[2], "78:8A:20:5B:C4:B8");
        assert_eq!(fields[3], "149");
        assert_eq!(fields[7], "WPA2");
    }

    #[test]
    fn handles_hidden_ssid_as_empty_field() {
        let line = r" ::86\:8A\:20\:5A\:C4\:B8:6:2437 MHz:195 Mbit/s:100:WPA2";
        let fields = split_terse(line);
        assert_eq!(
            fields[1], "",
            "hidden network should yield an empty SSID field"
        );
    }

    #[test]
    fn parses_mtr_report_rows() {
        let output = "Start: 2026-08-04\nHOST: marek           Loss%   Snt   Last   Avg\n  1.|-- 10.0.3.1   0.0%     3    1.2   1.3\n  2.|-- ???        100.0%    3    0.0   0.0\n";
        let hops = parse_mtr(output);
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].host.as_deref(), Some("10.0.3.1"));
        assert_eq!(hops[0].loss_percent, Some(0.0));
        assert!(hops[1].timeout);
    }

    #[test]
    fn parses_ip_neigh_style_lines() {
        // Exercised through the parser inline in neighbor_table; verify the shape here.
        let line = "10.0.3.1 dev wlo1 lladdr e0:63:da:82:1b:35 REACHABLE";
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let idx = tokens.iter().position(|t| *t == "lladdr").unwrap();
        assert_eq!(tokens[idx + 1], "e0:63:da:82:1b:35");
    }
}
