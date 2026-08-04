//! macOS platform support: BSD networking tools plus `scutil` and CoreWLAN helpers.

use super::Neighbor;
use crate::exec::{has_tool, run};
use crate::types::{
    DnsConfig, Gateway, ProbeResult, RouteInfo, TraceHop, TraceResult, WifiInfo, WifiNetwork,
};
use std::net::Ipv4Addr;
use std::time::Duration;

pub const ARP_TOOL: super::ToolRef = super::ToolRef {
    command: "arp",
    remedy: "Part of the macOS base system — if missing, the system install is damaged.",
};
pub const PING_TOOL: super::ToolRef = super::ToolRef {
    command: "ping",
    remedy: "Part of the macOS base system — if missing, the system install is damaged.",
};
pub const TRACE_TOOL: super::ToolRef = super::ToolRef {
    command: "traceroute",
    remedy: "Part of the macOS base system. `brew install mtr` adds per-hop loss reporting.",
};
pub const WIFI_TOOL: super::ToolRef = super::ToolRef {
    command: "system_profiler",
    remedy: "Part of the macOS base system. Note that macOS 14+ requires Location Services permission for this app before Wi-Fi SSID and BSSID become visible.",
};

/// BSD `ping` takes `-W` in **milliseconds**, unlike Linux where it is seconds —
/// passing the Linux value here would set a 1 ms timeout and report everything
/// as unreachable.
pub fn ping_args(ip: &str, count: u32, timeout_secs: u32) -> Vec<String> {
    vec![
        "-c".into(),
        count.to_string(),
        "-W".into(),
        (timeout_secs * 1000).to_string(),
        "-n".into(),
        "-q".into(),
        ip.to_string(),
    ]
}

pub fn ping_supports_flood() -> bool {
    false
}

/// `arp -an` output: `? (10.0.3.1) at e0:63:da:82:1b:35 on en0 ifscope [ethernet]`
pub async fn neighbor_table() -> Vec<Neighbor> {
    let result = run("arp", &["-an"], Duration::from_secs(5)).await;
    if !result.has_output() {
        return Vec::new();
    }
    parse_arp_an(&result.stdout)
}

pub(crate) fn parse_arp_an(output: &str) -> Vec<Neighbor> {
    let mut out = Vec::new();
    for line in output.lines() {
        let Some(start) = line.find('(') else {
            continue;
        };
        let Some(end) = line.find(')') else { continue };
        if end <= start + 1 {
            continue;
        }
        let Ok(ip) = line[start + 1..end].parse::<Ipv4Addr>() else {
            continue;
        };

        let Some(at_index) = line.find(" at ") else {
            continue;
        };
        let rest = &line[at_index + 4..];
        let mac_token = rest.split_whitespace().next().unwrap_or("");
        if mac_token.eq_ignore_ascii_case("(incomplete)") {
            continue;
        }

        // BSD prints single-digit octets unpadded (e.g. `e0:63:da:8:1b:35`).
        let normalized = normalize_bsd_mac(mac_token);
        if normalized.is_empty() || crate::netutil::is_meaningless_mac(&normalized) {
            continue;
        }
        out.push(Neighbor {
            ip,
            mac: normalized,
        });
    }
    out
}

/// Zero-pads each octet so BSD's unpadded form matches the OUI table's keys.
pub(crate) fn normalize_bsd_mac(mac: &str) -> String {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return String::new();
    }
    let mut out = Vec::with_capacity(6);
    for part in parts {
        if part.is_empty() || part.len() > 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return String::new();
        }
        out.push(format!("{:0>2}", part.to_ascii_lowercase()));
    }
    out.join(":")
}

pub async fn default_gateway() -> (Option<Gateway>, Vec<RouteInfo>) {
    let mut routes = Vec::new();
    let mut gateway = None;

    let result = run("route", &["-n", "get", "default"], Duration::from_secs(5)).await;
    if result.ok {
        let mut gw_ip = None;
        let mut dev = String::new();
        for line in result.stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("gateway:") {
                gw_ip = Some(rest.trim().to_string());
            }
            if let Some(rest) = trimmed.strip_prefix("interface:") {
                dev = rest.trim().to_string();
            }
        }
        if let Some(ip) = gw_ip {
            gateway = Some(Gateway { ip, dev });
        }
    }

    // Full table for display.
    let table = run("netstat", &["-rn", "-f", "inet"], Duration::from_secs(8)).await;
    for line in table.stdout.lines().skip(1) {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 4 || tokens[0] == "Destination" {
            continue;
        }
        routes.push(RouteInfo {
            destination: tokens[0].to_string(),
            via: tokens
                .get(1)
                .map(|s| s.to_string())
                .filter(|s| s.contains('.')),
            dev: tokens.last().unwrap_or(&"").to_string(),
            metric: None,
            raw: line.trim().to_string(),
        });
    }

    (gateway, routes)
}

pub async fn dns_servers() -> DnsConfig {
    let mut config = DnsConfig::default();

    let result = run("scutil", &["--dns"], Duration::from_secs(5)).await;
    if result.ok {
        for line in result.stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.split_once("nameserver[") {
                if let Some((_, value)) = rest.1.split_once(':') {
                    let server = value.trim().to_string();
                    if server.parse::<std::net::IpAddr>().is_ok()
                        && !config.servers.contains(&server)
                    {
                        config.servers.push(server);
                    }
                }
            }
            if let Some(rest) = trimmed.strip_prefix("search domain[") {
                if let Some((_, value)) = rest.split_once(':') {
                    let domain = value.trim().to_string();
                    if !domain.is_empty() && !config.search_domains.contains(&domain) {
                        config.search_domains.push(domain);
                    }
                }
            }
        }
    }

    if config.servers.is_empty() {
        config = crate::scan::hostinfo::parse_resolv_conf().await;
    }

    config
}

pub async fn traceroute(target: &str) -> ProbeResult<TraceResult> {
    if has_tool("mtr").await {
        let result = run(
            "mtr",
            &["--report", "--report-cycles", "3", "--no-dns", "-4", target],
            Duration::from_secs(35),
        )
        .await;
        if result.has_output() {
            let hops = super::super::platform::macos::parse_mtr(&result.stdout);
            if !hops.is_empty() {
                return ProbeResult::ok(TraceResult {
                    tool: "mtr".into(),
                    hops,
                });
            }
        }
    }

    if has_tool("traceroute").await {
        let result = run(
            "traceroute",
            &["-n", "-m", "15", "-w", "2", "-q", "1", target],
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

    ProbeResult::unavailable("neither traceroute nor mtr is available")
}

pub(crate) fn parse_mtr(output: &str) -> Vec<TraceHop> {
    let mut hops = Vec::new();
    for line in output.lines() {
        let Some((index_part, rest)) = line.split_once(".|--") else {
            continue;
        };
        let Ok(hop) = index_part.trim().parse::<u32>() else {
            continue;
        };
        let tokens: Vec<&str> = rest.split_whitespace().collect();
        let host = tokens.first().copied().unwrap_or("???");
        let timeout = host == "???";
        hops.push(TraceHop {
            hop,
            host: if timeout {
                None
            } else {
                Some(host.to_string())
            },
            rtt_ms: tokens.get(3).and_then(|t| t.parse().ok()),
            loss_percent: tokens
                .get(1)
                .and_then(|t| t.trim_end_matches('%').parse().ok()),
            timeout,
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
        let rtt = tokens.iter().skip(2).find_map(|t| t.parse::<f64>().ok());

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

/// Wi-Fi survey.
///
/// The old `airport -s` private binary was removed in macOS 14, so this uses
/// `system_profiler SPAirPortDataType`, which is stable across versions. Note
/// that macOS gates SSID/BSSID behind Location Services — when permission has
/// not been granted the fields come back empty rather than erroring, which the
/// doctor explains rather than leaving as a silent blank panel.
pub async fn wifi_survey() -> ProbeResult<WifiInfo> {
    let result = run(
        "system_profiler",
        &["SPAirPortDataType", "-detailLevel", "basic"],
        Duration::from_secs(20),
    )
    .await;

    if !result.has_output() {
        return ProbeResult::unavailable("system_profiler returned no Wi-Fi data");
    }

    let (interface, networks) = parse_system_profiler(&result.stdout);

    if networks.is_empty() {
        return ProbeResult::unavailable(
            "No Wi-Fi networks reported. On macOS 14+ this usually means Location Services permission has not been granted to this app, which macOS requires before SSID and BSSID are readable.",
        );
    }

    ProbeResult::ok(crate::scan::wifi::assemble(interface, networks))
}

/// Parses the indented `system_profiler SPAirPortDataType` report.
pub(crate) fn parse_system_profiler(output: &str) -> (Option<String>, Vec<WifiNetwork>) {
    let mut networks: Vec<WifiNetwork> = Vec::new();
    let mut interface = None;
    let mut current: Option<WifiNetwork> = None;
    let mut in_current_network = false;

    let indent_of = |line: &str| line.len() - line.trim_start().len();

    let mut name_indent = 0usize;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("en") && trimmed.ends_with(':') && interface.is_none() {
            interface = Some(trimmed.trim_end_matches(':').to_string());
            continue;
        }

        if trimmed == "Current Network Information:" {
            in_current_network = true;
            continue;
        }
        if trimmed == "Other Local Wi-Fi Networks:" {
            if let Some(net) = current.take() {
                networks.push(net);
            }
            in_current_network = false;
            continue;
        }

        // A network entry is a bare "Name:" header; its attributes are indented deeper.
        if trimmed.ends_with(':') && !trimmed.contains(": ") {
            let label = trimmed.trim_end_matches(':').to_string();
            if matches!(
                label.as_str(),
                "Software Versions" | "Interfaces" | "Wi-Fi" | "Card Type" | "Status"
            ) {
                continue;
            }
            if let Some(net) = current.take() {
                networks.push(net);
            }
            name_indent = indent_of(line);
            current = Some(WifiNetwork {
                ssid: label,
                bssid: None,
                active: in_current_network,
                signal: 0,
                channel: 0,
                band: "unknown".into(),
                rate: None,
                security: None,
            });
            continue;
        }

        let Some(net) = current.as_mut() else {
            continue;
        };
        if indent_of(line) <= name_indent {
            continue;
        }

        if let Some((key, value)) = trimmed.split_once(": ") {
            let value = value.trim();
            match key.trim() {
                "PHY Mode" => net.rate = Some(value.to_string()),
                "Channel" => {
                    // "149 (5GHz, 80MHz)"
                    let channel: u32 = value
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect::<String>()
                        .parse()
                        .unwrap_or(0);
                    net.channel = channel;
                    net.band = if value.contains("6GHz") {
                        "6 GHz".into()
                    } else if value.contains("5GHz") {
                        "5 GHz".into()
                    } else if value.contains("2GHz") || value.contains("2.4GHz") {
                        "2.4 GHz".into()
                    } else {
                        crate::scan::wifi::band_for_channel(channel).to_string()
                    };
                }
                "Signal / Noise" => {
                    // "-45 dBm / -92 dBm" — convert dBm to a 0-100 quality figure.
                    if let Some(dbm) = value
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse::<i32>().ok())
                    {
                        net.signal = crate::scan::wifi::dbm_to_quality(dbm);
                    }
                }
                "Security" => net.security = Some(value.to_string()),
                "BSSID" => net.bssid = Some(value.to_ascii_uppercase()),
                "Transmit Rate" => net.rate = Some(format!("{value} Mbit/s")),
                _ => {}
            }
        }
    }

    if let Some(net) = current.take() {
        networks.push(net);
    }

    networks.retain(|n| !n.ssid.is_empty());
    (interface, networks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bsd_arp_output_including_unpadded_octets() {
        let output = "? (10.0.3.1) at e0:63:da:82:1b:35 on en0 ifscope [ethernet]\n\
                      ? (10.0.3.9) at e0:63:da:8:1b:5 on en0 ifscope [ethernet]\n\
                      ? (10.0.3.4) at (incomplete) on en0 [ethernet]";
        let neighbors = parse_arp_an(output);
        assert_eq!(neighbors.len(), 2, "incomplete entries must be skipped");
        assert_eq!(neighbors[0].mac, "e0:63:da:82:1b:35");
        // Unpadded BSD octets must be zero-padded or the OUI lookup misses.
        assert_eq!(neighbors[1].mac, "e0:63:da:08:1b:05");
    }

    #[test]
    fn bsd_ping_timeout_is_expressed_in_milliseconds() {
        let args = ping_args("10.0.3.1", 1, 1);
        let w = args.iter().position(|a| a == "-W").unwrap();
        assert_eq!(
            args[w + 1],
            "1000",
            "BSD ping -W is milliseconds, not seconds"
        );
    }

    #[test]
    fn rejects_malformed_macs() {
        assert_eq!(normalize_bsd_mac("not:a:mac"), "");
        assert_eq!(normalize_bsd_mac("e0:63:da:82:1b"), "");
    }
}
