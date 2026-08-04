//! Windows platform support: `arp`, `route`, `netsh` and `ipconfig`.
//!
//! Everything here uses tools shipped with Windows itself, so a stock machine
//! needs no extra installation. Output is parsed defensively because these
//! commands are localised — Windows prints table headers in the user's display
//! language, so parsing keys on structure (IP-shaped tokens, MAC-shaped tokens)
//! rather than on English words wherever possible.

use super::Neighbor;
use crate::exec::{has_tool, run};
use crate::types::{
    DnsConfig, Gateway, ProbeResult, RouteInfo, TraceHop, TraceResult, WifiInfo, WifiNetwork,
};
use std::net::Ipv4Addr;
use std::time::Duration;

pub const ARP_TOOL: super::ToolRef = super::ToolRef {
    command: "arp",
    remedy: "Ships with Windows. If missing, check that %SystemRoot%\\System32 is on PATH.",
};
pub const PING_TOOL: super::ToolRef = super::ToolRef {
    command: "ping",
    remedy: "Ships with Windows. If missing, check that %SystemRoot%\\System32 is on PATH.",
};
pub const TRACE_TOOL: super::ToolRef = super::ToolRef {
    command: "tracert",
    remedy: "Ships with Windows. If missing, check that %SystemRoot%\\System32 is on PATH.",
};
pub const WIFI_TOOL: super::ToolRef = super::ToolRef {
    command: "netsh",
    remedy: "Ships with Windows. Wi-Fi scanning also requires the WLAN AutoConfig service to be running.",
};

/// Windows `ping` uses `-n` for count and `-w` for a per-reply timeout in
/// milliseconds. `-n` does *not* mean "numeric" here as it does on Unix.
pub fn ping_args(ip: &str, count: u32, timeout_secs: u32) -> Vec<String> {
    vec![
        "-n".into(),
        count.to_string(),
        "-w".into(),
        (timeout_secs * 1000).to_string(),
        "-4".into(),
        ip.to_string(),
    ]
}

pub fn ping_supports_flood() -> bool {
    false
}

pub async fn neighbor_table() -> Vec<Neighbor> {
    let result = run("arp", &["-a"], Duration::from_secs(8)).await;
    if !result.has_output() {
        return Vec::new();
    }
    parse_arp_a(&result.stdout)
}

/// Parses `arp -a`. Rows look like:
/// `  10.0.3.1              e0-63-da-82-1b-35     dynamic`
/// Static/invalid rows and the multicast block are filtered out.
pub(crate) fn parse_arp_a(output: &str) -> Vec<Neighbor> {
    let mut out = Vec::new();

    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }

        let Ok(ip) = tokens[0].parse::<Ipv4Addr>() else {
            continue;
        };
        let mac_token = tokens[1];

        // Windows uses dashes; normalize_mac converts them to colons.
        let normalized = crate::netutil::normalize_mac(mac_token);
        let hex: String = normalized
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
        if hex.len() != 12 {
            continue;
        }
        if crate::netutil::is_meaningless_mac(&normalized)
            || crate::netutil::is_multicast_mac(&normalized)
        {
            continue;
        }
        // Skip the 224.0.0.0/4 multicast and 255.255.255.255 rows Windows lists.
        if ip.is_multicast() || ip.is_broadcast() {
            continue;
        }

        out.push(Neighbor {
            ip,
            mac: normalized,
        });
    }

    out
}

pub async fn default_gateway() -> (Option<Gateway>, Vec<RouteInfo>) {
    let mut routes = Vec::new();
    let mut gateway = None;

    let result = run("route", &["print", "-4"], Duration::from_secs(10)).await;
    if result.has_output() {
        for line in result.stdout.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            // Active route rows: Destination Netmask Gateway Interface Metric
            if tokens.len() < 5 {
                continue;
            }
            let (Ok(dest), Ok(_mask)) =
                (tokens[0].parse::<Ipv4Addr>(), tokens[1].parse::<Ipv4Addr>())
            else {
                continue;
            };

            let via = tokens[2].parse::<Ipv4Addr>().ok().map(|v| v.to_string());
            let iface = tokens[3].to_string();
            let metric = tokens[4].parse::<u32>().ok();

            if dest == Ipv4Addr::UNSPECIFIED && gateway.is_none() {
                if let Some(ref via_ip) = via {
                    gateway = Some(Gateway {
                        ip: via_ip.clone(),
                        dev: iface.clone(),
                    });
                }
            }

            routes.push(RouteInfo {
                destination: if dest == Ipv4Addr::UNSPECIFIED {
                    "default".into()
                } else {
                    dest.to_string()
                },
                via,
                dev: iface,
                metric,
                raw: line.trim().to_string(),
            });
        }
    }

    (gateway, routes)
}

pub async fn dns_servers() -> DnsConfig {
    let mut config = DnsConfig::default();

    // PowerShell gives structured output that is not localised, unlike ipconfig.
    if has_tool("powershell").await {
        let result = run(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses",
            ],
            Duration::from_secs(15),
        )
        .await;

        if result.ok {
            for line in result.stdout.lines() {
                let server = line.trim().to_string();
                if server.parse::<Ipv4Addr>().is_ok() && !config.servers.contains(&server) {
                    config.servers.push(server);
                }
            }
        }
    }

    // Fall back to ipconfig, keying on IP-shaped tokens rather than the localised label.
    if config.servers.is_empty() {
        let result = run("ipconfig", &["/all"], Duration::from_secs(15)).await;
        let mut in_dns_block = false;
        for line in result.stdout.lines() {
            let has_label = line.contains(DNS_LABEL_EN);
            if has_label {
                in_dns_block = true;
            } else if line.contains(':') && !line.trim().starts_with(|c: char| c.is_ascii_digit()) {
                in_dns_block = false;
            }

            if in_dns_block {
                for token in line.split_whitespace() {
                    let candidate =
                        token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.');
                    if candidate.parse::<Ipv4Addr>().is_ok()
                        && !config.servers.contains(&candidate.to_string())
                    {
                        config.servers.push(candidate.to_string());
                    }
                }
            }
        }
    }

    config
}

/// `ipconfig` output is localised. This fallback only recognises the English
/// label; on other locales the PowerShell path above is what actually works,
/// which is why it is tried first rather than second.
const DNS_LABEL_EN: &str = "DNS Servers";

pub async fn traceroute(target: &str) -> ProbeResult<TraceResult> {
    if !has_tool("tracert").await {
        return ProbeResult::unavailable("tracert not available");
    }

    let result = run(
        "tracert",
        &["-d", "-h", "15", "-w", "2000", "-4", target],
        Duration::from_secs(60),
    )
    .await;

    if !result.has_output() {
        return ProbeResult::error("tracert produced no output");
    }

    let hops = parse_tracert(&result.stdout);
    if hops.is_empty() {
        return ProbeResult::error("could not parse tracert output");
    }

    ProbeResult::ok(TraceResult {
        tool: "tracert".into(),
        hops,
    })
}

/// Parses `tracert -d`. Rows: `  1     1 ms     1 ms     1 ms  10.0.3.1`
/// Timeouts appear as `  3     *        *        *     Request timed out.`
pub(crate) fn parse_tracert(output: &str) -> Vec<TraceHop> {
    let mut hops = Vec::new();

    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        let Ok(hop) = tokens[0].parse::<u32>() else {
            continue;
        };

        // The address is the last IP-shaped token on the row.
        let host = tokens
            .iter()
            .rev()
            .find_map(|t| t.parse::<Ipv4Addr>().ok().map(|_| *t));

        // Latencies are the numbers immediately preceding "ms".
        let mut rtts = Vec::new();
        for (i, token) in tokens.iter().enumerate() {
            if *token == "ms" && i > 0 {
                if let Ok(value) = tokens[i - 1].trim_start_matches('<').parse::<f64>() {
                    rtts.push(value);
                }
            }
        }

        let rtt = if rtts.is_empty() {
            None
        } else {
            Some(rtts.iter().sum::<f64>() / rtts.len() as f64)
        };

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

/// Wi-Fi survey via `netsh wlan`. Requires the WLAN AutoConfig service; on a
/// desktop with no wireless adapter netsh reports an error, which is surfaced
/// as "unavailable" rather than an error the user must act on.
pub async fn wifi_survey() -> ProbeResult<WifiInfo> {
    let interfaces = run(
        "netsh",
        &["wlan", "show", "interfaces"],
        Duration::from_secs(15),
    )
    .await;

    if !interfaces.has_output() {
        return ProbeResult::unavailable(
            "netsh reported no WLAN interface — this machine may have no Wi-Fi adapter, or the WLAN AutoConfig service is stopped",
        );
    }

    let (interface, current_ssid, current_bssid, current_rate) =
        parse_netsh_interfaces(&interfaces.stdout);

    let networks_out = run(
        "netsh",
        &["wlan", "show", "networks", "mode=bssid"],
        Duration::from_secs(20),
    )
    .await;

    let mut networks = parse_netsh_networks(&networks_out.stdout);

    // netsh lists the connected network alongside the rest without marking it.
    for network in networks.iter_mut() {
        let matches_bssid = match (&network.bssid, &current_bssid) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            _ => false,
        };
        if matches_bssid
            || (current_bssid.is_none() && Some(&network.ssid) == current_ssid.as_ref())
        {
            network.active = true;
            if network.rate.is_none() {
                network.rate.clone_from(&current_rate);
            }
        }
    }

    if networks.is_empty() {
        return ProbeResult::unavailable("no Wi-Fi networks visible");
    }

    ProbeResult::ok(crate::scan::wifi::assemble(interface, networks))
}

pub(crate) fn parse_netsh_interfaces(
    output: &str,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let mut interface = None;
    let mut ssid = None;
    let mut bssid = None;
    let mut rate = None;

    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().to_string();
        if value.is_empty() {
            continue;
        }

        match key {
            "Name" => interface = Some(value),
            "SSID" => ssid = Some(value),
            "BSSID" => bssid = Some(value.to_ascii_uppercase()),
            "Receive rate (Mbps)" | "Transmit rate (Mbps)" => {
                rate = Some(format!("{value} Mbit/s"));
            }
            _ => {}
        }
    }

    (interface, ssid, bssid, rate)
}

/// Parses `netsh wlan show networks mode=bssid`, which nests BSSID blocks under
/// each SSID. A single SSID can have several BSSIDs (mesh/repeaters); each
/// becomes its own entry so channel congestion counts radios, not names.
pub(crate) fn parse_netsh_networks(output: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();
    let mut current_ssid: Option<String> = None;
    let mut current_auth: Option<String> = None;
    let mut pending: Option<WifiNetwork> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        let Some((key_raw, value_raw)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key_raw.trim();
        let value = value_raw.trim().to_string();

        if key.starts_with("SSID") && !key.starts_with("BSSID") {
            if let Some(network) = pending.take() {
                networks.push(network);
            }
            // "SSID 3 : ADOFULL" — an empty value is a hidden network.
            current_ssid = Some(if value.is_empty() {
                "(hidden)".to_string()
            } else {
                value.clone()
            });
            current_auth = None;
            continue;
        }

        if key == "Authentication" {
            current_auth = Some(value);
            continue;
        }

        if key.starts_with("BSSID") {
            if let Some(network) = pending.take() {
                networks.push(network);
            }
            pending = Some(WifiNetwork {
                ssid: current_ssid.clone().unwrap_or_else(|| "(hidden)".into()),
                bssid: Some(value.to_ascii_uppercase()),
                active: false,
                signal: 0,
                channel: 0,
                band: "unknown".into(),
                rate: None,
                security: current_auth.clone(),
            });
            continue;
        }

        let Some(network) = pending.as_mut() else {
            continue;
        };

        match key {
            // netsh already reports signal as a percentage.
            "Signal" => {
                network.signal = value.trim_end_matches('%').parse().unwrap_or(0);
            }
            "Channel" => {
                let channel: u32 = value.parse().unwrap_or(0);
                network.channel = channel;
                network.band = crate::scan::wifi::band_for_channel(channel).to_string();
            }
            _ => {}
        }
    }

    if let Some(network) = pending.take() {
        networks.push(network);
    }

    networks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_arp_table_and_skips_multicast() {
        let output = "\nInterface: 10.0.3.221 --- 0xa\n  Internet Address      Physical Address      Type\n  \
                      10.0.3.1              e0-63-da-82-1b-35     dynamic\n  \
                      10.0.3.22             24-62-ab-e4-5f-a4     dynamic\n  \
                      224.0.0.22            01-00-5e-00-00-16     static\n  \
                      255.255.255.255       ff-ff-ff-ff-ff-ff     static\n";
        let neighbors = parse_arp_a(output);
        assert_eq!(
            neighbors.len(),
            2,
            "multicast and broadcast rows must be dropped"
        );
        assert_eq!(
            neighbors[0].mac, "e0:63:da:82:1b:35",
            "dashes must become colons"
        );
        assert_eq!(neighbors[1].mac, "24:62:ab:e4:5f:a4");
    }

    #[test]
    fn windows_ping_uses_n_for_count_and_w_in_milliseconds() {
        let args = ping_args("10.0.3.1", 1, 1);
        assert_eq!(args[0], "-n");
        assert_eq!(args[1], "1");
        let w = args.iter().position(|a| a == "-w").unwrap();
        assert_eq!(args[w + 1], "1000");
    }

    #[test]
    fn parses_tracert_rows_including_timeouts() {
        let output = "\nTracing route to 1.1.1.1 over a maximum of 15 hops\n\n  \
                      1     1 ms     1 ms     1 ms  10.0.3.1\n  \
                      2     *        *        *     Request timed out.\n  \
                      3    12 ms    11 ms    13 ms  1.1.1.1\n";
        let hops = parse_tracert(output);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].host.as_deref(), Some("10.0.3.1"));
        assert!(hops[1].timeout);
        assert!(hops[1].host.is_none());
        assert_eq!(hops[2].rtt_ms, Some(12.0));
    }

    #[test]
    fn parses_netsh_networks_with_multiple_bssids_per_ssid() {
        let output = "Interface name : Wi-Fi\nThere are 2 networks currently visible.\n\n\
            SSID 1 : ADOFULL\n    Network type            : Infrastructure\n    Authentication          : WPA2-Personal\n    Encryption              : CCMP\n    \
            BSSID 1                 : 78:8a:20:5b:c4:b8\n         Signal             : 97%\n         Radio type         : 802.11ac\n         Channel            : 149\n    \
            BSSID 2                 : 7e:8a:20:5a:c4:b8\n         Signal             : 100%\n         Radio type         : 802.11n\n         Channel            : 6\n\n\
            SSID 2 : \n    Network type            : Infrastructure\n    Authentication          : WPA2-Personal\n    \
            BSSID 1                 : 86:8a:20:5a:c4:b8\n         Signal             : 52%\n         Channel            : 6\n";

        let networks = parse_netsh_networks(output);
        assert_eq!(networks.len(), 3, "each BSSID is its own radio");
        assert_eq!(networks[0].ssid, "ADOFULL");
        assert_eq!(networks[0].channel, 149);
        assert_eq!(networks[0].band, "5 GHz");
        assert_eq!(networks[0].signal, 97);
        assert_eq!(networks[1].channel, 6);
        assert_eq!(networks[1].band, "2.4 GHz");
        assert_eq!(
            networks[2].ssid, "(hidden)",
            "an empty SSID is a hidden network"
        );
        assert_eq!(networks[0].security.as_deref(), Some("WPA2-Personal"));
    }

    #[test]
    fn parses_netsh_interface_block() {
        let output = "    Name                   : Wi-Fi\n    SSID                   : ADOFULL\n    BSSID                  : 78:8a:20:5b:c4:b8\n    Receive rate (Mbps)    : 405\n";
        let (iface, ssid, bssid, rate) = parse_netsh_interfaces(output);
        assert_eq!(iface.as_deref(), Some("Wi-Fi"));
        assert_eq!(ssid.as_deref(), Some("ADOFULL"));
        assert_eq!(bssid.as_deref(), Some("78:8A:20:5B:C4:B8"));
        assert_eq!(rate.as_deref(), Some("405 Mbit/s"));
    }
}
