//! Host, interface and route inspection, plus scan-target selection.
//!
//! Interface enumeration uses the `if-addrs` crate rather than shelling out.
//! That is deliberate: it removes the hardest dependency the tool would
//! otherwise have (`ip` / `ifconfig` / `ipconfig`), so the app can always at
//! minimum determine what network it is on and scan it.

use crate::netutil::{parse_cidr, MIN_PREFIX};
use crate::platform;
use crate::types::{
    DnsConfig, HostInfo, InterfaceInfo, Ipv4Addr4, Ipv6Addr6, ScanTarget, TargetSource,
};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

/// Interface name prefixes that are never worth scanning.
fn is_virtual_interface(name: &str) -> bool {
    const VIRTUAL_PREFIXES: &[&str] = &[
        "docker", "br-", "virbr", "veth", "tun", "tap", "vboxnet", "vmnet", "utun", "awdl", "llw",
        "bridge", "zt", "wg",
    ];
    VIRTUAL_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

pub async fn collect(extra_ranges: &[String]) -> (HostInfo, Vec<String>) {
    let mut warnings = Vec::new();
    let mut interfaces = enumerate_interfaces();

    let (gateway, routes) = platform::default_gateway().await;
    let dns = platform::dns_servers().await;

    // Attach MACs from the neighbour tooling's view of our own interfaces where
    // possible; a host never ARPs for itself, so this comes from the OS listing.
    attach_local_macs(&mut interfaces);

    let gateway_dev = gateway.as_ref().map(|g| g.dev.clone()).unwrap_or_default();
    classify(&mut interfaces, &gateway_dev, &mut warnings);

    let scan_targets = build_targets(&interfaces, extra_ranges, &mut warnings);

    let host = HostInfo {
        hostname: hostname(),
        platform: format!("{} {}", platform::os_label(), std::env::consts::ARCH),
        os: platform::os_label(),
        arch: std::env::consts::ARCH.to_string(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        interfaces,
        routes,
        gateway,
        dns,
        scan_targets,
    };

    (host, warnings)
}

/// The ranges a scan started right now would sweep.
///
/// Cheap on purpose — interface enumeration only, no gateway, DNS or neighbour
/// probes — so the UI can call it whenever its inputs change to show what
/// "Run scan" will actually do before it is pressed.
pub fn preview_targets(extra_ranges: &[String]) -> Vec<ScanTarget> {
    let mut warnings = Vec::new();
    let mut interfaces = enumerate_interfaces();
    // No gateway lookup here: it only sets `is_primary`, which the target
    // list does not depend on.
    classify(&mut interfaces, "", &mut warnings);
    build_targets(&interfaces, extra_ranges, &mut warnings)
}

fn enumerate_interfaces() -> Vec<InterfaceInfo> {
    let mut interfaces: Vec<InterfaceInfo> = Vec::new();

    let addrs = if_addrs::get_if_addrs().unwrap_or_default();

    for iface in addrs {
        let name = iface.name.clone();
        let entry = match interfaces.iter_mut().find(|i| i.name == name) {
            Some(existing) => existing,
            None => {
                interfaces.push(InterfaceInfo {
                    name: name.clone(),
                    state: if iface.is_loopback() {
                        "LOOPBACK".into()
                    } else {
                        "UP".into()
                    },
                    mac: None,
                    mtu: None,
                    flags: Vec::new(),
                    ipv4: Vec::new(),
                    ipv6: Vec::new(),
                    is_primary: false,
                    scannable: false,
                    skip_reason: None,
                });
                interfaces.last_mut().expect("just pushed")
            }
        };

        match iface.addr {
            if_addrs::IfAddr::V4(v4) => {
                entry.ipv4.push(Ipv4Addr4 {
                    address: v4.ip.to_string(),
                    cidr: mask_to_prefix(v4.netmask),
                });
            }
            if_addrs::IfAddr::V6(v6) => {
                let scope = if v6.ip.is_loopback() {
                    "host"
                } else if v6.ip.segments()[0] & 0xffc0 == 0xfe80 {
                    "link"
                } else {
                    "global"
                };
                entry.ipv6.push(Ipv6Addr6 {
                    address: v6.ip.to_string(),
                    cidr: u128::from(v6.netmask).count_ones() as u8,
                    scope: scope.into(),
                });
            }
        }
    }

    interfaces
}

#[cfg(target_os = "linux")]
fn attach_local_macs(interfaces: &mut [InterfaceInfo]) {
    // /sys is the cheapest reliable source and needs no external command.
    for iface in interfaces.iter_mut() {
        let path = format!("/sys/class/net/{}/address", iface.name);
        if let Ok(mac) = std::fs::read_to_string(&path) {
            let mac = mac.trim().to_string();
            if !mac.is_empty() && !crate::netutil::is_meaningless_mac(&mac) {
                iface.mac = Some(mac);
            }
        }
        let mtu_path = format!("/sys/class/net/{}/mtu", iface.name);
        if let Ok(mtu) = std::fs::read_to_string(&mtu_path) {
            iface.mtu = mtu.trim().parse().ok();
        }
        let flags_path = format!("/sys/class/net/{}/operstate", iface.name);
        if let Ok(state) = std::fs::read_to_string(&flags_path) {
            let state = state.trim().to_ascii_uppercase();
            if !state.is_empty() {
                iface.state = state;
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn attach_local_macs(_interfaces: &mut [InterfaceInfo]) {
    // macOS and Windows expose this only through platform APIs that would pull in
    // extra dependencies; the interface MAC is cosmetic here, since device MACs
    // come from the neighbour table.
}

fn classify(interfaces: &mut [InterfaceInfo], gateway_dev: &str, warnings: &mut Vec<String>) {
    for iface in interfaces.iter_mut() {
        iface.is_primary = !gateway_dev.is_empty() && iface.name == gateway_dev;

        let is_loopback = iface.name == "lo" || iface.name == "lo0" || {
            iface.ipv4.iter().any(|a| a.address.starts_with("127."))
        };

        if is_loopback {
            iface.scannable = false;
            iface.skip_reason = Some("loopback".into());
            continue;
        }
        if iface.ipv4.is_empty() {
            iface.scannable = false;
            iface.skip_reason = Some("no IPv4 address".into());
            continue;
        }
        if is_virtual_interface(&iface.name) {
            iface.scannable = false;
            iface.skip_reason = Some("virtual/container bridge".into());
            warnings.push(format!(
                "Skipping {} (virtual/container bridge)",
                iface.name
            ));
            continue;
        }
        if iface.state == "DOWN" || iface.flags.iter().any(|f| f == "NO-CARRIER") {
            iface.scannable = false;
            iface.skip_reason = Some("link down".into());
            continue;
        }
        if iface.ipv4.iter().all(|a| a.cidr < MIN_PREFIX) {
            iface.scannable = false;
            iface.skip_reason = Some(format!("subnet wider than /{MIN_PREFIX}"));
            warnings.push(format!(
                "Skipping {} — its subnet is wider than /{MIN_PREFIX} and would be too large to sweep",
                iface.name
            ));
            continue;
        }

        iface.scannable = true;
    }
}

fn build_targets(
    interfaces: &[InterfaceInfo],
    extra_ranges: &[String],
    warnings: &mut Vec<String>,
) -> Vec<ScanTarget> {
    let mut targets = Vec::new();
    let mut seen = HashSet::new();

    for iface in interfaces.iter().filter(|i| i.scannable) {
        for addr in &iface.ipv4 {
            if addr.cidr < MIN_PREFIX {
                continue;
            }
            let Ok(parsed) = parse_cidr(&format!("{}/{}", addr.address, addr.cidr)) else {
                continue;
            };
            let key = parsed.canonical();
            if !seen.insert(key.clone()) {
                continue;
            }
            targets.push(ScanTarget {
                cidr: key,
                source: TargetSource::Local,
                host_count: parsed.host_count(),
                note: Some(format!("local subnet on {}", iface.name)),
            });
        }
    }

    for raw in extra_ranges {
        match validate_range(raw) {
            Ok(normalized) => {
                let Ok(parsed) = parse_cidr(&normalized) else {
                    continue;
                };
                if !seen.insert(normalized.clone()) {
                    continue;
                }
                targets.push(ScanTarget {
                    cidr: normalized,
                    source: TargetSource::Manual,
                    host_count: parsed.host_count(),
                    note: Some("user-supplied range".into()),
                });
            }
            Err(error) => warnings.push(format!("Ignoring range \"{raw}\": {error}")),
        }
    }

    targets
}

/// Validates a user-supplied range, refusing public address space outright.
pub fn validate_range(cidr: &str) -> Result<String, String> {
    let parsed = parse_cidr(cidr)?;
    if !crate::netutil::is_private_ipv4(parsed.network) {
        return Err(format!(
            "{cidr} is not a private range — this tool refuses to scan public address space"
        ));
    }
    Ok(parsed.canonical())
}

pub async fn parse_resolv_conf() -> DnsConfig {
    let mut config = DnsConfig::default();
    let Ok(contents) = tokio::fs::read_to_string("/etc/resolv.conf").await else {
        return config;
    };

    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            let server = rest.trim().to_string();
            if server.parse::<IpAddr>().is_ok() && !config.servers.contains(&server) {
                config.servers.push(server);
            }
        }
        if let Some(rest) = trimmed.strip_prefix("search") {
            for domain in rest.split_whitespace() {
                if !config.search_domains.contains(&domain.to_string()) {
                    config.search_domains.push(domain.to_string());
                }
            }
        }
    }

    config
}

fn hostname() -> String {
    #[cfg(unix)]
    {
        if let Ok(name) = std::fs::read_to_string("/etc/hostname") {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ip: &str, cidr: u8, state: &str) -> InterfaceInfo {
        InterfaceInfo {
            name: name.into(),
            state: state.into(),
            mac: None,
            mtu: None,
            flags: Vec::new(),
            ipv4: vec![Ipv4Addr4 {
                address: ip.into(),
                cidr,
            }],
            ipv6: Vec::new(),
            is_primary: false,
            scannable: false,
            skip_reason: None,
        }
    }

    #[test]
    fn excludes_docker_bridges_and_loopback_but_keeps_the_real_link() {
        let mut interfaces = vec![
            iface("lo", "127.0.0.1", 8, "UNKNOWN"),
            iface("wlo1", "10.0.3.221", 24, "UP"),
            iface("docker0", "172.17.0.1", 16, "DOWN"),
        ];
        let mut warnings = Vec::new();
        classify(&mut interfaces, "wlo1", &mut warnings);

        assert!(!interfaces[0].scannable, "loopback must never be scanned");
        assert!(interfaces[1].scannable);
        assert!(interfaces[1].is_primary);
        assert!(
            !interfaces[2].scannable,
            "a /16 docker bridge would be 65k hosts"
        );
        assert!(warnings.iter().any(|w| w.contains("docker0")));
    }

    #[test]
    fn builds_local_targets_from_scannable_interfaces_only() {
        let mut interfaces = vec![
            iface("wlo1", "10.0.3.221", 24, "UP"),
            iface("docker0", "172.17.0.1", 16, "DOWN"),
        ];
        let mut warnings = Vec::new();
        classify(&mut interfaces, "wlo1", &mut warnings);

        let targets = build_targets(&interfaces, &[], &mut warnings);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].cidr, "10.0.3.0/24");
        assert_eq!(targets[0].host_count, 254);
    }

    #[test]
    fn refuses_public_ranges_and_oversized_prefixes() {
        assert!(validate_range("8.8.8.0/24")
            .unwrap_err()
            .contains("private"));
        assert!(validate_range("10.0.0.0/8")
            .unwrap_err()
            .contains("too large"));
        assert_eq!(validate_range("192.168.1.50/24").unwrap(), "192.168.1.0/24");
    }

    #[test]
    fn invalid_manual_ranges_become_warnings_not_failures() {
        let interfaces: Vec<InterfaceInfo> = Vec::new();
        let mut warnings = Vec::new();
        let targets = build_targets(&interfaces, &["not-a-cidr".into()], &mut warnings);
        assert!(targets.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Ignoring range"));
    }

    #[test]
    fn converts_netmasks_to_prefix_lengths() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 252)), 30);
    }

    #[tokio::test]
    async fn collects_real_host_info_on_this_machine() {
        let (host, _warnings) = collect(&[]).await;
        assert!(
            !host.interfaces.is_empty(),
            "there is always at least a loopback interface"
        );
        assert!(!host.hostname.is_empty());
    }
}
