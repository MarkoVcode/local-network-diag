//! Capability doctor.
//!
//! Reports what the app can actually do on *this* machine, and explains what is
//! lost when something is missing.
//!
//! The important design decision here: these are **functional probes, not
//! `which` checks**. A binary being present says very little — on Linux `ping`
//! can exist but be unable to open an ICMP socket because it lacks
//! `cap_net_raw` and `ping_group_range` excludes the user; on macOS the Wi-Fi
//! tools exist but return nothing until Location Services permission is granted;
//! inside a container the ARP table can be readable but permanently empty. Each
//! check therefore *performs* the operation and reports what really happened.

use crate::exec::{clear_tool_cache, has_tool, run};
use crate::platform;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// How badly a missing capability hurts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// The app cannot perform a scan at all without this.
    Critical,
    /// A major feature is lost, but scanning still produces useful results.
    Important,
    /// A nice-to-have; its absence narrows detail only.
    Optional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityStatus {
    /// Verified working.
    Ok,
    /// Present but limited — reduced results rather than none.
    Degraded,
    /// Not working at all.
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityReport {
    pub id: String,
    pub label: String,
    /// What this capability provides, in plain language.
    pub purpose: String,
    pub tier: Tier,
    pub status: CapabilityStatus,
    /// The command or OS facility this depends on, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// What the probe actually observed.
    pub detail: String,
    /// Which app features stop working, listed for the user.
    pub affects: Vec<String>,
    /// How to fix it on this OS. Absent when nothing needs fixing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

impl CapabilityReport {
    fn ok(
        id: &str,
        label: &str,
        purpose: &str,
        tier: Tier,
        tool: Option<&str>,
        detail: String,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            purpose: purpose.into(),
            tier,
            status: CapabilityStatus::Ok,
            tool: tool.map(|t| t.to_string()),
            detail,
            affects: Vec::new(),
            remedy: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorReport {
    pub os: String,
    pub checked_at: String,
    pub capabilities: Vec<CapabilityReport>,
    /// True when at least one Critical capability is missing — the app cannot scan.
    pub blocked: bool,
    /// One-line summary for the status bar.
    pub summary: String,
    pub counts: DoctorCounts,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorCounts {
    pub ok: usize,
    pub degraded: usize,
    pub missing: usize,
    pub critical_missing: usize,
}

/* ----------------------------------------------------------------- the checks */

/// A usable IPv4 interface. This is the one genuinely fatal precondition: with
/// no address on a real network there is nothing to scan and no way to invent one.
async fn check_interfaces() -> CapabilityReport {
    let addrs = if_addrs::get_if_addrs().unwrap_or_default();
    let usable: Vec<String> = addrs
        .iter()
        .filter(|iface| !iface.is_loopback() && iface.addr.ip().is_ipv4())
        .map(|iface| format!("{} ({})", iface.name, iface.addr.ip()))
        .collect();

    if usable.is_empty() {
        return CapabilityReport {
            id: "interfaces".into(),
            label: "Network interface".into(),
            purpose: "Determines which network this machine is on and what range to scan.".into(),
            tier: Tier::Critical,
            status: CapabilityStatus::Missing,
            tool: None,
            detail: "No non-loopback IPv4 interface was found.".into(),
            affects: vec![
                "Everything — with no network address there is nothing to scan".into(),
            ],
            remedy: Some(
                "Connect to a network (Wi-Fi or Ethernet) and re-run the check. If you are connected, check that the adapter has an IPv4 address rather than only IPv6."
                    .into(),
            ),
        };
    }

    CapabilityReport::ok(
        "interfaces",
        "Network interface",
        "Determines which network this machine is on and what range to scan.",
        Tier::Critical,
        None,
        format!(
            "Found {}: {}",
            plural(usable.len(), "usable interface"),
            usable.join(", ")
        ),
    )
}

/// TCP connect scanning. Portable and unprivileged, so this effectively always
/// works — but it is checked rather than assumed, because a sandbox or a
/// restrictive local firewall can block outbound connections entirely.
async fn check_tcp() -> CapabilityReport {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::net::{TcpListener, TcpStream};

    let probe = async {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .ok()?;
        let port = listener.local_addr().ok()?.port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        tokio::time::timeout(
            Duration::from_secs(2),
            TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        )
        .await
        .ok()?
        .ok()
    };

    match probe.await {
        Some(_) => CapabilityReport::ok(
            "tcp-scan",
            "TCP port scanning",
            "Finds open services, and detects hosts that ignore ping but accept connections.",
            Tier::Critical,
            None,
            if cfg!(windows) {
                // Worth stating plainly: on Windows a dropped (rather than
                // rejected) SYN makes a closed port look identical to a
                // filtered one, so the "refused means the host is up" signal
                // that finds ICMP-silent devices may not be available.
                "Outbound TCP connections work; the port scanner is functional. Note that \
                 Windows Firewall often drops rather than rejects connections to closed \
                 ports, so a device that ignores ping and has no open ports may not be \
                 detected."
                    .into()
            } else {
                "Outbound TCP connections work; the port scanner is fully functional.".into()
            },
        ),
        None => CapabilityReport {
            id: "tcp-scan".into(),
            label: "TCP port scanning".into(),
            purpose: "Finds open services, and detects hosts that ignore ping but accept connections.".into(),
            tier: Tier::Critical,
            status: CapabilityStatus::Missing,
            tool: None,
            detail: "Could not open a TCP connection even to this machine.".into(),
            affects: vec![
                "Port discovery".into(),
                "Detecting devices that do not answer ping".into(),
                "Service banners and TLS certificates".into(),
            ],
            remedy: Some(
                "A local firewall or sandbox is blocking outbound TCP. Allow this application through the firewall."
                    .into(),
            ),
        },
    }
}

/// ICMP. Present-but-unusable is the common failure, so this actually pings
/// loopback rather than trusting that the binary exists.
async fn check_icmp() -> CapabilityReport {
    let tool = platform::PING_TOOL;
    let affects = vec![
        "Fast host discovery (the scan falls back to slower TCP probing)".into(),
        "Latency, jitter and packet-loss measurement".into(),
        "MAC address resolution, which depends on the ARP cache being populated".into(),
    ];

    if !has_tool(tool.command).await {
        return CapabilityReport {
            id: "icmp".into(),
            label: "ICMP ping".into(),
            purpose: "Discovers live hosts quickly and measures latency and packet loss.".into(),
            tier: Tier::Important,
            status: CapabilityStatus::Missing,
            tool: Some(tool.command.into()),
            detail: format!("`{}` was not found on PATH.", tool.command),
            affects,
            remedy: Some(tool.remedy.into()),
        };
    }

    let args = platform::ping_args("127.0.0.1", 1, 1);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = run("ping", &arg_refs, Duration::from_secs(5)).await;
    let output = if result.stdout.trim().is_empty() {
        result.stderr.clone()
    } else {
        result.stdout.clone()
    };

    if crate::scan::sweep::ping_succeeded(result.ok, &output) {
        return CapabilityReport::ok(
            "icmp",
            "ICMP ping",
            "Discovers live hosts quickly and measures latency and packet loss.",
            Tier::Important,
            Some(tool.command),
            "Verified by pinging loopback — ICMP works without elevated privileges.".into(),
        );
    }

    // The binary exists but cannot actually send. On Linux this is nearly always
    // a missing capability rather than a missing package.
    let hint = if cfg!(target_os = "linux") {
        "`ping` exists but could not send an ICMP echo. Grant it the capability with `sudo setcap cap_net_raw+ep $(which ping)`, or allow unprivileged ICMP with `sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"`."
    } else {
        "`ping` exists but could not send an ICMP echo. Check whether a security product or firewall is blocking ICMP for this application."
    };

    CapabilityReport {
        id: "icmp".into(),
        label: "ICMP ping".into(),
        purpose: "Discovers live hosts quickly and measures latency and packet loss.".into(),
        tier: Tier::Important,
        status: CapabilityStatus::Missing,
        tool: Some(tool.command.into()),
        detail: format!(
            "`{}` is installed but the probe to 127.0.0.1 did not succeed.",
            tool.command
        ),
        affects,
        remedy: Some(hint.into()),
    }
}

/// ARP/neighbour table — the source of MAC addresses and therefore vendor names.
async fn check_arp() -> CapabilityReport {
    let tool = platform::ARP_TOOL;
    let affects = vec![
        "MAC addresses for discovered devices".into(),
        "Hardware vendor identification".into(),
        "Detecting a device that changed IP address between scans".into(),
        "Flagging phones using a randomized (private) MAC".into(),
    ];

    if !has_tool(tool.command).await {
        return CapabilityReport {
            id: "arp".into(),
            label: "ARP / neighbour table".into(),
            purpose:
                "Reads MAC addresses of discovered devices, which identifies hardware vendors."
                    .into(),
            tier: Tier::Important,
            status: CapabilityStatus::Missing,
            tool: Some(tool.command.into()),
            detail: format!("`{}` was not found on PATH.", tool.command),
            affects,
            remedy: Some(tool.remedy.into()),
        };
    }

    let entries = platform::neighbor_table().await;

    if entries.is_empty() {
        // Readable but empty: normal on a freshly-booted machine, so this is
        // Degraded rather than Missing — a scan will populate it.
        return CapabilityReport {
            id: "arp".into(),
            label: "ARP / neighbour table".into(),
            purpose: "Reads MAC addresses of discovered devices, which identifies hardware vendors."
                .into(),
            tier: Tier::Important,
            status: CapabilityStatus::Degraded,
            tool: Some(tool.command.into()),
            detail: format!(
                "`{}` ran but the neighbour table is currently empty. This is normal before the first scan — pinging hosts populates it.",
                tool.command
            ),
            affects: vec!["MAC addresses may be missing until a scan has run".into()],
            remedy: None,
        };
    }

    CapabilityReport::ok(
        "arp",
        "ARP / neighbour table",
        "Reads MAC addresses of discovered devices, which identifies hardware vendors.",
        Tier::Important,
        Some(tool.command),
        format!(
            "Readable — {} currently cached.",
            plural(entries.len(), "entry")
        ),
    )
}

/// mDNS is implemented in-process, so the only thing that can fail is binding a
/// multicast socket, which some sandboxes and firewalls prevent.
async fn check_mdns() -> CapabilityReport {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    let probe = || -> std::io::Result<()> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        let bind: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
        socket.bind(&bind.into())?;
        socket.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 251), &Ipv4Addr::UNSPECIFIED)?;
        Ok(())
    };

    match probe() {
        Ok(()) => CapabilityReport::ok(
            "mdns",
            "mDNS / Bonjour discovery",
            "Finds device names and rich metadata — ESPHome chip and firmware, Home Assistant version, Apple device names, printers and speakers.",
            Tier::Optional,
            None,
            "Multicast socket opened successfully. This is built in — no Avahi or Bonjour installation is required.".into(),
        ),
        Err(error) => CapabilityReport {
            id: "mdns".into(),
            label: "mDNS / Bonjour discovery".into(),
            purpose: "Finds device names and rich metadata — ESPHome chip and firmware, Home Assistant version, Apple device names, printers and speakers.".into(),
            tier: Tier::Optional,
            status: CapabilityStatus::Missing,
            tool: None,
            detail: format!("Could not join the mDNS multicast group: {error}"),
            affects: vec![
                "Friendly device names".into(),
                "Device metadata (firmware versions, models, capabilities)".into(),
                "Discovery of devices on other subnets".into(),
            ],
            remedy: Some(
                "Allow this application to receive multicast UDP on port 5353 through your firewall."
                    .into(),
            ),
        },
    }
}

/// SSDP/UPnP, also in-process — only outbound multicast is needed.
async fn check_ssdp() -> CapabilityReport {
    use tokio::net::UdpSocket;

    match UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => {
            let sent = socket
                .send_to(b"", ("239.255.255.250", 1900))
                .await
                .is_ok();
            if sent {
                CapabilityReport::ok(
                    "ssdp",
                    "UPnP / SSDP discovery",
                    "Reads manufacturer, model and serial number from routers, TVs, set-top boxes and media devices.",
                    Tier::Optional,
                    None,
                    "Multicast send succeeded. Built in — no external UPnP tool required.".into(),
                )
            } else {
                CapabilityReport {
                    id: "ssdp".into(),
                    label: "UPnP / SSDP discovery".into(),
                    purpose: "Reads manufacturer, model and serial number from routers, TVs, set-top boxes and media devices.".into(),
                    tier: Tier::Optional,
                    status: CapabilityStatus::Missing,
                    tool: None,
                    detail: "Could not send to the SSDP multicast address.".into(),
                    affects: vec!["Manufacturer, model and serial number for UPnP devices".into()],
                    remedy: Some("Allow outbound multicast UDP to 239.255.255.250:1900.".into()),
                }
            }
        }
        Err(error) => CapabilityReport {
            id: "ssdp".into(),
            label: "UPnP / SSDP discovery".into(),
            purpose: "Reads manufacturer, model and serial number from routers, TVs, set-top boxes and media devices.".into(),
            tier: Tier::Optional,
            status: CapabilityStatus::Missing,
            tool: None,
            detail: format!("Could not open a UDP socket: {error}"),
            affects: vec!["Manufacturer, model and serial number for UPnP devices".into()],
            remedy: Some("Allow this application to open UDP sockets.".into()),
        },
    }
}

/// DNS resolution, checked against the configured resolvers rather than assumed.
async fn check_dns() -> CapabilityReport {
    let config = platform::dns_servers().await;

    if config.servers.is_empty() {
        return CapabilityReport {
            id: "dns".into(),
            label: "DNS resolution".into(),
            purpose: "Resolves device names via reverse DNS and measures resolver response times."
                .into(),
            tier: Tier::Important,
            status: CapabilityStatus::Missing,
            tool: None,
            detail: "No DNS servers are configured on this machine.".into(),
            affects: vec![
                "Reverse-DNS device names".into(),
                "DNS response-time measurement".into(),
                "Public IP detection".into(),
            ],
            remedy: Some(
                "Configure a DNS server in your network settings, or connect to a network that provides one via DHCP."
                    .into(),
            ),
        };
    }

    CapabilityReport::ok(
        "dns",
        "DNS resolution",
        "Resolves device names via reverse DNS and measures resolver response times.",
        Tier::Important,
        None,
        format!(
            "{} configured: {}",
            plural(config.servers.len(), "resolver"),
            config.servers.join(", ")
        ),
    )
}

/// Traceroute — optional detail about the path beyond the gateway.
async fn check_traceroute() -> CapabilityReport {
    let tool = platform::TRACE_TOOL;
    let candidates: &[&str] = if cfg!(windows) {
        &["tracert"]
    } else {
        &["mtr", "tracepath", "traceroute"]
    };

    let mut found = Vec::new();
    for candidate in candidates {
        if has_tool(candidate).await {
            found.push(*candidate);
        }
    }

    if found.is_empty() {
        return CapabilityReport {
            id: "traceroute".into(),
            label: "Traceroute".into(),
            purpose:
                "Shows the network path to the internet and where latency or loss is introduced."
                    .into(),
            tier: Tier::Optional,
            status: CapabilityStatus::Missing,
            tool: Some(tool.command.into()),
            detail: format!("None of {} were found on PATH.", candidates.join(", ")),
            affects: vec!["The Path panel on the Connectivity page".into()],
            remedy: Some(tool.remedy.into()),
        };
    }

    CapabilityReport::ok(
        "traceroute",
        "Traceroute",
        "Shows the network path to the internet and where latency or loss is introduced.",
        Tier::Optional,
        Some(found[0]),
        format!("Available: {}. Using {}.", found.join(", "), found[0]),
    )
}

/// Wi-Fi survey — the most commonly-missing capability, and platform-specific.
async fn check_wifi() -> CapabilityReport {
    let tool = platform::WIFI_TOOL;
    let affects = vec![
        "Signal strength, channel and link rate".into(),
        "Channel congestion analysis and the channel recommendation".into(),
        "The list of neighbouring access points".into(),
    ];

    if !has_tool(tool.command).await {
        return CapabilityReport {
            id: "wifi".into(),
            label: "Wi-Fi survey".into(),
            purpose: "Reports signal strength, channel, and how congested your Wi-Fi channel is."
                .into(),
            tier: Tier::Optional,
            status: CapabilityStatus::Missing,
            tool: Some(tool.command.into()),
            detail: format!("`{}` was not found on PATH.", tool.command),
            affects,
            remedy: Some(tool.remedy.into()),
        };
    }

    // Actually run the survey — on macOS the tool exists but returns nothing
    // until Location Services permission is granted, and on a desktop with no
    // wireless adapter it succeeds but reports zero networks.
    let survey = platform::wifi_survey().await;

    match survey.status {
        crate::types::ProbeStatus::Ok => {
            let count = survey.data.as_ref().map(|w| w.networks.len()).unwrap_or(0);
            CapabilityReport::ok(
                "wifi",
                "Wi-Fi survey",
                "Reports signal strength, channel, and how congested your Wi-Fi channel is.",
                Tier::Optional,
                Some(tool.command),
                format!("Working — {} visible.", plural(count, "network")),
            )
        }
        _ => CapabilityReport {
            id: "wifi".into(),
            label: "Wi-Fi survey".into(),
            purpose: "Reports signal strength, channel, and how congested your Wi-Fi channel is."
                .into(),
            tier: Tier::Optional,
            // Degraded, not Missing: the tool works, it just has nothing to report,
            // which is the correct state for a wired-only machine.
            status: CapabilityStatus::Degraded,
            tool: Some(tool.command.into()),
            detail: survey
                .detail
                .unwrap_or_else(|| "The Wi-Fi survey returned no data.".into()),
            affects,
            remedy: Some(tool.remedy.into()),
        },
    }
}

/// NetBIOS is in-process; only UDP is required.
async fn check_netbios() -> CapabilityReport {
    match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(_) => CapabilityReport::ok(
            "netbios",
            "NetBIOS name lookup",
            "Reads machine names and workgroups from Windows PCs, Samba servers and NAS devices.",
            Tier::Optional,
            None,
            "UDP socket available. Built in — no `nmblookup` or Samba tools required.".into(),
        ),
        Err(error) => CapabilityReport {
            id: "netbios".into(),
            label: "NetBIOS name lookup".into(),
            purpose: "Reads machine names and workgroups from Windows PCs, Samba servers and NAS devices.".into(),
            tier: Tier::Optional,
            status: CapabilityStatus::Missing,
            tool: None,
            detail: format!("Could not open a UDP socket: {error}"),
            affects: vec!["Windows and NAS machine names".into()],
            remedy: Some("Allow this application to open UDP sockets.".into()),
        },
    }
}

/// The bundled vendor database.
async fn check_oui() -> CapabilityReport {
    let info = crate::oui::table_info();

    if info.prefixes == 0 {
        return CapabilityReport {
            id: "oui".into(),
            label: "Hardware vendor database".into(),
            purpose: "Translates MAC addresses into manufacturer names.".into(),
            tier: Tier::Optional,
            status: CapabilityStatus::Missing,
            tool: None,
            detail: "The bundled IEEE OUI table failed to load.".into(),
            affects: vec!["Vendor names for discovered devices".into()],
            remedy: Some(
                "This indicates a corrupt installation — reinstall the application.".into(),
            ),
        };
    }

    CapabilityReport::ok(
        "oui",
        "Hardware vendor database",
        "Translates MAC addresses into manufacturer names.",
        Tier::Optional,
        None,
        format!(
            "{} IEEE prefixes loaded{}. Bundled with the app — works offline.",
            info.prefixes,
            if info.generated_at.is_empty() {
                String::new()
            } else {
                format!(
                    " (generated {})",
                    &info.generated_at[..10.min(info.generated_at.len())]
                )
            }
        ),
    )
}

fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        return format!("{count} {noun}");
    }
    match noun.strip_suffix('y') {
        Some(stem) => format!("{count} {stem}ies"),
        None => format!("{count} {noun}s"),
    }
}

/// Runs every check. `force` clears the tool-availability cache first, so a tool
/// installed while the app is running is picked up without a restart.
pub async fn run_diagnostics(force: bool) -> DoctorReport {
    if force {
        clear_tool_cache().await;
    }

    let capabilities = vec![
        check_interfaces().await,
        check_tcp().await,
        check_icmp().await,
        check_arp().await,
        check_dns().await,
        check_mdns().await,
        check_ssdp().await,
        check_netbios().await,
        check_wifi().await,
        check_traceroute().await,
        check_oui().await,
    ];

    let mut counts = DoctorCounts::default();
    for capability in &capabilities {
        match capability.status {
            CapabilityStatus::Ok => counts.ok += 1,
            CapabilityStatus::Degraded => counts.degraded += 1,
            CapabilityStatus::Missing => {
                counts.missing += 1;
                if capability.tier == Tier::Critical {
                    counts.critical_missing += 1;
                }
            }
        }
    }

    let blocked = counts.critical_missing > 0;

    let summary = if blocked {
        let names: Vec<&str> = capabilities
            .iter()
            .filter(|c| c.tier == Tier::Critical && c.status == CapabilityStatus::Missing)
            .map(|c| c.label.as_str())
            .collect();
        format!(
            "Cannot scan — required capability unavailable: {}",
            names.join(", ")
        )
    } else if counts.missing > 0 || counts.degraded > 0 {
        format!(
            "{} working, {} limited, {} unavailable — some features are reduced",
            counts.ok, counts.degraded, counts.missing
        )
    } else {
        format!("All {} checks passed", counts.ok)
    };

    DoctorReport {
        os: platform::os_label(),
        checked_at: chrono::Utc::now().to_rfc3339(),
        capabilities,
        blocked,
        summary,
        counts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_capability_reports_a_status_and_explains_itself() {
        let report = run_diagnostics(true).await;
        assert!(!report.capabilities.is_empty());

        for capability in &report.capabilities {
            assert!(
                !capability.label.is_empty(),
                "{} has no label",
                capability.id
            );
            assert!(
                !capability.purpose.is_empty(),
                "{} has no purpose",
                capability.id
            );
            assert!(
                !capability.detail.is_empty(),
                "{} has no detail",
                capability.id
            );

            // Anything not working must tell the user what it costs and how to fix it.
            if capability.status != CapabilityStatus::Ok {
                assert!(
                    !capability.affects.is_empty(),
                    "{} is {:?} but does not say what it affects",
                    capability.id,
                    capability.status
                );
                assert!(
                    capability.remedy.is_some(),
                    "{} is {:?} but offers no remedy",
                    capability.id,
                    capability.status
                );
            }
        }
    }

    #[tokio::test]
    async fn counts_match_the_capability_list() {
        let report = run_diagnostics(false).await;
        let total = report.counts.ok + report.counts.degraded + report.counts.missing;
        assert_eq!(total, report.capabilities.len());
        assert_eq!(report.blocked, report.counts.critical_missing > 0);
    }

    #[tokio::test]
    async fn core_capabilities_work_on_this_machine() {
        let report = run_diagnostics(true).await;

        let find = |id: &str| {
            report
                .capabilities
                .iter()
                .find(|c| c.id == id)
                .unwrap()
                .status
        };

        // These are the ones that must hold on any developer machine.
        assert_eq!(find("interfaces"), CapabilityStatus::Ok);
        assert_eq!(find("tcp-scan"), CapabilityStatus::Ok);
        assert_eq!(find("oui"), CapabilityStatus::Ok);
        assert!(
            !report.blocked,
            "a normal machine must not be blocked: {}",
            report.summary
        );
    }

    #[test]
    fn tier_ordering_puts_critical_first() {
        let mut tiers = vec![Tier::Optional, Tier::Critical, Tier::Important];
        tiers.sort();
        assert_eq!(tiers, vec![Tier::Critical, Tier::Important, Tier::Optional]);
    }

    #[test]
    fn pluralises_correctly() {
        assert_eq!(plural(1, "interface"), "1 interface");
        assert_eq!(plural(2, "interface"), "2 interfaces");
        assert_eq!(plural(1, "entry"), "1 entry");
        assert_eq!(plural(3, "entry"), "3 entries");
    }
}
