//! Joining controller data to scan results.
//!
//! The useful output is not the union of the two sources — it is the small set
//! of findings that exist **only where they disagree**. A device the scanner can
//! reach but the controller has never issued a lease to is interesting precisely
//! because the two views conflict; neither tool can produce that category alone.

use super::model::UnifiSnapshot;
use crate::types::{Device, DeviceType};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Why a device is considered unaccounted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShadowReason {
    /// Reachable, but the controller has no record of this MAC at all.
    UnknownToController,
    /// The controller knows the MAC, but against a different address than the
    /// one answering — an IP conflict, or ARP being answered by something else.
    AddressMismatch,
    /// Found by scan with no MAC resolved and no controller match to anchor it.
    Unidentified,
}

impl ShadowReason {
    pub fn explain(&self) -> &'static str {
        match self {
            ShadowReason::UnknownToController => {
                "Responds on the network, but the controller has no record of it. Usually a \
                 static IP that never took a DHCP lease, or something plugged in behind an \
                 unmanaged switch. Worth confirming you recognise it."
            }
            ShadowReason::AddressMismatch => {
                "The controller associates this hardware address with a different IP than the \
                 one answering here. That is either an IP conflict or ARP being answered by \
                 another device."
            }
            ShadowReason::Unidentified => {
                "Answers on the network but could not be tied to any hardware address or \
                 controller record, so nothing can vouch for what it is."
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShadowDevice {
    pub ip: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    pub open_ports: Vec<u16>,
    pub reason: ShadowReason,
    pub explanation: String,
}

/// A device the controller knows but our scan never saw.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MissedDevice {
    pub mac: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub explanation: String,
}

/// A wireless client whose connection the controller itself rates as poor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WirelessHealthIssue {
    pub ip: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub satisfaction: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_dbm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_point: Option<String>,
    pub explanation: String,
}

/// A switch port linked far below what its own hardware demonstrates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DegradedLink {
    pub switch_name: String,
    pub port: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_name: Option<String>,
    pub speed_mbps: i64,
    pub explanation: String,
}

/// A client the controller's event log shows repeatedly dropping off.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlappingClient {
    pub mac: String,
    pub name: String,
    /// Disconnect events inside the event window (24 h).
    pub disconnects: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_point: Option<String>,
    pub explanation: String,
}

/// A network the controller defines but no scan target covered.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnscannedNetwork {
    pub name: String,
    pub subnet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenSegment {
    pub switch_name: String,
    pub port: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_name: Option<String>,
    pub mac_count: usize,
    pub explanation: String,
}

/// The reconciliation quadrant plus the inferences drawn from it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reconciliation {
    /// Seen by both — the healthy case.
    pub matched: usize,
    /// Seen by the scan, unknown to the controller.
    pub shadow: Vec<ShadowDevice>,
    /// Known to the controller, never seen by the scan.
    pub missed: Vec<MissedDevice>,
    /// Switch ports with several MACs behind them.
    pub hidden_segments: Vec<HiddenSegment>,
    /// Devices whose controller identity contradicts observed behaviour.
    pub identity_conflicts: Vec<String>,
    /// Wireless clients the controller itself rates as struggling.
    /// Defaulted so snapshots stored before 1.2 still load.
    #[serde(default)]
    pub wireless_issues: Vec<WirelessHealthIssue>,
    /// Switch ports negotiated far below the switch's demonstrated speed.
    #[serde(default)]
    pub degraded_links: Vec<DegradedLink>,
    /// Configured networks this scan's targets never covered — the scanner's
    /// own blind spots, stated by name.
    #[serde(default)]
    pub unscanned_networks: Vec<UnscannedNetwork>,
    /// Clients the controller's event log shows repeatedly disconnecting.
    #[serde(default)]
    pub flapping_clients: Vec<FlappingClient>,
    pub summary: String,
}

/// Merges controller data into the device list and produces the quadrant.
///
/// Enrichment is additive: a controller alias improves `display_name`, and
/// location/VLAN/signal become new fields. Nothing the scanner observed
/// first-hand is overwritten, because the scan measured it and the controller
/// only believes it.
///
/// `scanned_cidrs` is the list of ranges this scan actually targeted, used to
/// name the configured networks the scan never looked at.
pub fn apply(
    devices: &mut [Device],
    unifi: &UnifiSnapshot,
    scanned_cidrs: &[String],
) -> Reconciliation {
    let by_mac = unifi.clients_by_mac();
    let device_names = unifi.device_names();
    let unscanned_networks = find_unscanned_networks(unifi, scanned_cidrs);

    // Disconnect timestamps (epoch seconds) per client MAC, newest first.
    let mut disconnects_by_mac: std::collections::HashMap<String, Vec<i64>> =
        std::collections::HashMap::new();
    for event in &unifi.raw_events {
        if !event.is_disconnect() {
            continue;
        }
        let (Some(mac), Some(time)) = (event.client_mac(), event.time_seconds()) else {
            continue;
        };
        disconnects_by_mac
            .entry(mac.to_string())
            .or_default()
            .push(time);
    }
    for times in disconnects_by_mac.values_mut() {
        times.sort_unstable_by(|a, b| b.cmp(a));
    }

    // Configured VLAN id -> network name, to name a client whose record
    // carries only the number.
    let vlan_names: std::collections::HashMap<u32, String> = unifi
        .networks
        .iter()
        .filter_map(|net| net.vlan.map(|vlan| (vlan, net.name.clone())))
        .collect();

    let mut matched = 0usize;
    let mut shadow = Vec::new();
    let mut identity_conflicts = Vec::new();
    let mut wireless_issues = Vec::new();
    let mut seen_macs: HashSet<String> = HashSet::new();
    let now = chrono::Utc::now().timestamp();

    for device in devices.iter_mut() {
        // The scanner's own host and the gateway are not "clients" and would
        // otherwise be reported as shadows on every run.
        let exempt = device.is_self || device.is_gateway;

        let record = device.mac.as_ref().and_then(|mac| by_mac.get(mac).copied());

        let Some(record) = record else {
            if !exempt {
                let reason = if device.mac.is_some() {
                    ShadowReason::UnknownToController
                } else {
                    ShadowReason::Unidentified
                };
                shadow.push(ShadowDevice {
                    ip: device.ip.clone(),
                    display_name: device.display_name.clone(),
                    mac: device.mac.clone(),
                    vendor: device.vendor.clone(),
                    open_ports: device.ports.iter().map(|p| p.port).collect(),
                    reason,
                    explanation: reason.explain().to_string(),
                });
            }
            continue;
        };

        matched += 1;
        if let Some(mac) = &device.mac {
            seen_macs.insert(mac.clone());
        }

        if !device.discovered_by.iter().any(|s| s == "unifi") {
            device.discovered_by.push("unifi".to_string());
        }

        // An operator-assigned alias outranks anything inferred: a human typed
        // it specifically to identify this device.
        if let Some(name) = record.best_name() {
            device.unifi_name = Some(name.clone());
            let inferred_is_weak = device.display_name == device.ip
                || device
                    .vendor
                    .as_ref()
                    .map(|v| device.display_name.starts_with(v))
                    .unwrap_or(false);
            if inferred_is_weak || record.name.is_some() {
                device.display_name = name;
            }
        }

        device.unifi_fingerprint = record.fingerprint();
        device.vlan = record.vlan;
        device.is_wired = record.is_wired;
        device.rssi = record.rssi;
        device.unifi_network = record.network.clone().or_else(|| {
            // The client record sometimes carries only the VLAN number; the
            // configured name is what a human recognises.
            record.vlan.and_then(|vlan| vlan_names.get(&vlan).cloned())
        });
        device.satisfaction = record.satisfaction;
        device.channel = record.channel;
        device.wifi_generation = record.wifi_generation();
        device.tx_bytes = record.tx_bytes;
        device.rx_bytes = record.rx_bytes;
        device.unifi_uptime = record.uptime;
        device.unifi_first_seen = record.first_seen;
        device.is_guest = record.is_guest;
        device.unifi_note = record.note.clone().filter(|note| !note.trim().is_empty());

        // A brand-new client is worth a note: "first seen two hours ago" is
        // the strongest new-device evidence available.
        if record
            .first_seen
            .map(|seen| now - seen < 48 * 3600)
            .unwrap_or(false)
        {
            device
                .type_evidence
                .push("controller first saw this device within the last 48 hours".into());
        }

        // Physical location — the thing the scanner can never derive.
        if let (Some(sw_mac), Some(port)) = (&record.sw_mac, record.sw_port) {
            let switch = device_names
                .get(sw_mac)
                .cloned()
                .unwrap_or_else(|| sw_mac.clone());
            device.switch_port = Some(format!("{switch} port {port}"));
        }
        if let Some(ap_mac) = &record.ap_mac {
            let ap = device_names
                .get(ap_mac)
                .cloned()
                .unwrap_or_else(|| ap_mac.clone());
            device.access_point = Some(match record.essid.as_deref() {
                Some(ssid) if !ssid.is_empty() => format!("{ap} · {ssid}"),
                _ => ap,
            });
        }

        // A randomized MAC no longer blocks identification: the controller has a
        // stable hostname and fingerprint for it even though the OUI is useless.
        if device.mac_randomized == Some(true) && device.unifi_name.is_some() {
            device
                .type_evidence
                .push("identified via controller despite randomized MAC".into());
        }

        // Where the controller's DHCP fingerprint contradicts what the device
        // actually runs, the disagreement is the finding.
        if let Some(conflict) = detect_identity_conflict(device, record.fingerprint().as_deref()) {
            identity_conflicts.push(conflict);
        }

        // A guest-network device accepting connections is backwards: guests
        // browse out, they do not serve in.
        if record.is_guest == Some(true) && !device.ports.is_empty() {
            identity_conflicts.push(format!(
                "{} ({}) is on the guest network but is listening on {} open port(s). Guest \
                 devices normally initiate connections rather than accept them — worth checking \
                 whether it belongs on the main network instead, or should not be here at all.",
                device.display_name,
                device.ip,
                device.ports.len()
            ));
        }

        if let Some(issue) = detect_wireless_issue(device, record) {
            wireless_issues.push(issue);
        }
    }

    // Controller-known clients our scan never saw. `stat/alluser` includes every
    // client ever seen, so only recently-active ones are worth reporting —
    // otherwise a phone from last year shows up as a miss forever.
    let mut missed = Vec::new();
    let cutoff = now - 86_400;

    for record in &unifi.clients {
        let Some(mac) = &record.mac else { continue };
        if seen_macs.contains(mac) {
            continue;
        }
        if record.last_seen.map(|seen| seen < cutoff).unwrap_or(false) {
            continue;
        }

        let location = record
            .ap_mac
            .as_ref()
            .or(record.sw_mac.as_ref())
            .map(|mac| {
                device_names
                    .get(mac)
                    .cloned()
                    .unwrap_or_else(|| mac.clone())
            });

        let ip = record.effective_ip();

        // When the device sits on a network we know the scan never covered,
        // the generic guess upgrades to a statement.
        let blind_spot = unscanned_networks
            .iter()
            .find(|net| {
                record.network.as_deref() == Some(net.name.as_str())
                    || ip
                        .as_deref()
                        .and_then(|ip| ip.parse::<std::net::Ipv4Addr>().ok())
                        .zip(crate::netutil::parse_cidr_any(&net.subnet).ok())
                        .map(|(ip, cidr)| cidr.contains(ip))
                        .unwrap_or(false)
            })
            .map(|net| {
                format!(
                    "The controller shows this connected on \"{}\" ({}), a network this scan \
                     did not cover — so not reaching it is expected, not a fault.",
                    net.name, net.subnet
                )
            });

        // Failing that, the event log may explain the absence directly.
        let recent_drop = disconnects_by_mac
            .get(mac)
            .and_then(|times| times.first())
            .map(|last| {
                format!(
                    "The controller lists it as a client, but also logged it disconnecting {} \
                     ago — it was likely offline when the scan probed it.",
                    human_ago(now.saturating_sub(*last))
                )
            });

        missed.push(MissedDevice {
            mac: mac.clone(),
            name: record.best_name().unwrap_or_else(|| mac.clone()),
            ip,
            location,
            explanation: blind_spot.or(recent_drop).unwrap_or_else(|| {
                "The controller shows this connected, but the scan did not reach it. Usually a \
                 sleeping device, one that ignores probes, or one on a network this machine \
                 cannot route to."
                    .into()
            }),
        });
    }

    // Repeated disconnects are a finding on their own, reached or not: the
    // scan sees a device that answers, the log sees one that keeps falling off.
    let mut flapping_clients: Vec<FlappingClient> = disconnects_by_mac
        .iter()
        .filter(|(_, times)| times.len() >= 3)
        .map(|(mac, times)| {
            let record = by_mac.get(mac.as_str()).copied();
            let access_point = record
                .and_then(|r| r.ap_mac.clone())
                .map(|ap| device_names.get(&ap).cloned().unwrap_or(ap));
            FlappingClient {
                name: record
                    .and_then(|r| r.best_name())
                    .unwrap_or_else(|| mac.clone()),
                mac: mac.clone(),
                disconnects: times.len(),
                access_point,
                explanation: format!(
                    "The controller logged {} disconnects for this client in the last 24 hours. \
                     A connection dropping this often usually means weak signal, interference, \
                     or flaky power on the device itself.",
                    times.len()
                ),
            }
        })
        .collect();
    flapping_clients.sort_by_key(|flap| std::cmp::Reverse(flap.disconnects));

    let hidden_segments: Vec<HiddenSegment> = unifi
        .crowded_ports()
        .into_iter()
        .map(|port| HiddenSegment {
            explanation: format!(
                "{} hardware addresses are behind this single port, so an unmanaged switch, a \
                 virtual-machine host or a bridge sits there. The controller cannot see \
                 individual devices past it.",
                port.macs.len()
            ),
            switch_name: port.switch_name,
            port: port.port,
            port_name: port.port_name,
            mac_count: port.macs.len(),
        })
        .collect();

    let degraded_links: Vec<DegradedLink> = unifi
        .degraded_link_ports()
        .into_iter()
        .map(|port| DegradedLink {
            explanation: format!(
                "This link negotiated {} Mbps while other ports on {} run at {} Mbps or more. \
                 Either the connected device only supports this speed, or the cable is faulty — \
                 a gigabit link with a damaged wire pair falls back to exactly 100 Mbps.",
                port.speed_mbps, port.switch_name, port.fastest_mbps
            ),
            switch_name: port.switch_name,
            port: port.port,
            port_name: port.port_name,
            speed_mbps: port.speed_mbps,
        })
        .collect();

    let mut reconciliation = Reconciliation {
        matched,
        shadow,
        missed,
        hidden_segments,
        identity_conflicts,
        wireless_issues,
        degraded_links,
        unscanned_networks,
        flapping_clients,
        summary: String::new(),
    };
    reconciliation.summary = reconciliation.build_summary();
    reconciliation
}

fn human_ago(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 3_600 {
        format!("{} minute(s)", (seconds / 60).max(1))
    } else if seconds < 86_400 {
        format!("{} hour(s)", seconds / 3_600)
    } else {
        format!("{} day(s)", seconds / 86_400)
    }
}

/// Configured, enabled LAN networks whose subnet no scan target overlaps.
///
/// WAN and VPN entries in `rest/networkconf` are not LANs — nothing on them
/// could ever be a scan target — so they are excluded rather than reported as
/// blind spots.
fn find_unscanned_networks(
    unifi: &UnifiSnapshot,
    scanned_cidrs: &[String],
) -> Vec<UnscannedNetwork> {
    use crate::netutil::parse_cidr_any;

    let scanned: Vec<_> = scanned_cidrs
        .iter()
        .filter_map(|cidr| parse_cidr_any(cidr).ok())
        .collect();

    let mut out = Vec::new();
    for network in &unifi.networks {
        if !network.enabled {
            continue;
        }
        if matches!(
            network.purpose.as_deref(),
            Some("wan")
                | Some("wan2")
                | Some("vpn-client")
                | Some("site-vpn")
                | Some("remote-user-vpn")
        ) {
            continue;
        }
        let Some(subnet) = &network.subnet else {
            continue;
        };
        let Ok(cidr) = parse_cidr_any(subnet) else {
            continue;
        };
        let covered = scanned
            .iter()
            .any(|target| target.first <= cidr.last && cidr.first <= target.last);
        if covered {
            continue;
        }

        out.push(UnscannedNetwork {
            explanation: format!(
                "The controller defines \"{}\"{} at {}, but no target of this scan covered that \
                 range — devices there are invisible to it. If this machine can route there, \
                 add {} as an extra scan range; otherwise run a scan from that network.",
                network.name,
                network
                    .vlan
                    .map(|vlan| format!(" (VLAN {vlan})"))
                    .unwrap_or_default(),
                subnet,
                subnet
            ),
            name: network.name.clone(),
            subnet: subnet.clone(),
            vlan: network.vlan,
            purpose: network.purpose.clone(),
        });
    }

    out
}

/// Flags a wireless client the controller itself rates as struggling.
///
/// Two independent signals are consulted. `satisfaction` is UniFi's own 0–100
/// experience score. For signal strength, `signal` is dBm when present
/// (negative), while `rssi` in this API is dB above the noise floor (small
/// positive) — the same physical fact on two different scales, so each gets its
/// own threshold.
fn detect_wireless_issue(
    device: &Device,
    record: &crate::unifi::model::UnifiClientRecord,
) -> Option<WirelessHealthIssue> {
    let wireless = record.is_wired == Some(false) || record.ap_mac.is_some();
    if !wireless {
        return None;
    }

    let low_satisfaction = matches!(record.satisfaction, Some(score) if score < 60);
    let signal_dbm = record.signal.filter(|s| *s < 0);
    let weak_signal = matches!(signal_dbm, Some(dbm) if dbm <= -75)
        || matches!(record.rssi, Some(rssi) if (0..100).contains(&rssi) && rssi < 15);

    if !low_satisfaction && !weak_signal {
        return None;
    }

    let mut parts = Vec::new();
    if let Some(score) = record.satisfaction.filter(|_| low_satisfaction) {
        parts.push(format!(
            "the controller scores this client's experience at {score} %"
        ));
    }
    if weak_signal {
        parts.push(match signal_dbm {
            Some(dbm) => format!("the signal is weak ({dbm} dBm)"),
            None => "the signal is weak".to_string(),
        });
    }

    Some(WirelessHealthIssue {
        ip: device.ip.clone(),
        display_name: device.display_name.clone(),
        satisfaction: record.satisfaction,
        signal_dbm,
        access_point: device.access_point.clone(),
        explanation: format!(
            "This device works, but poorly: {}. Usually distance to the access point or a \
             congested channel — moving the device or the AP, or switching bands, is the \
             usual fix.",
            parts.join(", and ")
        ),
    })
}

/// Flags a device whose controller-declared identity disagrees with the services
/// it is actually running.
fn detect_identity_conflict(device: &Device, fingerprint: Option<&str>) -> Option<String> {
    let fingerprint = fingerprint?;
    let lowered = fingerprint.to_ascii_lowercase();

    let has_remote_shell = device
        .ports
        .iter()
        .any(|p| matches!(p.port, 22 | 23 | 3389));
    let looks_like_appliance = ["tv", "printer", "camera", "speaker", "thermostat"]
        .iter()
        .any(|needle| lowered.contains(needle));

    if looks_like_appliance && has_remote_shell {
        return Some(format!(
            "{} ({}) is identified by the controller as \"{}\", but exposes a remote-shell port. \
             Worth checking it is what it claims to be.",
            device.display_name, device.ip, fingerprint
        ));
    }

    // A phone or tablet listening for inbound connections is unusual.
    let looks_mobile = ["phone", "tablet", "ios", "android"]
        .iter()
        .any(|needle| lowered.contains(needle));
    if looks_mobile && device.ports.len() >= 3 && device.device_type != DeviceType::Computer {
        return Some(format!(
            "{} ({}) is identified as \"{}\" but is listening on {} ports, which is unusual for \
             a mobile device.",
            device.display_name,
            device.ip,
            fingerprint,
            device.ports.len()
        ));
    }

    None
}

impl Reconciliation {
    fn build_summary(&self) -> String {
        let matched = self.matched;
        if self.shadow.is_empty()
            && self.missed.is_empty()
            && self.hidden_segments.is_empty()
            && self.wireless_issues.is_empty()
            && self.degraded_links.is_empty()
            && self.unscanned_networks.is_empty()
            && self.flapping_clients.is_empty()
        {
            return format!("All {matched} devices are accounted for by the controller.");
        }

        let mut parts = vec![format!("{matched} accounted for")];
        if !self.shadow.is_empty() {
            parts.push(format!("{} unknown to the controller", self.shadow.len()));
        }
        if !self.missed.is_empty() {
            parts.push(format!("{} the scan did not reach", self.missed.len()));
        }
        if !self.hidden_segments.is_empty() {
            parts.push(format!(
                "{} port(s) hiding other devices",
                self.hidden_segments.len()
            ));
        }
        if !self.wireless_issues.is_empty() {
            parts.push(format!(
                "{} struggling on Wi-Fi",
                self.wireless_issues.len()
            ));
        }
        if !self.degraded_links.is_empty() {
            parts.push(format!("{} degraded link(s)", self.degraded_links.len()));
        }
        if !self.unscanned_networks.is_empty() {
            parts.push(format!(
                "{} network(s) never scanned",
                self.unscanned_networks.len()
            ));
        }
        if !self.flapping_clients.is_empty() {
            parts.push(format!(
                "{} client(s) flapping",
                self.flapping_clients.len()
            ));
        }
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PortInfo;
    use crate::unifi::model::{UnifiClientRecord, UnifiDeviceRecord};

    fn device(ip: &str, mac: Option<&str>, name: &str, ports: &[u16]) -> Device {
        Device {
            ip: ip.into(),
            mac: mac.map(|m| m.to_string()),
            vendor: None,
            mac_randomized: Some(false),
            hostnames: Vec::new(),
            display_name: name.into(),
            device_type: DeviceType::Unknown,
            type_evidence: Vec::new(),
            is_gateway: false,
            is_self: false,
            responded_to_ping: true,
            discovered_by: vec!["icmp".into()],
            latency_ms: None,
            ports: ports
                .iter()
                .map(|p| PortInfo {
                    port: *p,
                    protocol: "tcp".into(),
                    service: None,
                    banner: None,
                })
                .collect(),
            mdns: Vec::new(),
            ssdp: Vec::new(),
            netbios: None,
            reverse_dns: None,
            source_range: None,
            off_subnet: false,
            first_seen: None,
            last_seen: "t".into(),
            unifi_name: None,
            unifi_fingerprint: None,
            unifi_network: None,
            switch_port: None,
            access_point: None,
            vlan: None,
            rssi: None,
            is_wired: None,
            satisfaction: None,
            channel: None,
            wifi_generation: None,
            tx_bytes: None,
            rx_bytes: None,
            unifi_uptime: None,
            unifi_first_seen: None,
            is_guest: None,
            unifi_note: None,
        }
    }

    fn client(mac: &str, name: &str) -> UnifiClientRecord {
        UnifiClientRecord {
            mac: Some(mac.into()),
            name: Some(name.into()),
            last_seen: Some(chrono::Utc::now().timestamp()),
            ..Default::default()
        }
    }

    #[test]
    fn enriches_a_matched_device_with_alias_and_physical_location() {
        let mut devices = vec![device(
            "10.0.3.50",
            Some("aa:bb:cc:dd:ee:ff"),
            "10.0.3.50",
            &[80],
        )];

        let mut record = client("aa:bb:cc:dd:ee:ff", "Marek's Laptop");
        record.sw_mac = Some("11:22:33:44:55:66".into());
        record.sw_port = Some(4);
        record.vlan = Some(20);

        let switch: UnifiDeviceRecord = serde_json::from_str(
            r#"{"mac":"11:22:33:44:55:66","name":"USW_MINI","model":"USMINI","type":"usw"}"#,
        )
        .unwrap();

        let unifi = UnifiSnapshot {
            clients: vec![record],
            raw_devices: vec![switch],
            ..Default::default()
        };

        let result = apply(&mut devices, &unifi, &[]);

        assert_eq!(result.matched, 1);
        assert!(result.shadow.is_empty());
        assert_eq!(devices[0].display_name, "Marek's Laptop");
        assert_eq!(
            devices[0].switch_port.as_deref(),
            Some("USW_MINI (USMINI) port 4")
        );
        assert_eq!(devices[0].vlan, Some(20));
        assert!(devices[0].discovered_by.contains(&"unifi".to_string()));
    }

    #[test]
    fn flags_a_device_the_controller_has_never_seen() {
        let mut devices = vec![device(
            "10.0.3.99",
            Some("de:ad:be:ef:00:01"),
            "unknown",
            &[22],
        )];
        let result = apply(&mut devices, &UnifiSnapshot::default(), &[]);

        assert_eq!(result.shadow.len(), 1);
        assert_eq!(result.shadow[0].reason, ShadowReason::UnknownToController);
        assert!(
            !result.shadow[0].explanation.is_empty(),
            "every shadow device must state why"
        );
        assert_eq!(result.shadow[0].open_ports, vec![22]);
    }

    #[test]
    fn the_scanning_host_and_gateway_are_never_shadows() {
        // Neither is a controller "client", so both would false-positive forever.
        let mut devices = vec![
            device("10.0.3.221", Some("3c:58:c2:52:29:84"), "this machine", &[]),
            device("10.0.3.1", Some("e0:63:da:82:1b:35"), "gateway", &[443]),
        ];
        devices[0].is_self = true;
        devices[1].is_gateway = true;

        let result = apply(&mut devices, &UnifiSnapshot::default(), &[]);
        assert!(result.shadow.is_empty(), "self and gateway must be exempt");
    }

    #[test]
    fn recovers_identity_for_a_randomized_mac() {
        let mut devices = vec![device(
            "10.0.3.214",
            Some("ca:3a:94:02:94:de"),
            "10.0.3.214",
            &[],
        )];
        devices[0].mac_randomized = Some(true);

        let unifi = UnifiSnapshot {
            clients: vec![client("ca:3a:94:02:94:de", "Pixel 10")],
            ..Default::default()
        };

        apply(&mut devices, &unifi, &[]);

        assert_eq!(devices[0].display_name, "Pixel 10");
        assert!(devices[0]
            .type_evidence
            .iter()
            .any(|e| e.contains("randomized MAC")));
    }

    #[test]
    fn reports_controller_clients_the_scan_did_not_reach() {
        let mut devices: Vec<Device> = Vec::new();
        let unifi = UnifiSnapshot {
            clients: vec![client("aa:aa:aa:aa:aa:aa", "Sleeping Tablet")],
            ..Default::default()
        };

        let result = apply(&mut devices, &unifi, &[]);
        assert_eq!(result.missed.len(), 1);
        assert_eq!(result.missed[0].name, "Sleeping Tablet");
    }

    #[test]
    fn long_absent_clients_are_not_reported_as_missed() {
        // stat/alluser remembers forever; a phone from last year is not a finding.
        let mut stale = client("bb:bb:bb:bb:bb:bb", "Old Phone");
        stale.last_seen = Some(chrono::Utc::now().timestamp() - 60 * 86_400);

        let unifi = UnifiSnapshot {
            clients: vec![stale],
            ..Default::default()
        };
        let result = apply(&mut Vec::new(), &unifi, &[]);

        assert!(
            result.missed.is_empty(),
            "a device absent for 60 days is not news"
        );
    }

    #[test]
    fn infers_an_unmanaged_switch_from_a_crowded_port() {
        let switch: UnifiDeviceRecord = serde_json::from_str(
            r#"{"name":"USW_MINI","model":"USMINI","type":"usw","port_table":[
                {"port_idx":4,"mac_table":[{"mac":"a1:11:11:11:11:11"},{"mac":"b2:22:22:22:22:22"}]}]}"#,
        )
        .unwrap();

        let unifi = UnifiSnapshot {
            raw_devices: vec![switch],
            ..Default::default()
        };
        let result = apply(&mut Vec::new(), &unifi, &[]);

        assert_eq!(result.hidden_segments.len(), 1);
        assert_eq!(result.hidden_segments[0].mac_count, 2);
        assert!(result.hidden_segments[0]
            .explanation
            .contains("unmanaged switch"));
    }

    #[test]
    fn flags_an_appliance_that_exposes_a_shell() {
        let mut devices = vec![device(
            "10.0.3.60",
            Some("cc:cc:cc:cc:cc:cc"),
            "Living Room TV",
            &[22, 80],
        )];

        let mut record = client("cc:cc:cc:cc:cc:cc", "Living Room TV");
        record.dev_family = Some(serde_json::Value::String("Smart TV".into()));

        let unifi = UnifiSnapshot {
            clients: vec![record],
            ..Default::default()
        };
        let result = apply(&mut devices, &unifi, &[]);

        assert_eq!(result.identity_conflicts.len(), 1);
        assert!(result.identity_conflicts[0].contains("remote-shell"));
    }

    #[test]
    fn copies_experience_fields_onto_a_matched_device() {
        let mut devices = vec![device("10.0.3.50", Some("aa:bb:cc:dd:ee:ff"), "x", &[])];

        let mut record = client("aa:bb:cc:dd:ee:ff", "Laptop");
        record.satisfaction = Some(97);
        record.channel = Some(149);
        record.radio_proto = Some("ax".into());
        record.tx_bytes = Some(1_200);
        record.rx_bytes = Some(3_400);
        record.uptime = Some(7_200);
        record.is_guest = Some(false);
        record.note = Some("  ".into());

        let unifi = UnifiSnapshot {
            clients: vec![record],
            ..Default::default()
        };
        apply(&mut devices, &unifi, &[]);

        assert_eq!(devices[0].satisfaction, Some(97));
        assert_eq!(devices[0].channel, Some(149));
        assert_eq!(devices[0].wifi_generation.as_deref(), Some("Wi-Fi 6 (ax)"));
        assert_eq!(devices[0].tx_bytes, Some(1_200));
        assert_eq!(devices[0].rx_bytes, Some(3_400));
        assert_eq!(devices[0].unifi_uptime, Some(7_200));
        assert_eq!(devices[0].is_guest, Some(false));
        assert_eq!(devices[0].unifi_note, None, "a blank note is no note");
    }

    #[test]
    fn a_recently_first_seen_client_gets_new_device_evidence() {
        let mut devices = vec![device("10.0.3.50", Some("aa:bb:cc:dd:ee:ff"), "x", &[])];
        let mut record = client("aa:bb:cc:dd:ee:ff", "New Gadget");
        record.first_seen = Some(chrono::Utc::now().timestamp() - 3_600);

        let unifi = UnifiSnapshot {
            clients: vec![record],
            ..Default::default()
        };
        apply(&mut devices, &unifi, &[]);

        assert!(devices[0]
            .type_evidence
            .iter()
            .any(|e| e.contains("last 48 hours")));
    }

    #[test]
    fn a_struggling_wireless_client_is_reported_with_the_reason() {
        let mut devices = vec![device("10.0.3.70", Some("aa:bb:cc:dd:ee:01"), "x", &[])];
        let mut record = client("aa:bb:cc:dd:ee:01", "Garden Camera");
        record.is_wired = Some(false);
        record.satisfaction = Some(41);
        record.signal = Some(-82);

        let unifi = UnifiSnapshot {
            clients: vec![record],
            ..Default::default()
        };
        let result = apply(&mut devices, &unifi, &[]);

        assert_eq!(result.wireless_issues.len(), 1);
        let issue = &result.wireless_issues[0];
        assert_eq!(issue.satisfaction, Some(41));
        assert_eq!(issue.signal_dbm, Some(-82));
        assert!(issue.explanation.contains("41 %"));
        assert!(issue.explanation.contains("-82 dBm"));
    }

    #[test]
    fn wired_and_healthy_clients_are_not_wireless_issues() {
        let mut devices = vec![
            device("10.0.3.71", Some("aa:bb:cc:dd:ee:02"), "wired", &[]),
            device("10.0.3.72", Some("aa:bb:cc:dd:ee:03"), "healthy", &[]),
        ];

        // Low satisfaction, but wired: whatever is wrong, it is not the radio.
        let mut wired = client("aa:bb:cc:dd:ee:02", "NAS");
        wired.is_wired = Some(true);
        wired.satisfaction = Some(30);

        let mut healthy = client("aa:bb:cc:dd:ee:03", "Laptop");
        healthy.is_wired = Some(false);
        healthy.satisfaction = Some(95);
        healthy.signal = Some(-55);

        let unifi = UnifiSnapshot {
            clients: vec![wired, healthy],
            ..Default::default()
        };
        let result = apply(&mut devices, &unifi, &[]);
        assert!(result.wireless_issues.is_empty());
    }

    #[test]
    fn a_positive_rssi_scale_is_not_mistaken_for_dbm() {
        // UniFi's `rssi` is dB above noise: 45 is a *good* value, and must not
        // trip a threshold written for dBm. 8 genuinely is weak.
        let mut devices = vec![
            device("10.0.3.73", Some("aa:bb:cc:dd:ee:04"), "good", &[]),
            device("10.0.3.74", Some("aa:bb:cc:dd:ee:05"), "weak", &[]),
        ];

        let mut good = client("aa:bb:cc:dd:ee:04", "Strong Signal");
        good.is_wired = Some(false);
        good.rssi = Some(45);

        let mut weak = client("aa:bb:cc:dd:ee:05", "Far Away");
        weak.is_wired = Some(false);
        weak.rssi = Some(8);

        let unifi = UnifiSnapshot {
            clients: vec![good, weak],
            ..Default::default()
        };
        let result = apply(&mut devices, &unifi, &[]);

        assert_eq!(result.wireless_issues.len(), 1);
        // The controller alias renamed the device before the issue was filed.
        assert_eq!(result.wireless_issues[0].display_name, "Far Away");
    }

    #[test]
    fn a_guest_device_listening_on_ports_is_a_conflict() {
        let mut devices = vec![device(
            "10.0.3.80",
            Some("aa:bb:cc:dd:ee:06"),
            "Guest Box",
            &[80, 443],
        )];
        let mut record = client("aa:bb:cc:dd:ee:06", "Guest Box");
        record.is_guest = Some(true);

        let unifi = UnifiSnapshot {
            clients: vec![record],
            ..Default::default()
        };
        let result = apply(&mut devices, &unifi, &[]);

        assert_eq!(result.identity_conflicts.len(), 1);
        assert!(result.identity_conflicts[0].contains("guest network"));

        // The same guest with nothing listening is unremarkable.
        let mut quiet_devices = vec![device("10.0.3.80", Some("aa:bb:cc:dd:ee:06"), "g", &[])];
        let mut quiet = client("aa:bb:cc:dd:ee:06", "Guest Phone");
        quiet.is_guest = Some(true);
        let unifi = UnifiSnapshot {
            clients: vec![quiet],
            ..Default::default()
        };
        assert!(apply(&mut quiet_devices, &unifi, &[])
            .identity_conflicts
            .is_empty());
    }

    #[test]
    fn degraded_links_surface_with_an_explanation() {
        let switch: UnifiDeviceRecord = serde_json::from_str(
            r#"{"name":"USW","model":"US8","type":"usw","port_table":[
                {"port_idx":1,"up":true,"speed":1000},
                {"port_idx":5,"name":"Study","up":true,"speed":100}
            ]}"#,
        )
        .unwrap();

        let unifi = UnifiSnapshot {
            raw_devices: vec![switch],
            ..Default::default()
        };
        let result = apply(&mut Vec::new(), &unifi, &[]);

        assert_eq!(result.degraded_links.len(), 1);
        assert_eq!(result.degraded_links[0].port, 5);
        assert!(result.degraded_links[0].explanation.contains("cable"));
        assert!(result.summary.contains("degraded link"));
    }

    fn network(
        name: &str,
        subnet: &str,
        vlan: Option<u32>,
    ) -> crate::unifi::model::UnifiNetworkSummary {
        crate::unifi::model::UnifiNetworkSummary {
            name: name.into(),
            purpose: Some("corporate".into()),
            subnet: Some(subnet.into()),
            vlan,
            enabled: true,
            dhcp: Some(true),
        }
    }

    #[test]
    fn a_configured_network_no_target_covered_is_a_blind_spot() {
        let unifi = UnifiSnapshot {
            networks: vec![
                network("Main", "10.0.3.0/24", None),
                network("IoT", "10.0.30.0/24", Some(30)),
            ],
            ..Default::default()
        };

        let result = apply(&mut Vec::new(), &unifi, &["10.0.3.0/24".to_string()]);

        assert_eq!(result.unscanned_networks.len(), 1);
        let blind = &result.unscanned_networks[0];
        assert_eq!(blind.name, "IoT");
        assert_eq!(blind.vlan, Some(30));
        assert!(blind.explanation.contains("VLAN 30"));
        assert!(result.summary.contains("never scanned"));
    }

    #[test]
    fn overlap_with_any_target_counts_as_covered() {
        // A /22 target spans several /24 configured networks.
        let unifi = UnifiSnapshot {
            networks: vec![network("Main", "10.0.1.0/24", None)],
            ..Default::default()
        };
        let result = apply(&mut Vec::new(), &unifi, &["10.0.0.0/22".to_string()]);
        assert!(result.unscanned_networks.is_empty());
    }

    #[test]
    fn wan_vpn_and_disabled_networks_are_not_blind_spots() {
        let mut wan = network("WAN", "203.0.113.0/24", None);
        wan.purpose = Some("wan".into());
        let mut vpn = network("Road warriors", "192.168.99.0/24", None);
        vpn.purpose = Some("remote-user-vpn".into());
        let mut disabled = network("Old lab", "10.9.9.0/24", None);
        disabled.enabled = false;

        let unifi = UnifiSnapshot {
            networks: vec![wan, vpn, disabled],
            ..Default::default()
        };
        let result = apply(&mut Vec::new(), &unifi, &[]);
        assert!(result.unscanned_networks.is_empty());
    }

    #[test]
    fn a_missed_device_on_a_blind_spot_network_gets_the_concrete_explanation() {
        let mut record = client("aa:aa:aa:aa:aa:aa", "Camera");
        record.ip = Some("10.0.30.42".into());

        let unifi = UnifiSnapshot {
            clients: vec![record],
            networks: vec![network("IoT", "10.0.30.0/24", Some(30))],
            ..Default::default()
        };
        let result = apply(&mut Vec::new(), &unifi, &["10.0.3.0/24".to_string()]);

        assert_eq!(result.missed.len(), 1);
        assert!(
            result.missed[0].explanation.contains("\"IoT\""),
            "the guess must upgrade to a named network: {}",
            result.missed[0].explanation
        );
        assert!(result.missed[0]
            .explanation
            .contains("expected, not a fault"));
    }

    #[test]
    fn a_vlan_number_resolves_to_the_configured_network_name() {
        let mut devices = vec![device("10.0.30.5", Some("bb:bb:bb:bb:bb:bb"), "x", &[])];
        let mut record = client("bb:bb:bb:bb:bb:bb", "Sensor");
        record.vlan = Some(30);
        // No network name on the client record — only the number.

        let unifi = UnifiSnapshot {
            clients: vec![record],
            networks: vec![network("IoT", "10.0.30.0/24", Some(30))],
            ..Default::default()
        };
        apply(&mut devices, &unifi, &["10.0.30.0/24".to_string()]);

        assert_eq!(devices[0].unifi_network.as_deref(), Some("IoT"));
    }

    fn disconnect_event(mac: &str, seconds_ago: i64) -> crate::unifi::model::UnifiEventRecord {
        crate::unifi::model::UnifiEventRecord {
            key: Some("EVT_WU_Disconnected".into()),
            user: Some(mac.into()),
            time: Some((chrono::Utc::now().timestamp() - seconds_ago) * 1000),
            ..Default::default()
        }
    }

    #[test]
    fn a_missed_device_with_a_recent_disconnect_gets_the_event_explanation() {
        let mut record = client("aa:aa:aa:aa:aa:aa", "Tablet");
        record.ip = Some("10.0.3.90".into());

        let unifi = UnifiSnapshot {
            clients: vec![record],
            raw_events: vec![disconnect_event("aa:aa:aa:aa:aa:aa", 25 * 60)],
            ..Default::default()
        };
        let result = apply(&mut Vec::new(), &unifi, &[]);

        assert_eq!(result.missed.len(), 1);
        assert!(
            result.missed[0]
                .explanation
                .contains("logged it disconnecting"),
            "guess must upgrade to the logged fact: {}",
            result.missed[0].explanation
        );
        assert!(result.missed[0].explanation.contains("25 minute(s)"));
    }

    #[test]
    fn the_blind_spot_explanation_outranks_the_event_one() {
        // Being on an unscanned network explains more than a disconnect does.
        let mut record = client("aa:aa:aa:aa:aa:aa", "Camera");
        record.ip = Some("10.0.30.42".into());

        let unifi = UnifiSnapshot {
            clients: vec![record],
            networks: vec![network("IoT", "10.0.30.0/24", Some(30))],
            raw_events: vec![disconnect_event("aa:aa:aa:aa:aa:aa", 600)],
            ..Default::default()
        };
        let result = apply(&mut Vec::new(), &unifi, &["10.0.3.0/24".to_string()]);
        assert!(result.missed[0].explanation.contains("\"IoT\""));
    }

    #[test]
    fn three_disconnects_in_a_day_is_flapping_two_is_not() {
        let unifi = UnifiSnapshot {
            clients: vec![client("aa:aa:aa:aa:aa:01", "Doorbell")],
            raw_events: vec![
                disconnect_event("aa:aa:aa:aa:aa:01", 3_600),
                disconnect_event("aa:aa:aa:aa:aa:01", 7_200),
                disconnect_event("aa:aa:aa:aa:aa:01", 10_800),
                disconnect_event("bb:bb:bb:bb:bb:02", 3_600),
                disconnect_event("bb:bb:bb:bb:bb:02", 7_200),
            ],
            ..Default::default()
        };
        let result = apply(&mut Vec::new(), &unifi, &[]);

        assert_eq!(result.flapping_clients.len(), 1);
        let flap = &result.flapping_clients[0];
        assert_eq!(flap.name, "Doorbell", "named via the client record");
        assert_eq!(flap.disconnects, 3);
        assert!(flap.explanation.contains("3 disconnects"));
        assert!(result.summary.contains("flapping"));
    }

    #[test]
    fn a_pre_wp1_reconciliation_still_deserializes() {
        // Stored snapshots from 1.1.0 lack the new arrays entirely.
        let old = r#"{"matched":3,"shadow":[],"missed":[],"hiddenSegments":[],
                      "identityConflicts":[],"summary":"All 3 devices are accounted for."}"#;
        let parsed: Reconciliation = serde_json::from_str(old).unwrap();
        assert!(parsed.wireless_issues.is_empty());
        assert!(parsed.degraded_links.is_empty());
    }

    #[test]
    fn a_fully_reconciled_network_says_so_plainly() {
        let mut devices = vec![device("10.0.3.50", Some("aa:bb:cc:dd:ee:ff"), "x", &[])];
        let unifi = UnifiSnapshot {
            clients: vec![client("aa:bb:cc:dd:ee:ff", "Laptop")],
            ..Default::default()
        };

        let result = apply(&mut devices, &unifi, &[]);
        assert!(result.summary.contains("accounted for"));
        assert!(result.shadow.is_empty() && result.missed.is_empty());
    }
}
