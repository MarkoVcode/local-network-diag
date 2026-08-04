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
    pub summary: String,
}

/// Merges controller data into the device list and produces the quadrant.
///
/// Enrichment is additive: a controller alias improves `display_name`, and
/// location/VLAN/signal become new fields. Nothing the scanner observed
/// first-hand is overwritten, because the scan measured it and the controller
/// only believes it.
pub fn apply(devices: &mut [Device], unifi: &UnifiSnapshot) -> Reconciliation {
    let by_mac = unifi.clients_by_mac();
    let device_names = unifi.device_names();

    let mut matched = 0usize;
    let mut shadow = Vec::new();
    let mut identity_conflicts = Vec::new();
    let mut seen_macs: HashSet<String> = HashSet::new();

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
        device.unifi_network = record.network.clone();

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
    }

    // Controller-known clients our scan never saw. `stat/alluser` includes every
    // client ever seen, so only recently-active ones are worth reporting —
    // otherwise a phone from last year shows up as a miss forever.
    let mut missed = Vec::new();
    let cutoff = chrono::Utc::now().timestamp() - 86_400;

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

        missed.push(MissedDevice {
            mac: mac.clone(),
            name: record.best_name().unwrap_or_else(|| mac.clone()),
            ip: record.effective_ip(),
            location,
            explanation:
                "The controller shows this connected, but the scan did not reach it. Usually a \
                 sleeping device, one that ignores probes, or one on a network this machine \
                 cannot route to."
                    .into(),
        });
    }

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

    let summary = build_summary(matched, &shadow, &missed, &hidden_segments);

    Reconciliation {
        matched,
        shadow,
        missed,
        hidden_segments,
        identity_conflicts,
        summary,
    }
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

fn build_summary(
    matched: usize,
    shadow: &[ShadowDevice],
    missed: &[MissedDevice],
    hidden: &[HiddenSegment],
) -> String {
    if shadow.is_empty() && missed.is_empty() && hidden.is_empty() {
        return format!("All {matched} devices are accounted for by the controller.");
    }

    let mut parts = vec![format!("{matched} accounted for")];
    if !shadow.is_empty() {
        parts.push(format!("{} unknown to the controller", shadow.len()));
    }
    if !missed.is_empty() {
        parts.push(format!("{} the scan did not reach", missed.len()));
    }
    if !hidden.is_empty() {
        parts.push(format!("{} port(s) hiding other devices", hidden.len()));
    }
    parts.join(", ")
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

        let result = apply(&mut devices, &unifi);

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
        let result = apply(&mut devices, &UnifiSnapshot::default());

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

        let result = apply(&mut devices, &UnifiSnapshot::default());
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

        apply(&mut devices, &unifi);

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

        let result = apply(&mut devices, &unifi);
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
        let result = apply(&mut Vec::new(), &unifi);

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
        let result = apply(&mut Vec::new(), &unifi);

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
        let result = apply(&mut devices, &unifi);

        assert_eq!(result.identity_conflicts.len(), 1);
        assert!(result.identity_conflicts[0].contains("remote-shell"));
    }

    #[test]
    fn a_fully_reconciled_network_says_so_plainly() {
        let mut devices = vec![device("10.0.3.50", Some("aa:bb:cc:dd:ee:ff"), "x", &[])];
        let unifi = UnifiSnapshot {
            clients: vec![client("aa:bb:cc:dd:ee:ff", "Laptop")],
            ..Default::default()
        };

        let result = apply(&mut devices, &unifi);
        assert!(result.summary.contains("accounted for"));
        assert!(result.shadow.is_empty() && result.missed.is_empty());
    }
}
