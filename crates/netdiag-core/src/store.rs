//! Snapshot persistence and run-to-run diffing.
//!
//! Each run is one JSON file named by its id, so a directory listing is already
//! in chronological order. No database: a run is a few hundred KB and the
//! diffing is trivial in memory.

use crate::types::{ChangeKind, Device, DeviceChange, ScanDiff, ScanSnapshot, SnapshotSummary};
use std::path::{Path, PathBuf};

const MAX_SNAPSHOTS: usize = 200;

#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    async fn ensure_dir(&self) -> std::io::Result<()> {
        tokio::fs::create_dir_all(&self.root).await
    }

    /// Sortable, filesystem-safe id: `2026-08-04T13-05-22-123Z`.
    pub fn make_id(at: chrono::DateTime<chrono::Utc>) -> String {
        at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            .replace([':', '.'], "-")
    }

    /// Ids come from the frontend, so anything that could escape the directory
    /// is rejected rather than sanitised.
    fn is_valid_id(id: &str) -> bool {
        !id.is_empty()
            && id.len() < 64
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    pub async fn save(&self, snapshot: &ScanSnapshot) -> Result<(), String> {
        self.ensure_dir().await.map_err(|e| e.to_string())?;
        let path = self.root.join(format!("{}.json", snapshot.id));
        let json = serde_json::to_vec(snapshot).map_err(|e| e.to_string())?;
        tokio::fs::write(&path, json)
            .await
            .map_err(|e| e.to_string())?;
        self.trim().await;
        Ok(())
    }

    pub async fn list_ids(&self) -> Vec<String> {
        let Ok(mut entries) = tokio::fs::read_dir(&self.root).await else {
            return Vec::new();
        };

        let mut ids = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(".json") {
                ids.push(id.to_string());
            }
        }

        // Ids are ISO-derived, so lexical descending is newest-first.
        ids.sort_by(|a, b| b.cmp(a));
        ids
    }

    pub async fn load(&self, id: &str) -> Option<ScanSnapshot> {
        if !Self::is_valid_id(id) {
            return None;
        }
        let path = self.root.join(format!("{id}.json"));
        let bytes = tokio::fs::read(&path).await.ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub async fn load_latest(&self) -> Option<ScanSnapshot> {
        let ids = self.list_ids().await;
        self.load(ids.first()?).await
    }

    pub async fn summaries(&self, limit: usize) -> Vec<SnapshotSummary> {
        let ids = self.list_ids().await;
        let mut out = Vec::new();

        for id in ids.into_iter().take(limit) {
            let Some(snapshot) = self.load(&id).await else {
                continue;
            };
            out.push(SnapshotSummary {
                id: snapshot.id,
                started_at: snapshot.started_at,
                duration_ms: snapshot.duration_ms,
                device_count: snapshot.devices.len(),
                gateway_latency_ms: snapshot.connectivity.gateway.and_then(|g| g.avg_ms),
                wan_reachable: snapshot.connectivity.wan_reachable,
                warnings: snapshot.warnings.len(),
            });
        }

        out
    }

    pub async fn delete(&self, id: &str) -> bool {
        if !Self::is_valid_id(id) {
            return false;
        }
        tokio::fs::remove_file(self.root.join(format!("{id}.json")))
            .await
            .is_ok()
    }

    async fn trim(&self) {
        let ids = self.list_ids().await;
        for id in ids.into_iter().skip(MAX_SNAPSHOTS) {
            let _ = tokio::fs::remove_file(self.root.join(format!("{id}.json"))).await;
        }
    }
}

/* ------------------------------------------------------------------- pairing */

struct Pairing<'a> {
    pairs: Vec<(&'a Device, &'a Device)>,
    added: Vec<&'a Device>,
    removed: Vec<&'a Device>,
}

/// Pairs devices across two runs, by MAC first and then by IP.
///
/// Both passes matter. Matching on MAC makes a DHCP lease change read as "same
/// device, new address". The IP fallback exists because ARP resolution is
/// unreliable — the *same* device can have a MAC in one run and not the next,
/// and keying on a single composite identity would then report it as both
/// "disappeared" and "new", turning the one genuinely security-relevant signal
/// into noise.
fn pair_devices<'a>(previous: &'a [Device], current: &'a [Device]) -> Pairing<'a> {
    let mut matched_previous = vec![false; previous.len()];
    let mut pairs = Vec::new();
    let mut added = Vec::new();

    let mut unmatched_current: Vec<&Device> = Vec::new();

    // Pass 1 — MAC, the strongest identity.
    for device in current {
        let found = device.mac.as_ref().and_then(|mac| {
            previous
                .iter()
                .enumerate()
                .find(|(index, other)| !matched_previous[*index] && other.mac.as_ref() == Some(mac))
        });

        match found {
            Some((index, before)) => {
                matched_previous[index] = true;
                pairs.push((before, device));
            }
            None => unmatched_current.push(device),
        }
    }

    // Pass 2 — IP, for devices whose MAC resolved in only one of the two runs.
    for device in unmatched_current {
        let found = previous
            .iter()
            .enumerate()
            .find(|(index, other)| !matched_previous[*index] && other.ip == device.ip);

        match found {
            Some((index, before)) => {
                matched_previous[index] = true;
                pairs.push((before, device));
            }
            None => added.push(device),
        }
    }

    let removed = previous
        .iter()
        .enumerate()
        .filter(|(index, _)| !matched_previous[*index])
        .map(|(_, device)| device)
        .collect();

    Pairing {
        pairs,
        added,
        removed,
    }
}

pub fn diff(previous: &ScanSnapshot, current: &ScanSnapshot) -> ScanDiff {
    let Pairing {
        pairs,
        added,
        removed,
    } = pair_devices(&previous.devices, &current.devices);
    let mut changes = Vec::new();

    // Port deltas are only meaningful when both runs probed the same ports —
    // otherwise a quick scan after a standard one reports every IoT port as
    // "closed" purely because it was never probed.
    let comparable_ports = previous.config.port_profile == current.config.port_profile;

    for device in added {
        changes.push(DeviceChange {
            kind: ChangeKind::Appeared,
            detail: format!(
                "{} ({}) was not present in the previous scan",
                device.display_name, device.ip
            ),
            device: device.clone(),
            previous: None,
        });
    }

    for device in removed {
        changes.push(DeviceChange {
            kind: ChangeKind::Disappeared,
            detail: format!(
                "{} ({}) is no longer responding",
                device.display_name, device.ip
            ),
            device: device.clone(),
            previous: None,
        });
    }

    for (before, device) in pairs {
        if before.ip != device.ip {
            changes.push(DeviceChange {
                kind: ChangeKind::IpChanged,
                detail: format!(
                    "{} moved from {} to {}",
                    device.display_name, before.ip, device.ip
                ),
                device: device.clone(),
                previous: Some(before.clone()),
            });
        }

        if comparable_ports {
            let before_ports: Vec<u16> = before.ports.iter().map(|p| p.port).collect();
            let after_ports: Vec<u16> = device.ports.iter().map(|p| p.port).collect();

            let mut opened: Vec<u16> = after_ports
                .iter()
                .copied()
                .filter(|p| !before_ports.contains(p))
                .collect();
            let mut closed: Vec<u16> = before_ports
                .iter()
                .copied()
                .filter(|p| !after_ports.contains(p))
                .collect();
            opened.sort_unstable();
            opened.dedup();
            closed.sort_unstable();
            closed.dedup();

            if !opened.is_empty() {
                changes.push(DeviceChange {
                    kind: ChangeKind::PortsOpened,
                    detail: format!(
                        "{} ({}) opened port{} {}",
                        device.display_name,
                        device.ip,
                        if opened.len() == 1 { "" } else { "s" },
                        join_ports(&opened)
                    ),
                    device: device.clone(),
                    previous: Some(before.clone()),
                });
            }
            if !closed.is_empty() {
                changes.push(DeviceChange {
                    kind: ChangeKind::PortsClosed,
                    detail: format!(
                        "{} ({}) closed port{} {}",
                        device.display_name,
                        device.ip,
                        if closed.len() == 1 { "" } else { "s" },
                        join_ports(&closed)
                    ),
                    device: device.clone(),
                    previous: Some(before.clone()),
                });
            }
        }

        // mDNS returns a varying subset of records per pass, so a name can flip
        // between the service name and the hostname ("DIGITRADIO 370 CD IR" vs
        // "DIGITRADIO-370-CD-IR"). Those are the same name, and reporting them
        // every run would bury the real changes.
        let same_ignoring_separators =
            normalize_name(&before.display_name) == normalize_name(&device.display_name);

        if before.display_name != device.display_name
            && before.display_name != before.ip
            && !same_ignoring_separators
        {
            changes.push(DeviceChange {
                kind: ChangeKind::NameChanged,
                detail: format!(
                    "{} is now identified as {}",
                    before.display_name, device.display_name
                ),
                device: device.clone(),
                previous: Some(before.clone()),
            });
        }
    }

    // Newly-appeared devices first — that is the security-relevant signal.
    changes.sort_by_key(|change| match change.kind {
        ChangeKind::Appeared => 0,
        ChangeKind::PortsOpened => 1,
        ChangeKind::IpChanged => 2,
        ChangeKind::Disappeared => 3,
        ChangeKind::PortsClosed => 4,
        ChangeKind::NameChanged => 5,
    });

    ScanDiff {
        from_id: previous.id.clone(),
        to_id: current.id.clone(),
        changes,
    }
}

fn normalize_name(name: &str) -> String {
    name.to_ascii_lowercase()
        .chars()
        .filter(|c| !matches!(c, ' ' | '.' | '_' | '-'))
        .collect()
}

fn join_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Carries `first_seen` forward using the same pairing rules as the diff, so
/// "NEW" in the device table can never disagree with "appeared" in the changes.
pub fn apply_history(current: &mut ScanSnapshot, previous: Option<&ScanSnapshot>) {
    let Some(previous) = previous else {
        // No baseline exists yet: record when each device was first seen, but mark
        // the snapshot so the UI does not label all of them as newly appeared.
        current.baseline = true;
        let started = current.started_at.clone();
        for device in current.devices.iter_mut() {
            device.first_seen.get_or_insert_with(|| started.clone());
        }
        return;
    };

    current.baseline = false;

    let assignments: Vec<(String, String)> = {
        let Pairing { pairs, added, .. } = pair_devices(&previous.devices, &current.devices);
        let mut out = Vec::new();
        for (before, device) in pairs {
            let inherited = before
                .first_seen
                .clone()
                .unwrap_or_else(|| previous.started_at.clone());
            out.push((device.ip.clone(), inherited));
        }
        for device in added {
            out.push((device.ip.clone(), current.started_at.clone()));
        }
        out
    };

    for (ip, first_seen) in assignments {
        if let Some(device) = current.devices.iter_mut().find(|d| d.ip == ip) {
            device.first_seen = Some(first_seen);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

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
            last_seen: "2026-08-04T00:00:00Z".into(),
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

    fn snapshot(id: &str, devices: Vec<Device>, profile: PortProfile) -> ScanSnapshot {
        ScanSnapshot {
            id: id.into(),
            started_at: format!("2026-08-04T00:00:0{}Z", id.len() % 10),
            finished_at: "2026-08-04T00:01:00Z".into(),
            duration_ms: 1000,
            host: HostInfo {
                hostname: "test".into(),
                platform: "test".into(),
                os: "Linux".into(),
                arch: "x86_64".into(),
                app_version: "1.0.0".into(),
                interfaces: Vec::new(),
                routes: Vec::new(),
                gateway: None,
                dns: DnsConfig::default(),
                scan_targets: Vec::new(),
            },
            devices,
            connectivity: ConnectivityInfo {
                gateway: None,
                wan: Vec::new(),
                dns: Vec::new(),
                public_ip: None,
                wan_reachable: true,
                trace: ProbeResult::unavailable("test"),
            },
            wifi: ProbeResult::unavailable("test"),
            phases: Vec::new(),
            warnings: Vec::new(),
            config: ScanConfig {
                port_profile: profile,
                ..Default::default()
            },
            capabilities: Vec::new(),
            baseline: false,
            unifi: None,
            reconciliation: None,
        }
    }

    #[test]
    fn a_device_that_gains_a_mac_is_not_reported_as_both_gone_and_new() {
        // This is the regression that made the TypeScript version emit false
        // "new device" alerts every time ARP resolution flickered.
        let before = snapshot(
            "a",
            vec![device("10.0.3.221", None, "marek", &[])],
            PortProfile::Standard,
        );
        let after = snapshot(
            "b",
            vec![device(
                "10.0.3.221",
                Some("3c:58:c2:52:29:84"),
                "marek",
                &[],
            )],
            PortProfile::Standard,
        );

        let result = diff(&before, &after);
        assert!(
            result.changes.is_empty(),
            "gaining a MAC is not a change, got: {:?}",
            result.changes.iter().map(|c| &c.detail).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_dhcp_lease_change_reads_as_one_device_moving() {
        let before = snapshot(
            "a",
            vec![device("10.0.3.50", Some("aa:bb:cc:dd:ee:ff"), "phone", &[])],
            PortProfile::Standard,
        );
        let after = snapshot(
            "b",
            vec![device("10.0.3.77", Some("aa:bb:cc:dd:ee:ff"), "phone", &[])],
            PortProfile::Standard,
        );

        let result = diff(&before, &after);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].kind, ChangeKind::IpChanged);
    }

    #[test]
    fn port_deltas_are_suppressed_across_different_scan_profiles() {
        // A quick scan does not probe 6053, which is not the same as it being closed.
        let before = snapshot(
            "a",
            vec![device(
                "10.0.3.22",
                Some("24:62:ab:e4:5f:a4"),
                "esp",
                &[6053],
            )],
            PortProfile::Standard,
        );
        let after = snapshot(
            "b",
            vec![device("10.0.3.22", Some("24:62:ab:e4:5f:a4"), "esp", &[])],
            PortProfile::Quick,
        );

        let result = diff(&before, &after);
        assert!(
            result.changes.is_empty(),
            "unprobed must not be reported as closed, got: {:?}",
            result.changes.iter().map(|c| &c.detail).collect::<Vec<_>>()
        );
    }

    #[test]
    fn port_changes_are_reported_when_profiles_match() {
        let before = snapshot(
            "a",
            vec![device("10.0.3.10", Some("11:22:33:44:55:66"), "x", &[80])],
            PortProfile::Standard,
        );
        let after = snapshot(
            "b",
            vec![device(
                "10.0.3.10",
                Some("11:22:33:44:55:66"),
                "x",
                &[80, 443],
            )],
            PortProfile::Standard,
        );

        let result = diff(&before, &after);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].kind, ChangeKind::PortsOpened);
        assert!(result.changes[0].detail.contains("443"));
    }

    #[test]
    fn cosmetic_name_flips_are_not_reported() {
        let before = snapshot(
            "a",
            vec![device(
                "10.0.3.18",
                Some("30:58:90:c0:09:03"),
                "DIGITRADIO 370 CD IR",
                &[],
            )],
            PortProfile::Standard,
        );
        let after = snapshot(
            "b",
            vec![device(
                "10.0.3.18",
                Some("30:58:90:c0:09:03"),
                "DIGITRADIO-370-CD-IR",
                &[],
            )],
            PortProfile::Standard,
        );

        let result = diff(&before, &after);
        assert!(
            result.changes.is_empty(),
            "same name modulo separators is not a change"
        );
    }

    #[test]
    fn genuinely_new_devices_are_reported_first() {
        let before = snapshot(
            "a",
            vec![device("10.0.3.1", Some("aa:aa:aa:aa:aa:aa"), "gw", &[])],
            PortProfile::Standard,
        );
        let after = snapshot(
            "b",
            vec![
                device("10.0.3.1", Some("aa:aa:aa:aa:aa:aa"), "gw", &[]),
                device("10.0.3.99", Some("bb:bb:bb:bb:bb:bb"), "intruder", &[22]),
            ],
            PortProfile::Standard,
        );

        let result = diff(&before, &after);
        assert_eq!(result.changes[0].kind, ChangeKind::Appeared);
        assert!(result.changes[0].detail.contains("10.0.3.99"));
    }

    #[test]
    fn the_first_scan_is_marked_as_a_baseline() {
        // Without this, every device on a fresh install is flagged "new", which is
        // both meaningless and alarming — there is nothing to be new against.
        let mut first = snapshot(
            "a",
            vec![device("10.0.3.1", Some("aa:aa:aa:aa:aa:aa"), "gw", &[])],
            PortProfile::Standard,
        );
        apply_history(&mut first, None);

        assert!(first.baseline);
        assert_eq!(
            first.devices[0].first_seen.as_deref(),
            Some(first.started_at.as_str())
        );

        let mut second = snapshot(
            "b",
            vec![device("10.0.3.1", Some("aa:aa:aa:aa:aa:aa"), "gw", &[])],
            PortProfile::Standard,
        );
        apply_history(&mut second, Some(&first));
        assert!(
            !second.baseline,
            "a scan with a predecessor is not a baseline"
        );
    }

    #[test]
    fn first_seen_is_carried_forward_for_known_devices() {
        let mut before = snapshot(
            "a",
            vec![device("10.0.3.1", Some("aa:aa:aa:aa:aa:aa"), "gw", &[])],
            PortProfile::Standard,
        );
        before.devices[0].first_seen = Some("2026-01-01T00:00:00Z".into());

        let mut after = snapshot(
            "b",
            vec![
                device("10.0.3.1", Some("aa:aa:aa:aa:aa:aa"), "gw", &[]),
                device("10.0.3.99", Some("bb:bb:bb:bb:bb:bb"), "new", &[]),
            ],
            PortProfile::Standard,
        );

        apply_history(&mut after, Some(&before));

        assert_eq!(
            after.devices[0].first_seen.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
        assert_eq!(
            after.devices[1].first_seen.as_deref(),
            Some(after.started_at.as_str()),
            "a genuinely new device is first seen now"
        );
    }

    #[test]
    fn rejects_ids_that_could_escape_the_store_directory() {
        assert!(!Store::is_valid_id("../../etc/passwd"));
        assert!(!Store::is_valid_id("a/b"));
        assert!(!Store::is_valid_id(""));
        assert!(Store::is_valid_id("2026-08-04T13-05-22-123Z"));
    }

    #[tokio::test]
    async fn saves_and_reloads_a_snapshot() {
        let dir = std::env::temp_dir().join(format!("netdiag-test-{}", std::process::id()));
        let store = Store::new(&dir);

        let snap = snapshot(
            "2026-08-04T00-00-00-000Z",
            vec![device("10.0.3.1", None, "gw", &[])],
            PortProfile::Standard,
        );
        store.save(&snap).await.unwrap();

        let loaded = store.load(&snap.id).await.expect("should reload");
        assert_eq!(loaded.devices.len(), 1);
        assert_eq!(store.list_ids().await.len(), 1);

        assert!(store.delete(&snap.id).await);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
