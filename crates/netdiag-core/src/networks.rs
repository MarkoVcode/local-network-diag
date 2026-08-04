//! Separate scan histories per physical network.
//!
//! Without this, scanning at two sites writes into one history and the diff
//! becomes nonsense: every device at site A reads as "disappeared" and every
//! device at site B as "new". First-seen tracking is corrupted the same way.
//!
//! # Identifying a network
//!
//! The subnet cannot do it. Two different buildings routinely both use
//! `192.168.0.0/24`, and treating them as one network is exactly the bug this
//! module exists to prevent.
//!
//! The **gateway's MAC address** can: it is a specific piece of hardware, it is
//! observable without any configuration, and it survives the router's IP or SSID
//! changing. It is therefore the primary key, with SSID, subnet and resolvers as
//! weaker corroborating signals for the cases where no gateway MAC is available.

use crate::netutil::normalize_mac;
use crate::types::HostInfo;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Observable facts that together identify a physical network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkFingerprint {
    /// The gateway's hardware address — the strongest signal by far.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_ip: Option<String>,
    /// Local subnets in canonical form, e.g. `192.168.0.0/24`.
    pub subnets: Vec<String>,
    /// SSID when on Wi-Fi. Distinguishes two sites that share a subnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    pub dns_servers: Vec<String>,
}

impl NetworkFingerprint {
    pub fn from_host(host: &HostInfo, gateway_mac: Option<String>, ssid: Option<String>) -> Self {
        let mut subnets: Vec<String> = host
            .scan_targets
            .iter()
            .filter(|t| t.source == crate::types::TargetSource::Local)
            .map(|t| t.cidr.clone())
            .collect();
        subnets.sort();
        subnets.dedup();

        let mut dns_servers = host.dns.servers.clone();
        dns_servers.sort();
        dns_servers.dedup();

        Self {
            gateway_mac: gateway_mac.map(|mac| normalize_mac(&mac)),
            gateway_ip: host.gateway.as_ref().map(|g| g.ip.clone()),
            subnets,
            ssid: ssid.filter(|s| !s.is_empty() && s != "(hidden)"),
            dns_servers,
        }
    }

    /// A short human description, used when naming a newly-detected network.
    pub fn describe(&self) -> String {
        if let Some(ssid) = &self.ssid {
            return ssid.clone();
        }
        if let Some(subnet) = self.subnets.first() {
            return subnet.clone();
        }
        "Unnamed network".to_string()
    }
}

/// How confident a match is.
///
/// Ordered so the best candidate is simply the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchStrength {
    None,
    /// Subnet alone. Deliberately *not* enough to switch on — this is precisely
    /// the case where two different sites look identical.
    Weak,
    /// SSID plus subnet, or matching resolvers. Good enough to act on.
    Strong,
    /// Gateway MAC. A specific piece of hardware; treat as certain.
    Definitive,
}

/// Compares an observed fingerprint against a stored one.
pub fn match_strength(stored: &NetworkFingerprint, observed: &NetworkFingerprint) -> MatchStrength {
    if let (Some(a), Some(b)) = (&stored.gateway_mac, &observed.gateway_mac) {
        if a.eq_ignore_ascii_case(b) {
            return MatchStrength::Definitive;
        }
        // Both known and different: definitively a *different* network, whatever
        // else agrees. This is what stops two sites sharing 192.168.0.0/24 from
        // being merged.
        return MatchStrength::None;
    }

    let subnet_overlap = stored
        .subnets
        .iter()
        .any(|subnet| observed.subnets.contains(subnet));

    let ssid_match = match (&stored.ssid, &observed.ssid) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    };

    let dns_overlap = stored
        .dns_servers
        .iter()
        .any(|server| observed.dns_servers.contains(server));

    if ssid_match && subnet_overlap {
        return MatchStrength::Strong;
    }
    if ssid_match {
        // Same SSID on a different subnet — roaming within one site, or a
        // router that re-addressed. Still the same place.
        return MatchStrength::Strong;
    }
    if subnet_overlap && dns_overlap {
        return MatchStrength::Strong;
    }
    if subnet_overlap {
        return MatchStrength::Weak;
    }

    MatchStrength::None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkProfile {
    pub id: String,
    pub name: String,
    pub fingerprint: NetworkFingerprint,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<String>,
    #[serde(default)]
    pub scan_count: usize,
}

impl NetworkProfile {
    pub fn new(name: impl Into<String>, fingerprint: NetworkFingerprint) -> Self {
        Self {
            id: new_id(),
            name: name.into(),
            fingerprint,
            created_at: chrono::Utc::now().to_rfc3339(),
            last_seen_at: None,
            scan_count: 0,
        }
    }
}

/// Time-ordered, filesystem-safe id.
///
/// Not a UUID: this only has to be unique within one installation, and a
/// sortable id makes the directory listing meaningful.
///
/// The counter is not decoration. Deriving the suffix from the clock alone
/// collides on platforms whose sub-second resolution is coarse — two profiles
/// created in the same millisecond got identical ids on macOS. Two networks
/// sharing an id share a directory, which merges their histories: precisely the
/// failure this module exists to prevent.
fn new_id() -> String {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    let now = chrono::Utc::now();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let sequence = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    format!(
        "net-{}-{:05}-{:04x}",
        now.format("%Y%m%d-%H%M%S"),
        nanos % 100_000,
        sequence & 0xffff
    )
}

/// What the app should do about the network it is currently attached to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Detection {
    /// Matches the network already selected. Nothing to do.
    #[serde(rename_all = "camelCase")]
    Current { id: String, strength: MatchStrength },
    /// Matches a different saved network — offer to switch.
    #[serde(rename_all = "camelCase")]
    Switch {
        id: String,
        name: String,
        strength: MatchStrength,
    },
    /// Several saved networks look plausible and none is conclusive.
    #[serde(rename_all = "camelCase")]
    Ambiguous { candidates: Vec<NetworkCandidate> },
    /// Nothing matches — offer to create one.
    #[serde(rename_all = "camelCase")]
    Unknown { suggested_name: String },
    /// No usable network to fingerprint.
    #[serde(rename_all = "camelCase")]
    NoNetwork,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkCandidate {
    pub id: String,
    pub name: String,
    pub strength: MatchStrength,
}

/// The saved networks and which one is selected.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkIndex {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<String>,
    pub networks: Vec<NetworkProfile>,
}

impl NetworkIndex {
    pub fn index_path(root: &Path) -> PathBuf {
        root.join("networks.json")
    }

    /// Directory holding one network's data.
    pub fn network_dir(root: &Path, id: &str) -> PathBuf {
        root.join("networks").join(id)
    }

    pub fn scans_dir(root: &Path, id: &str) -> PathBuf {
        Self::network_dir(root, id).join("scans")
    }

    pub async fn load(root: &Path) -> Self {
        match tokio::fs::read(Self::index_path(root)).await {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub async fn save(&self, root: &Path) -> Result<(), String> {
        tokio::fs::create_dir_all(root)
            .await
            .map_err(|e| e.to_string())?;
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        tokio::fs::write(Self::index_path(root), json)
            .await
            .map_err(|e| e.to_string())
    }

    pub fn get(&self, id: &str) -> Option<&NetworkProfile> {
        self.networks.iter().find(|n| n.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut NetworkProfile> {
        self.networks.iter_mut().find(|n| n.id == id)
    }

    /// The selected network, falling back to the first if the id is stale.
    pub fn active_profile(&self) -> Option<&NetworkProfile> {
        self.active
            .as_ref()
            .and_then(|id| self.get(id))
            .or_else(|| self.networks.first())
    }

    /// Adds a network and selects it.
    ///
    /// Uniqueness is enforced here as well as in the generator. A counter resets
    /// when the process does, so two ids minted in the same second across a
    /// restart could still coincide — and a duplicate id would silently merge
    /// two networks' histories.
    pub fn add(&mut self, mut profile: NetworkProfile) -> String {
        if self.get(&profile.id).is_some() {
            let mut suffix = 1u32;
            let base = profile.id.clone();
            while self.get(&profile.id).is_some() {
                profile.id = format!("{base}-{suffix}");
                suffix += 1;
            }
        }

        let id = profile.id.clone();
        self.networks.push(profile);
        self.active = Some(id.clone());
        id
    }

    /// Decides what to do about an observed fingerprint.
    pub fn detect(&self, observed: &NetworkFingerprint) -> Detection {
        if observed.subnets.is_empty() && observed.gateway_mac.is_none() {
            return Detection::NoNetwork;
        }

        let mut scored: Vec<(MatchStrength, &NetworkProfile)> = self
            .networks
            .iter()
            .map(|profile| (match_strength(&profile.fingerprint, observed), profile))
            .filter(|(strength, _)| *strength != MatchStrength::None)
            .collect();

        scored.sort_by_key(|(strength, _)| std::cmp::Reverse(*strength));

        let Some((best_strength, best)) = scored.first().copied() else {
            return Detection::Unknown {
                suggested_name: observed.describe(),
            };
        };

        // A weak (subnet-only) match is not enough to act on — it is the very
        // ambiguity this module exists to surface rather than guess at.
        if best_strength == MatchStrength::Weak {
            return Detection::Ambiguous {
                candidates: scored
                    .iter()
                    .map(|(strength, profile)| NetworkCandidate {
                        id: profile.id.clone(),
                        name: profile.name.clone(),
                        strength: *strength,
                    })
                    .collect(),
            };
        }

        if self.active.as_deref() == Some(best.id.as_str()) {
            return Detection::Current {
                id: best.id.clone(),
                strength: best_strength,
            };
        }

        Detection::Switch {
            id: best.id.clone(),
            name: best.name.clone(),
            strength: best_strength,
        }
    }
}

/* ------------------------------------------------------- probing and migration */

/// Fingerprints the network this machine is on right now.
///
/// Deliberately cheap — this runs at launch and before every scan, so it must
/// not feel like a scan. The one non-trivial step is a single ping to the
/// gateway, which is what puts its MAC in the neighbour cache; without that the
/// strongest identifying signal is frequently unavailable on a cold start.
pub async fn probe_current() -> (HostInfo, NetworkFingerprint) {
    let (host, _warnings) = crate::scan::hostinfo::collect(&[]).await;

    let gateway_mac = match &host.gateway {
        Some(gateway) => resolve_gateway_mac(&gateway.ip).await,
        None => None,
    };

    // Best-effort: a machine with no Wi-Fi, or macOS without Location Services
    // permission, simply contributes no SSID rather than delaying startup.
    let ssid = tokio::time::timeout(std::time::Duration::from_secs(6), async {
        crate::platform::wifi_survey()
            .await
            .data
            .and_then(|wifi| wifi.current.map(|current| current.ssid))
    })
    .await
    .ok()
    .flatten();

    let fingerprint = NetworkFingerprint::from_host(&host, gateway_mac, ssid);
    (host, fingerprint)
}

async fn resolve_gateway_mac(gateway_ip: &str) -> Option<String> {
    let Ok(ip) = gateway_ip.parse::<std::net::Ipv4Addr>() else {
        return None;
    };

    // Check the cache first; only pay for a ping if the entry is missing.
    if let Some(mac) = crate::scan::sweep::read_neighbors().await.get(&ip) {
        return Some(mac.clone());
    }

    let args = crate::platform::ping_args(gateway_ip, 1, 1);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let _ = crate::exec::run("ping", &arg_refs, std::time::Duration::from_millis(2000)).await;
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    crate::scan::sweep::read_neighbors().await.get(&ip).cloned()
}

/// Moves a pre-networks installation into its first network.
///
/// Existing users have scans in a flat `scans/` directory. Those represent a
/// real network and must not be discarded, so they become the first profile,
/// fingerprinted from the newest snapshot they contain rather than from wherever
/// the machine happens to be when the upgrade is first run.
pub async fn migrate_flat_layout(root: &Path) -> Result<Option<String>, String> {
    let legacy = root.join("scans");
    if !legacy.is_dir() {
        return Ok(None);
    }

    // Already migrated, or a fresh install that happens to have the directory.
    let index = NetworkIndex::load(root).await;
    if !index.networks.is_empty() {
        return Ok(None);
    }

    let legacy_store = crate::store::Store::new(&legacy);
    let ids = legacy_store.list_ids().await;
    if ids.is_empty() {
        return Ok(None);
    }

    let newest = legacy_store.load_latest().await;
    let (name, fingerprint) = match &newest {
        Some(snapshot) => {
            let gateway_mac = snapshot
                .devices
                .iter()
                .find(|device| device.is_gateway)
                .and_then(|device| device.mac.clone());
            let ssid = snapshot
                .wifi
                .data
                .as_ref()
                .and_then(|wifi| wifi.current.as_ref().map(|c| c.ssid.clone()));

            let fingerprint = NetworkFingerprint::from_host(&snapshot.host, gateway_mac, ssid);
            (fingerprint.describe(), fingerprint)
        }
        None => ("Default network".to_string(), NetworkFingerprint::default()),
    };

    let profile = NetworkProfile {
        scan_count: ids.len(),
        last_seen_at: newest.as_ref().map(|s| s.started_at.clone()),
        ..NetworkProfile::new(name, fingerprint)
    };
    let id = profile.id.clone();

    let target = NetworkIndex::scans_dir(root, &id);
    tokio::fs::create_dir_all(&target)
        .await
        .map_err(|e| e.to_string())?;

    for scan_id in &ids {
        let from = legacy.join(format!("{scan_id}.json"));
        let to = target.join(format!("{scan_id}.json"));
        // Rename is atomic within a filesystem; copying is the fallback for the
        // rare case the app-data directory spans mounts.
        if tokio::fs::rename(&from, &to).await.is_err() {
            tokio::fs::copy(&from, &to)
                .await
                .map_err(|e| format!("could not migrate {scan_id}: {e}"))?;
            let _ = tokio::fs::remove_file(&from).await;
        }
    }

    // Controller settings belonged to that same network.
    let legacy_unifi = root.join("unifi.json");
    if legacy_unifi.is_file() {
        let to = NetworkIndex::network_dir(root, &id).join("unifi.json");
        if tokio::fs::rename(&legacy_unifi, &to).await.is_err() {
            let _ = tokio::fs::copy(&legacy_unifi, &to).await;
            let _ = tokio::fs::remove_file(&legacy_unifi).await;
        }
    }

    let mut index = index;
    index.add(profile);
    index.save(root).await?;

    // Leave the empty directory behind rather than removing it: if anything
    // above went wrong, the user still has a directory to look in.
    Ok(Some(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(
        gateway_mac: Option<&str>,
        subnet: &str,
        ssid: Option<&str>,
    ) -> NetworkFingerprint {
        NetworkFingerprint {
            gateway_mac: gateway_mac.map(|m| m.to_string()),
            gateway_ip: Some("192.168.0.1".into()),
            subnets: vec![subnet.to_string()],
            ssid: ssid.map(|s| s.to_string()),
            dns_servers: vec!["192.168.0.1".into()],
        }
    }

    #[test]
    fn the_same_subnet_at_two_places_is_not_the_same_network() {
        // The bug this module exists for: two sites both on 192.168.0.0/24.
        let home = fingerprint(
            Some("aa:aa:aa:aa:aa:aa"),
            "192.168.0.0/24",
            Some("HomeWiFi"),
        );
        let office = fingerprint(
            Some("bb:bb:bb:bb:bb:bb"),
            "192.168.0.0/24",
            Some("OfficeWiFi"),
        );

        assert_eq!(match_strength(&home, &office), MatchStrength::None);
    }

    #[test]
    fn a_differing_gateway_mac_overrides_everything_else_agreeing() {
        // Same subnet, same SSID name, same resolver — but different hardware.
        let a = fingerprint(Some("aa:aa:aa:aa:aa:aa"), "192.168.0.0/24", Some("linksys"));
        let b = fingerprint(Some("bb:bb:bb:bb:bb:bb"), "192.168.0.0/24", Some("linksys"));

        assert_eq!(
            match_strength(&a, &b),
            MatchStrength::None,
            "hardware identity must win over coincidental agreement"
        );
    }

    #[test]
    fn the_same_gateway_is_definitive_even_if_the_subnet_changed() {
        let before = fingerprint(Some("aa:aa:aa:aa:aa:aa"), "192.168.0.0/24", Some("Home"));
        let mut after = fingerprint(Some("AA:AA:AA:AA:AA:AA"), "10.0.0.0/24", Some("Home"));
        after.dns_servers = vec!["10.0.0.1".into()];

        assert_eq!(
            match_strength(&before, &after),
            MatchStrength::Definitive,
            "re-addressing the LAN does not make it a different place"
        );
    }

    #[test]
    fn ssid_identifies_a_site_when_no_gateway_mac_is_available() {
        let stored = fingerprint(None, "192.168.0.0/24", Some("Office"));
        let observed = fingerprint(None, "192.168.5.0/24", Some("Office"));
        assert_eq!(match_strength(&stored, &observed), MatchStrength::Strong);
    }

    #[test]
    fn subnet_alone_is_only_a_weak_match() {
        let stored = fingerprint(None, "192.168.0.0/24", None);
        let mut observed = fingerprint(None, "192.168.0.0/24", None);
        observed.dns_servers = vec!["1.1.1.1".into()];

        assert_eq!(
            match_strength(&stored, &observed),
            MatchStrength::Weak,
            "a shared subnet is exactly the ambiguous case, not a match"
        );
    }

    #[test]
    fn an_unrecognised_network_is_reported_as_unknown() {
        let index = NetworkIndex::default();
        let observed = fingerprint(Some("cc:cc:cc:cc:cc:cc"), "172.16.0.0/24", Some("Cafe"));

        match index.detect(&observed) {
            Detection::Unknown { suggested_name } => assert_eq!(suggested_name, "Cafe"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn a_definitive_match_on_another_network_offers_a_switch() {
        let mut index = NetworkIndex::default();
        let home = NetworkProfile::new(
            "Home",
            fingerprint(Some("aa:aa:aa:aa:aa:aa"), "192.168.0.0/24", Some("Home")),
        );
        let office = NetworkProfile::new(
            "Office",
            fingerprint(Some("bb:bb:bb:bb:bb:bb"), "192.168.0.0/24", Some("Office")),
        );
        index.networks.push(home);
        let office_id = office.id.clone();
        index.networks.push(office);
        index.active = Some(index.networks[0].id.clone());

        let observed = fingerprint(Some("bb:bb:bb:bb:bb:bb"), "192.168.0.0/24", Some("Office"));
        match index.detect(&observed) {
            Detection::Switch { id, name, strength } => {
                assert_eq!(id, office_id);
                assert_eq!(name, "Office");
                assert_eq!(strength, MatchStrength::Definitive);
            }
            other => panic!("expected Switch, got {other:?}"),
        }
    }

    #[test]
    fn staying_on_the_same_network_is_a_no_op() {
        let mut index = NetworkIndex::default();
        let profile = NetworkProfile::new(
            "Home",
            fingerprint(Some("aa:aa:aa:aa:aa:aa"), "192.168.0.0/24", Some("Home")),
        );
        let id = profile.id.clone();
        index.networks.push(profile);
        index.active = Some(id.clone());

        let observed = fingerprint(Some("aa:aa:aa:aa:aa:aa"), "192.168.0.0/24", Some("Home"));
        match index.detect(&observed) {
            Detection::Current { id: found, .. } => assert_eq!(found, id),
            other => panic!("expected Current, got {other:?}"),
        }
    }

    #[test]
    fn two_gateway_less_networks_sharing_a_subnet_are_reported_ambiguous() {
        // Never guess here — guessing is how histories get merged.
        let mut index = NetworkIndex::default();
        index.networks.push(NetworkProfile::new(
            "Site A",
            fingerprint(None, "192.168.0.0/24", None),
        ));
        index.networks.push(NetworkProfile::new(
            "Site B",
            fingerprint(None, "192.168.0.0/24", None),
        ));

        let mut observed = fingerprint(None, "192.168.0.0/24", None);
        observed.dns_servers = vec!["8.8.8.8".into()];

        match index.detect(&observed) {
            Detection::Ambiguous { candidates } => assert_eq!(candidates.len(), 2),
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn no_addresses_at_all_reports_no_network() {
        let index = NetworkIndex::default();
        assert!(matches!(
            index.detect(&NetworkFingerprint::default()),
            Detection::NoNetwork
        ));
    }

    #[test]
    fn ids_are_unique_even_when_minted_in_the_same_instant() {
        // A clock-only suffix collided here on macOS, and two networks sharing
        // an id share a directory — merging exactly the histories this module
        // keeps apart.
        let ids: std::collections::HashSet<String> = (0..1000).map(|_| new_id()).collect();
        assert_eq!(
            ids.len(),
            1000,
            "id generation must not collide under speed"
        );

        for id in &ids {
            assert!(
                id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "ids become directory names: {id}"
            );
        }
    }

    #[test]
    fn adding_a_duplicate_id_disambiguates_rather_than_merging() {
        let mut index = NetworkIndex::default();
        let first = NetworkProfile::new("A", NetworkFingerprint::default());

        // Force the collision the generator is supposed to make impossible.
        let mut second = NetworkProfile::new("B", NetworkFingerprint::default());
        second.id = first.id.clone();

        let first_id = index.add(first);
        let second_id = index.add(second);

        assert_ne!(
            first_id, second_id,
            "two networks must never share a directory"
        );
        assert_eq!(index.networks.len(), 2);
    }

    #[test]
    fn the_active_profile_falls_back_when_the_id_is_stale() {
        let mut index = NetworkIndex::default();
        index
            .networks
            .push(NetworkProfile::new("Home", NetworkFingerprint::default()));
        index.active = Some("net-does-not-exist".into());

        assert_eq!(
            index.active_profile().map(|p| p.name.as_str()),
            Some("Home"),
            "a dangling id must not leave the app with no network"
        );
    }
}
