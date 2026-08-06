//! Typed views of the controller's payloads.
//!
//! Deserialization is deliberately tolerant. UniFi adds, renames and removes
//! fields between Network releases, and a field this app does not use must never
//! break the ones it does — so every field is optional and unknown keys are
//! ignored. A firmware upgrade should degrade a single column, not the feature.

use crate::netutil::normalize_mac;
use serde::{Deserialize, Serialize};

fn de_mac<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    Ok(raw
        .map(|value| normalize_mac(&value))
        .filter(|value| !value.is_empty()))
}

/// One entry from `stat/sta` (active) or `stat/alluser` (all known).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UnifiClientRecord {
    #[serde(deserialize_with = "de_mac")]
    pub mac: Option<String>,
    pub ip: Option<String>,
    /// DHCP-supplied hostname.
    pub hostname: Option<String>,
    /// Alias a human typed into the controller. The best name available.
    pub name: Option<String>,
    pub oui: Option<String>,
    pub note: Option<String>,

    pub is_wired: Option<bool>,
    pub is_guest: Option<bool>,
    pub network: Option<String>,
    pub vlan: Option<u32>,

    /// AP this client is associated to.
    #[serde(deserialize_with = "de_mac")]
    pub ap_mac: Option<String>,
    pub essid: Option<String>,
    pub channel: Option<u32>,
    pub radio: Option<String>,
    pub radio_proto: Option<String>,
    pub rssi: Option<i32>,
    pub signal: Option<i32>,
    pub noise: Option<i32>,
    pub satisfaction: Option<i32>,

    /// Switch and port a wired client is on — the physical-location payload.
    #[serde(deserialize_with = "de_mac")]
    pub sw_mac: Option<String>,
    pub sw_port: Option<u32>,

    pub uptime: Option<i64>,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub tx_bytes: Option<i64>,
    pub rx_bytes: Option<i64>,

    /// The controller's own fingerprint of the device.
    pub dev_vendor: Option<serde_json::Value>,
    pub dev_family: Option<serde_json::Value>,
    pub dev_cat: Option<serde_json::Value>,
    pub os_name: Option<serde_json::Value>,

    pub use_fixedip: Option<bool>,
    pub fixed_ip: Option<String>,
}

impl UnifiClientRecord {
    /// Best human-readable name: an operator-assigned alias beats a DHCP
    /// hostname, which beats nothing.
    pub fn best_name(&self) -> Option<String> {
        [&self.name, &self.hostname]
            .into_iter()
            .flatten()
            .map(|value| value.trim())
            .find(|value| !value.is_empty())
            .map(str::to_string)
    }

    /// Human summary of the controller's fingerprint.
    ///
    /// UniFi returns these as numeric ids in some releases and strings in
    /// others, so both are accepted and numeric ids are simply skipped — a
    /// number would be meaningless to show a user.
    pub fn fingerprint(&self) -> Option<String> {
        let text = |value: &Option<serde_json::Value>| -> Option<String> {
            value.as_ref().and_then(|v| v.as_str()).and_then(|s| {
                let trimmed = s.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            })
        };

        let parts: Vec<String> = [
            text(&self.dev_vendor),
            text(&self.dev_family),
            text(&self.os_name),
        ]
        .into_iter()
        .flatten()
        .collect();

        (!parts.is_empty()).then(|| parts.join(" · "))
    }

    pub fn effective_ip(&self) -> Option<String> {
        [&self.ip, &self.fixed_ip]
            .into_iter()
            .flatten()
            .find(|value| value.parse::<std::net::Ipv4Addr>().is_ok())
            .cloned()
    }

    /// Normalizes `radio_proto` into the consumer Wi-Fi generation name.
    ///
    /// An unrecognized value passes through untouched — a future `radio_proto`
    /// should show up raw rather than disappear.
    pub fn wifi_generation(&self) -> Option<String> {
        let proto = self.radio_proto.as_deref()?.trim().to_ascii_lowercase();
        let label = match proto.as_str() {
            "" => return None,
            "b" | "g" => return Some(format!("802.11{proto}")),
            "n" | "ng" | "na" => "Wi-Fi 4 (n)",
            "ac" => "Wi-Fi 5 (ac)",
            "ax" => "Wi-Fi 6 (ax)",
            "be" => "Wi-Fi 7 (be)",
            _ => return Some(proto),
        };
        Some(label.to_string())
    }
}

/// A port on a UniFi switch.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PortEntry {
    pub port_idx: Option<u32>,
    pub name: Option<String>,
    pub up: Option<bool>,
    pub speed: Option<i64>,
    pub poe_enable: Option<bool>,
    pub poe_power: Option<serde_json::Value>,
    /// MACs the switch has learned on this port. More than one means something
    /// unmanaged is plugged in behind it.
    pub mac_table: Option<Vec<MacTableEntry>>,
}

impl PortEntry {
    /// PoE draw in watts. The controller returns this as a number in some
    /// releases and a numeric string in others; both are accepted.
    pub fn poe_watts(&self) -> Option<f64> {
        match self.poe_power.as_ref()? {
            serde_json::Value::Number(n) => n.as_f64(),
            serde_json::Value::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct MacTableEntry {
    #[serde(deserialize_with = "de_mac")]
    pub mac: Option<String>,
    pub vlan: Option<u32>,
}

/// One managed UniFi device from `stat/device`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UnifiDeviceRecord {
    #[serde(deserialize_with = "de_mac")]
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub name: Option<String>,
    pub model: Option<String>,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub version: Option<String>,
    pub adopted: Option<bool>,
    pub state: Option<i32>,
    pub uptime: Option<i64>,
    pub upgradable: Option<bool>,
    pub port_table: Option<Vec<PortEntry>>,
}

impl UnifiDeviceRecord {
    /// `model` is a short code (`U7PG2`, `US6XG`); pair it with the name so the
    /// UI can show something meaningful either way.
    pub fn describe(&self) -> String {
        match (&self.name, &self.model) {
            (Some(name), Some(model)) if !name.trim().is_empty() => {
                format!("{} ({model})", name.trim())
            }
            (Some(name), None) if !name.trim().is_empty() => name.trim().to_string(),
            (_, Some(model)) => model.clone(),
            _ => "UniFi device".to_string(),
        }
    }

    pub fn kind_label(&self) -> &'static str {
        match self.kind.as_deref() {
            Some("uap") => "Access point",
            Some("usw") => "Switch",
            Some("ugw") | Some("udm") => "Gateway",
            _ => "UniFi device",
        }
    }

    /// A label for an *abnormal* device state, or `None` when the device is
    /// simply connected.
    ///
    /// Unadopted devices return `None` too: "not adopted" already has its own
    /// badge, and stacking a state on top would say the same thing twice.
    pub fn state_problem(&self) -> Option<String> {
        let state = self.state?;
        if state == 1 || self.adopted != Some(true) {
            return None;
        }
        Some(match state {
            0 => "Disconnected".to_string(),
            2 => "Adoption pending".to_string(),
            4 => "Upgrading".to_string(),
            5 => "Provisioning".to_string(),
            6 => "Heartbeat missed".to_string(),
            7 => "Adopting".to_string(),
            9 => "Adoption error".to_string(),
            11 => "Isolated".to_string(),
            other => format!("State {other}"),
        })
    }
}

/// One entry from `rest/networkconf` — a network as the operator *configured*
/// it, as opposed to the networks this machine happens to be attached to.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UnifiNetworkConf {
    pub name: Option<String>,
    /// `corporate`, `guest`, `wan`, `vlan-only`, `vpn-client`, …
    pub purpose: Option<String>,
    /// Gateway address with prefix, e.g. `10.0.30.1/24`.
    pub ip_subnet: Option<String>,
    /// Number in current releases, string in some older ones.
    pub vlan: Option<serde_json::Value>,
    pub enabled: Option<bool>,
    pub vlan_enabled: Option<bool>,
    pub dhcpd_enabled: Option<bool>,
}

impl UnifiNetworkConf {
    pub fn vlan_id(&self) -> Option<u32> {
        match self.vlan.as_ref()? {
            serde_json::Value::Number(n) => n.as_u64().and_then(|v| u32::try_from(v).ok()),
            serde_json::Value::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    }
}

/// The configured network as stored in a snapshot, for the UI and correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiNetworkSummary {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Canonical network address, e.g. `10.0.30.0/24` — the configured
    /// `ip_subnet` is the *gateway's* address, which would mislead a reader.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u32>,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<bool>,
}

impl From<&UnifiNetworkConf> for UnifiNetworkSummary {
    fn from(record: &UnifiNetworkConf) -> Self {
        let subnet = record.ip_subnet.as_deref().map(|raw| {
            crate::netutil::parse_cidr_any(raw)
                .map(|cidr| cidr.canonical())
                .unwrap_or_else(|_| raw.to_string())
        });
        Self {
            name: record
                .name
                .clone()
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| "unnamed network".to_string()),
            purpose: record.purpose.clone(),
            subnet,
            vlan: record.vlan_id(),
            enabled: record.enabled.unwrap_or(true),
            dhcp: record.dhcpd_enabled,
        }
    }
}

/// One entry from `stat/event` — the controller's rolling log of connects,
/// disconnects, roams, adoptions and the like.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UnifiEventRecord {
    /// e.g. `EVT_WU_Disconnected` (wireless user), `EVT_LU_Connected` (LAN user).
    pub key: Option<String>,
    pub subsystem: Option<String>,
    /// Epoch **milliseconds** in every observed release.
    pub time: Option<i64>,
    pub msg: Option<String>,
    /// The client involved: `user` for normal clients, `guest` for guests.
    #[serde(deserialize_with = "de_mac")]
    pub user: Option<String>,
    #[serde(deserialize_with = "de_mac")]
    pub guest: Option<String>,
    pub hostname: Option<String>,
    #[serde(deserialize_with = "de_mac")]
    pub ap: Option<String>,
    pub ssid: Option<String>,
}

impl UnifiEventRecord {
    pub fn client_mac(&self) -> Option<&str> {
        self.user.as_deref().or(self.guest.as_deref())
    }

    /// Event time in epoch seconds, tolerating either unit: a value that would
    /// place the event thousands of years out is milliseconds.
    pub fn time_seconds(&self) -> Option<i64> {
        self.time
            .map(|t| if t > 100_000_000_000 { t / 1000 } else { t })
    }

    pub fn is_disconnect(&self) -> bool {
        self.key
            .as_deref()
            .map(|k| k.contains("Disconnected"))
            .unwrap_or(false)
    }
}

/// One entry from `list/alarm`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UnifiAlarmRecord {
    pub key: Option<String>,
    pub msg: Option<String>,
    /// Epoch milliseconds, like events.
    pub time: Option<i64>,
    pub subsystem: Option<String>,
    pub archived: Option<bool>,
}

/// An active alarm as stored in a snapshot. The controller already words these
/// for humans, so the message passes through verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiAlarmSummary {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<String>,
    /// Epoch seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<i64>,
}

impl UnifiAlarmRecord {
    pub fn summarize(&self) -> Option<UnifiAlarmSummary> {
        if self.archived == Some(true) {
            return None;
        }
        let message = self
            .msg
            .clone()
            .filter(|m| !m.trim().is_empty())
            .or_else(|| self.key.clone())?;
        Some(UnifiAlarmSummary {
            message,
            subsystem: self.subsystem.clone(),
            time: self
                .time
                .map(|t| if t > 100_000_000_000 { t / 1000 } else { t }),
        })
    }
}

/// One entry from `stat/rogueap` — a foreign access point overheard by the
/// site's own radios. Pure signal a host scanner can never produce.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UnifiRogueApRecord {
    pub essid: Option<String>,
    #[serde(deserialize_with = "de_mac")]
    pub bssid: Option<String>,
    pub channel: Option<u32>,
    /// dBm (negative) in most releases.
    pub signal: Option<i32>,
    /// dB above noise (small positive) — same fact, other scale.
    pub rssi: Option<i32>,
    pub security: Option<String>,
    pub oui: Option<String>,
}

/// A neighboring AP as stored in a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NeighborApSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bssid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_dbm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    /// A foreign radio broadcasting one of this site's own SSIDs — the
    /// evil-twin signature.
    pub evil_twin: bool,
}

/// Summarizes overheard APs: evil twins always survive, the rest keep only the
/// `cap` strongest. Returns the summaries and the total seen, so the UI can say
/// "30 of 174" instead of silently truncating.
pub fn summarize_neighbor_aps(
    records: &[UnifiRogueApRecord],
    own_ssids: &std::collections::HashSet<String>,
    cap: usize,
) -> (Vec<NeighborApSummary>, usize) {
    let mut summaries: Vec<NeighborApSummary> = records
        .iter()
        .map(|record| {
            let evil_twin = record
                .essid
                .as_deref()
                .map(|essid| !essid.trim().is_empty() && own_ssids.contains(essid))
                .unwrap_or(false);
            NeighborApSummary {
                ssid: record.essid.clone().filter(|s| !s.trim().is_empty()),
                bssid: record.bssid.clone(),
                channel: record.channel,
                signal_dbm: record
                    .signal
                    .filter(|s| *s < 0)
                    .or(record.rssi.filter(|r| *r < 0)),
                security: record.security.clone(),
                evil_twin,
            }
        })
        .collect();

    let total = summaries.len();
    // Evil twins first, then strongest signal — the order of interest.
    summaries.sort_by_key(|s| {
        (
            !s.evil_twin,
            std::cmp::Reverse(s.signal_dbm.unwrap_or(i32::MIN)),
        )
    });
    summaries.truncate(cap.max(summaries.iter().filter(|s| s.evil_twin).count()));
    (summaries, total)
}

/// One entry from `stat/health` — the controller's own verdict on a subsystem
/// (`wan`, `www`, `lan`, `wlan`, `vpn`).
///
/// `www` is the controller's *measured* view of internet reachability (it
/// probes an external target), while `wan` is the state of the uplink port.
/// Both matter: a WAN port can be up while the internet behind it is not.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UnifiHealthRecord {
    pub subsystem: Option<String>,
    pub status: Option<String>,
    pub wan_ip: Option<String>,
    pub gw_name: Option<String>,
    pub lan_ip: Option<String>,
    /// Milliseconds to the controller's external probe target.
    pub latency: Option<f64>,
    pub uptime: Option<i64>,
    /// Measured throughput in Mbps, when the controller runs an uplink monitor.
    pub xput_up: Option<f64>,
    pub xput_down: Option<f64>,
    pub speedtest_ping: Option<f64>,
    pub drops: Option<i64>,
    pub num_user: Option<i64>,
    pub num_guest: Option<i64>,
    pub num_ap: Option<i64>,
    pub num_sw: Option<i64>,
    pub num_adopted: Option<i64>,
    pub num_disconnected: Option<i64>,
}

/// The health entry as stored in a snapshot, for the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiHealthSummary {
    pub subsystem: String,
    /// `ok`, `warning`, `error` or `unknown`, as the controller reports it.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wan_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xput_up_mbps: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xput_down_mbps: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drops: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clients: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guests: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adopted: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnected: Option<i64>,
}

impl From<&UnifiHealthRecord> for UnifiHealthSummary {
    fn from(record: &UnifiHealthRecord) -> Self {
        Self {
            subsystem: record.subsystem.clone().unwrap_or_default(),
            status: record
                .status
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            wan_ip: record.wan_ip.clone(),
            gateway_name: record.gw_name.clone(),
            latency_ms: record.latency.or(record.speedtest_ping),
            xput_up_mbps: record.xput_up,
            xput_down_mbps: record.xput_down,
            drops: record.drops,
            clients: record.num_user,
            guests: record.num_guest,
            adopted: record.num_adopted,
            disconnected: record.num_disconnected,
        }
    }
}

/// The one sentence a home user actually wants: is the problem my LAN or my
/// internet? Answered from the controller's own health verdicts, so it works
/// even when this machine's own WAN probes are blocked.
///
/// Returns `None` when the controller offers nothing conclusive — an absent
/// or `unknown` internet subsystem must not produce false reassurance.
pub fn wan_triage(health: &[UnifiHealthSummary]) -> Option<String> {
    let find = |name: &str| health.iter().find(|h| h.subsystem == name);
    let www = find("www");
    let wan = find("wan");

    // Prefer the measured internet check; fall back to the uplink port state.
    let verdict = www.filter(|h| h.status != "unknown").or(wan)?;
    let latency = www.and_then(|h| h.latency_ms);

    match verdict.status.as_str() {
        "ok" => {
            let mut sentence = String::from("The controller reports the internet link healthy");
            if let Some(ms) = latency {
                sentence.push_str(&format!(" ({ms:.0} ms to its external probe)"));
            }
            sentence.push_str(" — if something feels slow, the cause is on the local network.");
            Some(sentence)
        }
        "warning" | "error" => {
            let mut details = Vec::new();
            if let Some(ms) = latency {
                details.push(format!("latency {ms:.0} ms"));
            }
            if let Some(drops) = www.and_then(|h| h.drops).filter(|d| *d > 0) {
                details.push(format!("{drops} dropped probe(s)"));
            }
            let detail = if details.is_empty() {
                String::new()
            } else {
                format!(" ({})", details.join(", "))
            };
            Some(format!(
                "The controller reports trouble on the internet link{detail} — slowness is \
                 likely upstream, not on your LAN."
            ))
        }
        _ => None,
    }
}

/// Everything fetched from the controller in one pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiSnapshot {
    pub controller_host: String,
    pub site: String,
    /// Managed infrastructure, keyed for display.
    pub devices: Vec<UnifiDeviceSummary>,
    /// Per-subsystem health verdicts. Defaulted so pre-1.2 snapshots load.
    #[serde(default)]
    pub health: Vec<UnifiHealthSummary>,
    /// Networks as configured on the controller — including ones this machine
    /// cannot see. Defaulted so pre-1.2 snapshots load.
    #[serde(default)]
    pub networks: Vec<UnifiNetworkSummary>,
    /// Active alarms, worded by the controller itself.
    #[serde(default)]
    pub alarms: Vec<UnifiAlarmSummary>,
    /// Foreign APs overheard by the site's radios — evil twins always kept,
    /// otherwise the strongest few.
    #[serde(default)]
    pub neighbor_aps: Vec<NeighborApSummary>,
    /// How many foreign APs were seen in total, before the strongest-N cut.
    #[serde(default)]
    pub neighbor_ap_total: usize,
    /// The LAN-or-internet triage sentence derived from `health`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_triage: Option<String>,
    /// Non-fatal problems — an endpoint this account cannot read, say.
    pub warnings: Vec<String>,
    #[serde(skip, default)]
    pub clients: Vec<UnifiClientRecord>,
    #[serde(skip, default)]
    pub known_clients: Vec<UnifiClientRecord>,
    #[serde(skip, default)]
    pub raw_devices: Vec<UnifiDeviceRecord>,
    /// Recent events, for correlation only — never persisted.
    #[serde(skip, default)]
    pub raw_events: Vec<UnifiEventRecord>,
}

/// The parts of a managed device worth putting in a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiDeviceSummary {
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub name: String,
    pub kind: String,
    pub model: Option<String>,
    pub version: Option<String>,
    pub adopted: bool,
    pub upgradable: bool,
    pub uptime_seconds: Option<i64>,
    /// Present only when the device is in an abnormal state — see
    /// [`UnifiDeviceRecord::state_problem`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_label: Option<String>,
    /// Physical ports, for switches. Defaulted so pre-1.2 snapshots still load.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<UnifiPortSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiPortSummary {
    pub index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub up: bool,
    /// Negotiated speed in Mbps, when the port is up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed_mbps: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poe_watts: Option<f64>,
}

impl From<&UnifiDeviceRecord> for UnifiDeviceSummary {
    fn from(record: &UnifiDeviceRecord) -> Self {
        let ports = record
            .port_table
            .iter()
            .flatten()
            .filter_map(|port| {
                Some(UnifiPortSummary {
                    index: port.port_idx?,
                    name: port.name.clone().filter(|n| !n.trim().is_empty()),
                    up: port.up.unwrap_or(false),
                    speed_mbps: port.speed.filter(|s| *s > 0),
                    poe_watts: port.poe_watts(),
                })
            })
            .collect();

        Self {
            mac: record.mac.clone(),
            ip: record.ip.clone(),
            name: record.describe(),
            kind: record.kind_label().to_string(),
            model: record.model.clone(),
            version: record.version.clone(),
            adopted: record.adopted.unwrap_or(false),
            upgradable: record.upgradable.unwrap_or(false),
            uptime_seconds: record.uptime,
            state_label: record.state_problem(),
            ports,
        }
    }
}

impl UnifiSnapshot {
    /// Index of every client the controller knows, keyed by MAC.
    ///
    /// Active clients win over historical ones, since `stat/alluser` carries a
    /// stale IP for anything currently offline.
    pub fn clients_by_mac(&self) -> std::collections::HashMap<String, &UnifiClientRecord> {
        let mut out = std::collections::HashMap::new();
        for record in &self.known_clients {
            if let Some(mac) = &record.mac {
                out.insert(mac.clone(), record);
            }
        }
        for record in &self.clients {
            if let Some(mac) = &record.mac {
                out.insert(mac.clone(), record);
            }
        }
        out
    }

    /// Names of managed devices by MAC, for resolving `ap_mac` / `sw_mac` into
    /// something a human can act on.
    pub fn device_names(&self) -> std::collections::HashMap<String, String> {
        self.raw_devices
            .iter()
            .filter_map(|d| d.mac.clone().map(|mac| (mac, d.describe())))
            .collect()
    }

    /// Switch ports with more than one learned MAC.
    ///
    /// A managed switch normally learns one MAC per access port. Several means
    /// an unmanaged switch, a VM host or a hypervisor bridge sits behind it —
    /// an entire network segment the controller cannot see into, inferred from
    /// data it already collects.
    pub fn crowded_ports(&self) -> Vec<CrowdedPort> {
        let mut out = Vec::new();

        for device in &self.raw_devices {
            let Some(ports) = &device.port_table else {
                continue;
            };
            for port in ports {
                let Some(table) = &port.mac_table else {
                    continue;
                };
                let macs: Vec<String> = table.iter().filter_map(|e| e.mac.clone()).collect();
                if macs.len() < 2 {
                    continue;
                }
                out.push(CrowdedPort {
                    switch_name: device.describe(),
                    port: port.port_idx.unwrap_or(0),
                    port_name: port.name.clone(),
                    macs,
                });
            }
        }

        out
    }

    /// Ports running at 10/100 Mbps on hardware that demonstrably does better.
    ///
    /// The comparison against the device's own fastest live port matters: it is
    /// what separates "gigabit switch with one struggling link" (a finding —
    /// often a damaged cable, since gigabit falls back to 100 Mbps when a wire
    /// pair fails) from "everything on this switch is a 100 Mbps device"
    /// (not a finding).
    pub fn degraded_link_ports(&self) -> Vec<DegradedLinkPort> {
        let mut out = Vec::new();

        for device in &self.raw_devices {
            let Some(ports) = &device.port_table else {
                continue;
            };
            let live = |port: &&PortEntry| port.up == Some(true) && port.speed.unwrap_or(0) > 0;
            let fastest = ports.iter().filter(live).filter_map(|p| p.speed).max();
            let Some(fastest) = fastest.filter(|speed| *speed >= 1000) else {
                continue;
            };
            for port in ports.iter().filter(live) {
                let speed = port.speed.unwrap_or(0);
                if speed > 100 {
                    continue;
                }
                out.push(DegradedLinkPort {
                    switch_name: device.describe(),
                    port: port.port_idx.unwrap_or(0),
                    port_name: port.name.clone().filter(|n| !n.trim().is_empty()),
                    speed_mbps: speed,
                    fastest_mbps: fastest,
                });
            }
        }

        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrowdedPort {
    pub switch_name: String,
    pub port: u32,
    pub port_name: Option<String>,
    pub macs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DegradedLinkPort {
    pub switch_name: String,
    pub port: u32,
    pub port_name: Option<String>,
    pub speed_mbps: i64,
    pub fastest_mbps: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_client_record_and_normalizes_the_mac() {
        let json = r#"{
            "mac":"E0-63-DA-82-1B-35","ip":"10.0.3.50","hostname":"my-laptop",
            "name":"Marek's Laptop","is_wired":false,"ap_mac":"78:8A:20:59:C4:B8",
            "essid":"ADOFULL","rssi":54,"channel":149,"vlan":10,
            "sw_mac":null,"sw_port":null,
            "dev_vendor":"Intel","os_name":"Linux","unknown_future_field":123
        }"#;

        let record: UnifiClientRecord = serde_json::from_str(json).unwrap();
        assert_eq!(
            record.mac.as_deref(),
            Some("e0:63:da:82:1b:35"),
            "dashes -> colons"
        );
        assert_eq!(
            record.best_name().as_deref(),
            Some("Marek's Laptop"),
            "alias beats hostname"
        );
        assert_eq!(record.ap_mac.as_deref(), Some("78:8a:20:59:c4:b8"));
        assert_eq!(record.fingerprint().as_deref(), Some("Intel · Linux"));
        assert_eq!(record.vlan, Some(10));
    }

    #[test]
    fn unknown_and_missing_fields_do_not_break_parsing() {
        // A controller upgrade must not take the feature down.
        let record: UnifiClientRecord =
            serde_json::from_str(r#"{"brand_new_field":true}"#).unwrap();
        assert!(record.mac.is_none());
        assert!(record.best_name().is_none());
        assert!(record.fingerprint().is_none());
    }

    #[test]
    fn numeric_fingerprint_ids_are_skipped_rather_than_shown() {
        // Some releases return integer ids; showing "2 · 47" would be useless.
        let record: UnifiClientRecord =
            serde_json::from_str(r#"{"dev_vendor":2,"os_name":47,"dev_family":"Phone"}"#).unwrap();
        assert_eq!(record.fingerprint().as_deref(), Some("Phone"));
    }

    #[test]
    fn falls_back_to_hostname_when_no_alias_is_set() {
        let record: UnifiClientRecord =
            serde_json::from_str(r#"{"hostname":"esp-kitchen","name":"  "}"#).unwrap();
        assert_eq!(record.best_name().as_deref(), Some("esp-kitchen"));
    }

    #[test]
    fn describes_devices_with_and_without_a_name() {
        let named: UnifiDeviceRecord =
            serde_json::from_str(r#"{"name":"ACProSalon","model":"U7PG2","type":"uap"}"#).unwrap();
        assert_eq!(named.describe(), "ACProSalon (U7PG2)");
        assert_eq!(named.kind_label(), "Access point");

        let unnamed: UnifiDeviceRecord =
            serde_json::from_str(r#"{"model":"USMINI","type":"usw"}"#).unwrap();
        assert_eq!(unnamed.describe(), "USMINI");
        assert_eq!(unnamed.kind_label(), "Switch");
    }

    #[test]
    fn active_clients_take_precedence_over_historical_ones() {
        let mut snapshot = UnifiSnapshot::default();
        snapshot.known_clients.push(UnifiClientRecord {
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            ip: Some("10.0.3.99".into()),
            ..Default::default()
        });
        snapshot.clients.push(UnifiClientRecord {
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            ip: Some("10.0.3.50".into()),
            ..Default::default()
        });

        let index = snapshot.clients_by_mac();
        assert_eq!(
            index["aa:bb:cc:dd:ee:ff"].ip.as_deref(),
            Some("10.0.3.50"),
            "the historical record's stale IP must not win"
        );
    }

    #[test]
    fn event_times_normalize_from_milliseconds() {
        let event: UnifiEventRecord = serde_json::from_str(
            r#"{"key":"EVT_WU_Disconnected","time":1754400000000,"user":"AA-BB-CC-DD-EE-FF"}"#,
        )
        .unwrap();
        assert_eq!(event.time_seconds(), Some(1_754_400_000));
        assert!(event.is_disconnect());
        assert_eq!(
            event.client_mac(),
            Some("aa:bb:cc:dd:ee:ff"),
            "MAC normalized"
        );

        let seconds: UnifiEventRecord =
            serde_json::from_str(r#"{"key":"EVT_WU_Connected","time":1754400000}"#).unwrap();
        assert_eq!(
            seconds.time_seconds(),
            Some(1_754_400_000),
            "already-seconds passes through"
        );
        assert!(!seconds.is_disconnect());
    }

    #[test]
    fn guest_events_still_yield_a_client_mac() {
        let event: UnifiEventRecord =
            serde_json::from_str(r#"{"key":"EVT_WG_Disconnected","guest":"aa:bb:cc:dd:ee:01"}"#)
                .unwrap();
        assert_eq!(event.client_mac(), Some("aa:bb:cc:dd:ee:01"));
    }

    #[test]
    fn alarms_summarize_verbatim_and_archived_ones_vanish() {
        let active: UnifiAlarmRecord = serde_json::from_str(
            r#"{"key":"EVT_AP_Lost_Contact","msg":"AP ACProSalon was disconnected","time":1754400000000,"subsystem":"wlan"}"#,
        )
        .unwrap();
        let summary = active.summarize().unwrap();
        assert_eq!(summary.message, "AP ACProSalon was disconnected");
        assert_eq!(summary.time, Some(1_754_400_000));

        let archived: UnifiAlarmRecord =
            serde_json::from_str(r#"{"msg":"old news","archived":true}"#).unwrap();
        assert!(archived.summarize().is_none());

        // No message at all falls back to the key rather than an empty entry.
        let keyed: UnifiAlarmRecord = serde_json::from_str(r#"{"key":"EVT_SOMETHING"}"#).unwrap();
        assert_eq!(keyed.summarize().unwrap().message, "EVT_SOMETHING");
    }

    #[test]
    fn a_foreign_ap_broadcasting_our_ssid_is_an_evil_twin() {
        let records: Vec<UnifiRogueApRecord> = serde_json::from_value(serde_json::json!([
            {"essid":"ADOFULL","bssid":"aa:aa:aa:aa:aa:01","signal":-88,"security":"open"},
            {"essid":"NextDoorWifi","bssid":"bb:bb:bb:bb:bb:02","signal":-40}
        ]))
        .unwrap();
        let own: std::collections::HashSet<String> = ["ADOFULL".to_string()].into();

        let (summaries, total) = summarize_neighbor_aps(&records, &own, 30);
        assert_eq!(total, 2);
        assert!(
            summaries[0].evil_twin,
            "the twin sorts first despite weaker signal"
        );
        assert_eq!(summaries[0].ssid.as_deref(), Some("ADOFULL"));
        assert!(!summaries[1].evil_twin);
    }

    #[test]
    fn the_neighbor_cap_never_drops_an_evil_twin() {
        let mut records: Vec<UnifiRogueApRecord> = (0..40)
            .map(|i| UnifiRogueApRecord {
                essid: Some(format!("neighbor-{i}")),
                signal: Some(-30 - i),
                ..Default::default()
            })
            .collect();
        records.push(UnifiRogueApRecord {
            essid: Some("ADOFULL".into()),
            signal: Some(-90), // weakest of all — would be cut by strength alone
            ..Default::default()
        });
        let own: std::collections::HashSet<String> = ["ADOFULL".to_string()].into();

        let (summaries, total) = summarize_neighbor_aps(&records, &own, 30);
        assert_eq!(total, 41);
        assert_eq!(summaries.len(), 30, "cap holds");
        assert!(
            summaries.iter().any(|s| s.evil_twin),
            "twin survived the cut"
        );
    }

    #[test]
    fn parses_network_configs_and_canonicalizes_the_subnet() {
        // ip_subnet is the *gateway's* address; the summary must show the network.
        let record: UnifiNetworkConf = serde_json::from_str(
            r#"{"name":"IoT","purpose":"corporate","ip_subnet":"10.0.30.1/24",
                "vlan":30,"enabled":true,"dhcpd_enabled":true}"#,
        )
        .unwrap();
        let summary = UnifiNetworkSummary::from(&record);

        assert_eq!(summary.name, "IoT");
        assert_eq!(summary.subnet.as_deref(), Some("10.0.30.0/24"));
        assert_eq!(summary.vlan, Some(30));
        assert!(summary.enabled);
        assert_eq!(summary.dhcp, Some(true));
    }

    #[test]
    fn vlan_ids_parse_from_both_number_and_string_forms() {
        let number: UnifiNetworkConf = serde_json::from_str(r#"{"vlan":30}"#).unwrap();
        assert_eq!(number.vlan_id(), Some(30));

        let string: UnifiNetworkConf = serde_json::from_str(r#"{"vlan":"30"}"#).unwrap();
        assert_eq!(string.vlan_id(), Some(30), "older releases send a string");

        let junk: UnifiNetworkConf = serde_json::from_str(r#"{"vlan":"untagged"}"#).unwrap();
        assert_eq!(junk.vlan_id(), None);
    }

    #[test]
    fn a_wide_configured_subnet_survives_canonicalization() {
        // /16 is wider than the scanner would ever accept as a target, but a
        // controller may legitimately define it; it must not be mangled.
        let record: UnifiNetworkConf =
            serde_json::from_str(r#"{"name":"Big","ip_subnet":"10.20.30.1/16"}"#).unwrap();
        let summary = UnifiNetworkSummary::from(&record);
        assert_eq!(summary.subnet.as_deref(), Some("10.20.0.0/16"));
    }

    fn health(subsystem: &str, status: &str) -> UnifiHealthSummary {
        UnifiHealthSummary::from(&UnifiHealthRecord {
            subsystem: Some(subsystem.into()),
            status: Some(status.into()),
            ..Default::default()
        })
    }

    #[test]
    fn parses_a_health_record_from_controller_json() {
        let record: UnifiHealthRecord = serde_json::from_str(
            r#"{"subsystem":"www","status":"ok","latency":12.0,"xput_up":48.2,
                "xput_down":940.1,"drops":0,"uptime":86400,"unknown_field":true}"#,
        )
        .unwrap();
        let summary = UnifiHealthSummary::from(&record);

        assert_eq!(summary.subsystem, "www");
        assert_eq!(summary.status, "ok");
        assert_eq!(summary.latency_ms, Some(12.0));
        assert_eq!(summary.xput_down_mbps, Some(940.1));
    }

    #[test]
    fn a_healthy_internet_link_points_the_finger_at_the_lan() {
        let mut www = health("www", "ok");
        www.latency_ms = Some(11.6);
        let verdict = wan_triage(&[health("wan", "ok"), www]).unwrap();

        assert!(verdict.contains("healthy"));
        assert!(
            verdict.contains("12 ms"),
            "latency is rounded in: {verdict}"
        );
        assert!(verdict.contains("local network"));
    }

    #[test]
    fn a_broken_internet_link_points_upstream() {
        let mut www = health("www", "error");
        www.latency_ms = Some(340.0);
        www.drops = Some(7);
        let verdict = wan_triage(&[www]).unwrap();

        assert!(verdict.contains("upstream"));
        assert!(verdict.contains("340 ms"));
        assert!(verdict.contains("7 dropped"));
    }

    #[test]
    fn no_conclusive_health_produces_no_verdict() {
        // False reassurance is worse than silence.
        assert_eq!(wan_triage(&[]), None);
        assert_eq!(wan_triage(&[health("www", "unknown")]), None);
        assert_eq!(
            wan_triage(&[health("lan", "ok")]),
            None,
            "LAN says nothing about WAN"
        );
    }

    #[test]
    fn an_unknown_www_falls_back_to_the_wan_port_state() {
        // Uplink port down, measured check unavailable: still conclusive.
        let verdict = wan_triage(&[health("www", "unknown"), health("wan", "error")]).unwrap();
        assert!(verdict.contains("upstream"));
    }

    #[test]
    fn pre_health_snapshots_still_deserialize() {
        let old = r#"{"controllerHost":"10.0.3.12","site":"default","devices":[],"warnings":[]}"#;
        let snapshot: UnifiSnapshot = serde_json::from_str(old).unwrap();
        assert!(snapshot.health.is_empty());
        assert!(snapshot.wan_triage.is_none());
    }

    #[test]
    fn radio_protocols_map_to_wifi_generations() {
        let gen = |proto: &str| {
            UnifiClientRecord {
                radio_proto: Some(proto.into()),
                ..Default::default()
            }
            .wifi_generation()
        };

        assert_eq!(gen("ax").as_deref(), Some("Wi-Fi 6 (ax)"));
        assert_eq!(gen("ac").as_deref(), Some("Wi-Fi 5 (ac)"));
        assert_eq!(gen("ng").as_deref(), Some("Wi-Fi 4 (n)"));
        assert_eq!(gen("na").as_deref(), Some("Wi-Fi 4 (n)"));
        assert_eq!(gen("be").as_deref(), Some("Wi-Fi 7 (be)"));
        assert_eq!(gen("g").as_deref(), Some("802.11g"));
        // A future protocol must pass through raw, not vanish.
        assert_eq!(gen("xy").as_deref(), Some("xy"));
        assert_eq!(gen("  ").as_deref(), None);
        assert_eq!(UnifiClientRecord::default().wifi_generation(), None);
    }

    #[test]
    fn poe_power_is_read_from_number_and_string_forms() {
        let watts = |raw: &str| -> Option<f64> {
            let port: PortEntry =
                serde_json::from_str(&format!(r#"{{"poe_power":{raw}}}"#)).unwrap();
            port.poe_watts()
        };

        assert_eq!(watts("6.5"), Some(6.5));
        assert_eq!(watts(r#""6.5""#), Some(6.5), "some releases send a string");
        assert_eq!(watts(r#""not a number""#), None);
        assert_eq!(PortEntry::default().poe_watts(), None);
    }

    #[test]
    fn abnormal_states_are_labelled_and_normal_ones_are_not() {
        let device = |state: i64, adopted: bool| -> UnifiDeviceRecord {
            serde_json::from_str(&format!(r#"{{"state":{state},"adopted":{adopted}}}"#)).unwrap()
        };

        assert_eq!(device(1, true).state_problem(), None, "connected is normal");
        assert_eq!(
            device(6, true).state_problem().as_deref(),
            Some("Heartbeat missed")
        );
        assert_eq!(
            device(0, true).state_problem().as_deref(),
            Some("Disconnected")
        );
        assert_eq!(
            device(42, true).state_problem().as_deref(),
            Some("State 42"),
            "unknown states surface rather than hide"
        );
        assert_eq!(
            device(0, false).state_problem(),
            None,
            "unadopted devices already carry their own badge"
        );
    }

    #[test]
    fn summaries_carry_ports_and_state() {
        let device: UnifiDeviceRecord = serde_json::from_str(
            r#"{"name":"USW_MINI","model":"USMINI","type":"usw","adopted":true,"state":6,
                "port_table":[
                    {"port_idx":1,"name":"Camera","up":true,"speed":100,"poe_power":"4.2"},
                    {"port_idx":2,"up":false},
                    {"name":"no index — dropped"}
                ]}"#,
        )
        .unwrap();

        let summary = UnifiDeviceSummary::from(&device);
        assert_eq!(summary.state_label.as_deref(), Some("Heartbeat missed"));
        assert_eq!(summary.ports.len(), 2, "a port without an index is useless");
        assert_eq!(summary.ports[0].speed_mbps, Some(100));
        assert_eq!(summary.ports[0].poe_watts, Some(4.2));
        assert!(!summary.ports[1].up);
        assert_eq!(summary.ports[1].speed_mbps, None);
    }

    #[test]
    fn pre_port_summaries_still_deserialize() {
        // A stored 1.1.0 snapshot has no stateLabel/ports keys.
        let old = r#"{"mac":null,"ip":null,"name":"AP","kind":"Access point",
                      "model":null,"version":null,"adopted":true,"upgradable":false,
                      "uptimeSeconds":null}"#;
        let summary: UnifiDeviceSummary = serde_json::from_str(old).unwrap();
        assert!(summary.ports.is_empty());
        assert!(summary.state_label.is_none());
    }

    #[test]
    fn a_slow_port_on_a_gigabit_switch_is_degraded() {
        let switch: UnifiDeviceRecord = serde_json::from_str(
            r#"{"name":"USW","model":"US8","type":"usw","port_table":[
                {"port_idx":1,"up":true,"speed":1000},
                {"port_idx":2,"name":"Study","up":true,"speed":100},
                {"port_idx":3,"up":false,"speed":0},
                {"port_idx":4,"up":true,"speed":10}
            ]}"#,
        )
        .unwrap();

        let snapshot = UnifiSnapshot {
            raw_devices: vec![switch],
            ..Default::default()
        };
        let degraded = snapshot.degraded_link_ports();

        assert_eq!(degraded.len(), 2, "down ports are not degraded, just off");
        assert_eq!(degraded[0].port, 2);
        assert_eq!(degraded[0].speed_mbps, 100);
        assert_eq!(degraded[0].fastest_mbps, 1000);
        assert_eq!(degraded[1].port, 4);
    }

    #[test]
    fn an_all_fast_ethernet_switch_has_no_degraded_links() {
        // Nothing proves this hardware can do better, so nothing is a finding.
        let switch: UnifiDeviceRecord = serde_json::from_str(
            r#"{"name":"OldSwitch","type":"usw","port_table":[
                {"port_idx":1,"up":true,"speed":100},
                {"port_idx":2,"up":true,"speed":100}
            ]}"#,
        )
        .unwrap();

        let snapshot = UnifiSnapshot {
            raw_devices: vec![switch],
            ..Default::default()
        };
        assert!(snapshot.degraded_link_ports().is_empty());
    }

    #[test]
    fn detects_ports_hiding_an_unmanaged_switch() {
        let device: UnifiDeviceRecord = serde_json::from_str(
            r#"{"name":"USW_MINI","model":"USMINI","type":"usw","port_table":[
                {"port_idx":1,"mac_table":[{"mac":"aa:aa:aa:aa:aa:aa"}]},
                {"port_idx":4,"name":"Office","mac_table":[
                    {"mac":"bb:bb:bb:bb:bb:bb"},{"mac":"cc:cc:cc:cc:cc:cc"},{"mac":"dd:dd:dd:dd:dd:dd"}]}
            ]}"#,
        )
        .unwrap();

        let snapshot = UnifiSnapshot {
            raw_devices: vec![device],
            ..Default::default()
        };
        let crowded = snapshot.crowded_ports();

        assert_eq!(crowded.len(), 1, "only the multi-MAC port is notable");
        assert_eq!(crowded[0].port, 4);
        assert_eq!(crowded[0].macs.len(), 3);
        assert_eq!(crowded[0].port_name.as_deref(), Some("Office"));
    }
}
