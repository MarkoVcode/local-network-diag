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
}

/// Everything fetched from the controller in one pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiSnapshot {
    pub controller_host: String,
    pub site: String,
    /// Managed infrastructure, keyed for display.
    pub devices: Vec<UnifiDeviceSummary>,
    /// Non-fatal problems — an endpoint this account cannot read, say.
    pub warnings: Vec<String>,
    #[serde(skip, default)]
    pub clients: Vec<UnifiClientRecord>,
    #[serde(skip, default)]
    pub known_clients: Vec<UnifiClientRecord>,
    #[serde(skip, default)]
    pub raw_devices: Vec<UnifiDeviceRecord>,
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
}

impl From<&UnifiDeviceRecord> for UnifiDeviceSummary {
    fn from(record: &UnifiDeviceRecord) -> Self {
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrowdedPort {
    pub switch_name: String,
    pub port: u32,
    pub port_name: Option<String>,
    pub macs: Vec<String>,
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
