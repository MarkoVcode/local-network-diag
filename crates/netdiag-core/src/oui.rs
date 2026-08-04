//! MAC → vendor lookup against the bundled IEEE registries.
//!
//! The table is embedded in the binary so the app identifies hardware with no
//! network access at all — which matters for a diagnostic tool, since it is
//! often run precisely when the internet is broken.

use crate::netutil::{is_locally_administered, is_meaningless_mac, normalize_mac};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

const OUI_JSON: &str = include_str!("../data/oui.json");

#[derive(Deserialize)]
struct OuiData {
    #[serde(default, rename = "generatedAt")]
    generated_at: String,
    /// 24-bit prefixes (6 hex chars).
    #[serde(default)]
    mal: HashMap<String, String>,
    /// 28-bit prefixes (7 hex chars).
    #[serde(default)]
    mam: HashMap<String, String>,
    /// 36-bit prefixes (9 hex chars).
    #[serde(default)]
    mas: HashMap<String, String>,
}

static TABLE: OnceLock<OuiData> = OnceLock::new();

fn table() -> &'static OuiData {
    TABLE.get_or_init(|| {
        serde_json::from_str(OUI_JSON).unwrap_or(OuiData {
            generated_at: String::new(),
            mal: HashMap::new(),
            mam: HashMap::new(),
            mas: HashMap::new(),
        })
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VendorLookup {
    pub vendor: Option<String>,
    pub randomized: bool,
}

/// Resolves a vendor, trying the most specific registry first (36 → 28 → 24 bit).
///
/// Locally-administered MACs short-circuit: those bits are chosen by the device
/// rather than assigned by IEEE, so any prefix "match" would be a coincidence.
pub fn lookup_vendor(mac: Option<&str>) -> VendorLookup {
    let Some(mac) = mac else {
        return VendorLookup::default();
    };

    if is_meaningless_mac(mac) {
        return VendorLookup::default();
    }

    if is_locally_administered(mac) {
        return VendorLookup {
            vendor: None,
            randomized: true,
        };
    }

    let hex: String = normalize_mac(mac)
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_uppercase();

    if hex.len() < 6 {
        return VendorLookup::default();
    }

    let data = table();
    let vendor = data
        .mas
        .get(&hex[..9.min(hex.len())])
        .or_else(|| data.mam.get(&hex[..7.min(hex.len())]))
        .or_else(|| data.mal.get(&hex[..6]))
        .cloned();

    VendorLookup {
        vendor,
        randomized: false,
    }
}

pub struct OuiTableInfo {
    pub generated_at: String,
    pub prefixes: usize,
}

pub fn table_info() -> OuiTableInfo {
    let data = table();
    OuiTableInfo {
        generated_at: data.generated_at.clone(),
        prefixes: data.mal.len() + data.mam.len() + data.mas.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_known_vendors_from_the_reference_network() {
        assert_eq!(
            lookup_vendor(Some("e0:63:da:82:1b:35")).vendor.as_deref(),
            Some("Ubiquiti")
        );
        assert_eq!(
            lookup_vendor(Some("24:62:ab:e4:5f:a4")).vendor.as_deref(),
            Some("Espressif")
        );
        assert_eq!(
            lookup_vendor(Some("3c:58:c2:52:29:84")).vendor.as_deref(),
            Some("Intel Corporate")
        );
    }

    #[test]
    fn flags_randomized_macs_instead_of_guessing_a_vendor() {
        let result = lookup_vendor(Some("f6:10:04:1c:20:08"));
        assert!(result.randomized);
        assert!(
            result.vendor.is_none(),
            "a randomized MAC must never report a vendor"
        );
    }

    #[test]
    fn ignores_meaningless_macs() {
        assert_eq!(
            lookup_vendor(Some("00:00:00:00:00:00")),
            VendorLookup::default()
        );
        assert_eq!(lookup_vendor(None), VendorLookup::default());
    }

    #[test]
    fn table_is_populated() {
        assert!(table_info().prefixes > 50_000, "OUI table looks truncated");
    }
}
