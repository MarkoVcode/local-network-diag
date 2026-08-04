//! UniFi controller integration.
//!
//! Read-only. The client issues GETs plus the login/logout pair and nothing
//! else, so a compromised or misconfigured deployment cannot alter the network.
//!
//! What this adds over the scanner alone is covered in
//! [`crate::unifi::correlate`]: the controller knows physical topology,
//! continuous history and configured intent, none of which can be observed from
//! a single host doing port scans.

pub mod client;
pub mod config;
pub mod correlate;
pub mod model;

pub use client::{Established, Flavour, UnifiClient, UnifiError};
pub use config::UnifiConfig;
pub use model::{UnifiClientRecord, UnifiDeviceRecord, UnifiSnapshot};

/// Endpoints fetched in a Phase 1 pass, with the label used if one fails.
const ENDPOINTS: &[(&str, &str)] = &[
    ("stat/sta", "active clients"),
    ("stat/device", "managed devices"),
    ("stat/alluser", "known clients"),
];

/// Signs in, fetches everything, signs out.
///
/// A failure on any single endpoint becomes a warning rather than an error: an
/// account restricted from one collection should still deliver the rest, in
/// keeping with the degrade-never-fail rule the scanner follows everywhere else.
pub async fn fetch(config: &UnifiConfig, password: &str) -> Result<UnifiSnapshot, UnifiError> {
    let mut client = UnifiClient::new(&config.host, config.port, config.fingerprint.clone())?;
    let established = client.login(&config.username, password).await?;

    let mut snapshot = UnifiSnapshot {
        controller_host: config.host.clone(),
        site: config.site.clone(),
        ..Default::default()
    };

    if established.newly_pinned {
        snapshot.warnings.push(format!(
            "Trusted this controller's certificate for the first time ({}). \
             Future connections are checked against it.",
            established.fingerprint
        ));
    }

    for (endpoint, label) in ENDPOINTS {
        match client.get_data(&config.site, endpoint).await {
            Ok(value) => match *endpoint {
                "stat/sta" => snapshot.clients = parse_list(value),
                "stat/alluser" => snapshot.known_clients = parse_list(value),
                "stat/device" => {
                    let devices: Vec<model::UnifiDeviceRecord> = parse_list(value);
                    snapshot.devices = devices.iter().map(Into::into).collect();
                    snapshot.raw_devices = devices;
                }
                _ => {}
            },
            Err(error) => snapshot
                .warnings
                .push(format!("Could not read {label}: {error}")),
        }
    }

    client.logout().await;

    // Losing every collection means the credentials work but the account can see
    // nothing — worth surfacing as an error rather than an empty success.
    if snapshot.clients.is_empty()
        && snapshot.known_clients.is_empty()
        && snapshot.raw_devices.is_empty()
        && !snapshot.warnings.is_empty()
    {
        return Err(UnifiError::Forbidden);
    }

    Ok(snapshot)
}

/// Deserializes an array, skipping entries that fail rather than the whole set.
fn parse_list<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Vec<T> {
    let serde_json::Value::Array(items) = value else {
        return Vec::new();
    };
    items
        .into_iter()
        .filter_map(|item| serde_json::from_value(item).ok())
        .collect()
}

/// Confirms the controller is reachable, pinned and readable. Used by the doctor
/// and by the "Test connection" button.
pub async fn verify(config: &UnifiConfig, password: &str) -> Result<VerifyReport, UnifiError> {
    let mut client = UnifiClient::new(&config.host, config.port, config.fingerprint.clone())?;
    let established = client.login(&config.username, password).await?;

    let clients = client.get_data(&config.site, "stat/sta").await?;
    let count = clients.as_array().map(|a| a.len()).unwrap_or(0);

    client.logout().await;

    Ok(VerifyReport {
        flavour: established.flavour,
        fingerprint: established.fingerprint,
        newly_pinned: established.newly_pinned,
        client_count: count,
    })
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub flavour: Flavour,
    pub fingerprint: String,
    pub newly_pinned: bool,
    pub client_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_malformed_entry_does_not_discard_the_rest() {
        let value = serde_json::json!([
            {"mac":"aa:bb:cc:dd:ee:ff","ip":"10.0.3.5"},
            "not an object",
            {"mac":"11:22:33:44:55:66","ip":"10.0.3.6"}
        ]);
        let records: Vec<model::UnifiClientRecord> = parse_list(value);
        assert_eq!(
            records.len(),
            2,
            "one bad entry must not lose the good ones"
        );
    }

    #[test]
    fn a_non_array_payload_yields_nothing_rather_than_panicking() {
        let records: Vec<model::UnifiClientRecord> = parse_list(serde_json::json!({"rc":"ok"}));
        assert!(records.is_empty());
    }
}
