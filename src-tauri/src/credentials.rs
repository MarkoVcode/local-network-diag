//! Credential storage in the OS keychain.
//!
//! Lives in the desktop layer rather than `netdiag-core` on purpose. The keyring
//! crate pulls in libdbus on Linux, and the engine crate's value is that it
//! builds and its tests run with no system dependencies — which is what lets CI
//! validate the per-OS scan logic cheaply on all three platforms.
//!
//! The engine therefore never reads a password; it is handed one.

use netdiag_core::unifi::UnifiConfig;

const SERVICE: &str = "dev.localnetdiag.app";

fn entry(config: &UnifiConfig) -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, &config.credential_id())
        .map_err(|e| format!("keychain unavailable: {e}"))
}

pub fn store(config: &UnifiConfig, password: &str) -> Result<(), String> {
    entry(config)?
        .set_password(password)
        .map_err(|e| format!("could not store password: {e}"))
}

pub fn load(config: &UnifiConfig) -> Result<String, String> {
    entry(config)?.get_password().map_err(|e| match e {
        keyring::Error::NoEntry => {
            "No password stored for this controller — re-enter it in Setup & Status".to_string()
        }
        other => format!("could not read password: {other}"),
    })
}

pub fn clear(config: &UnifiConfig) -> Result<(), String> {
    match entry(config)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(other) => Err(format!("could not clear password: {other}")),
    }
}
