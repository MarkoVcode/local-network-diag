//! UniFi connection settings.
//!
//! Settings (host, site, username, pinned fingerprint) live in a plain JSON file
//! alongside the snapshots. The **password never does** — the desktop layer puts
//! it in the OS keychain, and passes it in when a connection is made.
//!
//! Keychain access lives in `src-tauri` rather than here on purpose: the crate
//! that provides it pulls in libdbus on Linux, and this crate's usefulness rests
//! on building and testing with no system dependencies.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiConfig {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_site")]
    pub site: String,
    pub username: String,
    /// SHA-256 of the controller certificate, pinned on first connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_port() -> u16 {
    443
}
fn default_site() -> String {
    "default".to_string()
}
fn default_enabled() -> bool {
    true
}

impl Default for UnifiConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: default_port(),
            site: default_site(),
            username: String::new(),
            fingerprint: None,
            enabled: false,
        }
    }
}

impl UnifiConfig {
    pub fn is_configured(&self) -> bool {
        self.enabled && !self.host.trim().is_empty() && !self.username.trim().is_empty()
    }

    /// Stable identifier for this controller's credential, used as the keychain
    /// account name by the desktop layer. Per host+user so several coexist.
    pub fn credential_id(&self) -> String {
        format!("unifi:{}@{}", self.username, self.host)
    }

    pub fn config_path(root: &Path) -> PathBuf {
        root.join("unifi.json")
    }

    pub async fn load(root: &Path) -> Option<Self> {
        let bytes = tokio::fs::read(Self::config_path(root)).await.ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub async fn save(&self, root: &Path) -> Result<(), String> {
        tokio::fs::create_dir_all(root)
            .await
            .map_err(|e| e.to_string())?;
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        tokio::fs::write(Self::config_path(root), json)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn delete(root: &Path) -> Result<(), String> {
        match tokio::fs::remove_file(Self::config_path(root)).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.to_string()),
        }
    }
}

/// Strips anything secret from text before it reaches a log or the UI.
///
/// Errors from the HTTP layer can quote a request, and a login request contains
/// the password. This is the last line of defence rather than the first — the
/// client never logs bodies — but the cost of being wrong is high enough to
/// justify both.
pub fn redact(text: &str) -> String {
    const KEYS: &[&str] = &["password", "x-csrf-token", "csrf_token", "cookie", "token"];

    let mut out = String::with_capacity(text.len());
    let lowered = text.to_ascii_lowercase();
    let bytes = text.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        let matched = KEYS
            .iter()
            .find(|key| lowered[index..].starts_with(**key))
            .copied();

        let Some(key) = matched else {
            let ch = text[index..]
                .chars()
                .next()
                .expect("index is on a boundary");
            out.push(ch);
            index += ch.len_utf8();
            continue;
        };

        out.push_str(&text[index..index + key.len()]);
        let mut cursor = index + key.len();

        // Skip a closing quote on the key itself, then whitespace, then the
        // delimiter, then whitespace again: `"password": "secret"`.
        let copy_through =
            |cursor: &mut usize, out: &mut String, predicate: &dyn Fn(u8) -> bool| {
                while *cursor < bytes.len() && predicate(bytes[*cursor]) {
                    out.push(bytes[*cursor] as char);
                    *cursor += 1;
                }
            };

        copy_through(&mut cursor, &mut out, &|b| b == b'"' || b == b' ');
        if cursor >= bytes.len() || !matches!(bytes[cursor], b':' | b'=') {
            // Not a key/value pair — the word appeared in prose.
            index = cursor;
            continue;
        }
        out.push(bytes[cursor] as char);
        cursor += 1;
        copy_through(&mut cursor, &mut out, &|b| b == b' ');

        // The value is either quoted or runs to the next separator. Skipping the
        // opening quote matters: scanning for a terminator without doing so
        // finds that very quote and redacts nothing.
        let quoted = cursor < bytes.len() && bytes[cursor] == b'"';
        if quoted {
            out.push('"');
            cursor += 1;
        }

        let end = if quoted {
            text[cursor..]
                .find('"')
                .map(|i| cursor + i)
                .unwrap_or(bytes.len())
        } else {
            text[cursor..]
                .find([',', ';', '}', '\n', ' '])
                .map(|i| cursor + i)
                .unwrap_or(bytes.len())
        };

        if end > cursor {
            out.push_str("«redacted»");
        }
        index = end;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_without_host_or_user_is_not_configured() {
        assert!(!UnifiConfig::default().is_configured());

        let mut config = UnifiConfig {
            host: "10.0.3.12".into(),
            username: "viewer".into(),
            enabled: true,
            ..Default::default()
        };
        assert!(config.is_configured());

        config.enabled = false;
        assert!(!config.is_configured(), "disabled means do not contact it");
    }

    #[test]
    fn serialized_config_never_contains_a_password_field() {
        let config = UnifiConfig {
            host: "10.0.3.12".into(),
            username: "viewer".into(),
            fingerprint: Some("AA:BB".into()),
            enabled: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.to_lowercase().contains("password"));
        assert!(json.contains("AA:BB"), "the pin must persist");
    }

    #[test]
    fn keyring_accounts_are_scoped_per_host_and_user() {
        let a = UnifiConfig {
            host: "10.0.3.12".into(),
            username: "viewer".into(),
            ..Default::default()
        };
        let b = UnifiConfig {
            host: "10.0.4.12".into(),
            username: "viewer".into(),
            ..Default::default()
        };
        assert_ne!(a.credential_id(), b.credential_id());
    }

    #[test]
    fn redacts_secrets_from_diagnostic_text() {
        let text = r#"{"username":"viewer","password":"hunter2","remember":false}"#;
        let clean = redact(text);
        assert!(!clean.contains("hunter2"), "password leaked: {clean}");
        assert!(
            clean.contains("viewer"),
            "non-secret context should survive"
        );

        let header = "Cookie: TOKEN=abc123; Path=/";
        assert!(!redact(header).contains("abc123"));
    }

    #[test]
    fn redaction_terminates_on_pathological_input() {
        // Guard against the scanning loop failing to advance.
        let _ = redact(&"password".repeat(200));
        let _ = redact("password:");
        let _ = redact("password=");
    }
}
