//! Update check against GitHub Releases.
//!
//! Two constraints shape this more than anything else:
//!
//! * **This is a network diagnostic tool.** It is frequently launched precisely
//!   when the internet is broken. A failed check must be invisible — never an
//!   error, never a delay, never a blocked window.
//! * **The unauthenticated GitHub API allows 60 requests per hour per IP.** The
//!   result is cached, so relaunching the app repeatedly cannot exhaust that and
//!   start getting rate-limited answers.
//!
//! The request is made from Rust rather than the webview deliberately: the
//! webview runs under a strict CSP with no network permissions, and adding an
//! exception for api.github.com would widen that for everything.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

const RELEASES_API: &str =
    "https://api.github.com/repos/MarkoVcode/local-network-diag/releases/latest";
const RELEASES_PAGE: &str = "https://github.com/MarkoVcode/local-network-diag/releases/latest";

/// How long a result is reused before asking GitHub again.
const CACHE_TTL_HOURS: i64 = 6;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePreferences {
    /// Master switch. The check is opt-out rather than opt-in, but it must be
    /// possible to turn off entirely for an air-gapped install.
    #[serde(default = "default_true")]
    pub check_enabled: bool,
    /// A version the user chose to skip; never prompt for this one again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped_version: Option<String>,
    /// RFC3339 timestamp of the last successful check, for the cache TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked: Option<String>,
    /// Last result, reused inside the TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_latest: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Written by hand rather than derived.
///
/// `#[derive(Default)]` would give `check_enabled: false`, contradicting the
/// serde default of `true` — so a struct built in code would silently disable
/// update checks while one parsed from an empty file enabled them.
impl Default for UpdatePreferences {
    fn default() -> Self {
        Self {
            check_enabled: true,
            skipped_version: None,
            last_checked: None,
            cached_latest: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: String,
    /// True only when `latest` is genuinely newer *and* not skipped.
    pub update_available: bool,
    pub release_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
}

#[derive(Deserialize)]
struct GithubRelease {
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

impl UpdatePreferences {
    pub fn path(root: &Path) -> PathBuf {
        root.join("update-preferences.json")
    }

    pub async fn load(root: &Path) -> Self {
        match tokio::fs::read(Self::path(root)).await {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            // A missing or corrupt file must not disable the feature.
            Err(_) => Self::default(),
        }
    }

    pub async fn save(&self, root: &Path) -> Result<(), String> {
        tokio::fs::create_dir_all(root)
            .await
            .map_err(|e| e.to_string())?;
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        tokio::fs::write(Self::path(root), json)
            .await
            .map_err(|e| e.to_string())
    }

    fn cache_is_fresh(&self) -> bool {
        let Some(last) = &self.last_checked else {
            return false;
        };
        let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(last) else {
            return false;
        };
        chrono::Utc::now()
            .signed_duration_since(parsed.with_timezone(&chrono::Utc))
            .num_hours()
            < CACHE_TTL_HOURS
    }
}

/// A semantic version, compared numerically.
///
/// String comparison is wrong in a way that only shows up later: `"1.10.0"`
/// sorts before `"1.9.0"` lexically, so the tenth minor release would silently
/// stop offering updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    major: u32,
    minor: u32,
    patch: u32,
}

impl Version {
    pub fn parse(text: &str) -> Option<Self> {
        let cleaned = text.trim().trim_start_matches(['v', 'V']);
        // Discard any pre-release or build suffix: 1.2.3-beta.1+abc.
        let core = cleaned.split(['-', '+']).next().unwrap_or(cleaned);

        let mut parts = core.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next().unwrap_or("0").parse().unwrap_or(0);
        let patch = parts.next().unwrap_or("0").parse().unwrap_or(0);

        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

/// Fetches the latest release. Returns `None` on any failure — offline, rate
/// limited, malformed, anything. The caller cannot distinguish, and should not:
/// there is nothing useful to tell the user about a failed update check.
async fn fetch_latest() -> Option<GithubRelease> {
    let response = crate::scan::http::get_text_public(
        RELEASES_API,
        Duration::from_secs(8),
        512 * 1024,
        &[("Accept", "application/vnd.github+json")],
    )
    .await
    .ok()?;

    let release: GithubRelease = serde_json::from_str(&response).ok()?;

    // `/releases/latest` already excludes drafts and prereleases, but a redirect
    // or an API change should not surprise us into offering one.
    if release.draft || release.prerelease || release.tag_name.is_empty() {
        return None;
    }

    Some(release)
}

/// Checks for a newer release, honouring preferences and the cache.
///
/// `force` bypasses both, for an explicit "check now" button.
pub async fn check(root: &Path, force: bool) -> Option<UpdateInfo> {
    let mut prefs = UpdatePreferences::load(root).await;

    if !prefs.check_enabled && !force {
        return None;
    }

    let current = Version::parse(crate::VERSION)?;

    // Serve from cache when fresh, so relaunching does not spend rate limit.
    if !force && prefs.cache_is_fresh() {
        let cached = prefs.cached_latest.clone()?;
        return build_info(&prefs, current, &cached, RELEASES_PAGE, None, None);
    }

    let release = fetch_latest().await?;

    prefs.last_checked = Some(chrono::Utc::now().to_rfc3339());
    prefs.cached_latest = Some(release.tag_name.clone());
    let _ = prefs.save(root).await;

    build_info(
        &prefs,
        current,
        &release.tag_name,
        &release.html_url,
        release.body,
        release.published_at,
    )
}

fn build_info(
    prefs: &UpdatePreferences,
    current: Version,
    latest_tag: &str,
    url: &str,
    notes: Option<String>,
    published_at: Option<String>,
) -> Option<UpdateInfo> {
    let latest = Version::parse(latest_tag)?;

    let skipped = prefs
        .skipped_version
        .as_deref()
        .map(|v| v.trim_start_matches(['v', 'V']) == latest_tag.trim_start_matches(['v', 'V']))
        .unwrap_or(false);

    Some(UpdateInfo {
        current_version: crate::VERSION.to_string(),
        latest_version: latest_tag.trim_start_matches(['v', 'V']).to_string(),
        update_available: latest > current && !skipped,
        release_url: if url.is_empty() {
            RELEASES_PAGE.to_string()
        } else {
            url.to_string()
        },
        // Release notes can be long; the popup shows a summary, not a novel.
        release_notes: notes.map(|body| truncate_notes(&body)),
        published_at,
    })
}

fn truncate_notes(body: &str) -> String {
    const MAX: usize = 1200;
    let trimmed = body.trim();
    if trimmed.chars().count() <= MAX {
        return trimmed.to_string();
    }
    let mut out: String = trimmed.chars().take(MAX).collect();
    out.push_str("\n\n…");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_versions_numerically_not_lexically() {
        let v = |s: &str| Version::parse(s).unwrap();

        // The failure this guards: "1.10.0" < "1.9.0" as strings.
        assert!(v("1.10.0") > v("1.9.0"));
        assert!(v("2.0.0") > v("1.99.99"));
        assert!(v("1.0.1") > v("1.0.0"));
        assert_eq!(v("1.0.0"), v("1.0.0"));
    }

    #[test]
    fn accepts_the_tag_formats_github_actually_returns() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert_eq!(v("v1.2.3"), v("1.2.3"));
        assert_eq!(v("V1.2.3"), v("1.2.3"));
        assert_eq!(v(" 1.2.3 "), v("1.2.3"));
        // Short and suffixed forms should not be fatal.
        assert_eq!(v("1.2"), v("1.2.0"));
        assert_eq!(v("1.2.3-beta.1"), v("1.2.3"));
        assert_eq!(v("1.2.3+build7"), v("1.2.3"));
    }

    #[test]
    fn rejects_junk_rather_than_guessing() {
        assert!(Version::parse("").is_none());
        assert!(Version::parse("not-a-version").is_none());
        assert!(Version::parse("latest").is_none());
    }

    #[test]
    fn an_equal_or_older_release_is_not_an_update() {
        let prefs = UpdatePreferences::default();
        let current = Version::parse("1.0.0").unwrap();

        let same = build_info(&prefs, current, "v1.0.0", "u", None, None).unwrap();
        assert!(!same.update_available);

        let older = build_info(&prefs, current, "v0.9.0", "u", None, None).unwrap();
        assert!(!older.update_available);

        let newer = build_info(&prefs, current, "v1.1.0", "u", None, None).unwrap();
        assert!(newer.update_available);
        assert_eq!(
            newer.latest_version, "1.1.0",
            "the v prefix is stripped for display"
        );
    }

    #[test]
    fn a_skipped_version_stops_prompting_but_still_reports() {
        let prefs = UpdatePreferences {
            skipped_version: Some("1.1.0".into()),
            ..Default::default()
        };
        let info = build_info(
            &prefs,
            Version::parse("1.0.0").unwrap(),
            "v1.1.0",
            "u",
            None,
            None,
        )
        .unwrap();

        assert!(!info.update_available, "the user asked not to be prompted");
        assert_eq!(
            info.latest_version, "1.1.0",
            "but the version is still known"
        );

        // Skipping 1.1.0 must not suppress 1.2.0.
        let next = build_info(
            &prefs,
            Version::parse("1.0.0").unwrap(),
            "v1.2.0",
            "u",
            None,
            None,
        )
        .unwrap();
        assert!(next.update_available);
    }

    #[test]
    fn cache_freshness_respects_the_ttl() {
        let mut prefs = UpdatePreferences::default();
        assert!(!prefs.cache_is_fresh(), "never checked");

        prefs.last_checked = Some(chrono::Utc::now().to_rfc3339());
        assert!(prefs.cache_is_fresh());

        prefs.last_checked =
            Some((chrono::Utc::now() - chrono::Duration::hours(CACHE_TTL_HOURS + 1)).to_rfc3339());
        assert!(!prefs.cache_is_fresh());

        prefs.last_checked = Some("not a timestamp".into());
        assert!(
            !prefs.cache_is_fresh(),
            "corrupt state must re-check, not trust"
        );
    }

    #[test]
    fn release_notes_are_truncated_for_a_popup() {
        let short = truncate_notes("  Fixed a thing.  ");
        assert_eq!(short, "Fixed a thing.");

        let long = truncate_notes(&"x".repeat(5000));
        assert!(long.chars().count() < 1300);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn preferences_default_to_checking_enabled() {
        assert!(UpdatePreferences::default().check_enabled);
        let parsed: UpdatePreferences = serde_json::from_str("{}").unwrap();
        assert!(
            parsed.check_enabled,
            "an empty file must not silently disable checks"
        );
    }
}
