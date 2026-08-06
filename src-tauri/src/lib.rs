//! Tauri desktop shell.
//!
//! This layer is intentionally thin: it owns window/app lifecycle, scan state and
//! the auto-repeat timer, and forwards everything else to `netdiag-core`. All the
//! logic worth testing lives in the core crate, which builds without any GUI
//! toolchain.

mod credentials;

use netdiag_core::{
    doctor::{self, DoctorReport},
    netutil,
    networks::{self, Detection, NetworkIndex, NetworkProfile},
    scan,
    store::{self, Store},
    types::*,
    unifi::{self, UnifiConfig},
    update::{self, UpdateInfo, UpdatePreferences},
    ScanHandle,
};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;

/// Channel the frontend listens on for live scan progress.
const PROGRESS_EVENT: &str = "scan://progress";

#[derive(Default)]
struct AutoRepeat {
    enabled: bool,
    interval_minutes: u64,
    /// When the next automatic run is due. A single supervisor task watches this
    /// value rather than each run arming the next one — recursive re-arming made
    /// `execute_scan` and the scheduler mutually recursive, which is both harder
    /// to reason about and impossible for the compiler to prove `Send`.
    next_run_at: Option<chrono::DateTime<chrono::Utc>>,
}

struct AppState {
    /// Root of all application data. Each network owns a subdirectory beneath it.
    settings_root: std::path::PathBuf,
    /// Which network's history is being read and written. Everything
    /// network-scoped resolves through this, so switching is a single change
    /// rather than a cache to invalidate in several places.
    active_network: Mutex<Option<String>>,
    running: Mutex<Option<ScanHandle>>,
    phases: Mutex<Vec<PhaseState>>,
    auto_repeat: Mutex<AutoRepeat>,
    last_snapshot_id: Mutex<Option<String>>,
}

impl AppState {
    fn settings_root(&self) -> &std::path::Path {
        &self.settings_root
    }

    /// Snapshot store for the active network.
    ///
    /// Built on demand rather than cached: a stale store after a switch would
    /// write one network's scans into another's history, which is the exact
    /// failure this feature exists to prevent.
    async fn store(&self) -> Store {
        let id = self.active_network.lock().await.clone();
        match id {
            Some(id) => Store::new(NetworkIndex::scans_dir(&self.settings_root, &id)),
            // No network selected yet — a scratch location that is never shown.
            None => Store::new(self.settings_root.join("unassigned")),
        }
    }

    /// Directory holding the active network's settings (UniFi, etc.).
    async fn network_root(&self) -> std::path::PathBuf {
        match self.active_network.lock().await.clone() {
            Some(id) => NetworkIndex::network_dir(&self.settings_root, &id),
            None => self.settings_root.clone(),
        }
    }

    fn new(settings_root: std::path::PathBuf) -> Self {
        Self {
            settings_root,
            active_network: Mutex::new(None),
            running: Mutex::new(None),
            phases: Mutex::new(Vec::new()),
            auto_repeat: Mutex::new(AutoRepeat {
                interval_minutes: 15,
                ..Default::default()
            }),
            last_snapshot_id: Mutex::new(None),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AutoRepeatState {
    enabled: bool,
    interval_minutes: u64,
    next_run_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanStatus {
    running: bool,
    phases: Vec<PhaseState>,
    last_snapshot_id: Option<String>,
    auto_repeat: AutoRepeatState,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotWithDiff {
    snapshot: ScanSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<ScanDiff>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ScanRequest {
    #[serde(default)]
    extra_ranges: Vec<String>,
    #[serde(default)]
    port_profile: Option<PortProfile>,
    #[serde(default)]
    include_discovered_subnets: Option<bool>,
}

/* -------------------------------------------------------------------- helpers */

async fn current_auto_repeat(state: &AppState) -> AutoRepeatState {
    let guard = state.auto_repeat.lock().await;
    AutoRepeatState {
        enabled: guard.enabled,
        interval_minutes: guard.interval_minutes,
        next_run_at: guard.next_run_at.map(|at| at.to_rfc3339()),
    }
}

/// Moves the next automatic run one interval into the future.
async fn arm_next_run(state: &AppState) {
    let mut guard = state.auto_repeat.lock().await;
    if !guard.enabled {
        guard.next_run_at = None;
        return;
    }
    let minutes = guard.interval_minutes.clamp(1, 1440) as i64;
    guard.next_run_at = Some(chrono::Utc::now() + chrono::Duration::minutes(minutes));
}

/// Files the scan under the network the machine is actually on.
///
/// The dropdown selects which history is *viewed*; where a scan is *written*
/// must follow the physical network, or two sites' results end up mixed in one
/// history — the exact failure the per-network split exists to prevent. A
/// definitive or strong match to another saved network switches to it; an
/// unrecognised network gets a profile created for it. Only the genuinely
/// ambiguous case (subnet-only match to the selected network) stays put,
/// because there the evidence cannot tell sites apart.
///
/// Returns warnings to attach to the snapshot so the decision is visible.
async fn route_scan_to_network(
    app: &AppHandle,
    state: &AppState,
    extra_ranges: &[String],
) -> Vec<String> {
    let root = state.settings_root();
    let mut index = NetworkIndex::load(root).await;
    index.active = state
        .active_network
        .lock()
        .await
        .clone()
        .or_else(|| index.active.clone());

    // A scan explicitly aimed at the selected network's own subnet is a
    // *targeted* scan: the user chose where to look, so the result files
    // there. Rerouting applies only to default scans, where "wherever the
    // machine sits" is the only sensible meaning.
    if let Some(profile) = index.active.as_deref().and_then(|id| index.get(id)) {
        let targeted = extra_ranges.iter().any(|range| {
            profile
                .fingerprint
                .subnets
                .iter()
                .any(|subnet| netutil::cidrs_overlap(subnet, range))
        });
        if targeted {
            return Vec::new();
        }
    }

    let (_host, fingerprint) = networks::probe_current().await;

    match index.detect(&fingerprint) {
        Detection::Current { .. } | Detection::NoNetwork => Vec::new(),

        // The selected network is among the indistinguishable candidates: keep
        // it, but say so — guessing differently would be no better.
        Detection::Ambiguous { candidates }
            if index
                .active
                .as_deref()
                .map(|active| candidates.iter().any(|c| c.id == active))
                .unwrap_or(false) =>
        {
            vec![
                "Several saved networks share this subnet and nothing observable tells them \
                 apart, so the scan was filed under the selected one. Refreshing the network's \
                 fingerprint while on site makes future scans unambiguous."
                    .to_string(),
            ]
        }

        Detection::Switch { id, name, .. } => {
            index.active = Some(id.clone());
            let _ = index.save(root).await;
            *state.active_network.lock().await = Some(id.clone());
            let _ = app.emit(
                PROGRESS_EVENT,
                &ScanEvent::NetworkChanged {
                    id,
                    name: name.clone(),
                },
            );
            vec![format!(
                "This machine is on \"{name}\", so the scan was filed under that network \
                 instead of the previously selected one."
            )]
        }

        detection @ (Detection::Unknown { .. } | Detection::Ambiguous { .. }) => {
            let name = match detection {
                Detection::Unknown { suggested_name } => suggested_name,
                _ => fingerprint.describe(),
            };
            let profile = NetworkProfile::new(name.clone(), fingerprint);
            let id = index.add(profile);
            let _ = tokio::fs::create_dir_all(NetworkIndex::scans_dir(root, &id)).await;
            let _ = index.save(root).await;
            *state.active_network.lock().await = Some(id.clone());
            let _ = app.emit(
                PROGRESS_EVENT,
                &ScanEvent::NetworkChanged {
                    id,
                    name: name.clone(),
                },
            );
            vec![format!(
                "This machine is not on any saved network, so \"{name}\" was created and the \
                 scan filed there. It can be renamed under Networks."
            )]
        }
    }
}

/// Runs a scan, streaming progress to the frontend. Shared by the manual button
/// and the auto-repeat timer so both behave identically.
async fn execute_scan(
    app: AppHandle,
    state: Arc<AppState>,
    config: ScanConfig,
) -> Result<String, String> {
    let handle = {
        let mut running = state.running.lock().await;
        if running.is_some() {
            return Err("A scan is already running".into());
        }
        let handle = ScanHandle::default();
        *running = Some(handle.clone());
        handle
    };

    // Must precede `state.store()`: the store is bound to whichever network is
    // active when the scan starts writing.
    let routing_warnings = route_scan_to_network(&app, &state, &config.extra_ranges).await;
    for message in &routing_warnings {
        let _ = app.emit(
            PROGRESS_EVENT,
            &ScanEvent::Warning {
                message: message.clone(),
            },
        );
    }

    // The scan callback is synchronous, so progress is funnelled through a
    // channel and forwarded by a task that can await the emit.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ScanEvent>();

    let emitter = app.clone();
    let forward = tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            let _ = emitter.emit(PROGRESS_EVENT, &event);
        }
    });

    let phase_store = Arc::clone(&state);
    let sender = tx.clone();

    let store = state.store().await;
    let result = scan::run_scan(config, &store, handle, move |progress| {
        let event = match progress {
            scan::ScanProgress::Phases(phases) => {
                // Keep the latest phase list so a window opened mid-scan can
                // render current state immediately.
                if let Ok(mut guard) = phase_store.phases.try_lock() {
                    guard.clone_from(&phases);
                }
                ScanEvent::Phase { phases }
            }
            scan::ScanProgress::Warning(message) => ScanEvent::Warning { message },
        };
        let _ = sender.send(event);
    })
    .await;

    drop(tx);
    let _ = forward.await;

    *state.running.lock().await = None;

    let result = match result {
        Ok(mut snapshot) => {
            // The routing decision travels with the snapshot it applied to.
            snapshot.warnings.extend(routing_warnings.iter().cloned());

            // Controller correlation runs after the scan, in this layer, because
            // the engine deliberately holds no credentials. A controller that is
            // unreachable degrades to a warning: the scan itself is still valid.
            // Controller settings are per network: a different site has a
            // different controller, or none.
            let network_root = state.network_root().await;
            if let Some(config) = UnifiConfig::load(&network_root).await {
                if config.is_configured() {
                    match credentials::load(&config) {
                        Ok(password) => match unifi::fetch(&config, &password).await {
                            Ok(unifi_snapshot) => {
                                let scanned: Vec<String> = snapshot
                                    .host
                                    .scan_targets
                                    .iter()
                                    .map(|target| target.cidr.clone())
                                    .collect();
                                let reconciliation = unifi::correlate::apply(
                                    &mut snapshot.devices,
                                    &unifi_snapshot,
                                    &scanned,
                                );
                                snapshot.warnings.extend(unifi_snapshot.warnings.clone());
                                snapshot.unifi = Some(unifi_snapshot);
                                snapshot.reconciliation = Some(reconciliation);
                            }
                            Err(error) => {
                                let message = format!(
                                    "UniFi correlation unavailable: {}",
                                    unifi::config::redact(&error.to_string())
                                );
                                let _ = app.emit(
                                    PROGRESS_EVENT,
                                    &ScanEvent::Warning {
                                        message: message.clone(),
                                    },
                                );
                                snapshot.warnings.push(message);
                            }
                        },
                        Err(error) => snapshot
                            .warnings
                            .push(format!("UniFi password unavailable: {error}")),
                    }
                }
            }

            // Re-save so the correlated data is what history and diffs see.
            let _ = store.save(&snapshot).await;
            Ok(snapshot)
        }
        Err(error) => Err(error),
    };

    match result {
        Ok(snapshot) => {
            *state.last_snapshot_id.lock().await = Some(snapshot.id.clone());
            *state.phases.lock().await = snapshot.phases.clone();

            // Keep the network index's activity counters honest.
            if let Some(id) = state.active_network.lock().await.clone() {
                let root = state.settings_root();
                let mut index = NetworkIndex::load(root).await;
                if let Some(profile) = index.get_mut(&id) {
                    profile.scan_count += 1;
                    profile.last_seen_at = Some(snapshot.started_at.clone());
                }
                let _ = index.save(root).await;
            }
            let _ = app.emit(
                PROGRESS_EVENT,
                &ScanEvent::Done {
                    snapshot_id: snapshot.id.clone(),
                },
            );
            arm_next_run(&state).await;
            Ok(snapshot.id)
        }
        Err(error) => {
            let event = if error.contains("cancelled") {
                ScanEvent::Cancelled
            } else {
                ScanEvent::Error {
                    message: error.clone(),
                }
            };
            let _ = app.emit(PROGRESS_EVENT, &event);
            arm_next_run(&state).await;
            Err(error)
        }
    }
}

/// Single supervisor task, started once at launch.
///
/// It polls rather than sleeping for an exact interval, which keeps the design
/// free of re-arming recursion and makes it self-correcting: changing the
/// interval, disabling and re-enabling, or the machine waking from sleep are all
/// handled by simply re-reading `next_run_at` on the next tick.
fn spawn_auto_repeat_supervisor(app: AppHandle, state: Arc<AppState>) {
    // `tauri::async_runtime::spawn`, not `tokio::spawn`: this is called from
    // `setup()`, which runs before any Tokio reactor is entered, so a bare
    // `tokio::spawn` panics with "there is no reactor running".
    tauri::async_runtime::spawn(async move {
        const TICK: Duration = Duration::from_secs(15);

        loop {
            tokio::time::sleep(TICK).await;

            let due = {
                let guard = state.auto_repeat.lock().await;
                match (guard.enabled, guard.next_run_at) {
                    (true, Some(at)) => chrono::Utc::now() >= at,
                    _ => false,
                }
            };

            if !due || state.running.lock().await.is_some() {
                continue;
            }

            // Failures are already reported to the UI as events; swallow here so
            // one bad run does not stop the schedule. `execute_scan` re-arms
            // `next_run_at` on both success and failure.
            let _ = execute_scan(app.clone(), Arc::clone(&state), ScanConfig::default()).await;
        }
    });
}

/* ------------------------------------------------------------------- commands */

#[tauri::command]
async fn get_status(state: State<'_, Arc<AppState>>) -> Result<ScanStatus, String> {
    let running = state.running.lock().await.is_some();
    let phases = state.phases.lock().await.clone();
    let last = state.last_snapshot_id.lock().await.clone();

    // Only the id is needed here; `load_latest()` would parse the entire
    // newest snapshot just to read it, and the frontend immediately loads the
    // same snapshot again — a double full parse on every launch.
    let last_snapshot_id = match last {
        Some(id) => Some(id),
        None => state.store().await.list_ids().await.first().cloned(),
    };

    Ok(ScanStatus {
        running,
        phases,
        last_snapshot_id,
        auto_repeat: current_auto_repeat(&state).await,
    })
}

#[tauri::command]
async fn start_scan(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    request: Option<ScanRequest>,
) -> Result<String, String> {
    let request = request.unwrap_or_default();

    let mut config = ScanConfig {
        extra_ranges: request.extra_ranges.into_iter().take(8).collect(),
        ..Default::default()
    };
    if let Some(profile) = request.port_profile {
        config.port_profile = profile;
    }
    if let Some(include) = request.include_discovered_subnets {
        config.include_discovered_subnets = include;
    }

    execute_scan(app, Arc::clone(&state), config).await
}

#[tauri::command]
async fn cancel_scan(state: State<'_, Arc<AppState>>) -> Result<bool, String> {
    let guard = state.running.lock().await;
    match guard.as_ref() {
        Some(handle) => {
            handle.cancel();
            Ok(true)
        }
        None => Ok(false),
    }
}

#[tauri::command]
async fn run_doctor(state: State<'_, Arc<AppState>>, force: bool) -> Result<DoctorReport, String> {
    let network_root = state.network_root().await;
    // The engine never touches the keychain; the password is fetched here and
    // handed in, so the doctor can still probe a live connection.
    let password = match UnifiConfig::load(&network_root).await {
        Some(config) if config.is_configured() => credentials::load(&config).ok(),
        _ => None,
    };
    Ok(doctor::run_diagnostics_at(force, Some(&network_root), password.as_deref()).await)
}

/* -------------------------------------------------------------------- networks */

/// A saved network plus UI-only facts about it. `has_unifi` lives here rather
/// than on the core profile because it is derived from the network's settings
/// directory, not part of its identity.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkEntry {
    #[serde(flatten)]
    profile: NetworkProfile,
    /// A UniFi controller is configured for this network — the integration is
    /// per network, so the label tells the user where controller data applies.
    has_unifi: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkList {
    active: Option<String>,
    networks: Vec<NetworkEntry>,
}

#[tauri::command]
async fn list_networks(state: State<'_, Arc<AppState>>) -> Result<NetworkList, String> {
    let index = NetworkIndex::load(state.settings_root()).await;

    let mut networks = Vec::with_capacity(index.networks.len());
    for profile in index.networks {
        let dir = NetworkIndex::network_dir(state.settings_root(), &profile.id);
        let has_unifi = UnifiConfig::load(&dir)
            .await
            .map(|config| config.is_configured())
            .unwrap_or(false);
        networks.push(NetworkEntry { profile, has_unifi });
    }

    Ok(NetworkList {
        active: state.active_network.lock().await.clone().or(index.active),
        networks,
    })
}

/// Fingerprints the network this machine is on and says what to do about it.
///
/// Called at launch and before each scan. Nothing is changed here — the decision
/// is handed to the UI, because silently adopting a guess is how two sites end
/// up sharing one history.
#[tauri::command]
async fn detect_network(state: State<'_, Arc<AppState>>) -> Result<Detection, String> {
    let (_host, fingerprint) = networks::probe_current().await;
    let mut index = NetworkIndex::load(state.settings_root()).await;
    index.active = state.active_network.lock().await.clone().or(index.active);
    Ok(index.detect(&fingerprint))
}

/// Creates a network from what is currently observable and selects it.
#[tauri::command]
async fn create_network(
    state: State<'_, Arc<AppState>>,
    name: String,
) -> Result<NetworkProfile, String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("A network needs a name".into());
    }

    let (_host, fingerprint) = networks::probe_current().await;
    let profile = NetworkProfile::new(name, fingerprint);

    let root = state.settings_root();
    let mut index = NetworkIndex::load(root).await;
    let id = index.add(profile.clone());
    index.save(root).await?;

    tokio::fs::create_dir_all(NetworkIndex::scans_dir(root, &id))
        .await
        .map_err(|e| e.to_string())?;

    *state.active_network.lock().await = Some(id);
    Ok(profile)
}

#[tauri::command]
async fn switch_network(state: State<'_, Arc<AppState>>, id: String) -> Result<(), String> {
    let root = state.settings_root();
    let mut index = NetworkIndex::load(root).await;

    if index.get(&id).is_none() {
        return Err("No such network".into());
    }

    index.active = Some(id.clone());
    index.save(root).await?;
    *state.active_network.lock().await = Some(id);
    Ok(())
}

/// Re-fingerprints the active network from where the machine is now.
///
/// Useful when a network was created before its gateway MAC could be resolved,
/// or after the router was replaced.
#[tauri::command]
async fn refresh_network_fingerprint(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    let Some(id) = state.active_network.lock().await.clone() else {
        return Err("No network selected".into());
    };

    let (_host, fingerprint) = networks::probe_current().await;
    let root = state.settings_root();
    let mut index = NetworkIndex::load(root).await;

    if let Some(profile) = index.get_mut(&id) {
        profile.fingerprint = fingerprint;
    }
    index.save(root).await
}

#[tauri::command]
async fn rename_network(
    state: State<'_, Arc<AppState>>,
    id: String,
    name: String,
) -> Result<(), String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("A network needs a name".into());
    }

    let root = state.settings_root();
    let mut index = NetworkIndex::load(root).await;
    let Some(profile) = index.get_mut(&id) else {
        return Err("No such network".into());
    };
    profile.name = name;
    index.save(root).await
}

/// Deletes a network's scan history while keeping the network itself — the
/// fingerprint, name and controller settings survive.
///
/// Exists for starting over: scans recorded before the scan-routing fix could
/// mix several sites into one history, and there is no untangling them after
/// the fact — a clean slate is the honest reset.
#[tauri::command]
async fn clear_network_history(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<usize, String> {
    let root = state.settings_root();
    let mut index = NetworkIndex::load(root).await;
    if index.get(&id).is_none() {
        return Err("No such network".into());
    }

    let removed = Store::new(NetworkIndex::scans_dir(root, &id)).clear().await;

    if let Some(profile) = index.get_mut(&id) {
        profile.scan_count = 0;
        profile.last_seen_at = None;
    }
    index.save(root).await?;

    // The next scan against this network is a fresh baseline, and any
    // remembered "latest snapshot" no longer exists.
    if state.active_network.lock().await.as_deref() == Some(id.as_str()) {
        *state.last_snapshot_id.lock().await = None;
    }

    Ok(removed)
}

/// What "Run scan" would sweep right now. Interface enumeration only — cheap
/// enough for the UI to call as the user types an extra range.
#[tauri::command]
fn preview_scan_targets(extra_ranges: Vec<String>) -> Vec<ScanTarget> {
    scan::hostinfo::preview_targets(&extra_ranges)
}

/// A local subnet this machine can see right now, offered as a network to track.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiscoveredNetwork {
    cidr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
    host_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway_ip: Option<String>,
    /// A saved network already covers this range.
    already_tracked: bool,
}

/// Lists the subnets this machine is attached to, for the first-run picker
/// (and its on-demand reopening from the Networks panel).
#[tauri::command]
async fn discover_local_networks(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<DiscoveredNetwork>, String> {
    let targets = scan::hostinfo::preview_targets(&[]);
    let (_host, fingerprint) = networks::probe_current().await;
    let index = NetworkIndex::load(state.settings_root()).await;

    let gateway_in = |cidr: &str| -> bool {
        fingerprint
            .gateway_ip
            .as_deref()
            .and_then(|ip| ip.parse::<std::net::Ipv4Addr>().ok())
            .zip(netutil::parse_cidr_any(cidr).ok())
            .map(|(ip, parsed)| parsed.contains(ip))
            .unwrap_or(false)
    };

    Ok(targets
        .into_iter()
        .map(|target| {
            let with_gateway = gateway_in(&target.cidr);
            DiscoveredNetwork {
                interface: target
                    .note
                    .as_deref()
                    .and_then(|note| note.strip_prefix("local subnet on "))
                    .map(str::to_string),
                host_count: target.host_count,
                // The SSID belongs to whichever subnet the gateway is on; tagging
                // it onto every interface would mislabel wired segments.
                ssid: fingerprint.ssid.clone().filter(|_| with_gateway),
                gateway_ip: fingerprint.gateway_ip.clone().filter(|_| with_gateway),
                already_tracked: index.networks.iter().any(|profile| {
                    profile
                        .fingerprint
                        .subnets
                        .iter()
                        .any(|subnet| netutil::cidrs_overlap(subnet, &target.cidr))
                }),
                cidr: target.cidr,
            }
        })
        .collect())
}

/// Resolves a range to a saved network, creating one when nothing covers it.
///
/// This is what lets "scan this address range" and "networks are physical
/// sites" coexist: a range the user aims at becomes (or resolves to) a
/// network, and the scan router treats a scan aimed at the selected network's
/// own subnet as targeted rather than rerouting it to wherever the machine
/// happens to sit.
#[tauri::command]
async fn ensure_network_for_range(
    state: State<'_, Arc<AppState>>,
    cidr: String,
    name: Option<String>,
    select: Option<bool>,
) -> Result<NetworkProfile, String> {
    let normalized = scan::hostinfo::validate_range(&cidr)?;
    let select = select.unwrap_or(true);
    let root = state.settings_root();
    let mut index = NetworkIndex::load(root).await;

    // An existing network covering this range wins over creating a duplicate.
    if let Some(profile) = index
        .networks
        .iter()
        .find(|profile| {
            profile
                .fingerprint
                .subnets
                .iter()
                .any(|subnet| netutil::cidrs_overlap(subnet, &normalized))
        })
        .cloned()
    {
        if select {
            index.active = Some(profile.id.clone());
            index.save(root).await?;
            *state.active_network.lock().await = Some(profile.id.clone());
        }
        return Ok(profile);
    }

    // Enrich the fingerprint only with facts that belong to this subnet — the
    // gateway and SSID must not be stamped onto a range they are not on, or
    // two networks become indistinguishable copies of "here".
    let local = scan::hostinfo::preview_targets(&[]);
    let is_local = local
        .iter()
        .any(|target| netutil::cidrs_overlap(&target.cidr, &normalized));
    let current = if is_local {
        Some(networks::probe_current().await.1)
    } else {
        None
    };

    let gateway_in_range = current
        .as_ref()
        .and_then(|c| c.gateway_ip.as_deref())
        .and_then(|ip| ip.parse::<std::net::Ipv4Addr>().ok())
        .zip(netutil::parse_cidr_any(&normalized).ok())
        .map(|(ip, parsed)| parsed.contains(ip))
        .unwrap_or(false);

    let fingerprint = networks::NetworkFingerprint {
        gateway_mac: current
            .as_ref()
            .and_then(|c| c.gateway_mac.clone())
            .filter(|_| gateway_in_range),
        gateway_ip: current
            .as_ref()
            .and_then(|c| c.gateway_ip.clone())
            .filter(|_| gateway_in_range),
        subnets: vec![normalized.clone()],
        ssid: current
            .as_ref()
            .and_then(|c| c.ssid.clone())
            .filter(|_| gateway_in_range),
        dns_servers: current
            .as_ref()
            .map(|c| c.dns_servers.clone())
            .unwrap_or_default(),
    };

    let name = name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| {
            if gateway_in_range {
                fingerprint.describe()
            } else {
                normalized.clone()
            }
        });

    let previous_active = index.active.clone();
    let id = index.add(NetworkProfile::new(name, fingerprint));
    if !select {
        index.active = previous_active;
    }

    tokio::fs::create_dir_all(NetworkIndex::scans_dir(root, &id))
        .await
        .map_err(|e| e.to_string())?;
    index.save(root).await?;

    if select {
        *state.active_network.lock().await = Some(id.clone());
    }

    index
        .get(&id)
        .cloned()
        .ok_or_else(|| "network vanished during creation".into())
}

/// Wipes every stored setting and history, then quits.
///
/// Exists so a first-run experience can actually be tested: keyring
/// credentials are cleared first (deleting the settings that identify them
/// would orphan the entries), then the data directory's contents go, then the
/// process exits so the next launch starts from nothing.
#[tauri::command]
async fn factory_reset(app: AppHandle, state: State<'_, Arc<AppState>>) -> Result<(), String> {
    let root = state.settings_root();

    let index = NetworkIndex::load(root).await;
    for profile in &index.networks {
        let dir = NetworkIndex::network_dir(root, &profile.id);
        if let Some(config) = UnifiConfig::load(&dir).await {
            let _ = credentials::clear(&config);
        }
    }
    // A pre-networks installation kept controller settings at the root.
    if let Some(config) = UnifiConfig::load(root).await {
        let _ = credentials::clear(&config);
    }

    for entry in [
        "networks",
        "unassigned",
        "scans",
        "networks.json",
        "unifi.json",
        "update-preferences.json",
    ] {
        let path = root.join(entry);
        if tokio::fs::remove_dir_all(&path).await.is_err() {
            let _ = tokio::fs::remove_file(&path).await;
        }
    }

    app.exit(0);
    Ok(())
}

/// Removes a network and everything recorded for it.
#[tauri::command]
async fn delete_network(state: State<'_, Arc<AppState>>, id: String) -> Result<(), String> {
    let root = state.settings_root();
    let mut index = NetworkIndex::load(root).await;

    // Clear the controller credential before the settings that identify it are
    // deleted, or the keychain entry is orphaned with no way to find it again.
    let network_root = NetworkIndex::network_dir(root, &id);
    if let Some(config) = UnifiConfig::load(&network_root).await {
        let _ = credentials::clear(&config);
    }

    index.networks.retain(|profile| profile.id != id);
    if index.active.as_deref() == Some(id.as_str()) {
        index.active = index.networks.first().map(|profile| profile.id.clone());
    }
    index.save(root).await?;

    let _ = tokio::fs::remove_dir_all(&network_root).await;
    *state.active_network.lock().await = index.active.clone();
    Ok(())
}

/* ----------------------------------------------------------- update checking */

#[tauri::command]
async fn check_for_update(
    state: State<'_, Arc<AppState>>,
    force: bool,
) -> Result<Option<UpdateInfo>, String> {
    Ok(update::check(state.settings_root(), force).await)
}

#[tauri::command]
async fn get_update_preferences(
    state: State<'_, Arc<AppState>>,
) -> Result<UpdatePreferences, String> {
    Ok(UpdatePreferences::load(state.settings_root()).await)
}

#[tauri::command]
async fn skip_update_version(
    state: State<'_, Arc<AppState>>,
    version: String,
) -> Result<(), String> {
    let root = state.settings_root();
    let mut prefs = UpdatePreferences::load(root).await;
    prefs.skipped_version = Some(version);
    prefs.save(root).await
}

#[tauri::command]
async fn set_update_checks_enabled(
    state: State<'_, Arc<AppState>>,
    enabled: bool,
) -> Result<(), String> {
    let root = state.settings_root();
    let mut prefs = UpdatePreferences::load(root).await;
    prefs.check_enabled = enabled;
    prefs.save(root).await
}

/* -------------------------------------------------------------------- UniFi */

#[tauri::command]
async fn get_unifi_config(state: State<'_, Arc<AppState>>) -> Result<Option<UnifiConfig>, String> {
    Ok(UnifiConfig::load(&state.network_root().await).await)
}

/// Saves settings and, when a password is supplied, stores it in the OS keychain.
///
/// The password is a separate optional argument so the UI can update the host or
/// site without the user re-typing it, and so it is never round-tripped back to
/// the frontend.
#[tauri::command]
async fn save_unifi_config(
    state: State<'_, Arc<AppState>>,
    config: UnifiConfig,
    password: Option<String>,
) -> Result<(), String> {
    if let Some(password) = password {
        if !password.is_empty() {
            credentials::store(&config, &password)?;
        }
    }
    config.save(&state.network_root().await).await
}

#[tauri::command]
async fn clear_unifi_config(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    let root = state.network_root().await;
    if let Some(config) = UnifiConfig::load(&root).await {
        // Ignore a keychain miss: the settings must clear regardless.
        let _ = credentials::clear(&config);
    }
    UnifiConfig::delete(&root).await
}

/// Tests the connection, pinning the certificate on first success.
#[tauri::command]
async fn test_unifi_connection(
    state: State<'_, Arc<AppState>>,
    config: UnifiConfig,
    password: Option<String>,
) -> Result<String, String> {
    let password = match password.filter(|p| !p.is_empty()) {
        Some(password) => password,
        None => credentials::load(&config)?,
    };

    let report = unifi::verify(&config, &password)
        .await
        .map_err(|e| unifi::config::redact(&e.to_string()))?;

    // Persist the fingerprint so subsequent connections are pinned.
    if report.newly_pinned {
        let mut stored = config.clone();
        stored.fingerprint = Some(report.fingerprint.clone());
        credentials::store(&stored, &password)?;
        stored.save(&state.network_root().await).await?;
    }

    Ok(format!(
        "Connected to {} — {} client(s) visible.{}",
        config.host,
        report.client_count,
        if report.newly_pinned {
            " Certificate pinned for future connections."
        } else {
            ""
        }
    ))
}

#[tauri::command]
async fn list_snapshots(
    state: State<'_, Arc<AppState>>,
    limit: Option<usize>,
) -> Result<Vec<SnapshotSummary>, String> {
    Ok(state
        .store()
        .await
        .summaries(limit.unwrap_or(50).min(200))
        .await)
}

#[tauri::command]
async fn get_snapshot(
    state: State<'_, Arc<AppState>>,
    id: String,
    diff: Option<String>,
) -> Result<SnapshotWithDiff, String> {
    let store = state.store().await;
    let resolved = if id == "latest" {
        store
            .list_ids()
            .await
            .first()
            .cloned()
            .ok_or_else(|| "No scans recorded yet".to_string())?
    } else {
        id
    };

    let snapshot = store
        .load(&resolved)
        .await
        .ok_or_else(|| "Snapshot not found".to_string())?;

    let diff = match diff.as_deref() {
        None => None,
        Some("previous") => {
            let ids = store.list_ids().await;
            match ids.iter().position(|candidate| *candidate == resolved) {
                Some(index) if index + 1 < ids.len() => store
                    .load(&ids[index + 1])
                    .await
                    .map(|previous| store::diff(&previous, &snapshot)),
                _ => None,
            }
        }
        Some(other) => store
            .load(other)
            .await
            .map(|previous| store::diff(&previous, &snapshot)),
    };

    Ok(SnapshotWithDiff { snapshot, diff })
}

#[tauri::command]
async fn delete_snapshot(state: State<'_, Arc<AppState>>, id: String) -> Result<bool, String> {
    Ok(state.store().await.delete(&id).await)
}

#[tauri::command]
async fn deep_scan_host(ip: String) -> Result<Vec<PortInfo>, String> {
    let addr: Ipv4Addr = ip.parse().map_err(|_| "Invalid IPv4 address".to_string())?;

    // Validate even though the scanner takes a typed address: this also stops the
    // command being used to probe arbitrary public hosts.
    if !netutil::is_private_ipv4(addr) {
        return Err(
            "Refusing to scan a public address — this tool is for local networks only".into(),
        );
    }

    let mut ports =
        scan::ports::scan_host(addr, netutil::DEEP_PORTS, 200, Duration::from_millis(1500)).await;

    let tasks: Vec<(Ipv4Addr, u16)> = ports
        .iter()
        .filter(|p| scan::banners::is_banner_port(p.port))
        .map(|p| (addr, p.port))
        .collect();

    let banners = scan::banners::grab(&tasks, 16).await;
    for port in ports.iter_mut() {
        if let Some(banner) = banners.get(&format!("{addr}:{}", port.port)) {
            port.banner = Some(banner.clone());
        }
    }

    Ok(ports)
}

#[tauri::command]
async fn set_auto_repeat(
    state: State<'_, Arc<AppState>>,
    enabled: bool,
    interval_minutes: u64,
) -> Result<AutoRepeatState, String> {
    {
        let mut guard = state.auto_repeat.lock().await;
        guard.enabled = enabled;
        guard.interval_minutes = interval_minutes.clamp(1, 1440);
        guard.next_run_at = None;
    }

    arm_next_run(&state).await;
    Ok(current_auto_repeat(&state).await)
}

#[tauri::command]
async fn export_snapshot(
    state: State<'_, Arc<AppState>>,
    id: String,
    format: String,
    path: String,
) -> Result<String, String> {
    let snapshot = state
        .store()
        .await
        .load(&id)
        .await
        .ok_or_else(|| "Snapshot not found".to_string())?;

    let contents = match format.as_str() {
        "csv" => snapshot_to_csv(&snapshot),
        _ => serde_json::to_string_pretty(&snapshot).map_err(|e| e.to_string())?,
    };

    tokio::fs::write(&path, contents)
        .await
        .map_err(|e| e.to_string())?;
    Ok(path)
}

fn snapshot_to_csv(snapshot: &ScanSnapshot) -> String {
    fn escape(value: &str) -> String {
        if value.contains(['"', ',', '\n']) {
            format!("\"{}\"", value.replace('"', "\"\""))
        } else {
            value.to_string()
        }
    }

    let mut out = String::from(
        "ip,name,type,mac,vendor,randomized_mac,hostnames,open_ports,discovered_by,off_subnet,first_seen\n",
    );

    for device in &snapshot.devices {
        let row = [
            device.ip.clone(),
            device.display_name.clone(),
            format!("{:?}", device.device_type).to_lowercase(),
            device.mac.clone().unwrap_or_default(),
            device.vendor.clone().unwrap_or_default(),
            if device.mac_randomized == Some(true) {
                "yes".into()
            } else {
                String::new()
            },
            device.hostnames.join(" "),
            device
                .ports
                .iter()
                .map(|p| p.port.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            device.discovered_by.join(" "),
            if device.off_subnet {
                "yes".into()
            } else {
                String::new()
            },
            device.first_seen.clone().unwrap_or_default(),
        ]
        .iter()
        .map(|field| escape(field))
        .collect::<Vec<_>>()
        .join(",");

        out.push_str(&row);
        out.push('\n');
    }

    out
}

#[tauri::command]
async fn get_data_dir(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    Ok(state.store().await.root().to_string_lossy().into_owned())
}

#[tauri::command]
fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/* ----------------------------------------------------------------------- run */

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // Snapshots live in the OS-appropriate app data directory rather than
            // next to the binary, which would be read-only once installed.
            let root = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::env::temp_dir());

            let state = Arc::new(AppState::new(root.clone()));
            app.manage(Arc::clone(&state));

            // Adopt any pre-networks installation and select a network before
            // the UI asks for anything, so the first render is never against an
            // unassigned store.
            let startup_state = Arc::clone(&state);
            tauri::async_runtime::spawn(async move {
                if let Err(error) = networks::migrate_flat_layout(&root).await {
                    eprintln!("network migration failed: {error}");
                }
                let index = NetworkIndex::load(&root).await;
                if let Some(profile) = index.active_profile() {
                    *startup_state.active_network.lock().await = Some(profile.id.clone());
                }
            });

            spawn_auto_repeat_supervisor(app.handle().clone(), state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_scan,
            cancel_scan,
            run_doctor,
            list_snapshots,
            get_snapshot,
            delete_snapshot,
            deep_scan_host,
            set_auto_repeat,
            export_snapshot,
            get_data_dir,
            get_app_version,
            check_for_update,
            get_update_preferences,
            skip_update_version,
            set_update_checks_enabled,
            list_networks,
            detect_network,
            create_network,
            switch_network,
            refresh_network_fingerprint,
            rename_network,
            clear_network_history,
            preview_scan_targets,
            discover_local_networks,
            ensure_network_for_range,
            factory_reset,
            delete_network,
            get_unifi_config,
            save_unifi_config,
            clear_unifi_config,
            test_unifi_connection,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_export_escapes_separators_and_quotes() {
        let mut snapshot: ScanSnapshot = serde_json::from_str(
            r#"{
                "id":"x","startedAt":"t","finishedAt":"t","durationMs":0,
                "host":{"hostname":"h","platform":"p","os":"Linux","arch":"x86_64","appVersion":"1.0.0",
                        "interfaces":[],"routes":[],"dns":{"servers":[],"searchDomains":[]},"scanTargets":[]},
                "devices":[],
                "connectivity":{"wan":[],"dns":[],"wanReachable":true,"trace":{"status":"unavailable"}},
                "wifi":{"status":"unavailable"},
                "phases":[],"warnings":[],
                "config":{"extraRanges":[],"portProfile":"standard","includeDiscoveredSubnets":true,
                          "sweepConcurrency":64,"portConcurrency":400,"portTimeoutMs":1200},
                "capabilities":[],"baseline":false
            }"#,
        )
        .expect("fixture should deserialize");

        let mut device: Device = serde_json::from_str(
            r#"{"ip":"10.0.3.1","hostnames":[],"displayName":"x","deviceType":"router",
                "typeEvidence":[],"isGateway":true,"isSelf":false,"respondedToPing":true,
                "discoveredBy":["icmp"],"ports":[],"mdns":[],"ssdp":[],"offSubnet":false,
                "lastSeen":"t"}"#,
        )
        .expect("device fixture should deserialize");
        device.display_name = "Router, \"main\"".into();
        snapshot.devices.push(device);

        let csv = snapshot_to_csv(&snapshot);
        assert!(
            csv.contains("\"Router, \"\"main\"\"\""),
            "commas and quotes must be escaped: {csv}"
        );
    }
}
