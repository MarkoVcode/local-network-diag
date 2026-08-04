//! Tauri desktop shell.
//!
//! This layer is intentionally thin: it owns window/app lifecycle, scan state and
//! the auto-repeat timer, and forwards everything else to `netdiag-core`. All the
//! logic worth testing lives in the core crate, which builds without any GUI
//! toolchain.

use netdiag_core::{
    doctor::{self, DoctorReport},
    netutil, scan,
    store::{self, Store},
    types::*,
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
    store: Store,
    running: Mutex<Option<ScanHandle>>,
    phases: Mutex<Vec<PhaseState>>,
    auto_repeat: Mutex<AutoRepeat>,
    last_snapshot_id: Mutex<Option<String>>,
}

impl AppState {
    fn new(store: Store) -> Self {
        Self {
            store,
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

    let result = scan::run_scan(config, &state.store, handle, move |progress| {
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

    match result {
        Ok(snapshot) => {
            *state.last_snapshot_id.lock().await = Some(snapshot.id.clone());
            *state.phases.lock().await = snapshot.phases.clone();
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

    let last_snapshot_id = match last {
        Some(id) => Some(id),
        None => state.store.load_latest().await.map(|s| s.id),
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
async fn run_doctor(force: bool) -> Result<DoctorReport, String> {
    Ok(doctor::run_diagnostics(force).await)
}

#[tauri::command]
async fn list_snapshots(
    state: State<'_, Arc<AppState>>,
    limit: Option<usize>,
) -> Result<Vec<SnapshotSummary>, String> {
    Ok(state.store.summaries(limit.unwrap_or(50).min(200)).await)
}

#[tauri::command]
async fn get_snapshot(
    state: State<'_, Arc<AppState>>,
    id: String,
    diff: Option<String>,
) -> Result<SnapshotWithDiff, String> {
    let resolved = if id == "latest" {
        state
            .store
            .list_ids()
            .await
            .first()
            .cloned()
            .ok_or_else(|| "No scans recorded yet".to_string())?
    } else {
        id
    };

    let snapshot = state
        .store
        .load(&resolved)
        .await
        .ok_or_else(|| "Snapshot not found".to_string())?;

    let diff = match diff.as_deref() {
        None => None,
        Some("previous") => {
            let ids = state.store.list_ids().await;
            match ids.iter().position(|candidate| *candidate == resolved) {
                Some(index) if index + 1 < ids.len() => state
                    .store
                    .load(&ids[index + 1])
                    .await
                    .map(|previous| store::diff(&previous, &snapshot)),
                _ => None,
            }
        }
        Some(other) => state
            .store
            .load(other)
            .await
            .map(|previous| store::diff(&previous, &snapshot)),
    };

    Ok(SnapshotWithDiff { snapshot, diff })
}

#[tauri::command]
async fn delete_snapshot(state: State<'_, Arc<AppState>>, id: String) -> Result<bool, String> {
    Ok(state.store.delete(&id).await)
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
        .store
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
    Ok(state.store.root().to_string_lossy().into_owned())
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
            let dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::env::temp_dir())
                .join("scans");

            let state = Arc::new(AppState::new(Store::new(dir)));
            app.manage(Arc::clone(&state));
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
