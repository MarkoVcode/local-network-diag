/**
 * Bridge to the Rust engine.
 *
 * Every call is a Tauri command — the frontend performs no network I/O of its
 * own, which is what lets the app ship with a strict CSP and no network
 * permissions in the webview.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AutoRepeatState,
  DiscoveredNetwork,
  DoctorReport,
  Detection,
  NetworkList,
  NetworkProfile,
  UnifiConfig,
  UpdateInfo,
  UpdatePreferences,
  PortInfo,
  PortProfile,
  ScanDiff,
  ScanEvent,
  ScanSnapshot,
  ScanStatus,
  ScanTarget,
  SnapshotSummary,
} from "./types";

/** Next's dev server renders once on the server during export; guard against that. */
export const isDesktop = (): boolean =>
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export interface StartScanRequest {
  extraRanges?: string[];
  portProfile?: PortProfile;
  includeDiscoveredSubnets?: boolean;
}

export async function getStatus(): Promise<ScanStatus> {
  return invoke<ScanStatus>("get_status");
}

export async function startScan(request: StartScanRequest = {}): Promise<string> {
  return invoke<string>("start_scan", { request });
}

export async function cancelScan(): Promise<boolean> {
  return invoke<boolean>("cancel_scan");
}

export async function runDoctor(force = false): Promise<DoctorReport> {
  return invoke<DoctorReport>("run_doctor", { force });
}

export async function listSnapshots(limit = 50): Promise<SnapshotSummary[]> {
  return invoke<SnapshotSummary[]>("list_snapshots", { limit });
}

export interface SnapshotWithDiff {
  snapshot: ScanSnapshot;
  diff?: ScanDiff;
}

export async function getSnapshot(
  id: string,
  diff?: "previous" | string,
): Promise<SnapshotWithDiff> {
  return invoke<SnapshotWithDiff>("get_snapshot", { id, diff: diff ?? null });
}

export async function deleteSnapshot(id: string): Promise<boolean> {
  return invoke<boolean>("delete_snapshot", { id });
}

export async function deepScanHost(ip: string): Promise<PortInfo[]> {
  return invoke<PortInfo[]>("deep_scan_host", { ip });
}

export async function setAutoRepeat(
  enabled: boolean,
  intervalMinutes: number,
): Promise<AutoRepeatState> {
  return invoke<AutoRepeatState>("set_auto_repeat", { enabled, intervalMinutes });
}

export async function exportSnapshot(
  id: string,
  format: "json" | "csv",
  path: string,
): Promise<string> {
  return invoke<string>("export_snapshot", { id, format, path });
}

export async function getDataDir(): Promise<string> {
  return invoke<string>("get_data_dir");
}

export async function getAppVersion(): Promise<string> {
  return invoke<string>("get_app_version");
}

/** Subscribes to live scan progress. Returns an unsubscribe function. */
export async function onScanEvent(
  handler: (event: ScanEvent) => void,
): Promise<UnlistenFn> {
  return listen<ScanEvent>("scan://progress", (message) => handler(message.payload));
}

/* -------------------------------------------------------------------- update */

export async function checkForUpdate(force = false): Promise<UpdateInfo | null> {
  return invoke<UpdateInfo | null>("check_for_update", { force });
}

export async function getUpdatePreferences(): Promise<UpdatePreferences> {
  return invoke<UpdatePreferences>("get_update_preferences");
}

export async function skipUpdateVersion(version: string): Promise<void> {
  return invoke("skip_update_version", { version });
}

export async function setUpdateChecksEnabled(enabled: boolean): Promise<void> {
  return invoke("set_update_checks_enabled", { enabled });
}

/* --------------------------------------------------------------------- UniFi */

export async function getUnifiConfig(): Promise<UnifiConfig | null> {
  return invoke<UnifiConfig | null>("get_unifi_config");
}

/**
 * Saves settings. The password is optional so host/site can be edited without
 * re-typing it, and it is never read back to the frontend.
 */
export async function saveUnifiConfig(
  config: UnifiConfig,
  password?: string,
): Promise<void> {
  return invoke("save_unifi_config", { config, password: password ?? null });
}

export async function clearUnifiConfig(): Promise<void> {
  return invoke("clear_unifi_config");
}

export async function testUnifiConnection(
  config: UnifiConfig,
  password?: string,
): Promise<string> {
  return invoke<string>("test_unifi_connection", { config, password: password ?? null });
}

/* ------------------------------------------------------------------ networks */

export async function listNetworks(): Promise<NetworkList> {
  return invoke<NetworkList>("list_networks");
}

/**
 * Fingerprints the current network and reports what to do about it.
 * Changes nothing — the decision is the caller's.
 */
export async function detectNetwork(): Promise<Detection> {
  return invoke<Detection>("detect_network");
}

export async function createNetwork(name: string): Promise<NetworkProfile> {
  return invoke<NetworkProfile>("create_network", { name });
}

export async function switchNetwork(id: string): Promise<void> {
  return invoke("switch_network", { id });
}

export async function renameNetwork(id: string, name: string): Promise<void> {
  return invoke("rename_network", { id, name });
}

export async function deleteNetwork(id: string): Promise<void> {
  return invoke("delete_network", { id });
}

/** Deletes a network's scans but keeps the network and its settings. */
export async function clearNetworkHistory(id: string): Promise<number> {
  return invoke<number>("clear_network_history", { id });
}

/** Subnets this machine is attached to, for the network picker. */
export async function discoverLocalNetworks(): Promise<DiscoveredNetwork[]> {
  return invoke<DiscoveredNetwork[]>("discover_local_networks");
}

/** Resolves a range to a saved network, creating one when nothing covers it. */
export async function ensureNetworkForRange(
  cidr: string,
  name?: string,
  select = true,
): Promise<NetworkProfile> {
  return invoke<NetworkProfile>("ensure_network_for_range", { cidr, name, select });
}

/** Wipes all settings and histories, then quits the app. */
export async function factoryReset(): Promise<void> {
  return invoke("factory_reset");
}

/** What "Run scan" would sweep right now. */
export async function previewScanTargets(extraRanges: string[]): Promise<ScanTarget[]> {
  return invoke<ScanTarget[]>("preview_scan_targets", { extraRanges });
}

/** Re-fingerprints the active network from where the machine is now. */
export async function refreshNetworkFingerprint(): Promise<void> {
  return invoke("refresh_network_fingerprint");
}
