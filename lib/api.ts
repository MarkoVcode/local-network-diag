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
  DoctorReport,
  PortInfo,
  PortProfile,
  ScanDiff,
  ScanEvent,
  ScanSnapshot,
  ScanStatus,
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
