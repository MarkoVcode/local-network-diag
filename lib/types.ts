/**
 * TypeScript mirror of the Rust data model in `crates/netdiag-core/src/types.rs`.
 *
 * Serde is configured with `rename_all = "camelCase"`, so these names match the
 * wire format exactly. Keep the two in sync when changing either.
 */

export type ProbeStatus = "ok" | "unavailable" | "error";

export interface ProbeResult<T> {
  status: ProbeStatus;
  detail?: string;
  data?: T;
}

/* ---------------------------------------------------------------- host / link */

export interface Ipv4Address {
  address: string;
  cidr: number;
}

export interface Ipv6Address {
  address: string;
  cidr: number;
  scope: string;
}

export interface InterfaceInfo {
  name: string;
  state: string;
  mac?: string;
  mtu?: number;
  flags: string[];
  ipv4: Ipv4Address[];
  ipv6: Ipv6Address[];
  isPrimary: boolean;
  scannable: boolean;
  skipReason?: string;
}

export interface RouteInfo {
  destination: string;
  via?: string;
  dev: string;
  metric?: number;
  raw: string;
}

export interface DnsConfig {
  servers: string[];
  searchDomains: string[];
}

export type TargetSource = "local" | "discovered" | "manual";

export interface ScanTarget {
  cidr: string;
  source: TargetSource;
  hostCount: number;
  note?: string;
}

export interface HostInfo {
  hostname: string;
  platform: string;
  os: string;
  arch: string;
  appVersion: string;
  interfaces: InterfaceInfo[];
  routes: RouteInfo[];
  gateway?: { ip: string; dev: string };
  dns: DnsConfig;
  scanTargets: ScanTarget[];
}

/* ------------------------------------------------------------------- devices */

export interface HttpBanner {
  kind: "http";
  scheme: string;
  status?: number;
  server?: string;
  title?: string;
  headers: Record<string, string>;
  redirectLocation?: string;
}

export interface TlsBanner {
  kind: "tls";
  subject?: string;
  issuer?: string;
  altNames?: string[];
  validFrom?: string;
  validTo?: string;
  daysUntilExpiry?: number;
  selfSigned?: boolean;
}

export interface TextBanner {
  kind: "text";
  text: string;
}

export type Banner = HttpBanner | TlsBanner | TextBanner;

export interface PortInfo {
  port: number;
  protocol: string;
  service?: string;
  banner?: Banner;
}

export interface MdnsService {
  serviceType: string;
  name: string;
  hostname?: string;
  port?: number;
  address?: string;
  txt: Record<string, string>;
}

export interface SsdpRecord {
  st: string;
  usn?: string;
  server?: string;
  location?: string;
  deviceType?: string;
  friendlyName?: string;
  manufacturer?: string;
  modelName?: string;
  modelNumber?: string;
  serialNumber?: string;
}

export interface NetbiosResult {
  names: string[];
  workgroup?: string;
  mac?: string;
}

export type DeviceType =
  | "router"
  | "phone"
  | "computer"
  | "iot"
  | "media"
  | "printer"
  | "nas"
  | "camera"
  | "tv"
  | "server"
  | "unknown";

export interface Device {
  ip: string;
  mac?: string;
  vendor?: string;
  macRandomized?: boolean;
  hostnames: string[];
  displayName: string;
  deviceType: DeviceType;
  typeEvidence: string[];
  isGateway: boolean;
  isSelf: boolean;
  respondedToPing: boolean;
  discoveredBy: string[];
  latencyMs?: number;
  ports: PortInfo[];
  mdns: MdnsService[];
  ssdp: SsdpRecord[];
  netbios?: NetbiosResult;
  reverseDns?: string;
  sourceRange?: string;
  offSubnet: boolean;
  firstSeen?: string;
  lastSeen: string;

  /* Populated only when a UniFi controller is configured. */
  /** Operator-assigned alias from the controller. Outranks any inference. */
  unifiName?: string;
  /** The controller's DHCP fingerprint, e.g. "Apple · iPhone · iOS". */
  unifiFingerprint?: string;
  unifiNetwork?: string;
  /** Physical location for a wired client, e.g. "USW_MINI port 4". */
  switchPort?: string;
  /** Access point and SSID for a wireless client. */
  accessPoint?: string;
  vlan?: number;
  rssi?: number;
  isWired?: boolean;
}

/* --------------------------------------------------------------------- UniFi */

export interface UnifiConfig {
  host: string;
  port: number;
  site: string;
  username: string;
  /** SHA-256 of the controller certificate, pinned on first connection. */
  fingerprint?: string;
  enabled: boolean;
}

export interface UnifiDeviceSummary {
  mac?: string;
  ip?: string;
  name: string;
  kind: string;
  model?: string;
  version?: string;
  adopted: boolean;
  upgradable: boolean;
  uptimeSeconds?: number;
}

export interface UnifiSnapshot {
  controllerHost: string;
  site: string;
  devices: UnifiDeviceSummary[];
  warnings: string[];
}

export type ShadowReason =
  | "unknown-to-controller"
  | "address-mismatch"
  | "unidentified";

export interface ShadowDevice {
  ip: string;
  displayName: string;
  mac?: string;
  vendor?: string;
  openPorts: number[];
  reason: ShadowReason;
  explanation: string;
}

export interface MissedDevice {
  mac: string;
  name: string;
  ip?: string;
  location?: string;
  explanation: string;
}

export interface HiddenSegment {
  switchName: string;
  port: number;
  portName?: string;
  macCount: number;
  explanation: string;
}

/** Where the scan and the controller disagree — the point of the integration. */
export interface Reconciliation {
  matched: number;
  shadow: ShadowDevice[];
  missed: MissedDevice[];
  hiddenSegments: HiddenSegment[];
  identityConflicts: string[];
  summary: string;
}

/* ------------------------------------------------------------------ networks */

/** Observable facts that identify a physical network. */
export interface NetworkFingerprint {
  /** The gateway's MAC — the strongest signal, and what separates two sites
   *  that happen to share a subnet. */
  gatewayMac?: string;
  gatewayIp?: string;
  subnets: string[];
  ssid?: string;
  dnsServers: string[];
}

export type MatchStrength = "none" | "weak" | "strong" | "definitive";

export interface NetworkProfile {
  id: string;
  name: string;
  fingerprint: NetworkFingerprint;
  createdAt: string;
  lastSeenAt?: string;
  scanCount: number;
}

export interface NetworkCandidate {
  id: string;
  name: string;
  strength: MatchStrength;
}

/** What the app should do about the network it is currently attached to. */
export type Detection =
  | { kind: "current"; id: string; strength: MatchStrength }
  | { kind: "switch"; id: string; name: string; strength: MatchStrength }
  | { kind: "ambiguous"; candidates: NetworkCandidate[] }
  | { kind: "unknown"; suggestedName: string }
  | { kind: "noNetwork" };

export interface NetworkList {
  active?: string;
  networks: NetworkProfile[];
}

/* -------------------------------------------------------------------- update */

export interface UpdateInfo {
  currentVersion: string;
  latestVersion: string;
  /** True only when the release is genuinely newer and not skipped. */
  updateAvailable: boolean;
  releaseUrl: string;
  releaseNotes?: string;
  publishedAt?: string;
}

export interface UpdatePreferences {
  checkEnabled: boolean;
  skippedVersion?: string;
  lastChecked?: string;
  cachedLatest?: string;
}

/* -------------------------------------------------------------- connectivity */

export interface LatencyStats {
  target: string;
  label: string;
  sent: number;
  received: number;
  lossPercent: number;
  minMs?: number;
  avgMs?: number;
  maxMs?: number;
  jitterMs?: number;
  samples: number[];
}

export interface DnsTiming {
  server: string;
  query: string;
  ok: boolean;
  responseMs?: number;
  answers: string[];
  error?: string;
}

export interface TraceHop {
  hop: number;
  host?: string;
  rttMs?: number;
  lossPercent?: number;
  timeout: boolean;
}

export interface ConnectivityInfo {
  gateway?: LatencyStats;
  wan: LatencyStats[];
  dns: DnsTiming[];
  publicIp?: string;
  wanReachable: boolean;
  trace: ProbeResult<{ tool: string; hops: TraceHop[] }>;
}

/* ---------------------------------------------------------------------- wifi */

export interface WifiNetwork {
  ssid: string;
  bssid?: string;
  active: boolean;
  signal: number;
  channel: number;
  band: string;
  rate?: string;
  security?: string;
}

export interface ChannelUsage {
  channel: number;
  band: string;
  count: number;
  isCurrent: boolean;
}

export interface WifiInfo {
  interface?: string;
  current?: WifiNetwork;
  networks: WifiNetwork[];
  channelUsage: ChannelUsage[];
  recommendation?: string;
}

/* ------------------------------------------------------------------ snapshot */

export type ScanPhaseId =
  | "host"
  | "announce"
  | "sweep"
  | "ports"
  | "identity"
  | "connectivity"
  | "wifi"
  | "correlate";

export type PhaseStatus = "pending" | "running" | "done" | "skipped" | "error";

export interface PhaseState {
  phase: ScanPhaseId;
  label: string;
  status: PhaseStatus;
  progress?: { current: number; total: number };
  detail?: string;
}

export type PortProfile = "quick" | "standard" | "deep";

export interface ScanConfig {
  extraRanges: string[];
  portProfile: PortProfile;
  includeDiscoveredSubnets: boolean;
  sweepConcurrency: number;
  portConcurrency: number;
  portTimeoutMs: number;
}

/* ------------------------------------------------------------------- doctor */

export type Tier = "critical" | "important" | "optional";
export type CapabilityStatus = "ok" | "degraded" | "missing";

export interface CapabilityReport {
  id: string;
  label: string;
  purpose: string;
  tier: Tier;
  status: CapabilityStatus;
  tool?: string;
  detail: string;
  affects: string[];
  remedy?: string;
}

export interface DoctorCounts {
  ok: number;
  degraded: number;
  missing: number;
  criticalMissing: number;
}

export interface DoctorReport {
  os: string;
  checkedAt: string;
  capabilities: CapabilityReport[];
  /** True when a Critical capability is missing — the app cannot scan. */
  blocked: boolean;
  summary: string;
  counts: DoctorCounts;
}

/* ---------------------------------------------------------------- snapshots */

export interface ScanSnapshot {
  id: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  host: HostInfo;
  devices: Device[];
  connectivity: ConnectivityInfo;
  wifi: ProbeResult<WifiInfo>;
  phases: PhaseState[];
  warnings: string[];
  config: ScanConfig;
  capabilities: CapabilityReport[];
  /** First recorded scan — there is no baseline, so nothing counts as "new". */
  baseline: boolean;
  unifi?: UnifiSnapshot;
  reconciliation?: Reconciliation;
}

/** A device is only "new" when there was a previous scan to be absent from. */
export function isNewDevice(device: Device, snapshot: ScanSnapshot): boolean {
  return !snapshot.baseline && device.firstSeen === snapshot.startedAt;
}

/** Certificate entries are shown in the detail panel, not the compact port list. */
export function isCertificateEntry(port: PortInfo): boolean {
  return port.service?.includes("(certificate)") ?? false;
}

export interface SnapshotSummary {
  id: string;
  startedAt: string;
  durationMs: number;
  deviceCount: number;
  gatewayLatencyMs?: number;
  wanReachable: boolean;
  warnings: number;
}

export type ChangeKind =
  | "appeared"
  | "disappeared"
  | "ip-changed"
  | "ports-opened"
  | "ports-closed"
  | "name-changed";

export interface DeviceChange {
  kind: ChangeKind;
  device: Device;
  previous?: Device;
  detail: string;
}

export interface ScanDiff {
  fromId: string;
  toId: string;
  changes: DeviceChange[];
}

/* --------------------------------------------------------------------- state */

export interface AutoRepeatState {
  enabled: boolean;
  intervalMinutes: number;
  nextRunAt?: string;
}

export interface ScanStatus {
  running: boolean;
  phases: PhaseState[];
  lastSnapshotId?: string;
  autoRepeat: AutoRepeatState;
}

export type ScanEvent =
  | { type: "phase"; phases: PhaseState[] }
  | { type: "warning"; message: string }
  | { type: "done"; snapshotId: string }
  | { type: "error"; message: string }
  | { type: "cancelled" };
