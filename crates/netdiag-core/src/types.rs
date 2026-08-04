//! Shared data model.
//!
//! Everything the UI renders comes from a [`ScanSnapshot`], which is a complete,
//! self-contained record of one run. Probe results carry an explicit status so a
//! missing tool degrades the snapshot rather than failing the scan.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/* ------------------------------------------------------------- probe results */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeStatus {
    Ok,
    Unavailable,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult<T> {
    pub status: ProbeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T> ProbeResult<T> {
    pub fn ok(data: T) -> Self {
        Self {
            status: ProbeStatus::Ok,
            detail: None,
            data: Some(data),
        }
    }

    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Unavailable,
            detail: Some(detail.into()),
            data: None,
        }
    }

    pub fn error(detail: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Error,
            detail: Some(detail.into()),
            data: None,
        }
    }
}

/* ---------------------------------------------------------------- host / link */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ipv4Addr4 {
    pub address: String,
    pub cidr: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ipv6Addr6 {
    pub address: String,
    pub cidr: u8,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceInfo {
    pub name: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    pub flags: Vec<String>,
    pub ipv4: Vec<Ipv4Addr4>,
    pub ipv6: Vec<Ipv6Addr6>,
    /// Interface carrying the default route.
    pub is_primary: bool,
    pub scannable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteInfo {
    pub destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    pub dev: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metric: Option<u32>,
    pub raw: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsConfig {
    pub servers: Vec<String>,
    pub search_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Gateway {
    pub ip: String,
    pub dev: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetSource {
    Local,
    Discovered,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanTarget {
    pub cidr: String,
    pub source: TargetSource,
    pub host_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInfo {
    pub hostname: String,
    pub platform: String,
    pub os: String,
    pub arch: String,
    pub app_version: String,
    pub interfaces: Vec<InterfaceInfo>,
    pub routes: Vec<RouteInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Gateway>,
    pub dns: DnsConfig,
    pub scan_targets: Vec<ScanTarget>,
}

/* --------------------------------------------------------------- device data */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Banner {
    #[serde(rename_all = "camelCase")]
    Http {
        scheme: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        server: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        headers: BTreeMap<String, String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        redirect_location: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Tls {
        #[serde(skip_serializing_if = "Option::is_none")]
        subject: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        issuer: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        alt_names: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        valid_from: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        valid_to: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        days_until_expiry: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        self_signed: Option<bool>,
    },
    #[serde(rename_all = "camelCase")]
    Text { text: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<Banner>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MdnsService {
    /// e.g. `_esphomelib._tcp`
    pub service_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub txt: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsdpRecord {
    pub st: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub friendly_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetbiosResult {
    pub names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workgroup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Router,
    Phone,
    Computer,
    Iot,
    Media,
    Printer,
    Nas,
    Camera,
    Tv,
    Server,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Locally-administered MACs are chosen by the device, so a vendor lookup
    /// would be meaningless — flagged instead of guessed at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_randomized: Option<bool>,
    pub hostnames: Vec<String>,
    pub display_name: String,
    pub device_type: DeviceType,
    pub type_evidence: Vec<String>,
    pub is_gateway: bool,
    pub is_self: bool,
    pub responded_to_ping: bool,
    pub discovered_by: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    pub ports: Vec<PortInfo>,
    pub mdns: Vec<MdnsService>,
    pub ssdp: Vec<SsdpRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netbios: Option<NetbiosResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_dns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_range: Option<String>,
    pub off_subnet: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    pub last_seen: String,
}

/* -------------------------------------------------------------- connectivity */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LatencyStats {
    pub target: String,
    pub label: String,
    pub sent: u32,
    pub received: u32,
    pub loss_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jitter_ms: Option<f64>,
    pub samples: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsTiming {
    pub server: String,
    pub query: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_ms: Option<u64>,
    pub answers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceHop {
    pub hop: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loss_percent: Option<f64>,
    pub timeout: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceResult {
    pub tool: String,
    pub hops: Vec<TraceHop>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectivityInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<LatencyStats>,
    pub wan: Vec<LatencyStats>,
    pub dns: Vec<DnsTiming>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
    pub wan_reachable: bool,
    pub trace: ProbeResult<TraceResult>,
}

/* ---------------------------------------------------------------------- wifi */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WifiNetwork {
    pub ssid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bssid: Option<String>,
    pub active: bool,
    pub signal: u8,
    pub channel: u32,
    pub band: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelUsage {
    pub channel: u32,
    pub band: String,
    pub count: u32,
    pub is_current: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WifiInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<WifiNetwork>,
    pub networks: Vec<WifiNetwork>,
    pub channel_usage: Vec<ChannelUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
}

/* ------------------------------------------------------------------ snapshot */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanPhase {
    Host,
    Announce,
    Sweep,
    Ports,
    Identity,
    Connectivity,
    Wifi,
    Correlate,
}

impl ScanPhase {
    pub const ORDER: [ScanPhase; 8] = [
        ScanPhase::Host,
        ScanPhase::Announce,
        ScanPhase::Sweep,
        ScanPhase::Ports,
        ScanPhase::Identity,
        ScanPhase::Connectivity,
        ScanPhase::Wifi,
        ScanPhase::Correlate,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            ScanPhase::Host => "Interfaces, routes & DNS",
            ScanPhase::Announce => "mDNS & UPnP announcements",
            ScanPhase::Sweep => "Ping sweep & MAC harvest",
            ScanPhase::Ports => "TCP port scan",
            ScanPhase::Identity => "NetBIOS, reverse DNS & banners",
            ScanPhase::Connectivity => "Latency, DNS & path",
            ScanPhase::Wifi => "Wi-Fi & channel survey",
            ScanPhase::Correlate => "Correlating results",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PhaseStatus {
    Pending,
    Running,
    Done,
    Skipped,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhaseProgress {
    pub current: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhaseState {
    pub phase: ScanPhase,
    pub label: String,
    pub status: PhaseStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<PhaseProgress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PortProfile {
    Quick,
    #[default]
    Standard,
    Deep,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanConfig {
    pub extra_ranges: Vec<String>,
    pub port_profile: PortProfile,
    pub include_discovered_subnets: bool,
    pub sweep_concurrency: usize,
    pub port_concurrency: usize,
    pub port_timeout_ms: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            extra_ranges: Vec::new(),
            port_profile: PortProfile::Standard,
            include_discovered_subnets: true,
            sweep_concurrency: 64,
            port_concurrency: 400,
            port_timeout_ms: 1200,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSnapshot {
    pub id: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    pub host: HostInfo,
    pub devices: Vec<Device>,
    pub connectivity: ConnectivityInfo,
    pub wifi: ProbeResult<WifiInfo>,
    pub phases: Vec<PhaseState>,
    pub warnings: Vec<String>,
    pub config: ScanConfig,
    /// True when this is the first recorded scan. Without a previous run there is
    /// no baseline, so every device would otherwise be flagged "new" — which is
    /// both meaningless and alarming on first launch.
    #[serde(default)]
    pub baseline: bool,
    /// Capability report captured at scan time, so a stored snapshot explains
    /// its own gaps rather than being judged against today's environment.
    pub capabilities: Vec<crate::doctor::CapabilityReport>,
}

/* --------------------------------------------------------------------- diff */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    Appeared,
    Disappeared,
    IpChanged,
    PortsOpened,
    PortsClosed,
    NameChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceChange {
    pub kind: ChangeKind,
    pub device: Device,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<Device>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanDiff {
    pub from_id: String,
    pub to_id: String,
    pub changes: Vec<DeviceChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotSummary {
    pub id: String,
    pub started_at: String,
    pub duration_ms: u64,
    pub device_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_latency_ms: Option<f64>,
    pub wan_reachable: bool,
    pub warnings: usize,
}

/* --------------------------------------------------------------- scan events */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ScanEvent {
    #[serde(rename_all = "camelCase")]
    Phase { phases: Vec<PhaseState> },
    #[serde(rename_all = "camelCase")]
    Warning { message: String },
    #[serde(rename_all = "camelCase")]
    Done { snapshot_id: String },
    #[serde(rename_all = "camelCase")]
    Error { message: String },
    #[serde(rename_all = "camelCase")]
    Cancelled,
}
