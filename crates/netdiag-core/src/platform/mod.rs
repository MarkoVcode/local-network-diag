//! Per-OS implementations of everything that cannot be done portably.
//!
//! The engine calls only the functions re-exported here; each target OS supplies
//! its own module. Anything that *can* be done portably (TCP scanning, mDNS,
//! SSDP, NetBIOS, interface enumeration) deliberately lives outside this layer,
//! so the OS-specific surface stays small and the same discovery logic runs
//! everywhere.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub use linux as imp;
#[cfg(target_os = "macos")]
pub use macos as imp;
#[cfg(target_os = "windows")]
pub use windows as imp;

use std::net::Ipv4Addr;

/// The tool a capability depends on, per OS, so the doctor can name it precisely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolRef {
    pub command: &'static str,
    /// How to obtain it, phrased for this OS.
    pub remedy: &'static str,
}

pub use imp::{
    default_gateway, dns_servers, neighbor_table, ping_args, ping_supports_flood, traceroute,
    wifi_survey, ARP_TOOL, PING_TOOL, TRACE_TOOL, WIFI_TOOL,
};

/// One entry of the ARP/neighbour table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbor {
    pub ip: Ipv4Addr,
    pub mac: String,
}

/// Human-readable OS name for the snapshot header.
pub fn os_label() -> String {
    #[cfg(target_os = "linux")]
    {
        "Linux".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "macOS".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        "Windows".to_string()
    }
}
