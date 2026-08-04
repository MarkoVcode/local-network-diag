//! The scan pipeline.

pub mod banners;
pub mod connectivity;
pub mod correlate;
pub mod dns;
pub mod dnsmsg;
pub mod hostinfo;
pub mod http;
pub mod mdns;
pub mod netbios;
pub mod ports;
pub mod ssdp;
pub mod sweep;
pub mod wifi;

mod orchestrator;
pub use orchestrator::{run_scan, ScanHandle, ScanProgress};
