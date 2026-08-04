//! Cross-platform local network discovery and diagnostics engine.
//!
//! This crate has no GUI dependency of any kind, so it builds and its tests run
//! on a machine with no desktop toolchain installed. That is deliberate: it
//! keeps the scan logic verifiable independently of the Tauri shell, and makes
//! the engine reusable from a CLI or a test harness.
//!
//! # Design notes
//!
//! * **No elevated privileges.** Host discovery relies on the system `ping`
//!   binary plus the OS's own ARP table rather than raw sockets, and port
//!   scanning is a plain TCP connect. Nothing here needs root or Administrator.
//! * **Portable where it can be.** mDNS, SSDP, NetBIOS, DNS and the port scanner
//!   are implemented directly on sockets, so they behave identically on Linux,
//!   macOS and Windows. Only the handful of things that genuinely differ —
//!   reading the ARP table, the routing table, resolver config and the Wi-Fi
//!   survey — live behind [`platform`].
//! * **Degrade, never fail.** A missing tool produces a warning and a reduced
//!   snapshot, not an error. [`doctor`] explains exactly what was lost and why.

pub mod doctor;
pub mod exec;
pub mod netutil;
pub mod networks;
pub mod oui;
pub mod platform;
pub mod scan;
pub mod store;
pub mod types;
pub mod unifi;
pub mod update;

pub use doctor::{run_diagnostics, CapabilityReport, CapabilityStatus, DoctorReport, Tier};
pub use scan::{run_scan, ScanHandle, ScanProgress};
pub use store::{diff, Store};
pub use types::*;

/// Version of the engine, surfaced in snapshots and the about panel.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
