//! Drives the full scan as a sequence of phases.
//!
//! Phase order is load-bearing:
//!
//! * `announce` runs **before** `sweep` because mDNS and SSDP reveal addresses
//!   outside the local subnet, and the sweep needs the final target list.
//! * `connectivity` runs **after** `sweep` so latency is measured on an idle
//!   link rather than one saturated by our own probes.
//!
//! A phase that fails is recorded and skipped — a scan should always produce a
//! usable snapshot, even on a host missing half the tooling.

use crate::doctor;
use crate::netutil::{is_private_ipv4, parse_cidr, ports_for_profile, to_slash24};
use crate::scan::{
    banners, connectivity, correlate, dns, hostinfo, mdns, netbios, ports, ssdp, sweep,
};
use crate::store::{apply_history, Store};
use crate::types::*;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Emitted as the scan advances so the UI can render live.
pub enum ScanProgress {
    Phases(Vec<PhaseState>),
    Warning(String),
}

/// Cancellation handle shared with the caller.
#[derive(Clone, Default)]
pub struct ScanHandle {
    cancelled: Arc<AtomicBool>,
}

impl ScanHandle {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

struct Run<F: FnMut(ScanProgress) + Send> {
    phases: Vec<PhaseState>,
    warnings: Vec<String>,
    emit: F,
    handle: ScanHandle,
}

impl<F: FnMut(ScanProgress) + Send> Run<F> {
    fn new(emit: F, handle: ScanHandle) -> Self {
        Self {
            phases: ScanPhase::ORDER
                .iter()
                .map(|phase| PhaseState {
                    phase: *phase,
                    label: phase.label().to_string(),
                    status: PhaseStatus::Pending,
                    progress: None,
                    detail: None,
                })
                .collect(),
            warnings: Vec::new(),
            emit,
            handle,
        }
    }

    fn state(&mut self, phase: ScanPhase) -> &mut PhaseState {
        self.phases
            .iter_mut()
            .find(|p| p.phase == phase)
            .expect("phase exists")
    }

    fn start(&mut self, phase: ScanPhase) {
        self.state(phase).status = PhaseStatus::Running;
        self.push();
    }

    fn finish(&mut self, phase: ScanPhase, status: PhaseStatus, detail: Option<String>) {
        let state = self.state(phase);
        state.status = status;
        if detail.is_some() {
            state.detail = detail;
        }
        self.push();
    }

    fn progress(&mut self, phase: ScanPhase, current: u64, total: u64) {
        self.state(phase).progress = Some(PhaseProgress { current, total });
        self.push();
    }

    fn push(&mut self) {
        let snapshot = self.phases.clone();
        (self.emit)(ScanProgress::Phases(snapshot));
    }

    fn warn(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.warnings.push(message.clone());
        (self.emit)(ScanProgress::Warning(message));
    }

    fn cancelled(&self) -> bool {
        self.handle.is_cancelled()
    }
}

/// `Send` on the callback is required so callers can drive a scan from a spawned
/// task — the desktop app's auto-repeat timer does exactly that.
pub async fn run_scan<F>(
    config: ScanConfig,
    store: &Store,
    handle: ScanHandle,
    emit: F,
) -> Result<ScanSnapshot, String>
where
    F: FnMut(ScanProgress) + Send,
{
    let started_at = chrono::Utc::now();
    let start_instant = std::time::Instant::now();
    let mut run = Run::new(emit, handle);

    /* ---------------------------------------------------------- phase: host */
    run.start(ScanPhase::Host);

    let (mut host, host_warnings) = hostinfo::collect(&config.extra_ranges).await;
    for warning in host_warnings {
        run.warn(warning);
    }

    let capabilities = doctor::run_diagnostics(false).await;
    if capabilities.blocked {
        let message = capabilities.summary.clone();
        run.finish(ScanPhase::Host, PhaseStatus::Error, Some(message.clone()));
        return Err(message);
    }

    for capability in &capabilities.capabilities {
        if capability.status == doctor::CapabilityStatus::Missing
            && capability.tier != doctor::Tier::Optional
        {
            run.warn(format!(
                "{} unavailable — {}",
                capability.label, capability.detail
            ));
        }
    }

    let local_cidrs: Vec<String> = host
        .scan_targets
        .iter()
        .filter(|t| t.source == TargetSource::Local)
        .map(|t| t.cidr.clone())
        .collect();

    let self_ips: Vec<Ipv4Addr> = host
        .interfaces
        .iter()
        .flat_map(|i| i.ipv4.iter())
        .filter_map(|a| a.address.parse().ok())
        .collect();

    let mut self_macs: HashMap<Ipv4Addr, String> = HashMap::new();
    for iface in &host.interfaces {
        let Some(mac) = &iface.mac else { continue };
        for addr in &iface.ipv4 {
            if let Ok(ip) = addr.address.parse::<Ipv4Addr>() {
                self_macs.insert(ip, mac.clone());
            }
        }
    }

    let target_summary = format!("{} local range(s)", local_cidrs.len());
    run.finish(ScanPhase::Host, PhaseStatus::Done, Some(target_summary));
    if run.cancelled() {
        return Err("Scan cancelled".into());
    }

    /* ------------------------------------------------------ phase: announce */
    run.start(ScanPhase::Announce);

    let multicast_interfaces: Vec<Ipv4Addr> = host
        .interfaces
        .iter()
        .filter(|i| i.scannable)
        .flat_map(|i| i.ipv4.iter())
        .filter_map(|a| a.address.parse().ok())
        .collect();

    let (mdns_result, ssdp_result) = futures::join!(
        mdns::discover(&multicast_interfaces, Duration::from_secs(8)),
        ssdp::discover(Duration::from_secs(6))
    );

    let mdns_services = match mdns_result {
        Ok(services) => services,
        Err(error) => {
            run.warn(format!("mDNS discovery unavailable: {error}"));
            Vec::new()
        }
    };

    let ssdp_by_ip = match ssdp_result {
        Ok(map) => map,
        Err(error) => {
            run.warn(format!("SSDP discovery failed: {error}"));
            HashMap::new()
        }
    };

    // Off-subnet ranges announced by mDNS/SSDP become scan targets.
    if config.include_discovered_subnets {
        let mut hinted: Vec<Ipv4Addr> = Vec::new();
        for service in &mdns_services {
            if let Some(ip) = service.address.as_ref().and_then(|a| a.parse().ok()) {
                hinted.push(ip);
            }
        }
        for ip in ssdp_by_ip.keys() {
            if let Ok(ip) = ip.parse::<Ipv4Addr>() {
                hinted.push(ip);
            }
        }

        for ip in hinted {
            if !is_private_ipv4(ip) {
                continue;
            }
            let already = host.scan_targets.iter().any(|target| {
                parse_cidr(&target.cidr)
                    .map(|c| c.contains(ip))
                    .unwrap_or(false)
            });
            if already {
                continue;
            }

            let cidr = to_slash24(ip);
            if host.scan_targets.iter().any(|t| t.cidr == cidr) {
                continue;
            }
            let Ok(parsed) = parse_cidr(&cidr) else {
                continue;
            };

            host.scan_targets.push(ScanTarget {
                cidr: cidr.clone(),
                source: TargetSource::Discovered,
                host_count: parsed.host_count(),
                note: Some(format!("announced by a device at {ip}")),
            });
            run.warn(format!(
                "Discovered off-subnet range {cidr} announced by {ip} — including it in the scan"
            ));
        }
    }

    run.finish(
        ScanPhase::Announce,
        PhaseStatus::Done,
        Some(format!(
            "{} mDNS service(s), {} UPnP host(s)",
            mdns_services.len(),
            ssdp_by_ip.len()
        )),
    );
    if run.cancelled() {
        return Err("Scan cancelled".into());
    }

    /* --------------------------------------------------------- phase: sweep */
    run.start(ScanPhase::Sweep);

    let mut all_ips: Vec<Ipv4Addr> = Vec::new();
    for target in &host.scan_targets {
        if let Ok(parsed) = parse_cidr(&target.cidr) {
            all_ips.extend(parsed.hosts());
        }
    }
    all_ips.sort_unstable();
    all_ips.dedup();

    let sweep_result = {
        let mut pending: Vec<(u64, u64)> = Vec::new();
        let result = sweep::sweep(&all_ips, config.sweep_concurrency, |done, total| {
            pending.push((done, total));
        })
        .await;
        if let Some((done, total)) = pending.last() {
            run.progress(ScanPhase::Sweep, *done, *total);
        }
        result
    };

    run.finish(
        ScanPhase::Sweep,
        PhaseStatus::Done,
        Some(format!(
            "{} host(s) replied, {} MAC(s) resolved",
            sweep_result.alive.len(),
            sweep_result.neighbors.len()
        )),
    );
    if run.cancelled() {
        return Err("Scan cancelled".into());
    }

    /* --------------------------------------------------------- phase: ports */
    run.start(ScanPhase::Ports);

    // Scan every address in range, not just ping responders — plenty of devices
    // drop ICMP but happily accept TCP, and this is where they are found.
    let port_list = ports_for_profile(config.port_profile);
    let port_result = {
        let mut latest: Option<(u64, u64)> = None;
        let result = ports::scan(
            &all_ips,
            port_list,
            config.port_concurrency,
            Duration::from_millis(config.port_timeout_ms),
            |done, total| latest = Some((done, total)),
        )
        .await;
        if let Some((done, total)) = latest {
            run.progress(ScanPhase::Ports, done, total);
        }
        result
    };

    let open_count: usize = port_result.open.values().map(|v| v.len()).sum();
    run.finish(
        ScanPhase::Ports,
        PhaseStatus::Done,
        Some(format!(
            "{open_count} open port(s) across {} host(s)",
            port_result.open.len()
        )),
    );
    if run.cancelled() {
        return Err("Scan cancelled".into());
    }

    /* ------------------------------------------------------ phase: identity */
    run.start(ScanPhase::Identity);

    // The TCP phase will have populated ARP entries for hosts that ignored ICMP.
    let mut neighbors = sweep_result.neighbors.clone();
    sweep::refresh_neighbors(&mut neighbors).await;

    let mut live_ips: Vec<Ipv4Addr> = sweep_result
        .alive
        .keys()
        .copied()
        .chain(port_result.open.keys().copied())
        .chain(port_result.refused_hosts.iter().copied())
        .chain(neighbors.keys().copied())
        .filter(|ip| all_ips.binary_search(ip).is_ok())
        .collect();
    live_ips.sort_unstable();
    live_ips.dedup();

    let banner_tasks: Vec<(Ipv4Addr, u16)> = port_result
        .open
        .iter()
        .flat_map(|(ip, list)| {
            list.iter()
                .filter(|p| banners::is_banner_port(p.port))
                .map(move |p| (*ip, p.port))
        })
        .collect();

    let (netbios_results, reverse_dns, banner_map) = futures::join!(
        netbios::discover(&live_ips, 32, Duration::from_millis(1500)),
        dns::reverse_lookup_many(
            &live_ips,
            &host.dns.servers,
            16,
            Duration::from_millis(1500)
        ),
        banners::grab(&banner_tasks, 24)
    );

    run.finish(
        ScanPhase::Identity,
        PhaseStatus::Done,
        Some(format!(
            "{} NetBIOS, {} rDNS, {} banner(s)",
            netbios_results.len(),
            reverse_dns.len(),
            banner_map.len()
        )),
    );
    if run.cancelled() {
        return Err("Scan cancelled".into());
    }

    /* -------------------------------------------------- phase: connectivity */
    run.start(ScanPhase::Connectivity);

    let connectivity_info = connectivity::collect(
        host.gateway.as_ref().map(|g| g.ip.as_str()),
        &host.dns.servers,
    )
    .await;

    if !connectivity_info.wan_reachable {
        run.warn("WAN appears unreachable — no external target responded");
    }

    let gateway_detail = connectivity_info
        .gateway
        .as_ref()
        .and_then(|g| g.avg_ms)
        .map(|ms| format!("gateway {ms:.1} ms"));
    run.finish(ScanPhase::Connectivity, PhaseStatus::Done, gateway_detail);
    if run.cancelled() {
        return Err("Scan cancelled".into());
    }

    /* ---------------------------------------------------------- phase: wifi */
    run.start(ScanPhase::Wifi);
    let wifi = crate::platform::wifi_survey().await;
    match wifi.status {
        ProbeStatus::Ok => {
            let detail = wifi
                .data
                .as_ref()
                .and_then(|w| w.current.as_ref())
                .map(|c| format!("{} @ {}%", c.ssid, c.signal));
            run.finish(ScanPhase::Wifi, PhaseStatus::Done, detail);
        }
        _ => {
            let detail = wifi.detail.clone();
            run.finish(ScanPhase::Wifi, PhaseStatus::Skipped, detail);
        }
    }
    if run.cancelled() {
        return Err("Scan cancelled".into());
    }

    /* ----------------------------------------------------- phase: correlate */
    run.start(ScanPhase::Correlate);

    let devices = correlate::correlate(correlate::CorrelateInput {
        alive: sweep_result.alive,
        neighbors,
        open_ports: port_result.open,
        refused_hosts: port_result.refused_hosts.into_iter().collect(),
        mdns: mdns_services,
        ssdp: ssdp_by_ip,
        netbios: netbios_results,
        reverse_dns,
        banners: banner_map,
        gateway_ip: host.gateway.as_ref().and_then(|g| g.ip.parse().ok()),
        self_ips,
        self_macs,
        targets: host.scan_targets.clone(),
        local_cidrs,
    });

    let device_count = devices.len();
    // Close the phase before building the snapshot, or the saved copy records
    // `correlate` as still running forever.
    run.finish(
        ScanPhase::Correlate,
        PhaseStatus::Done,
        Some(format!("{device_count} device(s)")),
    );

    let finished_at = chrono::Utc::now();
    let mut snapshot = ScanSnapshot {
        id: Store::make_id(started_at),
        started_at: started_at.to_rfc3339(),
        finished_at: finished_at.to_rfc3339(),
        duration_ms: start_instant.elapsed().as_millis() as u64,
        host,
        devices,
        connectivity: connectivity_info,
        wifi,
        phases: run.phases.clone(),
        warnings: run.warnings.clone(),
        config,
        capabilities: capabilities.capabilities,
        // Set by `apply_history` once the previous snapshot is known.
        baseline: false,
    };

    let previous = store.load_latest().await;
    apply_history(&mut snapshot, previous.as_ref());

    store.save(&snapshot).await?;
    Ok(snapshot)
}
