//! Headless entry point for the engine.
//!
//! Exists so the scan and the capability doctor can be exercised on a machine
//! with no desktop toolchain — which is how the engine is verified in CI on all
//! three platforms, independently of whether the GUI builds.
//!
//! ```text
//! netdiag-cli doctor          # capability report
//! netdiag-cli scan [quick|standard|deep]
//! ```

use netdiag_core::{doctor, run_scan, types::*, ScanHandle, Store};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("doctor");

    match command {
        "doctor" => run_doctor().await,
        "scan" => {
            let profile = match args.get(2).map(|s| s.as_str()) {
                Some("quick") => PortProfile::Quick,
                Some("deep") => PortProfile::Deep,
                _ => PortProfile::Standard,
            };
            run_scan_command(profile).await;
        }
        other => {
            eprintln!(
                "Unknown command: {other}\nUsage: netdiag-cli [doctor|scan [quick|standard|deep]]"
            );
            std::process::exit(2);
        }
    }
}

async fn run_doctor() {
    let report = doctor::run_diagnostics(true).await;

    println!("Capability report — {} ({})", report.os, report.checked_at);
    println!("{}\n", report.summary);

    for capability in &report.capabilities {
        let mark = match capability.status {
            doctor::CapabilityStatus::Ok => "OK  ",
            doctor::CapabilityStatus::Degraded => "WARN",
            doctor::CapabilityStatus::Missing => "FAIL",
        };
        let tier = match capability.tier {
            doctor::Tier::Critical => "critical",
            doctor::Tier::Important => "important",
            doctor::Tier::Optional => "optional",
        };

        println!("[{mark}] {:<28} ({tier})", capability.label);
        println!("       {}", capability.detail);

        if capability.status != doctor::CapabilityStatus::Ok {
            for effect in &capability.affects {
                println!("       lost: {effect}");
            }
            if let Some(remedy) = &capability.remedy {
                println!("       fix:  {remedy}");
            }
        }
        println!();
    }

    if report.blocked {
        eprintln!("BLOCKED: {}", report.summary);
        std::process::exit(1);
    }
}

async fn run_scan_command(profile: PortProfile) {
    let store = Store::new(std::env::temp_dir().join("netdiag-cli-scans"));
    let config = ScanConfig {
        port_profile: profile,
        ..Default::default()
    };

    let result = run_scan(config, &store, ScanHandle::default(), |progress| {
        if let netdiag_core::ScanProgress::Warning(message) = progress {
            eprintln!("warning: {message}");
        }
    })
    .await;

    match result {
        Ok(snapshot) => print_snapshot(&snapshot),
        Err(error) => {
            eprintln!("Scan failed: {error}");
            std::process::exit(1);
        }
    }
}

fn print_snapshot(snapshot: &ScanSnapshot) {
    println!(
        "\nScan {} — {} devices in {:.1}s",
        snapshot.id,
        snapshot.devices.len(),
        snapshot.duration_ms as f64 / 1000.0
    );

    println!("\nTargets:");
    for target in &snapshot.host.scan_targets {
        println!(
            "  {:<18} {:?}  {} hosts  {}",
            target.cidr,
            target.source,
            target.host_count,
            target.note.clone().unwrap_or_default()
        );
    }

    println!("\nPhases:");
    for phase in &snapshot.phases {
        println!(
            "  {:<14} {:?}  {}",
            format!("{:?}", phase.phase),
            phase.status,
            phase.detail.clone().unwrap_or_default()
        );
    }

    println!("\nDevices:");
    for device in &snapshot.devices {
        let vendor = if device.mac_randomized == Some(true) {
            "[private MAC]".to_string()
        } else {
            device.vendor.clone().unwrap_or_else(|| "-".into())
        };
        let ports: Vec<String> = device.ports.iter().map(|p| p.port.to_string()).collect();

        println!(
            "  {:<15} {:<30} {:<9} {:<26} {:<18} [{}]{}",
            device.ip,
            truncate(&device.display_name, 30),
            format!("{:?}", device.device_type).to_lowercase(),
            truncate(&vendor, 26),
            device.mac.clone().unwrap_or_else(|| "-".into()),
            ports.join(","),
            if device.off_subnet { " OFF-SUBNET" } else { "" }
        );
    }

    if let Some(gateway) = &snapshot.connectivity.gateway {
        println!(
            "\nGateway: {} avg {:.2} ms, {:.0}% loss",
            gateway.target,
            gateway.avg_ms.unwrap_or(0.0),
            gateway.loss_percent
        );
    }
    println!(
        "WAN reachable: {}  public IP: {}",
        snapshot.connectivity.wan_reachable,
        snapshot
            .connectivity
            .public_ip
            .clone()
            .unwrap_or_else(|| "-".into())
    );

    if let Some(wifi) = &snapshot.wifi.data {
        if let Some(current) = &wifi.current {
            println!(
                "Wi-Fi: {} ch{} {} {}%",
                current.ssid, current.channel, current.band, current.signal
            );
        }
        if let Some(recommendation) = &wifi.recommendation {
            println!("Wi-Fi advice: {recommendation}");
        }
    }

    if !snapshot.warnings.is_empty() {
        println!("\nWarnings:");
        for warning in &snapshot.warnings {
            println!("  ! {warning}");
        }
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        text.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
    }
}
