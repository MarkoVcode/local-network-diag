//! Folds every probe's output into one [`Device`] per address.
//!
//! Each source knows something the others do not — mDNS has friendly names, SSDP
//! has model numbers, the neighbour table has MACs, open ports imply role. The
//! merge records *why* it concluded something (`type_evidence`, `discovered_by`)
//! so a surprising classification can be audited rather than merely distrusted.

use crate::netutil::parse_cidr;
use crate::oui::lookup_vendor;
use crate::types::{
    Banner, Device, DeviceType, MdnsService, NetbiosResult, PortInfo, ScanTarget, SsdpRecord,
};
use std::collections::HashMap;
use std::net::Ipv4Addr;

pub struct CorrelateInput {
    pub alive: HashMap<Ipv4Addr, Option<f64>>,
    pub neighbors: HashMap<Ipv4Addr, String>,
    pub open_ports: HashMap<Ipv4Addr, Vec<PortInfo>>,
    pub refused_hosts: Vec<Ipv4Addr>,
    pub mdns: Vec<MdnsService>,
    pub ssdp: HashMap<String, Vec<SsdpRecord>>,
    pub netbios: Vec<(Ipv4Addr, NetbiosResult)>,
    pub reverse_dns: Vec<(Ipv4Addr, String)>,
    pub banners: HashMap<String, Banner>,
    pub gateway_ip: Option<Ipv4Addr>,
    pub self_ips: Vec<Ipv4Addr>,
    /// This machine's own addresses never appear in its own ARP table.
    pub self_macs: HashMap<Ipv4Addr, String>,
    pub targets: Vec<ScanTarget>,
    pub local_cidrs: Vec<String>,
}

/// Vendor substrings that reliably imply a device class.
const VENDOR_HINTS: &[(&str, DeviceType, &str)] = &[
    (
        "espressif",
        DeviceType::Iot,
        "Espressif (ESP8266/ESP32) MAC",
    ),
    (
        "ubiquiti",
        DeviceType::Router,
        "networking-equipment vendor",
    ),
    (
        "mikrotik",
        DeviceType::Router,
        "networking-equipment vendor",
    ),
    ("tp-link", DeviceType::Router, "networking-equipment vendor"),
    ("netgear", DeviceType::Router, "networking-equipment vendor"),
    ("d-link", DeviceType::Router, "networking-equipment vendor"),
    ("zyxel", DeviceType::Router, "networking-equipment vendor"),
    ("avm ", DeviceType::Router, "networking-equipment vendor"),
    ("apple", DeviceType::Phone, "Apple MAC"),
    ("samsung", DeviceType::Phone, "mobile-device vendor"),
    ("xiaomi", DeviceType::Phone, "mobile-device vendor"),
    ("huawei", DeviceType::Phone, "mobile-device vendor"),
    ("oneplus", DeviceType::Phone, "mobile-device vendor"),
    ("raspberry", DeviceType::Computer, "Raspberry Pi MAC"),
    ("intel", DeviceType::Computer, "PC-hardware vendor"),
    ("dell", DeviceType::Computer, "PC-hardware vendor"),
    ("lenovo", DeviceType::Computer, "PC-hardware vendor"),
    ("hewlett", DeviceType::Computer, "PC-hardware vendor"),
    ("canon", DeviceType::Printer, "printer vendor"),
    ("epson", DeviceType::Printer, "printer vendor"),
    ("brother", DeviceType::Printer, "printer vendor"),
    ("synology", DeviceType::Nas, "NAS vendor"),
    ("qnap", DeviceType::Nas, "NAS vendor"),
    ("hikvision", DeviceType::Camera, "camera vendor"),
    ("dahua", DeviceType::Camera, "camera vendor"),
    ("reolink", DeviceType::Camera, "camera vendor"),
    ("sonos", DeviceType::Media, "media-device vendor"),
    ("roku", DeviceType::Media, "media-device vendor"),
    ("amazon", DeviceType::Media, "media-device vendor"),
    ("google", DeviceType::Media, "media-device vendor"),
    ("technisat", DeviceType::Tv, "TV/set-top vendor"),
    (
        "advanced digital broadcast",
        DeviceType::Tv,
        "TV/set-top vendor",
    ),
    ("frontier silicon", DeviceType::Media, "audio-device vendor"),
    ("lg electronics", DeviceType::Tv, "TV/set-top vendor"),
    ("sony", DeviceType::Tv, "TV/set-top vendor"),
];

const MDNS_HINTS: &[(&str, DeviceType, &str)] = &[
    ("_esphomelib", DeviceType::Iot, "IoT service advertised"),
    ("_matter", DeviceType::Iot, "IoT service advertised"),
    ("_hap", DeviceType::Iot, "HomeKit service advertised"),
    (
        "_home-assistant",
        DeviceType::Server,
        "Home Assistant advertised",
    ),
    (
        "_esphomebuilder",
        DeviceType::Server,
        "ESPHome Builder advertised",
    ),
    ("_googlecast", DeviceType::Media, "media service advertised"),
    ("_airplay", DeviceType::Media, "media service advertised"),
    ("_raop", DeviceType::Media, "media service advertised"),
    ("_sonos", DeviceType::Media, "media service advertised"),
    (
        "_plexmediasvr",
        DeviceType::Media,
        "media service advertised",
    ),
    (
        "_printer",
        DeviceType::Printer,
        "printing service advertised",
    ),
    ("_ipp", DeviceType::Printer, "printing service advertised"),
    (
        "_pdl-datastream",
        DeviceType::Printer,
        "printing service advertised",
    ),
    (
        "_scanner",
        DeviceType::Printer,
        "scanning service advertised",
    ),
    ("_smb", DeviceType::Nas, "file-sharing service advertised"),
    (
        "_afpovertcp",
        DeviceType::Nas,
        "file-sharing service advertised",
    ),
    ("_nfs", DeviceType::Nas, "file-sharing service advertised"),
    ("_adisk", DeviceType::Nas, "Time Machine target advertised"),
    (
        "_companion-link",
        DeviceType::Phone,
        "Apple device service advertised",
    ),
    (
        "_remotepairing",
        DeviceType::Phone,
        "Apple device service advertised",
    ),
    (
        "_workstation",
        DeviceType::Computer,
        "workstation service advertised",
    ),
];

const PORT_HINTS: &[(&[u16], DeviceType, &str)] = &[
    (&[6053], DeviceType::Iot, "ESPHome API port open"),
    (&[8123], DeviceType::Server, "Home Assistant port open"),
    (&[9100, 515, 631], DeviceType::Printer, "printing port open"),
    (
        &[32400, 8096, 8008, 8009, 8060, 1400, 7000],
        DeviceType::Media,
        "media-server port open",
    ),
    (&[445, 548, 2049], DeviceType::Nas, "file-sharing port open"),
    (&[554], DeviceType::Camera, "RTSP port open"),
    (
        &[3389, 5900],
        DeviceType::Computer,
        "remote-desktop port open",
    ),
    (
        &[3306, 5432, 27017, 6379, 9200],
        DeviceType::Server,
        "database port open",
    ),
];

fn classify(device: &Device, vendor: Option<&str>) -> (DeviceType, Vec<String>) {
    // The gateway and this machine are known outright — no inference needed.
    if device.is_gateway {
        return (DeviceType::Router, vec!["carries the default route".into()]);
    }
    if device.is_self {
        return (DeviceType::Computer, vec!["this machine".into()]);
    }

    let mut votes: HashMap<DeviceType, u32> = HashMap::new();
    let mut evidence: Vec<String> = Vec::new();

    let mut vote = |kind: DeviceType, weight: u32, label: &str, evidence: &mut Vec<String>| {
        *votes.entry(kind).or_insert(0) += weight;
        if !evidence.iter().any(|e| e == label) {
            evidence.push(label.to_string());
        }
    };

    let mdns_types = device
        .mdns
        .iter()
        .map(|s| s.service_type.as_str())
        .collect::<Vec<_>>()
        .join(" ");

    for (needle, kind, label) in MDNS_HINTS {
        if mdns_types.contains(needle) {
            vote(*kind, 3, label, &mut evidence);
        }
    }

    let ports: Vec<u16> = device.ports.iter().map(|p| p.port).collect();
    for (hint_ports, kind, label) in PORT_HINTS {
        if hint_ports.iter().any(|p| ports.contains(p)) {
            vote(*kind, 2, label, &mut evidence);
        }
    }

    if let Some(vendor) = vendor {
        let lower = vendor.to_ascii_lowercase();
        for (needle, kind, label) in VENDOR_HINTS {
            if lower.contains(needle) {
                vote(*kind, 1, label, &mut evidence);
                break;
            }
        }
    }

    for record in &device.ssdp {
        let device_type = record.device_type.as_deref().unwrap_or("");
        if device_type.contains("MediaRenderer") || device_type.contains("MediaServer") {
            vote(DeviceType::Media, 2, "UPnP media device", &mut evidence);
        }
        if device_type.contains("InternetGatewayDevice") {
            vote(DeviceType::Router, 3, "UPnP gateway device", &mut evidence);
        }
        if device_type.contains("Printer") {
            vote(DeviceType::Printer, 2, "UPnP printer", &mut evidence);
        }
    }

    if device
        .netbios
        .as_ref()
        .map(|n| !n.names.is_empty())
        .unwrap_or(false)
    {
        vote(
            DeviceType::Computer,
            1,
            "answers NetBIOS name query",
            &mut evidence,
        );
    }

    let best = votes.into_iter().max_by_key(|(_, weight)| *weight);
    match best {
        Some((kind, _)) => (kind, evidence),
        None => (DeviceType::Unknown, Vec::new()),
    }
}

/// Picks the most human-meaningful name available, in descending order of quality.
fn choose_display_name(device: &Device, vendor: Option<&str>) -> String {
    if let Some(hostname) = device.mdns.iter().find_map(|s| s.hostname.as_ref()) {
        let clean = hostname.trim_end_matches('.').trim_end_matches(".local");
        if !clean.is_empty() {
            return clean.to_string();
        }
    }

    // Skip instance names that are bare UUIDs — they identify nothing to a human.
    let looks_like_uuid =
        |name: &str| name.len() >= 20 && name.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    if let Some(name) = device
        .mdns
        .iter()
        .map(|s| s.name.as_str())
        .find(|name| !name.is_empty() && !looks_like_uuid(name))
    {
        return name.to_string();
    }

    if let Some(name) = device.ssdp.iter().find_map(|s| s.friendly_name.as_ref()) {
        return name.clone();
    }

    if let Some(name) = device.netbios.as_ref().and_then(|n| n.names.first()) {
        return name.clone();
    }

    if let Some(name) = &device.reverse_dns {
        return name.trim_end_matches('.').to_string();
    }

    if let Some(title) = device.ports.iter().find_map(|p| match &p.banner {
        Some(Banner::Http {
            title: Some(title), ..
        }) => Some(title.clone()),
        _ => None,
    }) {
        return title;
    }

    if device.is_gateway {
        return "Gateway".into();
    }

    match vendor {
        Some(vendor) => format!("{vendor} device"),
        None => device.ip.clone(),
    }
}

pub fn correlate(input: CorrelateInput) -> Vec<Device> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut devices: HashMap<Ipv4Addr, Device> = HashMap::new();

    let local_cidrs: Vec<_> = input
        .local_cidrs
        .iter()
        .filter_map(|c| parse_cidr(c).ok())
        .collect();

    let ensure = |devices: &mut HashMap<Ipv4Addr, Device>, ip: Ipv4Addr, source: &str| {
        let device = devices.entry(ip).or_insert_with(|| Device {
            ip: ip.to_string(),
            mac: None,
            vendor: None,
            mac_randomized: None,
            hostnames: Vec::new(),
            display_name: ip.to_string(),
            device_type: DeviceType::Unknown,
            type_evidence: Vec::new(),
            is_gateway: Some(ip) == input.gateway_ip,
            is_self: input.self_ips.contains(&ip),
            responded_to_ping: false,
            discovered_by: Vec::new(),
            latency_ms: None,
            ports: Vec::new(),
            mdns: Vec::new(),
            ssdp: Vec::new(),
            netbios: None,
            reverse_dns: None,
            source_range: None,
            off_subnet: !local_cidrs.iter().any(|cidr| cidr.contains(ip)),
            first_seen: None,
            last_seen: now.clone(),
        });
        if !device.discovered_by.iter().any(|s| s == source) {
            device.discovered_by.push(source.to_string());
        }
    };

    for (ip, latency) in &input.alive {
        ensure(&mut devices, *ip, "icmp");
        if let Some(device) = devices.get_mut(ip) {
            device.responded_to_ping = true;
            device.latency_ms = *latency;
        }
    }

    // A refused TCP connection proves the host is up even though it ignored ICMP.
    for ip in &input.refused_hosts {
        ensure(&mut devices, *ip, "tcp-refused");
    }

    for (ip, ports) in &input.open_ports {
        ensure(&mut devices, *ip, "tcp");
        if let Some(device) = devices.get_mut(ip) {
            device.ports.clone_from(ports);
        }
    }

    // Only attach MACs to hosts we already have evidence for; a stale cache entry
    // for a departed device must not resurrect it as a live host.
    for (ip, mac) in &input.neighbors {
        if let Some(device) = devices.get_mut(ip) {
            device.mac = Some(mac.clone());
        }
    }
    for (ip, mac) in &input.self_macs {
        if let Some(device) = devices.get_mut(ip) {
            if device.mac.is_none() {
                device.mac = Some(mac.clone());
            }
        }
    }

    for service in &input.mdns {
        let Some(address) = service
            .address
            .as_ref()
            .and_then(|a| a.parse::<Ipv4Addr>().ok())
        else {
            continue;
        };
        ensure(&mut devices, address, "mdns");
        if let Some(device) = devices.get_mut(&address) {
            device.mdns.push(service.clone());
            if let Some(hostname) = &service.hostname {
                let clean = hostname.trim_end_matches('.').to_string();
                if !clean.is_empty() && !device.hostnames.contains(&clean) {
                    device.hostnames.push(clean);
                }
            }
        }
    }

    for (ip_text, records) in &input.ssdp {
        let Ok(ip) = ip_text.parse::<Ipv4Addr>() else {
            continue;
        };
        ensure(&mut devices, ip, "ssdp");
        if let Some(device) = devices.get_mut(&ip) {
            device.ssdp.clone_from(records);
        }
    }

    for (ip, result) in &input.netbios {
        ensure(&mut devices, *ip, "netbios");
        if let Some(device) = devices.get_mut(ip) {
            for name in &result.names {
                if !device.hostnames.contains(name) {
                    device.hostnames.push(name.clone());
                }
            }
            // NetBIOS reports the adapter MAC directly, useful where ARP missed it.
            if device.mac.is_none() {
                device.mac.clone_from(&result.mac);
            }
            device.netbios = Some(result.clone());
        }
    }

    for (ip, name) in &input.reverse_dns {
        if let Some(device) = devices.get_mut(ip) {
            let clean = name.trim_end_matches('.').to_string();
            device.reverse_dns = Some(clean.clone());
            if !device.hostnames.contains(&clean) {
                device.hostnames.push(clean);
            }
        }
    }

    // Attach banners, keeping a TLS certificate as a sibling entry when the HTTP
    // view won the port's main slot.
    for device in devices.values_mut() {
        let mut extras: Vec<PortInfo> = Vec::new();

        for port in device.ports.iter_mut() {
            let key = format!("{}:{}", device.ip, port.port);
            if let Some(banner) = input.banners.get(&key) {
                port.banner = Some(banner.clone());
            }
            if let Some(tls) = input.banners.get(&format!("{key}:tls")) {
                if matches!(port.banner, Some(Banner::Http { .. })) {
                    extras.push(PortInfo {
                        port: port.port,
                        protocol: "tcp".into(),
                        service: Some(format!(
                            "{} (certificate)",
                            port.service.clone().unwrap_or_else(|| "tls".into())
                        )),
                        banner: Some(tls.clone()),
                    });
                }
            }
        }

        device.ports.extend(extras);
        device.ports.sort_by_key(|p| p.port);

        // Stable ordering so the chosen display name does not depend on the order
        // records happened to arrive in.
        device.mdns.sort_by(|a, b| {
            a.service_type
                .cmp(&b.service_type)
                .then_with(|| a.name.cmp(&b.name))
        });
    }

    // Vendor lookup and classification, once everything else is merged.
    for device in devices.values_mut() {
        let lookup = lookup_vendor(device.mac.as_deref());
        device.vendor = lookup.vendor.clone();
        device.mac_randomized = device.mac.as_ref().map(|_| lookup.randomized);

        let (kind, evidence) = classify(device, lookup.vendor.as_deref());
        device.device_type = kind;
        device.type_evidence = evidence;
        device.display_name = choose_display_name(device, lookup.vendor.as_deref());

        if let Ok(ip) = device.ip.parse::<Ipv4Addr>() {
            device.source_range = input
                .targets
                .iter()
                .find(|target| {
                    parse_cidr(&target.cidr)
                        .map(|c| c.contains(ip))
                        .unwrap_or(false)
                })
                .map(|target| target.cidr.clone());
        }
    }

    let mut list: Vec<Device> = devices.into_values().collect();
    list.sort_by(|a, b| {
        // Gateway first, then this machine, then by address.
        b.is_gateway
            .cmp(&a.is_gateway)
            .then_with(|| b.is_self.cmp(&a.is_self))
            .then_with(|| {
                let left = a.ip.parse::<Ipv4Addr>().map(u32::from).unwrap_or(0);
                let right = b.ip.parse::<Ipv4Addr>().map(u32::from).unwrap_or(0);
                left.cmp(&right)
            })
    });

    list
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn base_input() -> CorrelateInput {
        CorrelateInput {
            alive: HashMap::new(),
            neighbors: HashMap::new(),
            open_ports: HashMap::new(),
            refused_hosts: Vec::new(),
            mdns: Vec::new(),
            ssdp: HashMap::new(),
            netbios: Vec::new(),
            reverse_dns: Vec::new(),
            banners: HashMap::new(),
            gateway_ip: None,
            self_ips: Vec::new(),
            self_macs: HashMap::new(),
            targets: Vec::new(),
            local_cidrs: vec!["10.0.3.0/24".into()],
        }
    }

    #[test]
    fn identifies_the_gateway_from_the_routing_table_not_inference() {
        let ip: Ipv4Addr = "10.0.3.1".parse().unwrap();
        let mut input = base_input();
        input.gateway_ip = Some(ip);
        input.alive.insert(ip, Some(1.8));
        input.neighbors.insert(ip, "e0:63:da:82:1b:35".into());

        let devices = correlate(input);
        let gateway = &devices[0];
        assert!(gateway.is_gateway);
        assert_eq!(gateway.device_type, DeviceType::Router);
        assert_eq!(gateway.vendor.as_deref(), Some("Ubiquiti"));
        assert_eq!(
            gateway.type_evidence,
            vec!["carries the default route".to_string()]
        );
    }

    #[test]
    fn classifies_an_esphome_node_from_mdns_and_port() {
        let ip: Ipv4Addr = "10.0.3.22".parse().unwrap();
        let mut input = base_input();
        input.alive.insert(ip, Some(100.9));
        input.neighbors.insert(ip, "24:62:ab:e4:5f:a4".into());
        input.open_ports.insert(
            ip,
            vec![PortInfo {
                port: 6053,
                protocol: "tcp".into(),
                service: Some("esphome".into()),
                banner: None,
            }],
        );

        let mut txt = BTreeMap::new();
        txt.insert("platform".to_string(), "ESP32".to_string());
        input.mdns.push(MdnsService {
            service_type: "_esphomelib._tcp".into(),
            name: "sterownik".into(),
            hostname: Some("sterownik.local".into()),
            port: Some(6053),
            address: Some(ip.to_string()),
            txt,
        });

        let devices = correlate(input);
        let device = devices.iter().find(|d| d.ip == "10.0.3.22").unwrap();

        assert_eq!(device.display_name, "sterownik");
        assert_eq!(device.device_type, DeviceType::Iot);
        assert_eq!(device.vendor.as_deref(), Some("Espressif"));
        assert!(device
            .type_evidence
            .iter()
            .any(|e| e.contains("IoT service")));
        assert!(device.discovered_by.contains(&"mdns".to_string()));
    }

    #[test]
    fn flags_randomized_macs_and_never_names_a_vendor_for_them() {
        let ip: Ipv4Addr = "10.0.3.214".parse().unwrap();
        let mut input = base_input();
        input.alive.insert(ip, None);
        input.neighbors.insert(ip, "ca:3a:94:02:94:de".into());

        let devices = correlate(input);
        let device = &devices[0];
        assert_eq!(device.mac_randomized, Some(true));
        assert!(device.vendor.is_none());
    }

    #[test]
    fn stale_arp_entries_do_not_invent_devices() {
        let mut input = base_input();
        // A neighbour entry with no other evidence must not become a device.
        input
            .neighbors
            .insert("10.0.3.99".parse().unwrap(), "aa:bb:cc:dd:ee:ff".into());

        let devices = correlate(input);
        assert!(
            devices.is_empty(),
            "a MAC alone is not proof a host is present"
        );
    }

    #[test]
    fn marks_devices_outside_the_local_subnet() {
        let ip: Ipv4Addr = "10.0.107.110".parse().unwrap();
        let mut input = base_input();
        input.open_ports.insert(
            ip,
            vec![PortInfo {
                port: 8123,
                protocol: "tcp".into(),
                service: Some("home-assistant".into()),
                banner: None,
            }],
        );

        let devices = correlate(input);
        let device = &devices[0];
        assert!(device.off_subnet, "10.0.107.110 is outside 10.0.3.0/24");
        assert_eq!(device.device_type, DeviceType::Server);
    }

    #[test]
    fn self_is_identified_with_its_interface_mac() {
        let ip: Ipv4Addr = "10.0.3.221".parse().unwrap();
        let mut input = base_input();
        input.alive.insert(ip, Some(0.1));
        input.self_ips.push(ip);
        input.self_macs.insert(ip, "3c:58:c2:52:29:84".into());

        let devices = correlate(input);
        let device = &devices[0];
        assert!(device.is_self);
        assert_eq!(device.device_type, DeviceType::Computer);
        assert_eq!(device.vendor.as_deref(), Some("Intel Corporate"));
    }

    #[test]
    fn a_refused_connection_counts_as_a_live_host() {
        let ip: Ipv4Addr = "10.0.3.50".parse().unwrap();
        let mut input = base_input();
        input.refused_hosts.push(ip);

        let devices = correlate(input);
        assert_eq!(devices.len(), 1);
        assert!(!devices[0].responded_to_ping);
        assert!(devices[0]
            .discovered_by
            .contains(&"tcp-refused".to_string()));
    }
}
