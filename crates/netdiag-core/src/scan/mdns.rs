//! mDNS / DNS-SD discovery, implemented directly on a multicast socket.
//!
//! The TypeScript version shelled out to `avahi-browse`, which is Linux-only and
//! — as verified against the reference network — returns from avahi's *cache*
//! when given `-t`, silently missing anything not currently cached. Doing the
//! protocol here instead means one implementation that behaves identically on
//! Linux, macOS and Windows, with no external dependency and no cache surprises.
//!
//! Strategy: issue the DNS-SD meta-query for service types, then PTR queries for
//! each type discovered, collecting every record from every response for a fixed
//! window. Responders routinely bundle SRV/TXT/A into the additionals section,
//! so a single pass usually yields fully-resolved services.

use super::dnsmsg::{self, RData};
use crate::types::MdnsService;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const META_QUERY: &str = "_services._dns-sd._udp.local";

/// Binds a socket suitable for mDNS: reuse-address so it coexists with any
/// system responder (avahi, mDNSResponder, Bonjour) already holding port 5353.
fn bind_socket(interfaces: &[Ipv4Addr]) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;

    let bind_addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT).into();
    // Falling back to an ephemeral port still receives unicast responses, which
    // is enough for discovery when another daemon owns 5353 exclusively.
    if socket.bind(&bind_addr.into()).is_err() {
        let fallback: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
        socket.bind(&fallback.into())?;
    }

    for interface in interfaces {
        // Joining per-interface matters on multi-homed hosts: the default route
        // is not necessarily the interface the IoT devices are on.
        let _ = socket.join_multicast_v4(&MDNS_GROUP, interface);
    }
    if interfaces.is_empty() {
        let _ = socket.join_multicast_v4(&MDNS_GROUP, &Ipv4Addr::UNSPECIFIED);
    }

    socket.set_multicast_loop_v4(true)?;
    UdpSocket::from_std(socket.into())
}

/// Collected records, keyed for assembly once the window closes.
#[derive(Default)]
struct RecordCache {
    /// service type -> instance names
    ptr: HashMap<String, HashSet<String>>,
    /// instance -> (host, port)
    srv: HashMap<String, (String, u16)>,
    /// instance -> TXT map
    txt: HashMap<String, BTreeMap<String, String>>,
    /// hostname -> address
    a: HashMap<String, Ipv4Addr>,
    /// Addresses that sent us anything, used as a fallback when SRV is missing.
    responders: HashMap<String, Ipv4Addr>,
}

pub async fn discover(
    interfaces: &[Ipv4Addr],
    window: Duration,
) -> Result<Vec<MdnsService>, String> {
    let socket = bind_socket(interfaces).map_err(|e| format!("mDNS socket: {e}"))?;
    let target = SocketAddrV4::new(MDNS_GROUP, MDNS_PORT);

    let mut cache = RecordCache::default();
    let mut asked_types: HashSet<String> = HashSet::new();

    // Kick off with the meta-query that enumerates service types.
    let meta = dnsmsg::build_mdns_query(META_QUERY, dnsmsg::TYPE_PTR);
    let _ = socket.send_to(&meta, target).await;

    // Also ask directly for the service types worth finding even if a responder
    // omits them from the meta-query answer.
    for service_type in COMMON_SERVICE_TYPES {
        let query = dnsmsg::build_mdns_query(service_type, dnsmsg::TYPE_PTR);
        let _ = socket.send_to(&query, target).await;
        asked_types.insert((*service_type).to_string());
    }

    let deadline = tokio::time::Instant::now() + window;
    let mut buf = vec![0u8; 8192];
    // (name, record type) — service types to enumerate, and instances to resolve.
    let mut pending_queries: Vec<(String, u16)> = Vec::new();

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        // A receive error or an idle timeout is not a failure — the loop simply
        // falls through to sending any follow-up queries discovered so far.
        if let Ok(Ok((len, from))) = tokio::time::timeout(
            remaining.min(Duration::from_millis(400)),
            socket.recv_from(&mut buf),
        )
        .await
        {
            let source = match from {
                SocketAddr::V4(addr) => Some(*addr.ip()),
                SocketAddr::V6(_) => None,
            };

            if let Some(message) = dnsmsg::parse(&buf[..len]) {
                ingest(&mut cache, &message, source, &mut pending_queries);
            }
        }

        for (name, rtype) in std::mem::take(&mut pending_queries) {
            // Deduplicate per (name, type) so a repeatedly-announced service is
            // not re-queried on every packet.
            if asked_types.insert(format!("{rtype}:{name}")) {
                let query = dnsmsg::build_mdns_query(&name, rtype);
                let _ = socket.send_to(&query, target).await;
            }
        }
    }

    Ok(assemble(cache))
}

fn ingest(
    cache: &mut RecordCache,
    message: &dnsmsg::Message,
    source: Option<Ipv4Addr>,
    pending: &mut Vec<(String, u16)>,
) {
    for record in &message.records {
        match &record.data {
            RData::Ptr(target) => {
                if record.name == META_QUERY {
                    // The answer names a service type we should now enumerate.
                    pending.push((target.clone(), dnsmsg::TYPE_PTR));
                } else {
                    cache
                        .ptr
                        .entry(record.name.clone())
                        .or_default()
                        .insert(target.clone());
                    if let Some(ip) = source {
                        cache.responders.insert(target.clone(), ip);
                    }
                    // Ask for this instance's address, port and metadata directly
                    // rather than hoping the responder bundled them as additionals.
                    pending.push((target.clone(), dnsmsg::TYPE_SRV));
                    pending.push((target.clone(), dnsmsg::TYPE_TXT));
                }
            }
            RData::Srv { port, target, .. } => {
                cache
                    .srv
                    .insert(record.name.clone(), (target.clone(), *port));
                // Resolve the hostname the SRV points at, so the service gets an address.
                pending.push((target.clone(), dnsmsg::TYPE_A));
            }
            RData::Txt(strings) => {
                let map = dnsmsg::txt_to_map(strings);
                if !map.is_empty() {
                    cache.txt.insert(record.name.clone(), map);
                }
            }
            RData::A(addr) => {
                cache.a.insert(record.name.clone(), *addr);
            }
            RData::Other => {}
        }
    }
}

fn assemble(cache: RecordCache) -> Vec<MdnsService> {
    let mut services = Vec::new();

    for (service_type, instances) in &cache.ptr {
        for instance in instances {
            // "Living Room._airplay._tcp.local" -> instance label is everything
            // before the service type.
            let name = instance
                .strip_suffix(&format!(".{service_type}"))
                .unwrap_or(instance)
                .to_string();

            let srv = cache.srv.get(instance);
            let hostname = srv.map(|(host, _)| host.clone());
            let port = srv.map(|(_, port)| *port);

            let address = hostname
                .as_ref()
                .and_then(|host| cache.a.get(host).copied())
                .or_else(|| cache.responders.get(instance).copied());

            services.push(MdnsService {
                service_type: service_type.trim_end_matches(".local").to_string(),
                name: unescape_dns_label(&name),
                hostname: hostname.map(|h| h.trim_end_matches('.').to_string()),
                port,
                address: address.map(|a| a.to_string()),
                txt: cache.txt.get(instance).cloned().unwrap_or_default(),
            });
        }
    }

    services.sort_by(|a, b| {
        a.service_type
            .cmp(&b.service_type)
            .then_with(|| a.name.cmp(&b.name))
    });
    services.dedup_by(|a, b| {
        a.service_type == b.service_type && a.name == b.name && a.address == b.address
    });

    services
}

/// DNS-SD escapes spaces and dots inside instance labels as `\032` / `\.`.
fn unescape_dns_label(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    let mut chars = label.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }

        // `\DDD` decimal escape, otherwise a literal escaped character.
        let digits: String = chars.clone().take(3).collect();
        if digits.len() == 3 && digits.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(code) = digits.parse::<u8>() {
                out.push(code as char);
                for _ in 0..3 {
                    chars.next();
                }
                continue;
            }
        }
        if let Some(next) = chars.next() {
            out.push(next);
        }
    }

    out
}

/// Service types worth querying explicitly. The meta-query finds these too on a
/// well-behaved network, but asking directly is faster and more reliable.
const COMMON_SERVICE_TYPES: &[&str] = &[
    "_esphomelib._tcp.local",
    "_home-assistant._tcp.local",
    "_hap._tcp.local",
    "_matter._tcp.local",
    "_matterc._udp.local",
    "_googlecast._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_spotify-connect._tcp.local",
    "_sonos._tcp.local",
    "_printer._tcp.local",
    "_ipp._tcp.local",
    "_ipps._tcp.local",
    "_pdl-datastream._tcp.local",
    "_scanner._tcp.local",
    "_smb._tcp.local",
    "_afpovertcp._tcp.local",
    "_nfs._tcp.local",
    "_adisk._tcp.local",
    "_ssh._tcp.local",
    "_sftp-ssh._tcp.local",
    "_http._tcp.local",
    "_https._tcp.local",
    "_workstation._tcp.local",
    "_device-info._tcp.local",
    "_companion-link._tcp.local",
    "_remotepairing._tcp.local",
    "_rdlink._tcp.local",
    "_sleep-proxy._udp.local",
    "_plexmediasvr._tcp.local",
    "_mqtt._tcp.local",
    "_esphomebuilder._tcp.local",
];

/// Human-readable label for a DNS-SD service type.
pub fn label_for_service_type(service_type: &str) -> String {
    let base = service_type
        .trim_end_matches(".local")
        .trim_end_matches("._tcp")
        .trim_end_matches("._udp");

    let label = match base {
        "_esphomelib" => "ESPHome device",
        "_home-assistant" => "Home Assistant",
        "_esphomebuilder" => "ESPHome Builder",
        "_googlecast" => "Google Cast",
        "_airplay" => "AirPlay",
        "_raop" => "AirPlay audio",
        "_spotify-connect" => "Spotify Connect",
        "_printer" => "Printer",
        "_ipp" | "_ipps" => "Printer (IPP)",
        "_pdl-datastream" => "Printer (raw)",
        "_scanner" => "Scanner",
        "_smb" => "SMB file share",
        "_afpovertcp" => "AFP file share",
        "_nfs" => "NFS share",
        "_adisk" => "Time Machine target",
        "_ssh" => "SSH",
        "_sftp-ssh" => "SFTP",
        "_http" => "Web server",
        "_https" => "Web server (TLS)",
        "_workstation" => "Workstation",
        "_companion-link" => "Apple Companion",
        "_remotepairing" => "Apple remote pairing",
        "_rdlink" => "Apple Remote Desktop",
        "_sleep-proxy" => "Sleep proxy",
        "_hap" => "HomeKit accessory",
        "_matter" | "_matterc" => "Matter device",
        "_plexmediasvr" => "Plex Media Server",
        "_sonos" => "Sonos",
        "_mqtt" => "MQTT broker",
        "_device-info" => "Device info",
        other => return other.trim_start_matches('_').to_string(),
    };

    label.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescapes_dns_sd_decimal_and_literal_escapes() {
        // avahi renders "DIGITRADIO 370 CD IR" with \032 for each space.
        assert_eq!(
            unescape_dns_label(r"DIGITRADIO\032370\032CD\032IR"),
            "DIGITRADIO 370 CD IR"
        );
        assert_eq!(unescape_dns_label(r"Marek\'s\032Mac"), "Marek's Mac");
        assert_eq!(unescape_dns_label("plain"), "plain");
    }

    #[test]
    fn assembles_services_from_separate_ptr_srv_txt_and_a_records() {
        let mut cache = RecordCache::default();
        let instance = "sterownik._esphomelib._tcp.local".to_string();

        cache
            .ptr
            .entry("_esphomelib._tcp.local".into())
            .or_default()
            .insert(instance.clone());
        cache
            .srv
            .insert(instance.clone(), ("sterownik.local".into(), 6053));
        cache.txt.insert(
            instance.clone(),
            dnsmsg::txt_to_map(&["platform=ESP32".into(), "board=esp32dev".into()]),
        );
        cache
            .a
            .insert("sterownik.local".into(), Ipv4Addr::new(10, 0, 3, 22));

        let services = assemble(cache);
        assert_eq!(services.len(), 1);
        let service = &services[0];
        assert_eq!(service.name, "sterownik");
        assert_eq!(service.service_type, "_esphomelib._tcp");
        assert_eq!(service.port, Some(6053));
        assert_eq!(service.address.as_deref(), Some("10.0.3.22"));
        assert_eq!(service.txt.get("platform").unwrap(), "ESP32");
    }

    #[test]
    fn falls_back_to_the_responder_address_when_srv_is_missing() {
        let mut cache = RecordCache::default();
        let instance = "thing._http._tcp.local".to_string();
        cache
            .ptr
            .entry("_http._tcp.local".into())
            .or_default()
            .insert(instance.clone());
        cache
            .responders
            .insert(instance, Ipv4Addr::new(10, 0, 3, 99));

        let services = assemble(cache);
        assert_eq!(services[0].address.as_deref(), Some("10.0.3.99"));
    }

    #[test]
    fn labels_known_service_types() {
        assert_eq!(label_for_service_type("_esphomelib._tcp"), "ESPHome device");
        assert_eq!(
            label_for_service_type("_home-assistant._tcp.local"),
            "Home Assistant"
        );
        assert_eq!(label_for_service_type("_unknownthing._tcp"), "unknownthing");
    }
}
