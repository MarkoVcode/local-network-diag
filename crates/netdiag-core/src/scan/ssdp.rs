//! SSDP / UPnP discovery.
//!
//! Two steps: multicast M-SEARCH to collect responders, then fetch each
//! responder's description XML for manufacturer, model and serial — the best
//! identity data available for routers, TVs and set-top boxes that publish
//! nothing over mDNS.

use crate::scan::http;
use crate::types::SsdpRecord;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;

const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;

fn parse_headers(message: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for line in message.lines().skip(1) {
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    headers
}

pub async fn discover(window: Duration) -> Result<HashMap<String, Vec<SsdpRecord>>, String> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("SSDP socket: {e}"))?;
    socket.set_reuse_address(true).ok();
    socket.set_nonblocking(true).ok();
    let bind: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
    socket
        .bind(&bind.into())
        .map_err(|e| format!("SSDP bind: {e}"))?;

    let socket = UdpSocket::from_std(socket.into()).map_err(|e| format!("SSDP socket: {e}"))?;
    let target = SocketAddrV4::new(SSDP_GROUP, SSDP_PORT);

    let message = concat!(
        "M-SEARCH * HTTP/1.1\r\n",
        "HOST: 239.255.255.250:1900\r\n",
        "MAN: \"ssdp:discover\"\r\n",
        "MX: 3\r\n",
        "ST: ssdp:all\r\n",
        "\r\n"
    );

    // UDP is lossy and some devices answer only one burst.
    for _ in 0..3 {
        let _ = socket.send_to(message.as_bytes(), target).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    let mut by_ip: HashMap<String, Vec<SsdpRecord>> = HashMap::new();
    let mut seen: HashMap<String, Vec<String>> = HashMap::new();
    let deadline = tokio::time::Instant::now() + window;
    let mut buf = vec![0u8; 4096];

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Ok(Ok((len, from))) = tokio::time::timeout(
            remaining.min(Duration::from_millis(500)),
            socket.recv_from(&mut buf),
        )
        .await
        else {
            continue;
        };

        let text = String::from_utf8_lossy(&buf[..len]);
        // Ignore byebye notices — they announce a device leaving, not present.
        if text.starts_with("NOTIFY") && text.contains("byebye") {
            continue;
        }

        let headers = parse_headers(&text);
        let st = headers
            .get("st")
            .or_else(|| headers.get("nt"))
            .cloned()
            .unwrap_or_default();
        let location = headers.get("location").cloned();

        let ip = from.ip().to_string();
        let key = format!("{st}|{}", location.clone().unwrap_or_default());
        let entry = seen.entry(ip.clone()).or_default();
        if entry.contains(&key) {
            continue;
        }
        entry.push(key);

        by_ip.entry(ip).or_default().push(SsdpRecord {
            st,
            usn: headers.get("usn").cloned(),
            server: headers.get("server").cloned(),
            location,
            ..Default::default()
        });
    }

    enrich_from_descriptions(&mut by_ip).await;
    Ok(by_ip)
}

/// Fetches each unique LOCATION once and copies the parsed fields onto every
/// record that references it. Failures are silent — plenty of devices advertise
/// a description URL that no longer serves.
async fn enrich_from_descriptions(by_ip: &mut HashMap<String, Vec<SsdpRecord>>) {
    let mut locations: Vec<String> = Vec::new();
    for records in by_ip.values() {
        for record in records {
            if let Some(location) = &record.location {
                if !locations.contains(location) {
                    locations.push(location.clone());
                }
            }
        }
    }
    locations.truncate(40);

    let fetches = locations.into_iter().map(|location| async move {
        let parsed = match http::get_text(&location, Duration::from_secs(4), 200_000).await {
            Ok(body) => parse_description(&body),
            Err(_) => SsdpRecord::default(),
        };
        (location, parsed)
    });

    let results: Vec<(String, SsdpRecord)> = futures::future::join_all(fetches).await;
    let descriptions: HashMap<String, SsdpRecord> = results.into_iter().collect();

    for records in by_ip.values_mut() {
        for record in records.iter_mut() {
            let Some(location) = record.location.clone() else {
                continue;
            };
            let Some(description) = descriptions.get(&location) else {
                continue;
            };
            record.device_type.clone_from(&description.device_type);
            record.friendly_name.clone_from(&description.friendly_name);
            record.manufacturer.clone_from(&description.manufacturer);
            record.model_name.clone_from(&description.model_name);
            record.model_number.clone_from(&description.model_number);
            record.serial_number.clone_from(&description.serial_number);
        }
    }
}

pub(crate) fn parse_description(xml: &str) -> SsdpRecord {
    SsdpRecord {
        device_type: extract_tag(xml, "deviceType"),
        friendly_name: extract_tag(xml, "friendlyName"),
        manufacturer: extract_tag(xml, "manufacturer"),
        model_name: extract_tag(xml, "modelName"),
        model_number: extract_tag(xml, "modelNumber"),
        serial_number: extract_tag(xml, "serialNumber"),
        ..Default::default()
    }
}

/// Extracts the first occurrence of a tag. Deliberately not a full XML parser —
/// UPnP descriptions are small and flat, and pulling in a parser for six fields
/// would not earn its weight.
fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;

    let raw = xml[start..end].trim();
    let unwrapped = raw
        .strip_prefix("<![CDATA[")
        .and_then(|s| s.strip_suffix("]]>"))
        .unwrap_or(raw);

    let decoded = unwrapped
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
        .trim()
        .to_string();

    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_upnp_device_description() {
        let xml = r#"<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0">
            <device>
              <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
              <friendlyName>DIGITRADIO 370 CD IR</friendlyName>
              <manufacturer>TechniSat</manufacturer>
              <modelName>DIGITRADIO 370 CD IR</modelName>
              <modelNumber>1.2.3</modelNumber>
              <serialNumber>ABC123</serialNumber>
            </device></root>"#;

        let record = parse_description(xml);
        assert_eq!(record.manufacturer.as_deref(), Some("TechniSat"));
        assert_eq!(
            record.friendly_name.as_deref(),
            Some("DIGITRADIO 370 CD IR")
        );
        assert_eq!(record.serial_number.as_deref(), Some("ABC123"));
        assert!(record
            .device_type
            .as_deref()
            .unwrap()
            .contains("MediaRenderer"));
    }

    #[test]
    fn decodes_cdata_and_entities() {
        let xml = "<friendlyName><![CDATA[Marek's Router]]></friendlyName><modelName>A &amp; B</modelName>";
        assert_eq!(
            extract_tag(xml, "friendlyName").as_deref(),
            Some("Marek's Router")
        );
        assert_eq!(extract_tag(xml, "modelName").as_deref(), Some("A & B"));
    }

    #[test]
    fn missing_and_empty_tags_yield_none() {
        assert_eq!(extract_tag("<a>x</a>", "b"), None);
        assert_eq!(extract_tag("<b>   </b>", "b"), None);
    }

    #[test]
    fn parses_ssdp_response_headers_case_insensitively() {
        let response = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLocation: http://10.0.3.18:8080/dd.xml\r\nST: urn:schemas-upnp-org:service:RenderingControl:1\r\nSERVER: POSIX UPnP/1.0\r\n\r\n";
        let headers = parse_headers(response);
        assert_eq!(
            headers.get("location").unwrap(),
            "http://10.0.3.18:8080/dd.xml"
        );
        assert_eq!(headers.get("server").unwrap(), "POSIX UPnP/1.0");
    }
}
