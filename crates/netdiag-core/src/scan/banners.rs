//! Banner grabbing for the ports the sweep found open.
//!
//! Three kinds: an HTTP request for status/Server/title, a TLS handshake for
//! certificate detail, and a passive read for protocols that greet first (SSH,
//! SMTP, FTP). All strictly time-boxed — an unresponsive embedded web server is
//! common and must not stall the scan.

use crate::scan::http;
use crate::types::Banner;
use futures::stream::{self, StreamExt};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const HTTP_PORTS: &[u16] = &[
    80, 81, 631, 3000, 5000, 8000, 8008, 8060, 8080, 8081, 8085, 8096, 8123, 8181, 8888, 9000,
    9090, 10000, 11434, 32400,
];
const HTTPS_PORTS: &[u16] = &[443, 8443, 9443, 8009];
/// Protocols that send a greeting before the client says anything.
const GREETING_PORTS: &[u16] = &[21, 22, 23, 25, 110, 143, 587, 6379];

pub fn is_banner_port(port: u16) -> bool {
    HTTP_PORTS.contains(&port) || HTTPS_PORTS.contains(&port) || GREETING_PORTS.contains(&port)
}

async fn grab_http(ip: Ipv4Addr, port: u16, secure: bool) -> Option<Banner> {
    let response = http::fetch(
        &ip.to_string(),
        port,
        secure,
        Duration::from_millis(3500),
        65536,
    )
    .await
    .ok()?;

    let content_type = response
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    let title = if content_type.is_empty()
        || content_type.contains("text/html")
        || content_type.contains("xhtml")
    {
        http::extract_title(&response.body)
    } else {
        None
    };

    Some(Banner::Http {
        scheme: if secure {
            "https".into()
        } else {
            "http".into()
        },
        status: Some(response.status),
        server: response.headers.get("server").cloned(),
        title,
        redirect_location: response.headers.get("location").cloned(),
        headers: response.headers,
    })
}

/// Performs a TLS handshake purely to read the peer certificate.
async fn grab_tls(ip: Ipv4Addr, port: u16) -> Option<Banner> {
    use rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;
    use x509_parser::prelude::*;

    let work = async {
        let stream = TcpStream::connect(SocketAddrV4::new(ip, port)).await.ok()?;
        let connector = TlsConnector::from(http::tls_config());
        let server_name = ServerName::try_from("scan.invalid").ok()?;
        let tls = connector.connect(server_name, stream).await.ok()?;

        let (_, connection) = tls.get_ref();
        let chain = connection.peer_certificates()?;
        let leaf = chain.first()?;

        let (_, cert) = X509Certificate::from_der(leaf.as_ref()).ok()?;

        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();

        let alt_names: Vec<String> = cert
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|ext| {
                ext.value
                    .general_names
                    .iter()
                    .map(|name| name.to_string())
                    .collect()
            })
            .unwrap_or_default();

        let not_before = cert.validity().not_before.to_string();
        let not_after = cert.validity().not_after.to_string();

        let days_until_expiry = cert
            .validity()
            .not_after
            .timestamp()
            .checked_sub(chrono::Utc::now().timestamp())
            .map(|seconds| seconds / 86_400);

        Some(Banner::Tls {
            self_signed: Some(subject == issuer),
            subject: Some(subject),
            issuer: Some(issuer),
            alt_names: if alt_names.is_empty() {
                None
            } else {
                Some(alt_names)
            },
            valid_from: Some(not_before),
            valid_to: Some(not_after),
            days_until_expiry,
        })
    };

    tokio::time::timeout(Duration::from_secs(4), work)
        .await
        .ok()
        .flatten()
}

/// Reads a server greeting without sending anything — SSH/SMTP/FTP identify
/// themselves this way.
async fn grab_greeting(ip: Ipv4Addr, port: u16) -> Option<Banner> {
    let work = async {
        let mut stream = TcpStream::connect(SocketAddrV4::new(ip, port)).await.ok()?;
        let mut buf = vec![0u8; 512];
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
        if text.is_empty() {
            None
        } else {
            Some(Banner::Text { text })
        }
    };

    tokio::time::timeout(Duration::from_secs(3), work)
        .await
        .ok()
        .flatten()
}

/// Key format: `ip:port`, plus `ip:port:tls` for a certificate carried alongside
/// an HTTP banner on the same port.
pub async fn grab(tasks: &[(Ipv4Addr, u16)], concurrency: usize) -> HashMap<String, Banner> {
    let results = stream::iter(tasks.iter().copied())
        .map(|(ip, port)| async move {
            let mut out: Vec<(String, Banner)> = Vec::new();
            let key = format!("{ip}:{port}");

            if HTTPS_PORTS.contains(&port) {
                let (tls, http_banner) =
                    futures::join!(grab_tls(ip, port), grab_http(ip, port, true));

                // Prefer the HTTP view when it identifies the device; keep the
                // certificate alongside rather than discarding it.
                let http_useful = matches!(
                    &http_banner,
                    Some(Banner::Http { title: Some(_), .. })
                        | Some(Banner::Http {
                            server: Some(_),
                            ..
                        })
                );

                match (http_useful, http_banner, tls) {
                    (true, Some(http_banner), tls) => {
                        out.push((key.clone(), http_banner));
                        if let Some(tls) = tls {
                            out.push((format!("{key}:tls"), tls));
                        }
                    }
                    (_, http_banner, Some(tls)) => {
                        out.push((key.clone(), tls));
                        let _ = http_banner;
                    }
                    (_, Some(http_banner), None) => out.push((key.clone(), http_banner)),
                    _ => {}
                }
            } else if HTTP_PORTS.contains(&port) {
                if let Some(banner) = grab_http(ip, port, false).await {
                    out.push((key, banner));
                }
            } else if GREETING_PORTS.contains(&port) {
                if let Some(banner) = grab_greeting(ip, port).await {
                    out.push((key, banner));
                }
            }

            out
        })
        .buffer_unordered(concurrency.max(1))
        .collect::<Vec<_>>()
        .await;

    results.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_banner_ports() {
        assert!(is_banner_port(80));
        assert!(is_banner_port(443));
        assert!(is_banner_port(22));
        assert!(is_banner_port(8123));
        assert!(
            !is_banner_port(6053),
            "ESPHome's API port speaks no known banner protocol"
        );
        assert!(!is_banner_port(9100));
    }

    #[tokio::test]
    async fn grabs_an_http_banner_from_a_local_server() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        // Port 8080 is in HTTP_PORTS; bind it directly so the classifier applies.
        let listener = match TcpListener::bind("127.0.0.1:8080").await {
            Ok(listener) => listener,
            // Something else already owns 8080 on this machine; skip rather than fail.
            Err(_) => return,
        };

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut discard = [0u8; 1024];
                let _ = socket.read(&mut discard).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nServer: probe-test\r\n\r\n<title>Probe</title>")
                    .await;
            }
        });

        let banners = grab(&[(Ipv4Addr::LOCALHOST, 8080)], 4).await;
        let banner = banners
            .get("127.0.0.1:8080")
            .expect("should have grabbed a banner");
        match banner {
            Banner::Http {
                server,
                title,
                status,
                ..
            } => {
                assert_eq!(status, &Some(200));
                assert_eq!(server.as_deref(), Some("probe-test"));
                assert_eq!(title.as_deref(), Some("Probe"));
            }
            other => panic!("expected an HTTP banner, got {other:?}"),
        }
    }
}
