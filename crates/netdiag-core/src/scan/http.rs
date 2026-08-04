//! A deliberately small HTTP/1.1 client.
//!
//! Banner grabbing needs status line, a few headers and a bounded slice of the
//! body — nothing that justifies pulling a full HTTP stack and its TLS
//! verification machinery into the binary. Certificates here are *inspected*,
//! never trusted, so verification is intentionally disabled: self-signed certs
//! are the norm on LAN devices and are exactly what we want to report on.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

/// Accepts any certificate. This client only ever *inspects* certificates for
/// reporting; it never transmits credentials, so trust decisions are irrelevant
/// and rejecting self-signed LAN certs would defeat the purpose.
#[derive(Debug)]
struct InspectOnlyVerifier;

impl ServerCertVerifier for InspectOnlyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

pub fn tls_config() -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InspectOnlyVerifier))
        .with_no_client_auth();
    config.enable_sni = false;
    Arc::new(config)
}

fn build_request(host: &str, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: local-network-diag/1.0\r\nAccept: text/html,*/*\r\nConnection: close\r\n\r\n"
    )
}

pub(crate) fn parse_response(raw: &str) -> Option<HttpResponse> {
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
    let mut lines = head.lines();
    let status_line = lines.next()?;

    // "HTTP/1.1 301 Moved Permanently"
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    Some(HttpResponse {
        status,
        headers,
        body: body.to_string(),
    })
}

async fn read_bounded<S>(stream: &mut S, limit: usize) -> String
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];

    while buf.len() < limit {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }

    String::from_utf8_lossy(&buf).into_owned()
}

pub async fn fetch(
    host: &str,
    port: u16,
    secure: bool,
    timeout: Duration,
    limit: usize,
) -> Result<HttpResponse, String> {
    let work = async {
        let stream = TcpStream::connect((host, port))
            .await
            .map_err(|e| e.to_string())?;
        let request = build_request(&format!("{host}:{port}"), "/");

        let raw = if secure {
            use tokio_rustls::TlsConnector;
            let connector = TlsConnector::from(tls_config());
            // An IP is not a valid SNI name; SNI is disabled in the config and a
            // placeholder name satisfies the API without being sent.
            let server_name = ServerName::try_from("scan.invalid").map_err(|e| e.to_string())?;
            let mut tls = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| e.to_string())?;
            tls.write_all(request.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            read_bounded(&mut tls, limit).await
        } else {
            let mut stream = stream;
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            read_bounded(&mut stream, limit).await
        };

        parse_response(&raw).ok_or_else(|| "malformed HTTP response".to_string())
    };

    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| "timed out".to_string())?
}

/// Convenience wrapper for fetching a URL, used for SSDP description XML.
pub async fn get_text(url: &str, timeout: Duration, limit: usize) -> Result<String, String> {
    let (secure, rest) = if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else {
        return Err("unsupported scheme".into());
    };

    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };

    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse().unwrap_or(if secure { 443 } else { 80 }),
        ),
        None => (authority.to_string(), if secure { 443 } else { 80 }),
    };

    let work = async {
        let stream = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| e.to_string())?;
        let request = build_request(authority, path);

        let raw = if secure {
            use tokio_rustls::TlsConnector;
            let connector = TlsConnector::from(tls_config());
            let server_name = ServerName::try_from("scan.invalid").map_err(|e| e.to_string())?;
            let mut tls = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| e.to_string())?;
            tls.write_all(request.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            read_bounded(&mut tls, limit).await
        } else {
            let mut stream = stream;
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            read_bounded(&mut stream, limit).await
        };

        Ok::<String, String>(parse_response(&raw).map(|r| r.body).unwrap_or(raw))
    };

    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| "timed out".to_string())?
}

/// Extracts `<title>` from an HTML body, collapsing whitespace.
pub fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start_tag = lower.find("<title")?;
    let close = lower[start_tag..].find('>')? + start_tag + 1;
    let end = lower[close..].find("</title>")? + close;

    let title = body[close..end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let trimmed = title.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.chars().take(200).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_line_and_headers() {
        let raw = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://10.0.3.1/\r\nServer: Server\r\n\r\n<html></html>";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status, 301);
        assert_eq!(
            response.headers.get("location").unwrap(),
            "https://10.0.3.1/"
        );
        assert_eq!(response.headers.get("server").unwrap(), "Server");
    }

    #[test]
    fn extracts_title_with_attributes_and_whitespace() {
        assert_eq!(
            extract_title("<html><title>UniFi</title>"),
            Some("UniFi".into())
        );
        assert_eq!(
            extract_title("<TITLE lang=\"en\">  Router\n  Login  </TITLE>"),
            Some("Router Login".into())
        );
        assert_eq!(extract_title("<html>no title</html>"), None);
        assert_eq!(extract_title("<title>   </title>"), None);
    }

    #[test]
    fn malformed_responses_are_rejected_not_panicked() {
        assert!(parse_response("").is_none());
        assert!(parse_response("garbage").is_none());
        assert!(parse_response("HTTP/1.1\r\n\r\n").is_none());
    }

    #[tokio::test]
    async fn fetches_from_a_local_server() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut discard = [0u8; 1024];
                let _ = socket.read(&mut discard).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nServer: test-server\r\nContent-Type: text/html\r\n\r\n<title>Test Device</title>",
                    )
                    .await;
            }
        });

        let response = fetch("127.0.0.1", port, false, Duration::from_secs(3), 65536)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.headers.get("server").unwrap(), "test-server");
        assert_eq!(
            extract_title(&response.body).as_deref(),
            Some("Test Device")
        );
    }
}
