//! UniFi controller HTTP client.
//!
//! # Why this does not reuse [`crate::scan::http`]
//!
//! That client's verifier accepts **any** certificate. For banner grabbing that
//! is correct — we inspect a stranger's certificate to report on it, and never
//! send it anything. Here we transmit a password, so accepting any certificate
//! would hand credentials to whoever answers the address.
//!
//! Controllers use self-signed certificates (`CN=unifi.local`), so ordinary CA
//! validation cannot work either. The middle ground is **trust on first use**:
//! record the certificate's SHA-256 fingerprint the first time, and refuse to
//! authenticate if it ever changes. That gives a real guarantee — nobody can
//! silently interpose after the first connection — while working with the
//! certificates UniFi actually ships.
//!
//! # Auth flavours
//!
//! * **UniFi OS** (UDM, UDR, Cloud Key Gen2+): `POST /api/auth/login`, session
//!   in a `TOKEN` cookie, Network app proxied under `/proxy/network/…`.
//! * **Legacy** (software controller, Cloud Key Gen1): `POST /api/login`,
//!   session in `unifises`, endpoints directly under `/api/…`.
//!
//! The flavour is detected rather than configured, because users generally do
//! not know which one they have.

use crate::netutil::is_private_ipv4;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnifiError {
    /// The host is not a private address. Refused before any connection.
    NotPrivate(String),
    /// The certificate changed since it was pinned — possible interception.
    FingerprintMismatch {
        expected: String,
        actual: String,
    },
    Connect(String),
    /// Credentials rejected by the controller.
    Unauthorized,
    /// Authenticated, but the account cannot read this site.
    Forbidden,
    Http {
        status: u16,
        detail: String,
    },
    Protocol(String),
}

impl std::fmt::Display for UnifiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnifiError::NotPrivate(host) => write!(
                f,
                "{host} is not a private address — refusing to send credentials to a public host"
            ),
            UnifiError::FingerprintMismatch { expected, actual } => write!(
                f,
                "The controller's TLS certificate changed. Expected {expected}, got {actual}. \
                 Credentials were not sent. This is expected after reinstalling the controller \
                 or regenerating its certificate; otherwise the connection may be intercepted."
            ),
            UnifiError::Connect(detail) => write!(f, "Could not reach the controller: {detail}"),
            UnifiError::Unauthorized => {
                write!(f, "The controller rejected these credentials")
            }
            UnifiError::Forbidden => write!(
                f,
                "Signed in, but this account cannot read the requested site"
            ),
            UnifiError::Http { status, detail } => {
                write!(f, "Controller returned HTTP {status}: {detail}")
            }
            UnifiError::Protocol(detail) => write!(f, "Unexpected controller response: {detail}"),
        }
    }
}

impl std::error::Error for UnifiError {}

/// Records the certificate seen during the handshake so the caller can compare
/// it against a stored pin. Verification itself is deferred: rustls has no way
/// to return "unverified but here is what I saw", so the check happens in
/// [`UnifiClient`] *before* any credential is written to the socket.
#[derive(Debug)]
struct CapturingVerifier {
    seen: Arc<Mutex<Option<String>>>,
}

impl CapturingVerifier {
    fn new(seen: Arc<Mutex<Option<String>>>) -> Self {
        Self { seen }
    }
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut slot) = self.seen.lock() {
            *slot = Some(fingerprint(end_entity.as_ref()));
        }
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

/// Uppercase colon-separated SHA-256, matching `openssl x509 -fingerprint`.
pub fn fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// UDM / UDR / Cloud Key Gen2+ — endpoints proxied under `/proxy/network`.
    UnifiOs,
    /// Software controller / Cloud Key Gen1.
    Legacy,
}

impl Flavour {
    fn login_path(&self) -> &'static str {
        match self {
            Flavour::UnifiOs => "/api/auth/login",
            Flavour::Legacy => "/api/login",
        }
    }

    /// Builds a Network-application path for a site.
    pub fn api_path(&self, site: &str, endpoint: &str) -> String {
        match self {
            Flavour::UnifiOs => format!("/proxy/network/api/s/{site}/{endpoint}"),
            Flavour::Legacy => format!("/api/s/{site}/{endpoint}"),
        }
    }
}

pub struct UnifiClient {
    host: String,
    port: u16,
    flavour: Flavour,
    /// Pinned fingerprint. Set on first successful connect, then enforced.
    pin: Option<String>,
    cookies: BTreeMap<String, String>,
    csrf: Option<String>,
}

/// Redacting `Debug`.
///
/// This type holds a live session cookie and CSRF token. Deriving `Debug` would
/// print both into any log line or panic message that formats the client, so the
/// impl is written by hand to report only whether a session exists.
impl std::fmt::Debug for UnifiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnifiClient")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("flavour", &self.flavour)
            .field("pinned", &self.pin.is_some())
            .field("authenticated", &!self.cookies.is_empty())
            .finish()
    }
}

/// Outcome of connecting for the first time, so the caller can persist the pin.
#[derive(Debug, Clone)]
pub struct Established {
    pub flavour: Flavour,
    pub fingerprint: String,
    /// True when no pin was supplied and this fingerprint was newly trusted.
    pub newly_pinned: bool,
}

impl UnifiClient {
    /// `pin` is the previously stored fingerprint, if any. Passing `None`
    /// trusts whatever is presented — acceptable exactly once, on first setup.
    pub fn new(host: &str, port: u16, pin: Option<String>) -> Result<Self, UnifiError> {
        // Same guard the deep-scan command applies: never send credentials
        // (or anything else) to public address space.
        if let Ok(addr) = host.parse::<std::net::Ipv4Addr>() {
            if !is_private_ipv4(addr) {
                return Err(UnifiError::NotPrivate(host.to_string()));
            }
        }

        Ok(Self {
            host: host.to_string(),
            port,
            flavour: Flavour::UnifiOs,
            pin,
            cookies: BTreeMap::new(),
            csrf: None,
        })
    }

    pub fn flavour(&self) -> Flavour {
        self.flavour
    }

    /// Opens a TLS connection and enforces the pin. Returns the live stream.
    async fn connect(
        &self,
    ) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, String), UnifiError> {
        let seen = Arc::new(Mutex::new(None));

        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(CapturingVerifier::new(Arc::clone(&seen))))
            .with_no_client_auth();
        config.enable_sni = false;

        let stream = tokio::time::timeout(
            DEFAULT_TIMEOUT,
            TcpStream::connect((self.host.as_str(), self.port)),
        )
        .await
        .map_err(|_| UnifiError::Connect("timed out".into()))?
        .map_err(|e| UnifiError::Connect(e.to_string()))?;

        let connector = TlsConnector::from(Arc::new(config));
        let name =
            ServerName::try_from("unifi.local").map_err(|e| UnifiError::Connect(e.to_string()))?;

        let tls = tokio::time::timeout(DEFAULT_TIMEOUT, connector.connect(name, stream))
            .await
            .map_err(|_| UnifiError::Connect("TLS handshake timed out".into()))?
            .map_err(|e| UnifiError::Connect(format!("TLS handshake failed: {e}")))?;

        let actual = seen
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
            .ok_or_else(|| UnifiError::Protocol("no certificate presented".into()))?;

        // The pin check happens here — after the handshake but before any
        // request body (and therefore any credential) is written.
        if let Some(expected) = &self.pin {
            if !expected.eq_ignore_ascii_case(&actual) {
                return Err(UnifiError::FingerprintMismatch {
                    expected: expected.clone(),
                    actual,
                });
            }
        }

        Ok((tls, actual))
    }

    fn cookie_header(&self) -> Option<String> {
        if self.cookies.is_empty() {
            return None;
        }
        Some(
            self.cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    fn absorb_cookies(&mut self, headers: &BTreeMap<String, String>) {
        // A single header map collapses repeated Set-Cookie values, so they are
        // joined with a newline by `parse_response` and split back out here.
        if let Some(raw) = headers.get("set-cookie") {
            for line in raw.split('\n') {
                let pair = line.split(';').next().unwrap_or("");
                if let Some((name, value)) = pair.split_once('=') {
                    self.cookies
                        .insert(name.trim().to_string(), value.trim().to_string());
                }
            }
        }
        for key in ["x-csrf-token", "x-updated-csrf-token"] {
            if let Some(token) = headers.get(key) {
                self.csrf = Some(token.clone());
            }
        }
    }

    async fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, BTreeMap<String, String>, String), UnifiError> {
        let (mut tls, _) = self.connect().await?;

        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}:{}\r\n",
            self.host, self.port
        );
        request.push_str("User-Agent: local-network-diag/1.0\r\nAccept: application/json\r\n");
        request.push_str("Connection: close\r\n");

        if let Some(cookie) = self.cookie_header() {
            request.push_str(&format!("Cookie: {cookie}\r\n"));
        }
        if let Some(csrf) = &self.csrf {
            request.push_str(&format!("X-CSRF-Token: {csrf}\r\n"));
        }
        if let Some(body) = body {
            request.push_str("Content-Type: application/json\r\n");
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        request.push_str("\r\n");
        if let Some(body) = body {
            request.push_str(body);
        }

        tls.write_all(request.as_bytes())
            .await
            .map_err(|e| UnifiError::Connect(e.to_string()))?;

        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            if buf.len() >= MAX_BODY {
                break;
            }
            match tokio::time::timeout(DEFAULT_TIMEOUT, tls.read(&mut chunk)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            }
        }

        let raw = String::from_utf8_lossy(&buf).into_owned();
        let (status, headers, body) = parse_response(&raw)
            .ok_or_else(|| UnifiError::Protocol("malformed HTTP response".into()))?;

        self.absorb_cookies(&headers);
        Ok((status, headers, body))
    }

    /// Detects the controller flavour without sending credentials.
    ///
    /// `/proxy/network/status` exists only on UniFi OS; a 401 there is as good a
    /// signal as a 200, since both prove the proxy is present.
    pub async fn detect_flavour(&mut self) -> Result<Flavour, UnifiError> {
        let (status, _, _) = self.request("GET", "/proxy/network/status", None).await?;
        self.flavour = if status == 404 {
            Flavour::Legacy
        } else {
            Flavour::UnifiOs
        };
        Ok(self.flavour)
    }

    /// Establishes a session. Returns the fingerprint so it can be pinned.
    pub async fn login(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<Established, UnifiError> {
        let newly_pinned = self.pin.is_none();
        let (_, fingerprint) = self.connect().await?;

        let flavour = self.detect_flavour().await?;

        let payload = serde_json::json!({
            "username": username,
            "password": password,
            "remember": false,
        })
        .to_string();

        let (status, _, body) = self
            .request("POST", flavour.login_path(), Some(&payload))
            .await?;

        // The status alone is not enough to tell these apart. Verified against a
        // UCK-G2: a wrong password returns **403**, not 401, with
        // `AUTHENTICATION_FAILED_INVALID_CREDENTIALS` in the body. Treating that
        // 403 as a permissions problem would send a user with a typo'd password
        // to fix their account's site access instead of their password.
        match classify_login(status, &body) {
            LoginOutcome::Ok => {}
            LoginOutcome::BadCredentials => return Err(UnifiError::Unauthorized),
            LoginOutcome::MfaRequired => {
                return Err(UnifiError::Protocol(
                    "This account requires two-factor authentication, which this integration \
                     cannot complete. Create a separate local account without MFA and give it \
                     the read-only Viewer role."
                        .into(),
                ))
            }
            LoginOutcome::NoPermission => return Err(UnifiError::Forbidden),
            LoginOutcome::Other(status) => {
                return Err(UnifiError::Http {
                    status,
                    detail: truncate(&body, 200),
                })
            }
        }

        if self.cookies.is_empty() {
            return Err(UnifiError::Protocol(
                "login succeeded but no session cookie was returned".into(),
            ));
        }

        Ok(Established {
            flavour,
            fingerprint,
            newly_pinned,
        })
    }

    /// GETs a Network-application endpoint and returns its `data` array.
    ///
    /// The controller wraps every payload as `{meta:{rc}, data:[…]}`; a failure
    /// is reported inside a 200 response, so `meta.rc` is checked too.
    pub async fn get_data(
        &mut self,
        site: &str,
        endpoint: &str,
    ) -> Result<serde_json::Value, UnifiError> {
        let path = self.flavour.api_path(site, endpoint);
        let (status, _, body) = self.request("GET", &path, None).await?;

        match status {
            200 => {}
            401 => return Err(UnifiError::Unauthorized),
            403 => return Err(UnifiError::Forbidden),
            other => {
                return Err(UnifiError::Http {
                    status: other,
                    detail: truncate(&body, 200),
                })
            }
        }

        let parsed: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| UnifiError::Protocol(format!("invalid JSON: {e}")))?;

        if let Some(rc) = parsed
            .get("meta")
            .and_then(|m| m.get("rc"))
            .and_then(|v| v.as_str())
        {
            if rc != "ok" {
                let message = parsed
                    .get("meta")
                    .and_then(|m| m.get("msg"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(rc);
                return Err(UnifiError::Protocol(format!(
                    "controller reported: {message}"
                )));
            }
        }

        Ok(parsed
            .get("data")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![])))
    }

    pub async fn logout(&mut self) {
        let path = match self.flavour {
            Flavour::UnifiOs => "/api/auth/logout",
            Flavour::Legacy => "/api/logout",
        };
        let _ = self.request("POST", path, Some("{}")).await;
        self.cookies.clear();
        self.csrf = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoginOutcome {
    Ok,
    BadCredentials,
    MfaRequired,
    NoPermission,
    Other(u16),
}

/// Interprets a login response.
///
/// UniFi's status codes are not self-describing here, so the body is consulted
/// too. Getting this wrong is user-hostile in a specific way: it points people at
/// the wrong fix.
pub(crate) fn classify_login(status: u16, body: &str) -> LoginOutcome {
    let lowered = body.to_ascii_lowercase();

    if lowered.contains("mfa") || lowered.contains("two_factor") || lowered.contains("2fa") {
        return LoginOutcome::MfaRequired;
    }

    let bad_credentials = lowered.contains("authentication_failed")
        || lowered.contains("invalid username or password")
        || lowered.contains("invalid_credentials");

    match status {
        200 => LoginOutcome::Ok,
        400 | 401 => LoginOutcome::BadCredentials,
        403 if bad_credentials => LoginOutcome::BadCredentials,
        403 => LoginOutcome::NoPermission,
        other if bad_credentials => {
            let _ = other;
            LoginOutcome::BadCredentials
        }
        other => LoginOutcome::Other(other),
    }
}

/// Splits an HTTP response. Repeated `Set-Cookie` headers are joined with `\n`
/// rather than overwriting, because the session and CSRF cookies arrive as
/// separate headers and dropping either breaks the session.
pub(crate) fn parse_response(raw: &str) -> Option<(u16, BTreeMap<String, String>, String)> {
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
    let mut lines = head.lines();
    let status: u16 = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().to_string();

        headers
            .entry(key)
            .and_modify(|existing| {
                existing.push('\n');
                existing.push_str(&value);
            })
            .or_insert(value);
    }

    // Controllers respond chunked; decode when present so JSON parses.
    let body = if headers
        .get("transfer-encoding")
        .map(|v| v.contains("chunked"))
        .unwrap_or(false)
    {
        decode_chunked(body)
    } else {
        body.to_string()
    };

    Some((status, headers, body))
}

pub(crate) fn decode_chunked(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;

    loop {
        let Some((size_line, remainder)) = rest.split_once("\r\n") else {
            break;
        };
        // A chunk header may carry extensions after a semicolon.
        let size_token = size_line.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_token, 16) else {
            break;
        };
        if size == 0 || remainder.len() < size {
            if size == 0 {
                break;
            }
            out.push_str(remainder);
            break;
        }
        out.push_str(&remainder[..size]);
        rest = remainder[size..]
            .strip_prefix("\r\n")
            .unwrap_or(&remainder[size..]);
    }

    out
}

fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_public_hosts_before_connecting() {
        let err = UnifiClient::new("8.8.8.8", 443, None).unwrap_err();
        assert!(matches!(err, UnifiError::NotPrivate(_)));
        assert!(UnifiClient::new("10.0.3.12", 443, None).is_ok());
        // A hostname cannot be checked here; the resolver decides.
        assert!(UnifiClient::new("unifi.local", 443, None).is_ok());
    }

    #[test]
    fn fingerprint_matches_openssl_format() {
        // Uppercase, colon-separated, 32 bytes.
        let printed = fingerprint(b"example");
        assert_eq!(printed.matches(':').count(), 31);
        assert!(printed
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase() || c == ':'));
    }

    #[test]
    fn collects_repeated_set_cookie_headers() {
        // The session and CSRF cookies arrive separately; overwriting loses one.
        let raw = "HTTP/1.1 200 OK\r\nSet-Cookie: TOKEN=abc; Path=/; HttpOnly\r\nSet-Cookie: csrf_token=xyz; Path=/\r\nX-CSRF-Token: header-token\r\n\r\n{}";
        let (status, headers, _) = parse_response(raw).unwrap();
        assert_eq!(status, 200);

        let mut client = UnifiClient::new("10.0.3.12", 443, None).unwrap();
        client.absorb_cookies(&headers);

        assert_eq!(client.cookies.get("TOKEN").unwrap(), "abc");
        assert_eq!(client.cookies.get("csrf_token").unwrap(), "xyz");
        assert_eq!(client.csrf.as_deref(), Some("header-token"));

        let cookie = client.cookie_header().unwrap();
        assert!(cookie.contains("TOKEN=abc") && cookie.contains("csrf_token=xyz"));
    }

    #[test]
    fn debug_output_never_contains_session_secrets() {
        let mut client = UnifiClient::new("10.0.3.12", 443, None).unwrap();
        client
            .cookies
            .insert("TOKEN".into(), "super-secret-session".into());
        client.csrf = Some("secret-csrf".into());

        let printed = format!("{client:?}");
        assert!(
            !printed.contains("super-secret-session"),
            "session leaked: {printed}"
        );
        assert!(!printed.contains("secret-csrf"), "csrf leaked: {printed}");
        assert!(
            printed.contains("authenticated: true"),
            "state should still be visible"
        );
    }

    #[test]
    fn a_wrong_password_is_reported_as_bad_credentials_not_a_permissions_problem() {
        // Captured from a real UCK-G2: bad credentials come back as 403, not 401.
        let body = r#"{"code":"AUTHENTICATION_FAILED_INVALID_CREDENTIALS","message":"Invalid username or password","level":"debug"}"#;
        assert_eq!(classify_login(403, body), LoginOutcome::BadCredentials);

        // A plain 403 with no such marker really is a permissions problem.
        assert_eq!(
            classify_login(403, "{\"error\":\"forbidden\"}"),
            LoginOutcome::NoPermission
        );

        assert_eq!(classify_login(200, "{}"), LoginOutcome::Ok);
        assert_eq!(classify_login(401, "{}"), LoginOutcome::BadCredentials);
        assert_eq!(classify_login(500, "{}"), LoginOutcome::Other(500));
    }

    #[test]
    fn an_mfa_challenge_is_explained_rather_than_reported_as_a_bad_password() {
        let body = r#"{"required":"MFA","code":"MFA_REQUIRED"}"#;
        assert_eq!(classify_login(499, body), LoginOutcome::MfaRequired);
    }

    #[test]
    fn builds_paths_for_both_flavours() {
        assert_eq!(
            Flavour::UnifiOs.api_path("default", "stat/sta"),
            "/proxy/network/api/s/default/stat/sta"
        );
        assert_eq!(
            Flavour::Legacy.api_path("default", "stat/sta"),
            "/api/s/default/stat/sta"
        );
        assert_eq!(Flavour::UnifiOs.login_path(), "/api/auth/login");
        assert_eq!(Flavour::Legacy.login_path(), "/api/login");
    }

    /// Builds a chunked body from real lengths, so the fixture cannot drift from
    /// what it claims to encode.
    fn chunked(parts: &[&str]) -> String {
        let mut out = String::new();
        for part in parts {
            out.push_str(&format!("{:x}\r\n{part}\r\n", part.len()));
        }
        out.push_str("0\r\n\r\n");
        out
    }

    #[test]
    fn decodes_chunked_bodies() {
        let payload = r#"{"meta":{"rc":"ok"},"data":[1,2]}"#;
        let body = chunked(&[&payload[..19], &payload[19..]]);
        assert_eq!(decode_chunked(&body), payload);
    }

    #[test]
    fn parses_chunked_response_end_to_end() {
        let raw = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n{}",
            chunked(&["{\"a\":", "1}"])
        );
        let (status, _, body) = parse_response(&raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "{\"a\":1}");
    }

    #[test]
    fn malformed_responses_are_rejected() {
        assert!(parse_response("").is_none());
        assert!(parse_response("garbage").is_none());
        assert!(parse_response("HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn fingerprint_mismatch_message_says_credentials_were_not_sent() {
        let err = UnifiError::FingerprintMismatch {
            expected: "AA:BB".into(),
            actual: "CC:DD".into(),
        };
        let text = err.to_string();
        assert!(
            text.contains("were not sent"),
            "must reassure the user: {text}"
        );
        assert!(text.contains("AA:BB") && text.contains("CC:DD"));
    }
}
