# Security Policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/MarkoVcode/local-network-diag/security/advisories/new)
rather than opening a public issue.

Include what you can reproduce, the platform you saw it on, and the impact you
believe it has. You can expect an initial response within a few days.

## Scope

This is a desktop network-diagnostic tool. The security properties it aims to
hold are:

| Property | How it is maintained |
| --- | --- |
| **No shell injection** | Every external command runs through `crates/netdiag-core/src/exec.rs` using argv arrays with no shell, so an IP or CIDR from the UI cannot be interpreted as shell syntax. |
| **No privilege escalation** | The app runs entirely as an ordinary user. It never requests root/Administrator and has no setuid component. |
| **Private ranges only** | Scanning is restricted to RFC1918/CGNAT/link-local space, and ranges wider than `/22` are refused. The per-host deep scan rejects public addresses. |
| **No untrusted code in the webview** | A strict CSP is enforced, the webview has no network permissions, and all I/O happens in Rust. |
| **Bounded parsing** | Network responses (DNS/mDNS, NetBIOS, SSDP, HTTP) are parsed with explicit length checks and jump budgets. Malformed or hostile packets must not panic or hang. |
| **Credentials never leave the keychain** | UniFi controller passwords are stored in the OS keychain, never in snapshots (which are exportable) or logs. The client's `Debug` impl is written by hand so a session cookie cannot be printed. |
| **Credentials only over a pinned connection** | The controller's TLS certificate is pinned on first use and verified **before** the login request is written. A changed fingerprint aborts without transmitting anything. The permissive verifier used for LAN banner-grabbing is deliberately *not* reused here. |
| **Public HTTPS is fully verified** | The update check validates certificates against real CA roots — the opposite of the LAN inspection path, and a distinction worth preserving. |

Findings that would break any of the above are in scope, as are memory-safety
issues and anything that causes the app to send data off the local network
unexpectedly.

## Out of scope

- The fact that the app performs unauthenticated network scanning. That is its
  purpose; it is intended for networks you are responsible for.
- Unsigned release binaries. This is a known, documented state — see the README.
- Findings that require an attacker to already have code execution on the
  machine running the app.
- The update check contacting `api.github.com` on launch. It is documented, can
  be disabled, and sends nothing but the request itself.

## A note on what the app collects

Scan snapshots contain MAC addresses, hostnames, open ports and service banners
for your network. They are stored locally in the OS application-data directory
and are never transmitted anywhere. Review them before sharing in a bug report.
