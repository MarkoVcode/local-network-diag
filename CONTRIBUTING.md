# Contributing

Thanks for considering a contribution.

## Getting set up

You need **Node ≥ 20** and **Rust ≥ 1.77**, plus the Tauri system dependencies
for your OS ([prerequisites](https://tauri.app/start/prerequisites/)).

On Ubuntu/Debian:

```bash
sudo apt install libwebkit2gtk-4.1-dev libsoup-3.0-dev librsvg2-dev \
                 libxdo-dev libssl-dev libayatana-appindicator3-dev patchelf
```

Then:

```bash
npm install
npm run dev
```

## Working on the engine without a GUI

`crates/netdiag-core` has **no Tauri dependency**, so you can build and test the
entire scan engine without installing any desktop toolchain:

```bash
cargo test -p netdiag-core
cargo run -p netdiag-core --bin netdiag-cli -- doctor
cargo run -p netdiag-core --bin netdiag-cli -- scan standard
```

This is usually the fastest way to iterate on discovery logic.

## Before opening a pull request

CI runs these on Linux, macOS and Windows, and `clippy` is enforced with
`-D warnings`:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run typecheck
npm run lint
```

## What good changes look like

**Parsing changes need a test with real output.** Every platform parser
(`crates/netdiag-core/src/platform/`) is tested against captured command output.
If you fix a parser, paste the actual output your machine produced into a test
case — that is what stops the fix regressing on someone else's locale, OS
version, or hardware.

**Be careful with cross-platform assumptions.** Several bugs in this codebase
came from tools that look identical but are not:

- BSD/macOS `ping` takes `-W` in **milliseconds**; Linux takes **seconds**.
- Windows `ping` exits `0` even when every reply is "Destination host
  unreachable", so exit status alone is not a liveness signal.
- `ipconfig` output is **localised**; parse structurally or use PowerShell.
- BSD `arp` prints unpadded MAC octets (`e0:63:da:8:1b:5`).

**Prefer portable implementations.** mDNS, SSDP, NetBIOS, DNS and port scanning
are implemented directly on sockets rather than shelling out, which is why they
work identically everywhere and need nothing installed. Reach for the platform
layer only when there is genuinely no portable way.

**Never require elevated privileges.** The app must keep working as an ordinary
user. If a feature seems to need root, it probably has an unprivileged
alternative — see how MAC addresses are obtained via the ARP cache rather than
raw sockets.

**Degrade, don't fail.** A missing tool must produce a warning and a reduced
result, never an error. If you add a dependency on an external tool, add a
matching check in `crates/netdiag-core/src/doctor.rs` that says what breaks
without it and how to fix it on each OS.

## Adding a capability check

Doctor checks are **functional probes, not `which` checks** — they perform the
operation and report what actually happened. A binary being present says very
little: `ping` can exist without `cap_net_raw`, macOS Wi-Fi tools return nothing
without Location Services permission, and a container's ARP table can be
readable but permanently empty.

Each check must supply a tier (`Critical`/`Important`/`Optional`), what it is
for, what stops working without it, and a per-OS remedy. There is a test that
enforces the last two for anything not in the `Ok` state.

## Reporting bugs

Please include the output of:

```bash
cargo run -p netdiag-core --bin netdiag-cli -- doctor
```

or a screenshot of the **Setup & Status** page. It shows exactly which
capabilities are available on your machine, which is the first thing worth
knowing for almost any scan issue.

Do not paste full scan output publicly without reviewing it — it contains MAC
addresses, hostnames and open ports for your network.

## Scope

This tool deliberately scans **only private address ranges** and refuses
anything wider than a `/22`. Please don't send changes that remove those guards.
