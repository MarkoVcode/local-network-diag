# UniFi integration — Phase 2 plan

Phase 1 (shipped in 1.1.0) fetches `stat/sta`, `stat/device` and `stat/alluser`,
enriches scanned devices with controller identity and physical location, and
produces the reconciliation quadrant (matched / shadow / missed / hidden
segments / identity conflicts).

Phase 2 keeps every Phase 1 invariant:

- **Read-only** — GETs plus login/logout, nothing else. All new endpoints below
  are GETs (`stat/event` accepts query parameters on GET, so no POST is needed).
- **Degrade, never fail** — each new endpoint goes through the existing
  per-endpoint warning path in `unifi::fetch` (`crates/netdiag-core/src/unifi/mod.rs`).
  A Viewer account that cannot read one collection still delivers the rest.
- **Tolerant models** — every field optional, unknown keys ignored
  (`crates/netdiag-core/src/unifi/model.rs` doc comment is the contract).
- **Scanner measurements win** — controller data enriches, never overwrites
  what the scan observed first-hand (`correlate.rs` rule).

The four work packages are ordered by leverage: WP1 needs no new endpoints at
all, WP2–WP4 each add endpoints of increasing interpretation effort.

---

## WP1 — Surface data already parsed and dropped ✅ (implemented)

No new HTTP calls. `UnifiClientRecord` and `PortEntry` already deserialize
these fields; they are discarded in `correlate::apply` today.

### 1a. Per-client wireless experience

- **New `Device` fields** (`crates/netdiag-core/src/types.rs`, mirrored in
  `lib/types.ts`): `satisfaction`, `channel`, `radio_proto` (normalize to
  "Wi-Fi 4/5/6/7" labels from `ng`/`ac`/`ax`/`be`), `tx_bytes`, `rx_bytes`,
  `unifi_uptime`, `unifi_first_seen`, `is_guest`, `unifi_note`.
- **Copy them in `correlate::apply`** next to the existing `rssi`/`vlan` block.
- **UI**: extend the "From the UniFi controller" card in
  `components/DeviceDetail.tsx` — satisfaction as a percentage with a
  low-satisfaction hint ("below ~70 % usually means weak signal or a congested
  channel"), radio generation, traffic counters humanized.
- **New finding — poor wireless experience**: in `correlate.rs`, collect
  clients with `satisfaction < 60` or `rssi < -75 dBm` into a new
  `Vec<WirelessHealthIssue>` on `Reconciliation`, each with the AP/SSID it is
  associated to and a plain-language explanation. This turns "the device is
  slow" from a support mystery into a stated cause.
- **New finding — recent arrival**: `first_seen` within the last 48 h and not
  matched to a prior snapshot → note on the shadow/new-device path. Strengthens
  the existing new-device story with controller-side evidence.
- **Guest flag**: a guest-network client with open TCP ports joins
  `identity_conflicts` ("guest devices normally initiate connections, not
  accept them").

### 1b. Infrastructure port detail

- **Extend `UnifiDeviceSummary`** (model.rs) with a `ports` summary built from
  the already-parsed `PortEntry`: index, name, up, negotiated speed,
  `poe_power` (watts, when the JSON value is numeric or numeric-string).
- **New finding — degraded link**: a port that is up at 10/100 Mbps on a
  switch whose other ports negotiate 1000+ suggests a bad cable — classic
  diagnostics gold, zero extra requests. Add to `Reconciliation` as
  `degraded_links`.
- **Device state check**: `UnifiDeviceRecord.state` is parsed but never read.
  State ≠ 1 (connected) on an adopted device → warning in the infrastructure
  section ("controller reports this AP heartbeat-missed / isolated").
- **UI**: expandable port table under each switch in the
  "Controller infrastructure" section of `components/ReconciliationPanel.tsx`.

**Tests**: fixture-driven, same style as existing `model.rs`/`correlate.rs`
tests — satisfaction thresholds, speed-mismatch detection, numeric-vs-string
`poe_power`, state ≠ 1.

---

## WP2 — Site health: "is it my LAN or my internet?" (`stat/health`) ✅ (implemented)

- **Endpoint**: add `("stat/health", "site health")` to the `ENDPOINTS` table.
- **Model**: `HealthSubsystem { subsystem, status, wan_ip, latency, xput_up,
  xput_down, drops, gw_name, num_sta, ... }` — all optional. The payload is one
  record per subsystem (`wan`, `www`, `wlan`, `lan`, `vpn`).
- **Snapshot**: `UnifiSnapshot.health: Vec<HealthSubsystem>` (serialized —
  unlike raw clients it is small and belongs in stored snapshots; note the
  `#[serde(skip)]` pattern on the raw collections and deliberately do NOT skip
  this one).
- **Interpretation** (new fn in `correlate.rs` or a small `health.rs`):
  - `www.status == "ok"` + LAN findings → "your internet link is healthy;
    the problem is local".
  - `www` latency / drops elevated → banner "controller reports WAN latency
    of X ms — slowness is upstream, not on your LAN".
  - `wan_ip` shown in the infrastructure section.
- **UI**: a compact status strip at the top of `ReconciliationPanel.tsx`
  (WAN · WWW · WLAN · LAN chips, green/amber/red), plus the triage sentence.
- **TS**: mirror types in `lib/types.ts`.

This is the single highest-value user-facing sentence the app can add: it
answers the question every home user actually has.

---

## WP3 — Configured networks: scan what the controller knows (`rest/networkconf`)

- **Endpoint**: add `("rest/networkconf", "configured networks")`.
- **Model**: `NetworkConf { name, purpose, ip_subnet, vlan, enabled,
  vlan_enabled, dhcpd_enabled, ... }` — all optional.
- **Correlation** (this is the payload):
  1. Compare each enabled network's `ip_subnet` against the ranges the scan
     actually covered (`Device.source_range` / the per-network scan history
     from `crates/netdiag-core/src/networks.rs`).
  2. Emit a new `Reconciliation.unscanned_networks: Vec<UnscannedNetwork>`
     entry for every configured subnet the scanner has never visited:
     "The controller defines *IoT (VLAN 30, 10.0.30.0/24)* but this machine
     has never scanned it — devices there are invisible to every scan so far."
  3. Upgrade the missed-device explanation: when a missed client's
     `network` names one of these subnets, replace the generic "a network this
     machine cannot route to" guess with the concrete network name and VLAN.
  4. Resolve `Device.vlan` numbers into network names in the UI (a name is
     meaningful; "VLAN 30" is not).
- **UI**: new card in `ReconciliationPanel.tsx` listing configured networks
  with a scanned/never-scanned badge; clicking a never-scanned one can
  pre-fill the custom-range scan input in `DesktopApp.tsx`.
- **Caveat to handle**: some Viewer roles cannot read `rest/` configuration
  endpoints — the per-endpoint warning path already covers this; just verify
  the warning copy tells the user *which role* fixes it.

This work package closes the loop with the per-network scan history shipped in
1.1.0: the controller becomes the source of truth for *which networks exist*,
and the scanner reports its own blind spots.

---

## WP4 — Events, alarms and rogue APs (`stat/event`, `list/alarm`, `stat/rogueap`)

- **Endpoints** (all GET; note `get_data` appends the endpoint verbatim, so
  query strings ride along):
  - `stat/event?_limit=200&within=24` — recent event log
  - `list/alarm?archived=false` — active alarms
  - `stat/rogueap?within=24` — neighboring/foreign APs overheard by radios
- **Models**: `EventRecord { key, subsystem, time, msg, user (client mac),
  ap, ssid, ... }`, `AlarmRecord`, `RogueApRecord { essid, bssid, channel,
  rssi, security, is_default? }` — all optional fields.
- **Correlation**:
  - **Missed-device upgrade**: a missed device whose MAC appears in a
    disconnect/roam event inside the scan window gets "the controller logged
    it disconnecting N minutes before the scan" instead of a guess.
  - **Flapping detection**: ≥ 3 connect/disconnect events for one client in
    24 h → new finding ("unstable association — usually weak signal or a
    failing power supply on the device").
  - **Active alarms** surface verbatim (they are already human sentences).
  - **Rogue AP list**: shown as an RF-environment section — open networks
    nearby, and a hard warning if a foreign AP broadcasts one of the site's
    own SSIDs (evil-twin signature). Pure signal a host scanner can never see.
- **UI**: "Controller events" and "Nearby networks" cards in
  `ReconciliationPanel.tsx`; event correlation notes inline on missed devices.
- **Volume control**: keep only events referencing MACs in the current
  snapshot plus alarms; do not persist the raw event list (same
  `#[serde(skip)]` treatment as raw clients).

**Stretch (WP5, unordered)**: `list/wlanconf` — flag open/WPA1 SSIDs and
disabled guest isolation; `stat/report/hourly.site` for trend lines;
`stat/sitedpi` traffic categories where DPI is enabled.

---

## Cross-cutting notes

- **Rust → TS type mirroring**: every new snapshot/reconciliation field needs
  its camelCase mirror in `lib/types.ts`; the existing `#[serde(rename_all =
  "camelCase")]` pattern carries the wire format.
- **Stored snapshots**: all new fields are `Option`/`#[serde(default)]`, so
  old snapshots in the store load unchanged (same tolerance rule as the
  controller payloads themselves).
- **CLI doctor**: extend `netdiag-cli doctor` to print which of the Phase 2
  endpoints the configured account can actually read, so permission problems
  are diagnosed before a scan.
- **Sequencing**: land WP1 alone first (pure surfacing, lowest risk), then
  WP2, WP3, WP4 as independent PRs — each is one endpoint family plus one
  Reconciliation extension plus one UI card, individually revertible.

---

## Capability inventory (for the project landing page)

Kept here so the landing page can be written from one list. Phrase benefits,
not endpoints.

### Shipped today (scanner core)

- Cross-platform desktop app (Tauri) — no cloud, no account, data never
  leaves the machine
- Multi-method discovery: ICMP, TCP sweep (finds ping-ignoring hosts), mDNS,
  SSDP, NetBIOS, reverse DNS, ARP/MAC + OUI vendor lookup
- Device-type inference with stated evidence, randomized-MAC detection
- Port scan with service banners; per-network scan history and
  new/changed-device tracking

### Shipped today (UniFi integration, Phase 1)

- Read-only by construction — the client can only GET; it cannot change the
  network even if misconfigured
- Credentials guarded: TOFU certificate pinning, refuses public addresses,
  password kept in the OS keychain, secrets redacted from every error path
- Enrichment the scanner alone can never know: operator-assigned device
  names, which switch port / which AP + SSID each device is on, VLAN,
  wired/wireless, signal strength, controller device fingerprint
- Identifies devices with randomized MACs via controller history
- **Reconciliation** — the headline: scan vs controller as cross-checking
  witnesses. Shadow devices (on the wire but unknown to the controller —
  including IP-conflict/ARP-spoof signatures), missed devices (controller
  says connected, scan can't reach), hidden segments (unmanaged switches
  inferred from crowded ports), identity conflicts (a "smart TV" exposing
  SSH)
- Degrades per endpoint instead of failing; survives controller upgrades by
  design

### Phase 2 (planned — this document)

- Wireless experience diagnostics: satisfaction, signal, channel, Wi-Fi
  generation per device — "why is this device slow", answered
- Bad-cable detection from switch port speeds; PoE power draw per port;
  AP/switch health states
- WAN-vs-LAN triage from controller site health: "the problem is (not) your
  internet"
- Network blind-spot detection: configured VLANs/subnets the scanner has
  never visited, named missed-device locations
- Event correlation: disconnect/flap history explains unreachable devices
- RF environment: nearby/rogue APs, evil-twin SSID warning
