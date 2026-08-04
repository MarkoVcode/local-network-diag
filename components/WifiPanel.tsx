"use client";

import { ChannelCongestionChart, SignalMeter } from "./charts";
import { Card, KeyValue, StatusBadge, signalTone } from "./ui";
import type { ProbeResult, WifiInfo } from "@/lib/types";

export function WifiPanel({ wifi }: { wifi: ProbeResult<WifiInfo> }) {
  if (wifi.status !== "ok" || !wifi.data) {
    return (
      <Card title="Wi-Fi">
        <p className="text-xs" style={{ color: "var(--text-muted)" }}>
          {wifi.detail ?? "Wi-Fi information unavailable."}
        </p>
      </Card>
    );
  }

  const { current, networks, interface: iface } = wifi.data;

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Current link" subtitle={iface ? `Interface ${iface}` : undefined}>
        {!current ? (
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>
            Not associated with a Wi-Fi network.
          </p>
        ) : (
          <dl>
            <KeyValue label="SSID" value={<span className="font-medium">{current.ssid}</span>} />
            <KeyValue label="BSSID" value={current.bssid ?? "—"} mono />
            <KeyValue
              label="Signal"
              value={
                <span className="flex flex-wrap items-center gap-2">
                  <SignalMeter percent={current.signal} />
                  <StatusBadge tone={signalTone(current.signal)} label={`${current.signal}%`} />
                </span>
              }
            />
            <KeyValue label="Channel" value={`${current.channel} (${current.band})`} />
            <KeyValue label="Max rate" value={current.rate ?? "—"} />
            <KeyValue
              label="Security"
              value={
                current.security && current.security !== "Open" ? (
                  <StatusBadge tone="good" label={current.security} />
                ) : (
                  <StatusBadge tone="critical" label="Open — unencrypted" />
                )
              }
            />
          </dl>
        )}
      </Card>

      <Card title="Channel congestion" subtitle={`${networks.length} access points visible`}>
        <ChannelCongestionChart wifi={wifi.data} />
      </Card>

      <Card title="Visible networks" subtitle="Sorted by signal strength" className="lg:col-span-2">
        <div className="scroll-x">
          <table className="w-full min-w-[560px] border-collapse text-sm">
            <thead>
              <tr className="border-b text-left" style={{ borderColor: "var(--border)" }}>
                {["SSID", "Signal", "Channel", "Band", "Security"].map((label) => (
                  <th
                    key={label}
                    className="pb-2 pr-3 text-xs font-semibold"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    {label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {networks.map((network, i) => (
                <tr
                  key={`${network.bssid ?? network.ssid}-${i}`}
                  className="border-b"
                  style={{ borderColor: "var(--border)" }}
                >
                  <td className="py-1.5 pr-3">
                    <span className="flex flex-wrap items-center gap-1.5">
                      <span className={network.active ? "font-semibold" : ""}>{network.ssid}</span>
                      {network.active && <StatusBadge tone="good" label="Connected" />}
                    </span>
                    {network.bssid && (
                      <p className="mt-0.5 font-mono text-[11px] tabular" style={{ color: "var(--text-muted)" }}>
                        {network.bssid}
                      </p>
                    )}
                  </td>
                  <td className="py-1.5 pr-3">
                    <span className="flex items-center gap-2">
                      <SignalMeter percent={network.signal} />
                      <span className="font-mono text-xs tabular">{network.signal}%</span>
                    </span>
                  </td>
                  <td className="py-1.5 pr-3 font-mono text-xs tabular">{network.channel}</td>
                  <td className="py-1.5 pr-3 text-xs">{network.band}</td>
                  <td className="py-1.5 text-xs">{network.security}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
