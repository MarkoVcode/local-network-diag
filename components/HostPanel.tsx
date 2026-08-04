"use client";

import { Card, KeyValue, StatusBadge } from "./ui";
import type { ScanSnapshot } from "@/lib/types";

export function HostPanel({ snapshot }: { snapshot: ScanSnapshot }) {
  const { host } = snapshot;

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Interfaces" subtitle="Addresses, link state and what gets scanned">
        <ul className="space-y-3">
          {host.interfaces.map((iface) => (
            <li key={iface.name} className="rounded-lg border p-3" style={{ borderColor: "var(--border)" }}>
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-sm font-semibold">{iface.name}</span>
                {iface.isPrimary && <StatusBadge tone="good" label="Default route" />}
                {iface.scannable ? (
                  <StatusBadge tone="good" label="Scanned" />
                ) : (
                  <StatusBadge tone="neutral" label={iface.skipReason ?? "Not scanned"} />
                )}
              </div>

              <dl className="mt-1.5">
                <KeyValue
                  label="State"
                  value={`${iface.state}${iface.mtu ? ` · MTU ${iface.mtu}` : ""}`}
                />
                {iface.mac && <KeyValue label="MAC" value={iface.mac} mono />}
                {iface.ipv4.length > 0 && (
                  <KeyValue
                    label="IPv4"
                    value={iface.ipv4.map((a) => `${a.address}/${a.cidr}`).join(", ")}
                    mono
                  />
                )}
                {iface.ipv6.length > 0 && (
                  <KeyValue
                    label="IPv6"
                    value={
                      <span className="text-xs">
                        {iface.ipv6.map((a) => `${a.address}/${a.cidr} (${a.scope})`).join(", ")}
                      </span>
                    }
                    mono
                  />
                )}
              </dl>
            </li>
          ))}
        </ul>
      </Card>

      <div className="min-w-0 space-y-4">
        <Card title="DNS configuration">
          <dl>
            <KeyValue
              label="Servers"
              value={host.dns.servers.length ? host.dns.servers.join(", ") : "none configured"}
              mono
            />
            <KeyValue
              label="Search domains"
              value={host.dns.searchDomains.length ? host.dns.searchDomains.join(", ") : "—"}
              mono
            />
          </dl>
        </Card>

        <Card title="Scan targets" subtitle="Ranges swept in this run">
          <ul className="space-y-2">
            {host.scanTargets.map((target) => (
              <li key={target.cidr} className="flex flex-wrap items-center justify-between gap-2">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm tabular">{target.cidr}</span>
                  {target.source === "discovered" && <StatusBadge tone="warning" label="Discovered" />}
                  {target.source === "manual" && <StatusBadge tone="neutral" label="Manual" />}
                </span>
                <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                  {target.hostCount} hosts{target.note ? ` · ${target.note}` : ""}
                </span>
              </li>
            ))}
          </ul>
        </Card>

        <Card title="Routing table">
          <div className="scroll-x">
            <ul className="min-w-fit space-y-1">
              {host.routes.map((route, i) => (
                <li
                  key={i}
                  className="font-mono text-xs whitespace-nowrap"
                  style={{ color: "var(--text-secondary)" }}
                >
                  {route.raw}
                </li>
              ))}
            </ul>
          </div>
        </Card>

        <Card title="Scan environment">
          <dl>
            <KeyValue label="Host" value={host.hostname} />
            <KeyValue label="Platform" value={host.platform} />
            <KeyValue label="Engine version" value={host.appVersion} mono />
            <KeyValue label="Port profile" value={snapshot.config.portProfile} />
          </dl>

          {/*
            Capabilities are recorded at scan time, so a stored snapshot explains
            its own gaps rather than being judged against today's environment.
          */}
          <div className="mt-3">
            <h4 className="mb-1.5 text-xs font-semibold">Capabilities during this scan</h4>
            <ul className="flex flex-wrap gap-1.5">
              {snapshot.capabilities.map((capability) => (
                <li key={capability.id}>
                  <span
                    className="inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-xs"
                    style={{
                      borderColor: "var(--border)",
                      color:
                        capability.status === "ok"
                          ? "var(--text-primary)"
                          : "var(--text-secondary)",
                    }}
                  >
                    <span
                      aria-hidden
                      style={{
                        fontSize: "0.7em",
                        color:
                          capability.status === "ok"
                            ? "var(--status-good)"
                            : capability.status === "degraded"
                              ? "var(--status-warning)"
                              : "var(--status-critical)",
                      }}
                    >
                      ●
                    </span>
                    {capability.label}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </Card>
      </div>

      {snapshot.warnings.length > 0 && (
        <Card title={`Warnings (${snapshot.warnings.length})`} className="lg:col-span-2">
          <ul className="space-y-1.5">
            {snapshot.warnings.map((warning, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                <span aria-hidden style={{ color: "var(--status-warning)" }}>
                  ▲
                </span>
                <span style={{ color: "var(--text-secondary)" }}>{warning}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
