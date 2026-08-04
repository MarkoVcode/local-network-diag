"use client";

import { LatencySparkline } from "./charts";
import { Card, KeyValue, Pill, StatusBadge, latencyTone, lossTone } from "./ui";
import type { ConnectivityInfo, LatencyStats } from "@/lib/types";

/**
 * Separates the three places "the internet is slow" actually originates: the
 * local hop to the gateway, name resolution, and the path beyond.
 */
export function ConnectivityPanel({ connectivity }: { connectivity: ConnectivityInfo }) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Latency" subtitle="Round-trip time to the gateway and to external hosts">
        <div className="space-y-5">
          {connectivity.gateway && <LatencyBlock stats={connectivity.gateway} isLocal />}
          {connectivity.wan.map((stats) => (
            <LatencyBlock key={stats.target} stats={stats} isLocal={false} />
          ))}
        </div>
      </Card>

      <div className="min-w-0 space-y-4">
        <Card title="DNS" subtitle="Resolution time per configured server">
          {connectivity.dns.length === 0 ? (
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              No DNS servers configured.
            </p>
          ) : (
            <ul className="space-y-2.5">
              {connectivity.dns.map((entry) => (
                <li key={entry.server}>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-sm tabular">{entry.server}</span>
                    {entry.ok ? (
                      <StatusBadge
                        tone={latencyTone(entry.responseMs, false)}
                        label={entry.responseMs !== undefined ? `${entry.responseMs} ms` : "resolved"}
                      />
                    ) : (
                      <StatusBadge tone="critical" label={entry.error ?? "failed"} />
                    )}
                  </div>
                  {entry.answers.length > 0 && (
                    <p className="mt-0.5 font-mono text-xs" style={{ color: "var(--text-muted)" }}>
                      {entry.query} → {entry.answers.slice(0, 3).join(", ")}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Internet" subtitle="Reachability beyond the gateway">
          <dl>
            <KeyValue
              label="WAN status"
              value={
                connectivity.wanReachable ? (
                  <StatusBadge tone="good" label="Reachable" />
                ) : (
                  <StatusBadge tone="critical" label="Unreachable" />
                )
              }
            />
            <KeyValue
              label="Public IP"
              value={
                connectivity.publicIp ? (
                  <span className="font-mono tabular">{connectivity.publicIp}</span>
                ) : (
                  <span style={{ color: "var(--text-muted)" }}>not determined</span>
                )
              }
            />
            <KeyValue
              label="Resolvers"
              value={
                connectivity.dns.length > 0 ? (
                  <span className="font-mono text-xs">
                    {connectivity.dns.map((entry) => entry.server).join(", ")}
                  </span>
                ) : (
                  <span style={{ color: "var(--text-muted)" }}>none configured</span>
                )
              }
            />
          </dl>
        </Card>
      </div>

      <Card
        title="Path"
        subtitle={
          connectivity.trace.status === "ok"
            ? `Hops reported by ${connectivity.trace.data?.tool}`
            : "Route to the first external hop"
        }
        className="lg:col-span-2"
      >
        {connectivity.trace.status !== "ok" || !connectivity.trace.data ? (
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>
            {connectivity.trace.detail ?? "Traceroute unavailable."}
          </p>
        ) : (
          <div className="scroll-x">
            <table className="w-full min-w-[420px] border-collapse text-sm">
              <thead>
                <tr className="border-b text-left" style={{ borderColor: "var(--border)" }}>
                  <th className="pb-2 pr-3 text-xs font-semibold" style={{ color: "var(--text-secondary)" }}>
                    Hop
                  </th>
                  <th className="pb-2 pr-3 text-xs font-semibold" style={{ color: "var(--text-secondary)" }}>
                    Host
                  </th>
                  <th className="pb-2 pr-3 text-xs font-semibold" style={{ color: "var(--text-secondary)" }}>
                    RTT
                  </th>
                  <th className="pb-2 text-xs font-semibold" style={{ color: "var(--text-secondary)" }}>
                    Loss
                  </th>
                </tr>
              </thead>
              <tbody>
                {connectivity.trace.data.hops.map((hop, i) => (
                  <tr key={`${hop.hop}-${i}`} className="border-b" style={{ borderColor: "var(--border)" }}>
                    <td className="py-1.5 pr-3 font-mono text-xs tabular">{hop.hop}</td>
                    <td className="py-1.5 pr-3 font-mono text-xs">
                      {hop.timeout ? (
                        <span style={{ color: "var(--text-muted)" }}>no reply</span>
                      ) : (
                        (hop.host ?? "—")
                      )}
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-xs tabular">
                      {hop.rttMs !== undefined ? `${hop.rttMs.toFixed(1)} ms` : "—"}
                    </td>
                    <td className="py-1.5 text-xs">
                      {hop.lossPercent !== undefined && hop.lossPercent > 0 ? (
                        <StatusBadge tone={lossTone(hop.lossPercent)} label={`${hop.lossPercent}%`} />
                      ) : (
                        <span className="font-mono tabular" style={{ color: "var(--text-muted)" }}>
                          0%
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

function LatencyBlock({ stats, isLocal }: { stats: LatencyStats; isLocal: boolean }) {
  return (
    <div>
      <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-baseline gap-2">
          <h4 className="text-sm font-medium">{stats.label}</h4>
          <span className="font-mono text-xs tabular" style={{ color: "var(--text-muted)" }}>
            {stats.target}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <StatusBadge
            tone={latencyTone(stats.avgMs, isLocal)}
            label={stats.avgMs !== undefined ? `avg ${stats.avgMs.toFixed(1)} ms` : "no reply"}
          />
          <StatusBadge tone={lossTone(stats.lossPercent)} label={`${stats.lossPercent.toFixed(0)}% loss`} />
        </div>
      </div>

      <LatencySparkline stats={stats} />

      <div className="mt-1.5 flex flex-wrap gap-1.5">
        {stats.minMs !== undefined && <Pill mono>min {stats.minMs.toFixed(1)}</Pill>}
        {stats.maxMs !== undefined && <Pill mono>max {stats.maxMs.toFixed(1)}</Pill>}
        {stats.jitterMs !== undefined && <Pill mono>jitter {stats.jitterMs.toFixed(1)}</Pill>}
        <Pill mono>
          {stats.received}/{stats.sent} replies
        </Pill>
      </div>
    </div>
  );
}
