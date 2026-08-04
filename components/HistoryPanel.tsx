"use client";

import { useEffect, useState } from "react";
import { Button, Card, EmptyState, formatDuration, formatRelativeTime, StatusBadge } from "./ui";
import { listSnapshots, getSnapshot } from "@/lib/api";
import type { DeviceChange, ScanDiff, SnapshotSummary } from "@/lib/types";

/**
 * The history view is where repeated scanning pays off: the diff turns a pile of
 * snapshots into "what actually changed on the network since last time".
 */
export function HistoryPanel({
  currentId,
  onSelect,
  refreshToken,
  onExport,
  onRevealDataDir,
}: {
  currentId?: string;
  onSelect: (id: string) => void;
  refreshToken: number;
  onExport: (format: "json" | "csv") => void;
  onRevealDataDir?: () => void;
}) {
  const [snapshots, setSnapshots] = useState<SnapshotSummary[] | null>(null);
  const [diff, setDiff] = useState<ScanDiff | null>(null);

  // `null` doubles as the loading state, so the effect never has to set state
  // synchronously just to flip a loading flag.
  const loading = snapshots === null;

  useEffect(() => {
    let cancelled = false;

    listSnapshots(50)
      .then((list) => {
        if (!cancelled) setSnapshots(list);
      })
      .catch(() => {
        if (!cancelled) setSnapshots([]);
      });

    return () => {
      cancelled = true;
    };
  }, [refreshToken]);

  useEffect(() => {
    if (!currentId) return;
    let cancelled = false;

    getSnapshot(currentId, "previous")
      .then((result) => {
        if (!cancelled) setDiff(result.diff ?? null);
      })
      .catch(() => {
        if (!cancelled) setDiff(null);
      });

    return () => {
      cancelled = true;
    };
  }, [currentId, refreshToken]);

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Changes since the previous scan" subtitle="New devices are listed first">
        {!diff ? (
          <EmptyState
            title="No comparison available"
            hint="Run at least two scans to see what changed between them."
          />
        ) : diff.changes.length === 0 ? (
          <EmptyState title="Nothing changed" hint="The network looks identical to the previous scan." />
        ) : (
          <ul className="space-y-2">
            {diff.changes.map((change, i) => (
              <ChangeRow key={i} change={change} />
            ))}
          </ul>
        )}
      </Card>

      <div className="min-w-0 space-y-4">
        <Card title="Scan history" subtitle={`${snapshots?.length ?? 0} run(s) stored on disk`}>
          {loading ? (
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Loading…
            </p>
          ) : snapshots.length === 0 ? (
            <EmptyState title="No scans recorded yet" />
          ) : (
            <ul className="max-h-[24rem] space-y-1 overflow-y-auto">
              {snapshots.map((snapshot) => {
                const active = snapshot.id === currentId;
                return (
                  <li key={snapshot.id}>
                    <button
                      type="button"
                      onClick={() => onSelect(snapshot.id)}
                      className="w-full rounded-lg border px-3 py-2 text-left transition-colors hover:bg-[var(--surface-raised)]"
                      style={{
                        borderColor: active ? "var(--series-1)" : "var(--border)",
                        background: active ? "var(--surface-raised)" : "transparent",
                      }}
                    >
                      <div className="flex flex-wrap items-baseline justify-between gap-2">
                        <span className="text-sm font-medium">
                          {new Date(snapshot.startedAt).toLocaleString()}
                        </span>
                        <span className="text-xs tabular" style={{ color: "var(--text-muted)" }}>
                          {formatRelativeTime(snapshot.startedAt)}
                        </span>
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-1.5">
                        <StatusBadge tone="neutral" label={`${snapshot.deviceCount} devices`} />
                        {snapshot.gatewayLatencyMs !== undefined && (
                          <StatusBadge
                            tone="neutral"
                            label={`gw ${snapshot.gatewayLatencyMs.toFixed(1)} ms`}
                          />
                        )}
                        {!snapshot.wanReachable && <StatusBadge tone="critical" label="No WAN" />}
                        {snapshot.warnings > 0 && (
                          <StatusBadge tone="warning" label={`${snapshot.warnings} note(s)`} />
                        )}
                        <span className="text-xs tabular" style={{ color: "var(--text-muted)" }}>
                          {formatDuration(snapshot.durationMs)}
                        </span>
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        <Card title="Export">
          <div className="flex flex-wrap gap-2">
            <Button onClick={() => onExport("json")} disabled={!currentId}>
              Export JSON
            </Button>
            <Button onClick={() => onExport("csv")} disabled={!currentId}>
              Export CSV
            </Button>
            {onRevealDataDir && <Button onClick={onRevealDataDir}>Show data folder</Button>}
          </div>
          <p className="mt-2 text-xs" style={{ color: "var(--text-secondary)" }}>
            Snapshots are kept on disk (last 200). JSON contains everything extracted; CSV is the
            device list flattened for spreadsheets.
          </p>
        </Card>
      </div>
    </div>
  );
}

const CHANGE_META: Record<
  DeviceChange["kind"],
  { tone: "good" | "warning" | "serious" | "critical" | "neutral"; label: string }
> = {
  appeared: { tone: "warning", label: "New device" },
  "ports-opened": { tone: "serious", label: "Ports opened" },
  "ip-changed": { tone: "neutral", label: "IP changed" },
  disappeared: { tone: "neutral", label: "Gone" },
  "ports-closed": { tone: "neutral", label: "Ports closed" },
  "name-changed": { tone: "neutral", label: "Renamed" },
};

function ChangeRow({ change }: { change: DeviceChange }) {
  const meta = CHANGE_META[change.kind];
  return (
    <li
      className="flex flex-wrap items-start gap-2 rounded-lg border p-2.5"
      style={{ borderColor: "var(--border)" }}
    >
      <StatusBadge tone={meta.tone} label={meta.label} />
      <span className="min-w-0 flex-1 text-sm" style={{ color: "var(--text-secondary)" }}>
        {change.detail}
      </span>
    </li>
  );
}
