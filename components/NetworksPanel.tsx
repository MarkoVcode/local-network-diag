"use client";

import { useState } from "react";
import { Button, Card, EmptyState, Pill, StatusBadge, formatRelativeTime } from "./ui";
import * as api from "@/lib/api";
import type { NetworkProfile } from "@/lib/types";

/**
 * Managing the tracked networks.
 *
 * The fingerprint is shown rather than hidden, because when detection gets it
 * wrong the reason is always visible here — usually a gateway address that was
 * never resolved, leaving nothing but the subnet to go on.
 */
export function NetworksPanel({
  networks,
  activeId,
  onChanged,
  onDiscover,
}: {
  networks: NetworkProfile[];
  activeId?: string;
  onChanged: () => void;
  /** Reopens the first-run picker of currently-visible subnets. */
  onDiscover?: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [draftName, setDraftName] = useState("");
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState<string | null>(null);
  const [newName, setNewName] = useState("");

  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await action();
      onChanged();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
      setRenaming(null);
      setConfirmDelete(null);
      setConfirmClear(null);
    }
  };

  return (
    <div className="space-y-4">
      <Card
        title="Networks"
        subtitle="Each network keeps its own scan history, diffs and controller settings"
        actions={
          onDiscover && (
            <Button onClick={onDiscover} disabled={busy}>
              Discover networks…
            </Button>
          )
        }
      >
        <p className="mb-3 text-sm" style={{ color: "var(--text-secondary)" }}>
          Two places often use the same subnet — <code>192.168.0.0/24</code> is not unusual at
          both home and an office. Networks are told apart primarily by the gateway&apos;s
          hardware address, so scanning at a new site keeps its results separate instead of
          corrupting the history of the last one.
        </p>

        {networks.length === 0 ? (
          <EmptyState
            title="No networks yet"
            hint="Create one for the network you are on now."
          />
        ) : (
          <ul className="space-y-2">
            {networks.map((network) => {
              const active = network.id === activeId;
              const weak = !network.fingerprint.gatewayMac && !network.fingerprint.ssid;

              return (
                <li
                  key={network.id}
                  className="rounded-lg border p-3"
                  style={{ borderColor: active ? "var(--series-1)" : "var(--border)" }}
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      {renaming === network.id ? (
                        <div className="flex flex-wrap items-center gap-2">
                          <input
                            type="text"
                            value={draftName}
                            onChange={(e) => setDraftName(e.target.value)}
                            autoFocus
                            className="rounded border px-2 py-1 text-sm"
                            style={{
                              borderColor: "var(--border-strong)",
                              background: "var(--surface-raised)",
                              color: "var(--text-primary)",
                            }}
                          />
                          <Button
                            onClick={() => run(() => api.renameNetwork(network.id, draftName))}
                            disabled={busy || !draftName.trim()}
                          >
                            Save
                          </Button>
                          <button
                            type="button"
                            onClick={() => setRenaming(null)}
                            className="text-xs hover:underline"
                            style={{ color: "var(--text-muted)" }}
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-medium">{network.name}</span>
                          {active && <StatusBadge tone="good" label="Active" />}
                          {network.hasUnifi && (
                            <span
                              className="rounded border px-1 text-[9px] font-semibold uppercase tracking-wide"
                              style={{ borderColor: "var(--border-strong)", color: "var(--series-1)" }}
                              title="A UniFi controller is configured for this network"
                            >
                              UniFi
                            </span>
                          )}
                          {weak && (
                            <StatusBadge tone="warning" label="Weak fingerprint" />
                          )}
                        </div>
                      )}

                      <div className="mt-1 flex flex-wrap gap-1.5">
                        {network.fingerprint.subnets.map((subnet) => (
                          <Pill key={subnet} mono>
                            {subnet}
                          </Pill>
                        ))}
                        {network.fingerprint.ssid && <Pill>{network.fingerprint.ssid}</Pill>}
                        {network.fingerprint.gatewayMac && (
                          <Pill mono>gw {network.fingerprint.gatewayMac}</Pill>
                        )}
                      </div>

                      <p className="mt-1 text-xs" style={{ color: "var(--text-muted)" }}>
                        {network.scanCount} scan{network.scanCount === 1 ? "" : "s"}
                        {network.lastSeenAt
                          ? ` · last ${formatRelativeTime(network.lastSeenAt)}`
                          : " · never scanned"}
                      </p>

                      {weak && (
                        <p className="mt-1.5 text-xs" style={{ color: "var(--text-secondary)" }}>
                          Only the subnet identifies this network, so it cannot be told apart
                          from another site using the same range. Select it and use{" "}
                          <em>Re-detect</em> while connected to pick up the gateway address.
                        </p>
                      )}
                    </div>

                    <div className="flex shrink-0 flex-wrap gap-2">
                      {!active && (
                        <Button
                          onClick={() => run(() => api.switchNetwork(network.id))}
                          disabled={busy}
                        >
                          Switch
                        </Button>
                      )}
                      <button
                        type="button"
                        onClick={() => {
                          setRenaming(network.id);
                          setDraftName(network.name);
                        }}
                        disabled={busy}
                        className="text-xs hover:underline"
                        style={{ color: "var(--text-muted)" }}
                      >
                        Rename
                      </button>
                      {network.scanCount > 0 && (
                        <button
                          type="button"
                          onClick={() => setConfirmClear(network.id)}
                          disabled={busy}
                          className="text-xs hover:underline"
                          style={{ color: "var(--text-muted)" }}
                        >
                          Clear history
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => setConfirmDelete(network.id)}
                        disabled={busy}
                        className="text-xs hover:underline"
                        style={{ color: "var(--status-critical)" }}
                      >
                        Delete
                      </button>
                    </div>
                  </div>

                  {confirmClear === network.id && (
                    <div
                      className="mt-2 rounded-lg border p-2.5"
                      style={{ borderColor: "var(--status-warning)" }}
                    >
                      <p className="text-sm">
                        Delete all {network.scanCount} scan{network.scanCount === 1 ? "" : "s"}{" "}
                        recorded for <strong>{network.name}</strong>? The network itself, its
                        fingerprint and controller settings stay; the next scan starts a fresh
                        history. Useful when scans from before version 1.2 mixed several sites
                        into one list.
                      </p>
                      <div className="mt-2 flex flex-wrap gap-2">
                        <Button
                          variant="danger"
                          onClick={() => run(() => api.clearNetworkHistory(network.id))}
                          disabled={busy}
                        >
                          Clear history
                        </Button>
                        <Button onClick={() => setConfirmClear(null)} disabled={busy}>
                          Cancel
                        </Button>
                      </div>
                    </div>
                  )}

                  {confirmDelete === network.id && (
                    <div
                      className="mt-2 rounded-lg border p-2.5"
                      style={{ borderColor: "var(--status-critical)" }}
                    >
                      <p className="text-sm">
                        Delete <strong>{network.name}</strong> and all {network.scanCount} of its
                        scans? This cannot be undone.
                      </p>
                      <div className="mt-2 flex flex-wrap gap-2">
                        <Button
                          variant="danger"
                          onClick={() => run(() => api.deleteNetwork(network.id))}
                          disabled={busy}
                        >
                          Delete permanently
                        </Button>
                        <Button onClick={() => setConfirmDelete(null)} disabled={busy}>
                          Cancel
                        </Button>
                      </div>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}

        {error && (
          <p className="mt-3 text-xs" style={{ color: "var(--status-critical)" }}>
            {error}
          </p>
        )}
      </Card>

      <Card title="Add the network you are on now">
        <div className="flex flex-wrap items-end gap-2">
          <label className="min-w-48 flex-1">
            <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
              Name
            </span>
            <input
              type="text"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Home, Office, client name…"
              disabled={busy}
              className="mt-1 w-full rounded-lg border px-2 py-1.5 text-sm"
              style={{
                borderColor: "var(--border-strong)",
                background: "var(--surface-raised)",
                color: "var(--text-primary)",
              }}
            />
          </label>
          <Button
            variant="primary"
            onClick={() =>
              run(async () => {
                await api.createNetwork(newName);
                setNewName("");
              })
            }
            disabled={busy || !newName.trim()}
          >
            Create
          </Button>
        </div>
        <p className="mt-2 text-xs" style={{ color: "var(--text-secondary)" }}>
          The fingerprint is taken from the network this machine is attached to right now.
        </p>
      </Card>

      {activeId && (
        <Card title="Re-detect">
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            Updates the active network&apos;s fingerprint from where this machine is now. Use it
            if the network was created before its gateway address could be read, or after the
            router was replaced.
          </p>
          <div className="mt-2">
            <Button onClick={() => run(api.refreshNetworkFingerprint)} disabled={busy}>
              Re-detect this network
            </Button>
          </div>
        </Card>
      )}
    </div>
  );
}
