"use client";

import { useState } from "react";
import { Button, Pill, StatusBadge } from "./ui";
import * as api from "@/lib/api";
import type { DiscoveredNetwork } from "@/lib/types";

/**
 * The network picker: every subnet this machine can currently see, offered as
 * a network to track.
 *
 * Shown automatically on a true first run (no networks saved) and reopenable
 * from the Networks panel — deleting a network and wanting it back should not
 * require remembering its range.
 */
export function NetworkDiscovery({
  candidates,
  onDone,
  onSkip,
}: {
  candidates: DiscoveredNetwork[];
  onDone: () => void;
  onSkip: () => void;
}) {
  // Untracked subnets start selected: the common case is "track what I have".
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set(candidates.filter((c) => !c.alreadyTracked).map((c) => c.cidr)),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggle = (cidr: string) => {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(cidr)) {
        next.delete(cidr);
      } else {
        next.add(cidr);
      }
      return next;
    });
  };

  const track = async () => {
    setBusy(true);
    setError(null);
    try {
      const chosen = candidates.filter((c) => selected.has(c.cidr));
      // The subnet holding the gateway becomes the selected network — it is
      // the one the user is "on"; the rest are created without switching.
      const primaryIndex = Math.max(
        0,
        chosen.findIndex((c) => c.gatewayIp !== undefined),
      );
      for (const [index, candidate] of chosen.entries()) {
        await api.ensureNetworkForRange(
          candidate.cidr,
          candidate.ssid,
          index === primaryIndex,
        );
      }
      onDone();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-6"
      style={{ background: "rgba(0,0,0,0.45)" }}
    >
      <div
        role="dialog"
        aria-modal="true"
        className="w-full max-w-lg rounded-xl border shadow-xl"
        style={{ borderColor: "var(--border-strong)", background: "var(--surface-1)" }}
      >
        <header className="border-b px-5 py-4" style={{ borderColor: "var(--border)" }}>
          <h2 className="text-base font-semibold">Which networks should be tracked?</h2>
          <p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>
            These are the networks this machine can see right now. Each tracked network keeps
            its own scan history and settings, and appears in the switcher at the top left.
          </p>
        </header>

        <div className="max-h-80 overflow-y-auto px-5 py-4">
          {candidates.length === 0 ? (
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              No scannable networks were found. Connect to a network and reopen this from the
              Networks page.
            </p>
          ) : (
            <ul className="space-y-2">
              {candidates.map((candidate) => (
                <li key={candidate.cidr}>
                  <label
                    className="flex cursor-pointer items-center gap-3 rounded-lg border p-3"
                    style={{
                      borderColor: selected.has(candidate.cidr)
                        ? "var(--series-1)"
                        : "var(--border)",
                      opacity: candidate.alreadyTracked ? 0.6 : 1,
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={selected.has(candidate.cidr)}
                      onChange={() => toggle(candidate.cidr)}
                      disabled={busy || candidate.alreadyTracked}
                    />
                    <span className="min-w-0 flex-1">
                      <span className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-sm font-medium tabular">
                          {candidate.cidr}
                        </span>
                        {candidate.ssid && <Pill>{candidate.ssid}</Pill>}
                        {candidate.gatewayIp && <Pill mono>gw {candidate.gatewayIp}</Pill>}
                        {candidate.alreadyTracked && (
                          <StatusBadge tone="good" label="Already tracked" />
                        )}
                      </span>
                      <span className="mt-0.5 block text-xs" style={{ color: "var(--text-muted)" }}>
                        {candidate.interface ? `on ${candidate.interface} · ` : ""}
                        {candidate.hostCount} addresses
                      </span>
                    </span>
                  </label>
                </li>
              ))}
            </ul>
          )}
          {error && (
            <p className="mt-3 text-xs" style={{ color: "var(--status-critical)" }}>
              {error}
            </p>
          )}
        </div>

        <footer
          className="flex flex-wrap items-center justify-end gap-2 border-t px-5 py-3"
          style={{ borderColor: "var(--border)" }}
        >
          <Button onClick={onSkip} disabled={busy}>
            Not now
          </Button>
          <Button
            variant="primary"
            onClick={track}
            disabled={busy || selected.size === 0}
          >
            {busy ? "Creating…" : `Track ${selected.size} network${selected.size === 1 ? "" : "s"}`}
          </Button>
        </footer>
      </div>
    </div>
  );
}
