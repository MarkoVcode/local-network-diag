"use client";

import { Card, EmptyState, Pill, StatusBadge } from "./ui";
import type { Reconciliation, UnifiSnapshot } from "@/lib/types";

/**
 * Where the scan and the controller disagree.
 *
 * The quadrant is the point of the integration: a host answering TCP that the
 * controller has never issued a lease to is interesting *because* the two views
 * conflict. Neither tool can produce that category on its own.
 */
export function ReconciliationPanel({
  reconciliation,
  unifi,
}: {
  reconciliation?: Reconciliation;
  unifi?: UnifiSnapshot;
}) {
  if (!reconciliation) {
    return (
      <Card title="Controller reconciliation">
        <EmptyState
          title="No controller connected"
          hint="Connect a UniFi controller under Setup & Status to compare what the scan finds against what the controller knows."
        />
      </Card>
    );
  }

  const { matched, shadow, missed, hiddenSegments, identityConflicts } = reconciliation;
  const clean =
    shadow.length === 0 &&
    missed.length === 0 &&
    hiddenSegments.length === 0 &&
    identityConflicts.length === 0;

  return (
    <div className="space-y-4">
      <Card title="Reconciliation" subtitle={reconciliation.summary}>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { label: "Accounted for", value: matched, tone: "good" as const },
            { label: "Unknown to controller", value: shadow.length, tone: "critical" as const },
            { label: "Scan did not reach", value: missed.length, tone: "warning" as const },
            { label: "Ports hiding devices", value: hiddenSegments.length, tone: "warning" as const },
          ].map((tile) => (
            <div
              key={tile.label}
              className="rounded-lg border p-3"
              style={{ borderColor: "var(--border)" }}
            >
              <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
                {tile.label}
              </p>
              <p className="mt-1 flex items-center gap-2 text-xl font-semibold tabular">
                {tile.value}
                {tile.value > 0 && tile.tone !== "good" && (
                  <span
                    aria-hidden
                    style={{
                      fontSize: "0.5em",
                      color:
                        tile.tone === "critical"
                          ? "var(--status-critical)"
                          : "var(--status-warning)",
                    }}
                  >
                    ●
                  </span>
                )}
              </p>
            </div>
          ))}
        </div>

        {clean && (
          <p className="mt-3 text-sm" style={{ color: "var(--text-secondary)" }}>
            Everything the scan found is known to the controller, and everything the controller
            knows was reachable. Nothing to investigate.
          </p>
        )}
      </Card>

      {shadow.length > 0 && (
        <Card
          title={`Unknown to the controller — ${shadow.length}`}
          subtitle="Reachable on the network, but the controller has no record of them"
        >
          <ul className="space-y-2">
            {shadow.map((device) => (
              <li
                key={device.ip}
                className="rounded-lg border p-3"
                style={{ borderColor: "var(--status-critical)" }}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge tone="critical" label="Unaccounted" />
                  <span className="font-medium">{device.displayName}</span>
                  <span className="font-mono text-xs tabular" style={{ color: "var(--text-muted)" }}>
                    {device.ip}
                  </span>
                  {device.vendor && <Pill>{device.vendor}</Pill>}
                </div>

                {device.mac && (
                  <p className="mt-1 font-mono text-[11px] tabular" style={{ color: "var(--text-muted)" }}>
                    {device.mac}
                  </p>
                )}

                {device.openPorts.length > 0 && (
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {device.openPorts.slice(0, 8).map((port, i) => (
                      <Pill key={`${port}-${i}`} mono>
                        {port}
                      </Pill>
                    ))}
                  </div>
                )}

                <p className="mt-2 text-sm" style={{ color: "var(--text-secondary)" }}>
                  {device.explanation}
                </p>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {missed.length > 0 && (
        <Card
          title={`The scan did not reach — ${missed.length}`}
          subtitle="Known to the controller but not seen by this scan — where our own coverage is blind"
        >
          <ul className="space-y-2">
            {missed.map((device) => (
              <li key={device.mac} className="rounded-lg border p-3" style={{ borderColor: "var(--border)" }}>
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge tone="warning" label="Not reached" />
                  <span className="font-medium">{device.name}</span>
                  {device.ip && (
                    <span className="font-mono text-xs tabular" style={{ color: "var(--text-muted)" }}>
                      {device.ip}
                    </span>
                  )}
                  {device.location && <Pill>{device.location}</Pill>}
                </div>
                <p className="mt-2 text-sm" style={{ color: "var(--text-secondary)" }}>
                  {device.explanation}
                </p>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {hiddenSegments.length > 0 && (
        <Card
          title={`Ports hiding other devices — ${hiddenSegments.length}`}
          subtitle="Several hardware addresses behind one switch port"
        >
          <ul className="space-y-2">
            {hiddenSegments.map((segment, i) => (
              <li key={i} className="rounded-lg border p-3" style={{ borderColor: "var(--border)" }}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{segment.switchName}</span>
                  <Pill mono>port {segment.port}</Pill>
                  {segment.portName && <Pill>{segment.portName}</Pill>}
                  <StatusBadge tone="warning" label={`${segment.macCount} devices`} />
                </div>
                <p className="mt-2 text-sm" style={{ color: "var(--text-secondary)" }}>
                  {segment.explanation}
                </p>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {identityConflicts.length > 0 && (
        <Card
          title={`Identity conflicts — ${identityConflicts.length}`}
          subtitle="The controller's idea of what a device is disagrees with what it actually runs"
        >
          <ul className="space-y-1.5">
            {identityConflicts.map((conflict, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                <span aria-hidden style={{ color: "var(--status-serious)" }}>
                  ▲
                </span>
                <span style={{ color: "var(--text-secondary)" }}>{conflict}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {unifi && unifi.devices.length > 0 && (
        <Card
          title={`Controller infrastructure — ${unifi.devices.length}`}
          subtitle={`${unifi.controllerHost} · site "${unifi.site}"`}
        >
          <div className="scroll-x">
            <table className="w-full min-w-[560px] border-collapse text-sm">
              <thead>
                <tr className="border-b text-left" style={{ borderColor: "var(--border)" }}>
                  {["Device", "Type", "Model", "Firmware", "Status"].map((label) => (
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
                {unifi.devices.map((device, i) => (
                  <tr key={i} className="border-b" style={{ borderColor: "var(--border)" }}>
                    <td className="py-1.5 pr-3">
                      <span className="font-medium">{device.name}</span>
                      {device.ip && (
                        <p className="font-mono text-[11px] tabular" style={{ color: "var(--text-muted)" }}>
                          {device.ip}
                        </p>
                      )}
                    </td>
                    <td className="py-1.5 pr-3 text-xs">{device.kind}</td>
                    <td className="py-1.5 pr-3 font-mono text-xs">{device.model ?? "—"}</td>
                    <td className="py-1.5 pr-3 font-mono text-xs">{device.version ?? "—"}</td>
                    <td className="py-1.5">
                      <span className="flex flex-wrap gap-1.5">
                        {!device.adopted && <StatusBadge tone="warning" label="Not adopted" />}
                        {device.upgradable && <StatusBadge tone="warning" label="Update available" />}
                        {device.adopted && !device.upgradable && (
                          <StatusBadge tone="good" label="Up to date" />
                        )}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
