"use client";

import { Fragment, useMemo, useState } from "react";
import { DeviceDetail } from "./DeviceDetail";
import { DEVICE_TYPE_META, DeviceTypeBadge, EmptyState, Pill, StatusBadge } from "./ui";
import { compareIp } from "@/lib/service-labels";
import { isCertificateEntry, isNewDevice, type Device, type DeviceType, type ScanSnapshot } from "@/lib/types";

type SortKey = "ip" | "name" | "vendor" | "ports" | "type";

export function DeviceTable({ snapshot }: { snapshot: ScanSnapshot }) {
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<DeviceType | "all">("all");
  const [sortKey, setSortKey] = useState<SortKey>("ip");
  const [ascending, setAscending] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  const typeCounts = useMemo(() => {
    const counts = new Map<DeviceType, number>();
    for (const device of snapshot.devices) {
      counts.set(device.deviceType, (counts.get(device.deviceType) ?? 0) + 1);
    }
    return counts;
  }, [snapshot.devices]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();

    const matches = snapshot.devices.filter((device) => {
      if (typeFilter !== "all" && device.deviceType !== typeFilter) return false;
      if (!needle) return true;

      // Search across every identifying field, not just the display name — looking
      // up a device by a port number or a MAC prefix is a common need.
      const haystack = [
        device.ip,
        device.mac ?? "",
        device.vendor ?? "",
        device.displayName,
        device.reverseDns ?? "",
        ...device.hostnames,
        ...device.ports.map((p) => `${p.port} ${p.service ?? ""}`),
        ...device.mdns.map((s) => s.serviceType),
      ]
        .join(" ")
        .toLowerCase();

      return haystack.includes(needle);
    });

    const sorted = [...matches].sort((a, b) => {
      switch (sortKey) {
        case "name":
          return a.displayName.localeCompare(b.displayName);
        case "vendor":
          return (a.vendor ?? "￿").localeCompare(b.vendor ?? "￿");
        case "ports":
          return b.ports.length - a.ports.length;
        case "type":
          return a.deviceType.localeCompare(b.deviceType);
        default:
          return compareIp(a.ip, b.ip);
      }
    });

    return ascending ? sorted : sorted.reverse();
  }, [snapshot.devices, query, typeFilter, sortKey, ascending]);

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) setAscending((prev) => !prev);
    else {
      setSortKey(key);
      setAscending(true);
    }
  };

  const isNew = (device: Device) => isNewDevice(device, snapshot);

  return (
    <div>
      {/* Filters sit in one row above the table. */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search IP, MAC, vendor, hostname, port…"
          className="min-w-56 flex-1 rounded-lg border px-3 py-1.5 text-sm outline-none"
          style={{
            borderColor: "var(--border-strong)",
            background: "var(--surface-raised)",
            color: "var(--text-primary)",
          }}
        />

        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value as DeviceType | "all")}
          className="rounded-lg border px-2 py-1.5 text-sm"
          style={{
            borderColor: "var(--border-strong)",
            background: "var(--surface-raised)",
            color: "var(--text-primary)",
          }}
          aria-label="Filter by device type"
        >
          <option value="all">All types ({snapshot.devices.length})</option>
          {[...typeCounts.entries()]
            .sort((a, b) => b[1] - a[1])
            .map(([type, count]) => (
              <option key={type} value={type}>
                {DEVICE_TYPE_META[type].label} ({count})
              </option>
            ))}
        </select>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          title="No devices match"
          hint={query ? `Nothing matched "${query}".` : "Try a different filter."}
        />
      ) : (
        <div className="scroll-x">
          <table className="w-full min-w-[720px] border-collapse text-sm">
            <thead>
              <tr className="border-b text-left" style={{ borderColor: "var(--border)" }}>
                <Th onClick={() => toggleSort("ip")} active={sortKey === "ip"} ascending={ascending}>
                  IP
                </Th>
                <Th onClick={() => toggleSort("name")} active={sortKey === "name"} ascending={ascending}>
                  Name
                </Th>
                <Th onClick={() => toggleSort("type")} active={sortKey === "type"} ascending={ascending}>
                  Type
                </Th>
                <Th onClick={() => toggleSort("vendor")} active={sortKey === "vendor"} ascending={ascending}>
                  Vendor / MAC
                </Th>
                <Th onClick={() => toggleSort("ports")} active={sortKey === "ports"} ascending={ascending}>
                  Open ports
                </Th>
              </tr>
            </thead>

            <tbody>
              {filtered.map((device) => {
                const open = expanded === device.ip;
                return (
                  <Fragment key={device.ip}>
                    <tr
                      onClick={() => setExpanded(open ? null : device.ip)}
                      className="cursor-pointer border-b transition-colors hover:bg-[var(--surface-raised)]"
                      style={{ borderColor: "var(--border)" }}
                      aria-expanded={open}
                    >
                      <td className="py-2.5 pr-3 align-top">
                        <span className="font-mono text-xs tabular">{device.ip}</span>
                      </td>

                      <td className="py-2.5 pr-3 align-top">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="font-medium">{device.displayName}</span>
                          {device.isGateway && <StatusBadge tone="good" label="Gateway" />}
                          {device.isSelf && <StatusBadge tone="neutral" label="This machine" />}
                          {isNew(device) && <StatusBadge tone="warning" label="New" />}
                          {device.offSubnet && <StatusBadge tone="warning" label="Off-subnet" />}
                        </div>
                        {device.hostnames.length > 0 && device.hostnames[0] !== device.displayName && (
                          <p className="mt-0.5 font-mono text-xs" style={{ color: "var(--text-muted)" }}>
                            {device.hostnames[0]}
                          </p>
                        )}
                      </td>

                      <td className="py-2.5 pr-3 align-top">
                        <DeviceTypeBadge type={device.deviceType} />
                      </td>

                      <td className="py-2.5 pr-3 align-top">
                        {device.macRandomized ? (
                          <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                            Private MAC
                          </span>
                        ) : (
                          <span className="text-xs">{device.vendor ?? "—"}</span>
                        )}
                        {device.mac && (
                          <p className="mt-0.5 font-mono text-[11px] tabular" style={{ color: "var(--text-muted)" }}>
                            {device.mac}
                          </p>
                        )}
                      </td>

                      <td className="py-2.5 align-top">
                        {(() => {
                          // Certificate pseudo-entries share a port number with
                          // their HTTP sibling; showing both would read as a
                          // duplicate here. The detail panel lists them in full.
                          const listed = device.ports.filter((p) => !isCertificateEntry(p));

                          if (listed.length === 0) {
                            return (
                              <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                                none
                              </span>
                            );
                          }

                          return (
                            <div className="flex max-w-xs flex-wrap gap-1">
                              {listed.slice(0, 6).map((port, i) => (
                                <Pill key={`${port.port}-${i}`} mono>
                                  {port.port}
                                </Pill>
                              ))}
                              {listed.length > 6 && (
                                <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                                  +{listed.length - 6}
                                </span>
                              )}
                            </div>
                          );
                        })()}
                      </td>
                    </tr>

                    {open && (
                      <tr style={{ background: "var(--surface-raised)" }}>
                        <td colSpan={5} className="border-b p-4" style={{ borderColor: "var(--border)" }}>
                          <DeviceDetail device={device} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <p className="mt-3 text-xs" style={{ color: "var(--text-muted)" }}>
        Showing {filtered.length} of {snapshot.devices.length} devices. Click a row for everything extracted.
      </p>
    </div>
  );
}

function Th({
  children,
  onClick,
  active,
  ascending,
}: {
  children: React.ReactNode;
  onClick: () => void;
  active: boolean;
  ascending: boolean;
}) {
  return (
    <th className="pb-2 pr-3 text-xs font-semibold">
      <button
        type="button"
        onClick={onClick}
        className="inline-flex items-center gap-1 hover:underline"
        style={{ color: active ? "var(--text-primary)" : "var(--text-secondary)" }}
      >
        {children}
        {active && <span aria-hidden>{ascending ? "↑" : "↓"}</span>}
      </button>
    </th>
  );
}
