"use client";

import { useState } from "react";
import { Button, KeyValue, Pill, StatusBadge } from "./ui";
import { labelForServiceType } from "@/lib/service-labels";
import { deepScanHost } from "@/lib/api";
import type { Device, HttpBanner, PortInfo, TextBanner, TlsBanner } from "@/lib/types";

/**
 * Everything extracted about one device. This is deliberately exhaustive — the
 * point of the tool is that nothing discovered gets thrown away, including the
 * raw TXT records and HTTP headers.
 */
export function DeviceDetail({ device }: { device: Device }) {
  const [deepPorts, setDeepPorts] = useState<PortInfo[] | null>(null);
  const [deepScanning, setDeepScanning] = useState(false);
  const [deepError, setDeepError] = useState<string | null>(null);

  const runDeepScan = async () => {
    setDeepScanning(true);
    setDeepError(null);
    try {
      setDeepPorts(await deepScanHost(device.ip));
    } catch (err) {
      setDeepError(err instanceof Error ? err.message : String(err));
    } finally {
      setDeepScanning(false);
    }
  };

  const ports = deepPorts ?? device.ports;

  return (
    <div className="space-y-5 text-sm">
      <div className="grid gap-x-8 gap-y-1 md:grid-cols-2">
        <dl>
          <KeyValue label="IP address" value={device.ip} mono />
          <KeyValue
            label="MAC address"
            value={
              device.mac ? (
                <span className="flex flex-wrap items-center gap-2">
                  <span className="font-mono tabular">{device.mac}</span>
                  {device.macRandomized && <StatusBadge tone="warning" label="Randomized" />}
                </span>
              ) : (
                <span style={{ color: "var(--text-muted)" }}>not resolved</span>
              )
            }
          />
          <KeyValue
            label="Vendor"
            value={
              device.macRandomized ? (
                <span style={{ color: "var(--text-secondary)" }}>
                  Hidden — this device uses a private (randomized) MAC
                </span>
              ) : (
                device.vendor ?? <span style={{ color: "var(--text-muted)" }}>unknown</span>
              )
            }
          />
          <KeyValue label="Reverse DNS" value={device.reverseDns ?? <span style={{ color: "var(--text-muted)" }}>none</span>} />
        </dl>

        <dl>
          <KeyValue
            label="Responded to ping"
            value={device.respondedToPing ? `yes${device.latencyMs !== undefined ? ` (${device.latencyMs.toFixed(1)} ms)` : ""}` : "no"}
          />
          <KeyValue label="Discovered by" value={device.discoveredBy.join(", ")} />
          <KeyValue
            label="Range"
            value={
              <span className="flex flex-wrap items-center gap-2">
                <span className="font-mono">{device.sourceRange ?? "—"}</span>
                {device.offSubnet && <StatusBadge tone="warning" label="Off-subnet" />}
              </span>
            }
          />
          <KeyValue
            label="First seen"
            value={device.firstSeen ? new Date(device.firstSeen).toLocaleString() : "—"}
          />
        </dl>
      </div>

      {/* Controller data — the things a scan cannot observe from outside. */}
      {(device.switchPort ||
        device.accessPoint ||
        device.unifiFingerprint ||
        device.unifiNetwork ||
        device.vlan !== undefined) && (
        <div>
          <h4 className="mb-1.5 text-xs font-semibold">From the UniFi controller</h4>
          <dl>
            {device.switchPort && (
              <KeyValue
                label="Physical port"
                value={
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{device.switchPort}</span>
                    <StatusBadge tone="good" label="Wired" />
                  </span>
                }
              />
            )}
            {device.accessPoint && (
              <KeyValue
                label="Access point"
                value={
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{device.accessPoint}</span>
                    {device.rssi !== undefined && <Pill mono>RSSI {device.rssi}</Pill>}
                  </span>
                }
              />
            )}
            {device.unifiNetwork && <KeyValue label="Network" value={device.unifiNetwork} />}
            {device.vlan !== undefined && <KeyValue label="VLAN" value={String(device.vlan)} mono />}
            {device.unifiFingerprint && (
              <KeyValue label="Controller fingerprint" value={device.unifiFingerprint} />
            )}
            {device.unifiName && <KeyValue label="Controller alias" value={device.unifiName} />}
          </dl>
        </div>
      )}

      {device.typeEvidence.length > 0 && (
        <div>
          <h4 className="mb-1.5 text-xs font-semibold">Why it was classified this way</h4>
          <ul className="flex flex-wrap gap-1.5">
            {device.typeEvidence.map((evidence, i) => (
              <li key={i}>
                <Pill>{evidence}</Pill>
              </li>
            ))}
          </ul>
        </div>
      )}

      {device.hostnames.length > 0 && (
        <div>
          <h4 className="mb-1.5 text-xs font-semibold">Hostnames</h4>
          <ul className="flex flex-wrap gap-1.5">
            {device.hostnames.map((name) => (
              <li key={name}>
                <Pill mono>{name}</Pill>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* ---------------------------------------------------------- ports */}
      <div>
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h4 className="text-xs font-semibold">
            Open ports{deepPorts ? " (deep scan)" : ""} — {ports.length}
          </h4>
          <Button onClick={runDeepScan} disabled={deepScanning}>
            {deepScanning ? "Scanning ~150 ports…" : "Deep port scan"}
          </Button>
        </div>

        {deepError && (
          <p className="mb-2 text-xs" style={{ color: "var(--status-critical)" }}>
            {deepError}
          </p>
        )}

        {ports.length === 0 ? (
          <p className="text-xs" style={{ color: "var(--text-muted)" }}>
            No open TCP ports found.
          </p>
        ) : (
          <ul className="space-y-2">
            {ports.map((port, i) => (
              <li
                key={`${port.port}-${i}`}
                className="rounded-lg border p-2.5"
                style={{ borderColor: "var(--border)" }}
              >
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="font-mono text-sm font-semibold tabular">{port.port}</span>
                  {port.service && (
                    <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                      {port.service}
                    </span>
                  )}
                </div>
                {port.banner && <BannerView banner={port.banner} />}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* ----------------------------------------------------------- mDNS */}
      {device.mdns.length > 0 && (
        <div>
          <h4 className="mb-2 text-xs font-semibold">mDNS / Bonjour services — {device.mdns.length}</h4>
          <ul className="space-y-2">
            {device.mdns.map((service, i) => (
              <li key={i} className="rounded-lg border p-2.5" style={{ borderColor: "var(--border)" }}>
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="text-sm font-medium">
                    {labelForServiceType(service.serviceType)}
                  </span>
                  <span className="font-mono text-xs" style={{ color: "var(--text-muted)" }}>
                    {service.serviceType}
                  </span>
                  {service.port && <Pill mono>port {service.port}</Pill>}
                </div>
                {service.hostname && (
                  <p className="mt-1 font-mono text-xs" style={{ color: "var(--text-secondary)" }}>
                    {service.hostname}
                  </p>
                )}
                {Object.keys(service.txt).length > 0 && (
                  <dl className="mt-2 grid gap-x-4 sm:grid-cols-2">
                    {Object.entries(service.txt).map(([key, value]) => (
                      <div key={key} className="flex gap-2 py-0.5 text-xs">
                        <dt className="shrink-0 font-mono" style={{ color: "var(--text-muted)" }}>
                          {key}
                        </dt>
                        <dd className="min-w-0 break-all font-mono">{value || "—"}</dd>
                      </div>
                    ))}
                  </dl>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* ----------------------------------------------------------- SSDP */}
      {device.ssdp.length > 0 && (
        <div>
          <h4 className="mb-2 text-xs font-semibold">UPnP / SSDP — {device.ssdp.length}</h4>
          <ul className="space-y-2">
            {device.ssdp.map((record, i) => (
              <li key={i} className="rounded-lg border p-2.5" style={{ borderColor: "var(--border)" }}>
                {record.friendlyName && <p className="text-sm font-medium">{record.friendlyName}</p>}
                <dl className="mt-1">
                  {record.manufacturer && <KeyValue label="Manufacturer" value={record.manufacturer} />}
                  {record.modelName && <KeyValue label="Model" value={record.modelName} />}
                  {record.modelNumber && <KeyValue label="Model number" value={record.modelNumber} />}
                  {record.serialNumber && <KeyValue label="Serial" value={record.serialNumber} mono />}
                  {record.deviceType && <KeyValue label="Device type" value={record.deviceType} mono />}
                  {record.server && <KeyValue label="Server" value={record.server} mono />}
                  <KeyValue label="Service type" value={<span className="font-mono text-xs">{record.st}</span>} />
                  {record.location && (
                    <KeyValue
                      label="Description URL"
                      value={
                        <a
                          href={record.location}
                          target="_blank"
                          rel="noreferrer"
                          className="font-mono text-xs underline"
                          style={{ color: "var(--series-1)" }}
                        >
                          {record.location}
                        </a>
                      }
                    />
                  )}
                </dl>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* -------------------------------------------------------- NetBIOS */}
      {device.netbios && (
        <div>
          <h4 className="mb-1.5 text-xs font-semibold">NetBIOS</h4>
          <dl>
            <KeyValue label="Names" value={device.netbios.names.join(", ") || "—"} mono />
            {device.netbios.workgroup && <KeyValue label="Workgroup" value={device.netbios.workgroup} mono />}
            {device.netbios.mac && <KeyValue label="Adapter MAC" value={device.netbios.mac} mono />}
          </dl>
        </div>
      )}
    </div>
  );
}

function BannerView({ banner }: { banner: HttpBanner | TlsBanner | TextBanner }) {
  if (banner.kind === "http") {
    return (
      <div className="mt-2">
        <div className="flex flex-wrap items-center gap-2">
          <Pill mono>{banner.scheme.toUpperCase()}</Pill>
          {banner.status !== undefined && <Pill mono>HTTP {banner.status}</Pill>}
          {banner.server && <Pill>{banner.server}</Pill>}
        </div>
        {banner.title && <p className="mt-1.5 text-sm font-medium">{banner.title}</p>}
        {banner.redirectLocation && (
          <p className="mt-1 font-mono text-xs" style={{ color: "var(--text-secondary)" }}>
            → {banner.redirectLocation}
          </p>
        )}
        <details className="mt-1.5">
          <summary className="cursor-pointer text-xs" style={{ color: "var(--text-secondary)" }}>
            Response headers ({Object.keys(banner.headers).length})
          </summary>
          <dl className="mt-1.5">
            {Object.entries(banner.headers).map(([key, value]) => (
              <div key={key} className="flex gap-2 py-0.5 text-xs">
                <dt className="w-40 shrink-0 font-mono" style={{ color: "var(--text-muted)" }}>
                  {key}
                </dt>
                <dd className="min-w-0 break-all font-mono">{value}</dd>
              </div>
            ))}
          </dl>
        </details>
      </div>
    );
  }

  if (banner.kind === "tls") {
    const expiring = banner.daysUntilExpiry !== undefined && banner.daysUntilExpiry < 30;
    return (
      <div className="mt-2">
        <div className="flex flex-wrap items-center gap-2">
          {banner.selfSigned && <StatusBadge tone="warning" label="Self-signed" />}
          {banner.daysUntilExpiry !== undefined && (
            <StatusBadge
              tone={banner.daysUntilExpiry < 0 ? "critical" : expiring ? "warning" : "good"}
              label={
                banner.daysUntilExpiry < 0
                  ? `Expired ${Math.abs(banner.daysUntilExpiry)}d ago`
                  : `Expires in ${banner.daysUntilExpiry}d`
              }
            />
          )}
        </div>
        <dl className="mt-1.5">
          {banner.subject && <KeyValue label="Subject" value={<span className="text-xs">{banner.subject}</span>} />}
          {banner.issuer && <KeyValue label="Issuer" value={<span className="text-xs">{banner.issuer}</span>} />}
          {banner.altNames && banner.altNames.length > 0 && (
            <KeyValue label="Alt names" value={<span className="text-xs">{banner.altNames.join(", ")}</span>} />
          )}
          {banner.validTo && <KeyValue label="Valid until" value={<span className="text-xs">{banner.validTo}</span>} />}
        </dl>
      </div>
    );
  }

  return (
    <pre
      className="mt-2 max-h-32 overflow-auto rounded border p-2 font-mono text-xs whitespace-pre-wrap"
      style={{ borderColor: "var(--border)", color: "var(--text-secondary)" }}
    >
      {banner.text}
    </pre>
  );
}
