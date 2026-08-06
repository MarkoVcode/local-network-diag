"use client";

import { useState } from "react";
import { Button, Card, StatusBadge, type StatusTone } from "./ui";
import * as api from "@/lib/api";
import type { CapabilityReport, CapabilityStatus, DoctorReport, Tier } from "@/lib/types";

/**
 * Setup & Status.
 *
 * Every entry is the result of a *functional* probe, not a "is the binary on
 * PATH" check — so the report reflects what the app can actually do on this
 * machine rather than what is merely installed.
 */

const STATUS_TONE: Record<CapabilityStatus, StatusTone> = {
  ok: "good",
  degraded: "warning",
  missing: "critical",
};

const STATUS_LABEL: Record<CapabilityStatus, string> = {
  ok: "Working",
  degraded: "Limited",
  missing: "Unavailable",
};

const TIER_LABEL: Record<Tier, string> = {
  critical: "Required",
  important: "Important",
  optional: "Optional",
};

const TIER_EXPLANATION: Record<Tier, string> = {
  critical: "The app cannot scan without this.",
  important: "Scanning still works, but a major feature is lost.",
  optional: "Only narrows the level of detail.",
};

export function SetupPanel({
  report,
  onRecheck,
  loading,
  dataDir,
  appVersion,
}: {
  report: DoctorReport | null;
  onRecheck: () => void;
  loading: boolean;
  dataDir?: string;
  appVersion?: string;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (!report) {
    return (
      <Card title="Setup & Status">
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          {loading ? "Running capability checks…" : "No capability report yet."}
        </p>
      </Card>
    );
  }

  const byTier = (tier: Tier) => report.capabilities.filter((c) => c.tier === tier);
  const problems = report.capabilities.filter((c) => c.status !== "ok");

  return (
    <div className="space-y-4">
      {/* The blocking case gets its own unmissable panel. */}
      {report.blocked && (
        <section
          className="rounded-xl border p-4"
          style={{
            borderColor: "var(--status-critical)",
            background: "color-mix(in srgb, var(--status-critical) 10%, transparent)",
          }}
        >
          <div className="flex items-start gap-3">
            <span aria-hidden className="text-lg" style={{ color: "var(--status-critical)" }}>
              ■
            </span>
            <div className="min-w-0">
              <h2 className="text-sm font-semibold" style={{ color: "var(--status-critical)" }}>
                The app cannot run a scan on this machine
              </h2>
              <p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>
                {report.summary} Scanning is disabled until this is resolved. Each required item
                below explains what to do.
              </p>
            </div>
          </div>
        </section>
      )}

      <Card
        title="Capability check"
        subtitle={`${report.os} · checked ${new Date(report.checkedAt).toLocaleString()}`}
        actions={
          <Button onClick={onRecheck} disabled={loading}>
            {loading ? "Checking…" : "Re-check"}
          </Button>
        }
      >
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge
            tone={report.blocked ? "critical" : problems.length > 0 ? "warning" : "good"}
            label={report.summary}
          />
        </div>

        <dl className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            { label: "Working", value: report.counts.ok, tone: "good" as StatusTone },
            { label: "Limited", value: report.counts.degraded, tone: "warning" as StatusTone },
            { label: "Unavailable", value: report.counts.missing, tone: "critical" as StatusTone },
            {
              label: "Required missing",
              value: report.counts.criticalMissing,
              tone: report.counts.criticalMissing > 0 ? ("critical" as StatusTone) : ("neutral" as StatusTone),
            },
          ].map((tile) => (
            <div
              key={tile.label}
              className="rounded-lg border p-3"
              style={{ borderColor: "var(--border)" }}
            >
              <dt className="text-xs" style={{ color: "var(--text-secondary)" }}>
                {tile.label}
              </dt>
              <dd className="mt-1 text-xl font-semibold tabular">{tile.value}</dd>
            </div>
          ))}
        </dl>
      </Card>

      {(["critical", "important", "optional"] as Tier[]).map((tier) => {
        const entries = byTier(tier);
        if (entries.length === 0) return null;

        return (
          <Card key={tier} title={TIER_LABEL[tier]} subtitle={TIER_EXPLANATION[tier]}>
            <ul className="space-y-2">
              {entries.map((capability) => (
                <CapabilityRow
                  key={capability.id}
                  capability={capability}
                  open={expanded === capability.id}
                  onToggle={() =>
                    setExpanded(expanded === capability.id ? null : capability.id)
                  }
                />
              ))}
            </ul>
          </Card>
        );
      })}

      <Card title="About">
        <dl className="space-y-1 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <dt className="w-40 shrink-0 text-xs" style={{ color: "var(--text-secondary)" }}>
              Version
            </dt>
            <dd className="flex flex-wrap items-center gap-3 tabular">
              {appVersion ?? "—"}
              <UpdateCheckButton />
            </dd>
          </div>
          <div className="flex flex-wrap gap-2">
            <dt className="w-40 shrink-0 text-xs" style={{ color: "var(--text-secondary)" }}>
              Platform
            </dt>
            <dd>{report.os}</dd>
          </div>
          <div className="flex flex-wrap gap-2">
            <dt className="w-40 shrink-0 text-xs" style={{ color: "var(--text-secondary)" }}>
              Scan data
            </dt>
            <dd className="min-w-0 flex-1 break-all font-mono text-xs">{dataDir ?? "—"}</dd>
          </div>
        </dl>
        <p className="mt-3 text-xs" style={{ color: "var(--text-secondary)" }}>
          This app runs without administrator privileges. It scans only private address ranges,
          and refuses anything wider than a /22.
        </p>
      </Card>

      <DangerZone />
    </div>
  );
}

/**
 * The factory reset. Exists so a true first run can be reproduced: everything
 * the app has stored — networks, scan histories, controller settings and their
 * keychain entries, preferences — is deleted, and the app quits. The next
 * launch starts from nothing, including the network discovery prompt.
 */
function DangerZone() {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.factoryReset();
      // The app exits inside the command; nothing to do on success.
    } catch (err) {
      setError(String(err));
      setBusy(false);
    }
  };

  return (
    <Card title="Danger zone">
      <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
        Forget all configuration: deletes every network, its scan history, controller settings
        and stored credentials, then quits the app. The next launch behaves like a first run.
      </p>

      {confirming ? (
        <div
          className="mt-3 rounded-lg border p-3"
          style={{ borderColor: "var(--status-critical)" }}
        >
          <p className="text-sm">
            Really delete <strong>everything</strong> this app has stored? This cannot be
            undone, and the app will close immediately.
          </p>
          <div className="mt-2 flex flex-wrap gap-2">
            <Button variant="danger" onClick={reset} disabled={busy}>
              {busy ? "Wiping…" : "Forget everything and quit"}
            </Button>
            <Button onClick={() => setConfirming(false)} disabled={busy}>
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        <div className="mt-3">
          <Button variant="danger" onClick={() => setConfirming(true)}>
            Forget all configuration…
          </Button>
        </div>
      )}

      {error && (
        <p className="mt-2 text-xs" style={{ color: "var(--status-critical)" }}>
          {error}
        </p>
      )}
    </Card>
  );
}

/**
 * A manual, cache-bypassing update check.
 *
 * The automatic startup check caches its result for several hours to protect
 * the GitHub rate limit — which means a release published within that window
 * is invisible until the cache expires. This button is the escape hatch.
 */
function UpdateCheckButton() {
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<string | React.ReactNode | null>(null);

  const check = async () => {
    setChecking(true);
    setResult(null);
    try {
      const info = await api.checkForUpdate(true);
      if (!info) {
        setResult("Could not reach GitHub — check again later.");
      } else if (info.updateAvailable) {
        setResult(
          <a
            href={info.releaseUrl}
            target="_blank"
            rel="noreferrer"
            className="underline"
            style={{ color: "var(--series-1)" }}
          >
            Version {info.latestVersion} is available →
          </a>,
        );
      } else {
        setResult(`Up to date — ${info.latestVersion} is the latest release.`);
      }
    } catch {
      setResult("The update check failed.");
    } finally {
      setChecking(false);
    }
  };

  return (
    <span className="flex flex-wrap items-center gap-2 text-xs">
      <Button onClick={check} disabled={checking}>
        {checking ? "Checking…" : "Check for updates"}
      </Button>
      {result && <span style={{ color: "var(--text-secondary)" }}>{result}</span>}
    </span>
  );
}

function CapabilityRow({
  capability,
  open,
  onToggle,
}: {
  capability: CapabilityReport;
  open: boolean;
  onToggle: () => void;
}) {
  const problem = capability.status !== "ok";

  return (
    <li className="rounded-lg border" style={{ borderColor: "var(--border)" }}>
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full flex-wrap items-center justify-between gap-2 p-3 text-left"
        aria-expanded={open}
      >
        <span className="flex min-w-0 flex-wrap items-center gap-2">
          <span className="text-sm font-medium">{capability.label}</span>
          {capability.tool && (
            <span className="font-mono text-xs" style={{ color: "var(--text-muted)" }}>
              {capability.tool}
            </span>
          )}
        </span>
        <span className="flex shrink-0 items-center gap-2">
          <StatusBadge
            tone={STATUS_TONE[capability.status]}
            label={STATUS_LABEL[capability.status]}
          />
          <span aria-hidden style={{ color: "var(--text-muted)" }}>
            {open ? "▾" : "▸"}
          </span>
        </span>
      </button>

      {/* Problems always show their detail; healthy entries stay collapsed. */}
      {(open || problem) && (
        <div className="border-t px-3 pb-3 pt-2" style={{ borderColor: "var(--border)" }}>
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            {capability.purpose}
          </p>

          <p className="mt-2 text-sm">{capability.detail}</p>

          {problem && capability.affects.length > 0 && (
            <div className="mt-3">
              <h4 className="text-xs font-semibold">What stops working</h4>
              <ul className="mt-1 space-y-0.5">
                {capability.affects.map((effect, i) => (
                  <li
                    key={i}
                    className="flex items-start gap-2 text-sm"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    <span aria-hidden style={{ color: "var(--status-warning)" }}>
                      •
                    </span>
                    {effect}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {problem && capability.remedy && (
            <div
              className="mt-3 rounded-lg border p-2.5"
              style={{ borderColor: "var(--border)", background: "var(--surface-raised)" }}
            >
              <h4 className="text-xs font-semibold">How to fix it</h4>
              <p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>
                {capability.remedy}
              </p>
            </div>
          )}
        </div>
      )}
    </li>
  );
}

/**
 * Compact banner shown above the scan controls when something is wrong, so a
 * degraded environment is visible without opening the Setup page.
 */
export function CapabilityBanner({
  report,
  onOpenSetup,
}: {
  report: DoctorReport | null;
  onOpenSetup: () => void;
}) {
  if (!report) return null;

  // Only surface things that are actually broken. An Optional capability sitting
  // at "degraded" because the user simply has not configured it is not a
  // problem — nagging about it on every launch would devalue the banner for the
  // cases that matter. Those still appear on the Setup page.
  const problems = report.capabilities.filter(
    (c) => c.status === "missing" || (c.status === "degraded" && c.tier !== "optional"),
  );
  if (problems.length === 0) return null;

  const critical = report.blocked;

  return (
    <div
      className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-3"
      style={{
        borderColor: critical ? "var(--status-critical)" : "var(--border-strong)",
        background: critical
          ? "color-mix(in srgb, var(--status-critical) 10%, transparent)"
          : "var(--surface-1)",
      }}
    >
      <div className="flex min-w-0 items-start gap-3">
        <span
          aria-hidden
          style={{ color: critical ? "var(--status-critical)" : "var(--status-warning)" }}
        >
          {critical ? "■" : "▲"}
        </span>
        <div className="min-w-0">
          <p className="text-sm font-medium">
            {critical
              ? "Scanning is unavailable on this machine"
              : `${problems.length} capabilit${problems.length === 1 ? "y is" : "ies are"} limited or unavailable`}
          </p>
          <p className="mt-0.5 text-xs" style={{ color: "var(--text-secondary)" }}>
            {critical
              ? report.summary
              : problems.map((p) => p.label).join(", ") +
                " — results will be less complete."}
          </p>
        </div>
      </div>

      <Button variant={critical ? "danger" : "secondary"} onClick={onOpenSetup}>
        Open Setup &amp; Status
      </Button>
    </div>
  );
}
