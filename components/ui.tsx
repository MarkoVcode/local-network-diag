import type { ReactNode } from "react";
import type { DeviceType } from "@/lib/types";

/** Shared presentational primitives. Kept server-safe (no hooks) so any panel can use them. */

export function Card({
  title,
  subtitle,
  actions,
  children,
  className = "",
}: {
  title?: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`min-w-0 rounded-xl border bg-[var(--surface-1)] ${className}`}
      style={{ borderColor: "var(--border)" }}
    >
      {(title || actions) && (
        <header
          className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3"
          style={{ borderColor: "var(--border)" }}
        >
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold">{title}</h2>}
            {subtitle && (
              <p className="mt-0.5 text-xs" style={{ color: "var(--text-secondary)" }}>
                {subtitle}
              </p>
            )}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className="min-w-0 p-4">{children}</div>
    </section>
  );
}

export type StatusTone = "good" | "warning" | "serious" | "critical" | "neutral";

const TONE_COLOR: Record<StatusTone, string> = {
  good: "var(--status-good)",
  warning: "var(--status-warning)",
  serious: "var(--status-serious)",
  critical: "var(--status-critical)",
  neutral: "var(--text-muted)",
};

const TONE_ICON: Record<StatusTone, string> = {
  good: "●",
  warning: "▲",
  serious: "▲",
  critical: "■",
  neutral: "○",
};

/**
 * Status is never carried by color alone — every badge pairs the swatch with an
 * icon and a text label, which is what the sub-3:1 `warning` step requires on a
 * light surface.
 */
export function StatusBadge({ tone, label }: { tone: StatusTone; label: string }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium"
      style={{ borderColor: "var(--border)", color: "var(--text-primary)" }}
    >
      <span aria-hidden style={{ color: TONE_COLOR[tone], fontSize: "0.7em" }}>
        {TONE_ICON[tone]}
      </span>
      {label}
    </span>
  );
}

export function Pill({ children, mono = false }: { children: ReactNode; mono?: boolean }) {
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs ${mono ? "font-mono tabular" : ""}`}
      style={{ borderColor: "var(--border)", color: "var(--text-secondary)" }}
    >
      {children}
    </span>
  );
}

/**
 * Device types get an icon plus a written label rather than a color code — with
 * eleven categories, cycling hues would be unreadable and meaningless.
 */
export const DEVICE_TYPE_META: Record<DeviceType, { icon: string; label: string }> = {
  // Covers switches and APs too — the vendor signal cannot tell them apart, and
  // labelling a UniFi switch "Router" would be wrong.
  router: { icon: "🛜", label: "Network gear" },
  phone: { icon: "📱", label: "Phone" },
  computer: { icon: "💻", label: "Computer" },
  iot: { icon: "🔌", label: "IoT" },
  media: { icon: "🎬", label: "Media" },
  printer: { icon: "🖨️", label: "Printer" },
  nas: { icon: "🗄️", label: "Storage" },
  camera: { icon: "📷", label: "Camera" },
  tv: { icon: "📺", label: "TV" },
  server: { icon: "🖥️", label: "Server" },
  unknown: { icon: "❔", label: "Unknown" },
};

export function DeviceTypeBadge({ type }: { type: DeviceType }) {
  const meta = DEVICE_TYPE_META[type];
  return (
    <span className="inline-flex items-center gap-1.5 text-xs whitespace-nowrap">
      <span aria-hidden>{meta.icon}</span>
      <span style={{ color: "var(--text-secondary)" }}>{meta.label}</span>
    </span>
  );
}

export function Button({
  children,
  onClick,
  variant = "secondary",
  disabled,
  title,
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "danger";
  disabled?: boolean;
  title?: string;
  type?: "button" | "submit";
}) {
  const base =
    "inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50";

  const styles: Record<string, React.CSSProperties> = {
    primary: { background: "var(--series-1)", color: "#ffffff" },
    secondary: {
      background: "transparent",
      color: "var(--text-primary)",
      border: "1px solid var(--border-strong)",
    },
    danger: {
      background: "transparent",
      color: "var(--status-critical)",
      border: "1px solid var(--status-critical)",
    },
  };

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={base}
      style={styles[variant]}
    >
      {children}
    </button>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="py-10 text-center">
      <p className="text-sm font-medium">{title}</p>
      {hint && (
        <p className="mx-auto mt-1 max-w-md text-xs" style={{ color: "var(--text-secondary)" }}>
          {hint}
        </p>
      )}
    </div>
  );
}

export function KeyValue({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 py-1">
      <dt className="w-40 shrink-0 text-xs" style={{ color: "var(--text-secondary)" }}>
        {label}
      </dt>
      <dd className={`min-w-0 flex-1 text-sm break-words ${mono ? "font-mono tabular" : ""}`}>{value}</dd>
    </div>
  );
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds % 60)}s`;
}

export function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return "just now";
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

/** Latency thresholds tuned for a LAN gateway, where >20 ms already means trouble. */
export function latencyTone(ms: number | undefined, isLocal: boolean): StatusTone {
  if (ms === undefined) return "neutral";
  const limits = isLocal ? [5, 20, 50] : [30, 80, 150];
  if (ms <= limits[0]) return "good";
  if (ms <= limits[1]) return "warning";
  if (ms <= limits[2]) return "serious";
  return "critical";
}

export function lossTone(percent: number): StatusTone {
  if (percent === 0) return "good";
  if (percent < 2) return "warning";
  if (percent < 10) return "serious";
  return "critical";
}

export function signalTone(percent: number): StatusTone {
  if (percent >= 70) return "good";
  if (percent >= 50) return "warning";
  if (percent >= 30) return "serious";
  return "critical";
}
