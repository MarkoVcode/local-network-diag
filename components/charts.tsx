"use client";

import { useId, useState } from "react";
import type { LatencyStats, WifiInfo } from "@/lib/types";

/**
 * Inline SVG charts. Every chart here is single-series, so the categorical
 * palette reduces to slot 1 and no legend box is needed — the title names the
 * series. Emphasis within a series is carried by a ring plus a direct label,
 * never by introducing a second hue.
 */

/* ------------------------------------------------- Wi-Fi channel congestion */

export function ChannelCongestionChart({ wifi }: { wifi: WifiInfo }) {
  const [hovered, setHovered] = useState<string | null>(null);
  const titleId = useId();

  const bands = [...new Set(wifi.channelUsage.map((u) => u.band))].filter((b) => b !== "unknown");
  if (bands.length === 0) return null;

  const max = Math.max(...wifi.channelUsage.map((u) => u.count), 1);

  return (
    <div>
      <p id={titleId} className="text-xs" style={{ color: "var(--text-secondary)" }}>
        Access points visible per channel. Your channel is ringed and labelled.
      </p>

      {/*
        Both bands share one axis and one scale. Splitting them into separate
        plots would need either two scales — which makes a 2-AP channel look as
        busy as a 15-AP one — or leave most of the quieter band's plot empty.
      */}
      <div className="scroll-x mt-4">
        <div className="flex min-w-fit items-end gap-6">
          {bands.map((band) => {
            const entries = wifi.channelUsage.filter((u) => u.band === band);
            return (
              <div key={band}>
                <div className="flex min-w-fit items-end gap-1.5" style={{ height: 120 }}>
                  {entries.map((entry) => {
                    const key = `${entry.band}-${entry.channel}`;
                    const heightPct = (entry.count / max) * 100;
                    const isHovered = hovered === key;

                    return (
                      <div
                        key={key}
                        className="flex w-9 shrink-0 flex-col items-center justify-end"
                        style={{ height: "100%" }}
                        onMouseEnter={() => setHovered(key)}
                        onMouseLeave={() => setHovered(null)}
                        onFocus={() => setHovered(key)}
                        onBlur={() => setHovered(null)}
                        tabIndex={0}
                        aria-label={`Channel ${entry.channel}, ${entry.count} access point${entry.count === 1 ? "" : "s"}${entry.isCurrent ? ", your channel" : ""}`}
                      >
                        {/*
                          Every bar is labelled — there are only a handful, and a
                          short bar on the shared scale would otherwise be
                          unreadable. The label sits in flow, on top of its bar.
                        */}
                        <span
                          className="mb-0.5 text-[10px] font-semibold tabular"
                          style={{ color: isHovered || entry.isCurrent ? "var(--text-primary)" : "var(--text-secondary)" }}
                        >
                          {entry.count}
                        </span>

                        <div
                          style={{
                            height: `${Math.max(heightPct, 4)}%`,
                            width: "100%",
                            minHeight: 4,
                            background: "var(--series-1)",
                            borderRadius: "4px 4px 0 0",
                            // A 2px surface ring marks the current channel without
                            // spending a second hue on it.
                            outline: entry.isCurrent ? "2px solid var(--text-primary)" : "none",
                            outlineOffset: 2,
                            opacity: isHovered ? 0.85 : 1,
                          }}
                        />

                        <span
                          className="mt-1 text-[10px] tabular"
                          style={{ color: "var(--text-muted)" }}
                        >
                          {entry.channel}
                        </span>
                      </div>
                    );
                  })}
                </div>

                <div
                  className="mt-1 border-t pt-1 text-center text-[10px] font-semibold"
                  style={{ borderColor: "var(--baseline)", color: "var(--text-secondary)" }}
                >
                  {band}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {wifi.recommendation && (
        <p className="mt-4 text-xs" style={{ color: "var(--text-secondary)" }}>
          {wifi.recommendation}
        </p>
      )}
    </div>
  );
}

/* --------------------------------------------------------- latency sparkline */

export function LatencySparkline({
  stats,
  height = 56,
}: {
  stats: LatencyStats;
  height?: number;
}) {
  const [hover, setHover] = useState<{ index: number; x: number; y: number } | null>(null);

  const samples = stats.samples;
  if (samples.length < 2) {
    return (
      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
        {stats.received === 0 ? "No replies" : "Not enough samples to plot"}
      </p>
    );
  }

  const width = 320;
  const padding = { top: 6, right: 4, bottom: 6, left: 4 };
  const innerW = width - padding.left - padding.right;
  const innerH = height - padding.top - padding.bottom;

  const min = Math.min(...samples);
  const max = Math.max(...samples);
  // A flat line should sit mid-height rather than collapse onto the baseline.
  const span = max - min || Math.max(max, 1);

  const points = samples.map((value, i) => ({
    x: padding.left + (i / (samples.length - 1)) * innerW,
    y: padding.top + innerH - ((value - min) / span) * innerH * 0.85 - innerH * 0.075,
    value,
  }));

  const path = points.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(" ");

  return (
    <div className="relative">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        width="100%"
        height={height}
        preserveAspectRatio="none"
        role="img"
        aria-label={`Round-trip time across ${samples.length} probes to ${stats.target}: min ${min.toFixed(1)}, max ${max.toFixed(1)} milliseconds`}
        onMouseLeave={() => setHover(null)}
        onMouseMove={(event) => {
          const rect = event.currentTarget.getBoundingClientRect();
          const ratio = (event.clientX - rect.left) / rect.width;
          const index = Math.round(ratio * (samples.length - 1));
          const clamped = Math.max(0, Math.min(samples.length - 1, index));
          setHover({ index: clamped, x: points[clamped].x, y: points[clamped].y });
        }}
      >
        <line
          x1={padding.left}
          x2={width - padding.right}
          y1={height - padding.bottom}
          y2={height - padding.bottom}
          stroke="var(--gridline)"
          strokeWidth={1}
        />

        <path d={path} fill="none" stroke="var(--series-1)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />

        {hover && (
          <>
            <line
              x1={hover.x}
              x2={hover.x}
              y1={padding.top}
              y2={height - padding.bottom}
              stroke="var(--baseline)"
              strokeWidth={1}
            />
            <circle
              cx={hover.x}
              cy={hover.y}
              r={4}
              fill="var(--series-1)"
              stroke="var(--surface-1)"
              strokeWidth={2}
            />
          </>
        )}
      </svg>

      <div className="mt-1 flex items-baseline justify-between text-[10px] tabular" style={{ color: "var(--text-muted)" }}>
        <span>min {min.toFixed(1)} ms</span>
        {hover && (
          <span style={{ color: "var(--text-primary)" }}>
            probe {hover.index + 1}: {samples[hover.index].toFixed(1)} ms
          </span>
        )}
        <span>max {max.toFixed(1)} ms</span>
      </div>
    </div>
  );
}

/* ----------------------------------------------------------- signal strength */

export function SignalMeter({ percent }: { percent: number }) {
  const bars = 5;
  const filled = Math.max(0, Math.min(bars, Math.round((percent / 100) * bars)));

  return (
    <span
      className="inline-flex items-end gap-0.5"
      role="img"
      aria-label={`Signal strength ${percent}%`}
      style={{ height: 14 }}
    >
      {Array.from({ length: bars }, (_, i) => (
        <span
          key={i}
          style={{
            width: 3,
            height: 4 + i * 2.5,
            borderRadius: 1,
            background: i < filled ? "var(--series-1)" : "var(--gridline)",
          }}
        />
      ))}
    </span>
  );
}
