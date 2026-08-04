"use client";

import { useEffect, useRef, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Button } from "./ui";
import * as api from "@/lib/api";
import type { UpdateInfo } from "@/lib/types";

/**
 * Startup update notice.
 *
 * Deliberately quiet. The check runs in Rust, fails silently when offline — this
 * app is often launched *because* the internet is broken — and the dialog only
 * appears when there is genuinely a newer release the user has not skipped.
 */
export function UpdateDialog({ info, onClose }: { info: UpdateInfo; onClose: () => void }) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const [busy, setBusy] = useState(false);

  // Focus the dialog so Escape works and screen readers announce it.
  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const download = async () => {
    setBusy(true);
    try {
      await openUrl(info.releaseUrl);
      onClose();
    } catch {
      // The permission is scoped to this repository; a failure here means the
      // release URL was unexpected, which is not worth an error dialog.
      onClose();
    }
  };

  const skip = async () => {
    setBusy(true);
    try {
      await api.skipUpdateVersion(info.latestVersion);
    } catch {
      // Not being able to persist the preference is not worth interrupting for.
    }
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-6"
      style={{ background: "rgba(0,0,0,0.45)" }}
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="update-title"
        className="w-full max-w-lg rounded-xl border shadow-xl"
        style={{ borderColor: "var(--border-strong)", background: "var(--surface-1)" }}
      >
        <header className="border-b px-5 py-4" style={{ borderColor: "var(--border)" }}>
          <h2 id="update-title" className="text-base font-semibold">
            Version {info.latestVersion} is available
          </h2>
          <p className="mt-1 text-sm" style={{ color: "var(--text-secondary)" }}>
            You have {info.currentVersion}.
            {info.publishedAt
              ? ` Released ${new Date(info.publishedAt).toLocaleDateString()}.`
              : ""}
          </p>
        </header>

        {info.releaseNotes && (
          <div className="max-h-64 overflow-y-auto px-5 py-4">
            <h3 className="mb-2 text-xs font-semibold" style={{ color: "var(--text-secondary)" }}>
              What&apos;s new
            </h3>
            <pre
              className="text-xs whitespace-pre-wrap"
              style={{ color: "var(--text-secondary)", fontFamily: "inherit" }}
            >
              {info.releaseNotes}
            </pre>
          </div>
        )}

        <footer
          className="flex flex-wrap items-center justify-between gap-2 border-t px-5 py-3"
          style={{ borderColor: "var(--border)" }}
        >
          <button
            type="button"
            onClick={skip}
            disabled={busy}
            className="text-xs hover:underline disabled:opacity-50"
            style={{ color: "var(--text-muted)" }}
          >
            Skip this version
          </button>

          <div className="flex items-center gap-2">
            <Button onClick={onClose} disabled={busy}>
              Later
            </Button>
            <Button variant="primary" onClick={download} disabled={busy}>
              Download
            </Button>
          </div>
        </footer>

        <button ref={closeRef} className="sr-only" onClick={onClose} type="button">
          Close
        </button>
      </div>
    </div>
  );
}

/**
 * Runs the check once on mount and renders the dialog if there is something to
 * say. Returns nothing otherwise — no spinner, no error, no trace.
 */
export function UpdateGate() {
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    if (!api.isDesktop()) return;
    let cancelled = false;

    // Deliberately not awaited into any loading state: a slow or failed check
    // must never delay the window.
    api
      .checkForUpdate(false)
      .then((result) => {
        if (!cancelled && result?.updateAvailable) setInfo(result);
      })
      .catch(() => {
        // Offline is the expected case for this app. Silence is correct.
      });

    return () => {
      cancelled = true;
    };
  }, []);

  if (!info || dismissed) return null;
  return <UpdateDialog info={info} onClose={() => setDismissed(true)} />;
}
