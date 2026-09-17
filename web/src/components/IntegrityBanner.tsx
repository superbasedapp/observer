import { useState } from "react";
import { useApi } from "@/lib/useApi";
import { integrityDismissKey, integrityNotice } from "@/lib/integrity";
import type { StatusSnapshot } from "@/lib/types";

// IntegrityBanner — the slim strip under the TopBar reporting the daemon's
// persisted startup `PRAGMA quick_check` verdict (RES-3, codebase audit
// 2026-09-16; internal/diag/status.go's StatusSnapshot.integrity).
//
// The probe runs once at db.Open (daemon startup), never on a timer, so this
// is a single loopback GET on mount — the AnnouncementBanner / UpdateBanner
// pattern, not the polling RestartPendingBanner one. Renders nothing for
// "ok" or an absent verdict (a fresh install, or a database size-gated off
// the check); an "error" verdict is a probe that could NOT complete and gets
// the softer warn tone, never the "corrupt" danger tone.
//
// Dismissal is per SESSION (sessionStorage, not the other banners'
// persistent localStorage ack): an integrity finding is worth re-surfacing
// the next time the operator opens the dashboard, since nothing about the
// underlying condition self-resolves without operator action.
const DISMISS_KEY = "sb_integrity_dismissed_session";

function dismissedKey(): string | null {
  try {
    return sessionStorage.getItem(DISMISS_KEY);
  } catch {
    return null;
  }
}

function setDismissedKey(key: string): void {
  try {
    sessionStorage.setItem(DISMISS_KEY, key);
  } catch {
    // Storage unavailable (private mode) — the banner just won't dismiss;
    // nothing breaks.
  }
}

const toneClass: Record<"danger" | "warn", { strip: string; label: string }> = {
  danger: {
    strip: "border-danger/30 bg-danger-soft",
    label: "font-semibold text-danger",
  },
  warn: {
    strip: "border-warn/30 bg-warn-soft",
    label: "font-semibold text-warn",
  },
};

export function IntegrityBanner() {
  const status = useApi<StatusSnapshot>("/api/status");
  const [, bump] = useState(0);
  const notice = integrityNotice(status.data?.integrity);
  if (!notice || !status.data?.integrity) return null;

  const key = integrityDismissKey(status.data.integrity);
  if (dismissedKey() === key) return null;

  const style = toneClass[notice.tone];
  const dismiss = () => {
    setDismissedKey(key);
    bump((n) => n + 1);
  };

  return (
    <div
      role="status"
      data-testid="integrity-banner"
      className={`flex items-center gap-2 border-b px-4 py-1.5 text-[11.5px] text-fg-2 ${style.strip}`}
    >
      <span className={style.label}>{notice.label}</span>
      <span className="min-w-0 truncate">{notice.text}</span>
      <div className="flex-1" />
      <button
        type="button"
        onClick={dismiss}
        className="shrink-0 rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-fg-2 hover:bg-bg-3"
      >
        dismiss
      </button>
    </div>
  );
}
