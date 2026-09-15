import { useEffect, useState } from "react";
import { useApi } from "@/lib/useApi";
import type { StatusSnapshot } from "@/lib/types";
import { useDaemonRestart } from "@/lib/useDaemonRestart";
import { RestartOverlay } from "@/components/RestartOverlay";
import {
  RESTART_PENDING_EVENT,
  clearRestartPending,
  getRestartPending,
  type RestartPending,
} from "@/lib/restartPending";

// RestartPendingBanner — slim, persistent strip under the TopBar that
// appears after any restart-required config save and survives
// navigation + page reloads (usability arc P1.9). Honesty contract:
// it names the saved sections, says exactly what to do, and clears
// ITSELF when /api/status shows the daemon actually restarted (its
// started_at is newer than the last save) — no false "all applied"
// while the old process is still serving.
//
// "Restart now" (docs/plans/dashboard-daemon-restart-plan-2026-07-14.md) POSTs
// /api/admin/restart — the daemon runs its graceful shutdown + self re-exec, so
// the operator never drops to the CLI. A reconnecting overlay polls /api/status
// until the NEW process answers (started_at advances), then reloads.
export function RestartPendingBanner() {
  const [pending, setPending] = useState<RestartPending | null>(
    getRestartPending,
  );
  const { restarting, error: restartErr, restart } = useDaemonRestart();

  useEffect(() => {
    const onChange = () => setPending(getRestartPending());
    window.addEventListener(RESTART_PENDING_EVENT, onChange);
    return () => window.removeEventListener(RESTART_PENDING_EVENT, onChange);
  }, []);

  // Poll status while something is pending (slow) so the banner self-clears when
  // the daemon restarts by any means. The in-flight reconnect polling +
  // reload-on-new-process live in useDaemonRestart.
  const status = useApi<StatusSnapshot>(
    pending ? "/api/status" : null,
    undefined,
    [pending != null],
    { refreshMs: 15000 },
  );

  // Self-clear the pending banner once the daemon has actually restarted.
  useEffect(() => {
    if (!pending || !status.data?.started_at) return;
    const startedAt = new Date(status.data.started_at).getTime();
    const savedAt = new Date(pending.at).getTime();
    if (Number.isFinite(startedAt) && Number.isFinite(savedAt) && startedAt > savedAt) {
      clearRestartPending();
    }
  }, [pending, status.data?.started_at]);

  function onRestart() {
    void restart(
      "Restart the daemon now?\n\nThis applies pending config changes. Reconnecting takes ~1s.",
    );
  }

  if (restarting) {
    return (
      <RestartOverlay
        title="Restarting the daemon…"
        body="Applying your changes and reconnecting. This page reloads automatically when the new process is up."
      />
    );
  }

  if (!pending) return null;
  return (
    <div className="flex items-center gap-2 border-b border-warn/30 bg-warn-soft px-4 py-1.5 text-[11.5px] text-fg-2">
      <span className="font-semibold text-warn">Restart pending</span>
      <span className="min-w-0 truncate">
        {pending.keys && pending.keys.length > 0 ? (
          <>
            {pending.keys.length} setting{pending.keys.length === 1 ? "" : "s"} apply on
            restart:{" "}
            <span className="font-mono" title={pending.keys.join(", ")}>
              {pending.keys.slice(0, 4).join(", ")}
              {pending.keys.length > 4 ? `, +${pending.keys.length - 4} more` : ""}
            </span>
          </>
        ) : (
          <>
            saved changes to{" "}
            <span className="font-mono">{pending.sections.join(", ")}</span> apply
            on the next daemon start
          </>
        )}
        {restartErr && <span className="ml-2 text-danger">- {restartErr}</span>}
      </span>
      <div className="flex-1" />
      <button
        type="button"
        onClick={onRestart}
        className="shrink-0 rounded-2 border border-accent/50 bg-accent/15 px-2 py-0.5 text-accent hover:bg-accent/25"
      >
        Restart now
      </button>
      <button
        type="button"
        onClick={clearRestartPending}
        className="shrink-0 rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-fg-2 hover:bg-bg-3"
      >
        dismiss
      </button>
    </div>
  );
}
