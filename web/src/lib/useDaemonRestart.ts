import { useEffect, useRef, useState } from "react";
import { ApiError, fetchJSON } from "@/lib/api";
import type { StatusSnapshot } from "@/lib/types";
import { confirmDialog } from "@shared/primitives/confirmDialogModel";
import { probeUnsavedLive, restartConfirmBody, type RestartConfirm } from "@/lib/restartConfirm";
import { isNewProcess, waitForNewProcess } from "@/lib/restartReconnect";

// useDaemonRestart owns the on-demand daemon-restart flow shared by the
// RestartPendingBanner and the Settings → Health control: POST
// /api/admin/restart (the daemon runs its graceful shutdown + self re-exec),
// then poll /api/status until the NEW process answers and reload into it. The
// poll is its own loop (restartReconnect.ts, UI review U-22), not the shared
// query cache: every attempt has a timeout and every failure is retried on a
// bounded backoff, so the overlay cannot outlive the old process. The new
// process is told apart by its started_at differing from the one read just
// before the restart (or, with no earlier read, being later than the click). The backend returns 501 when RestartFunc is
// nil (standalone `observer dashboard`, not `observer start`) — surfaced as
// `error` so callers can render honest copy.
//
// Proxy-route honesty (dashboard-config-management plan §3.3 item 3): before
// the confirm dialog (the shared confirmDialog), GET /api/admin/restart
// reports how many proxied API turns landed in the last minute. The daemon IS the proxy on its port, so a
// restart drops in-flight proxy requests; the dialog says so with the number
// instead of a vague warning. It never automates the route OFF/ON dance (see
// restartConfirm.ts for why); the dialog names scripts/restart-daemon.sh with
// the reason it is a shell step.
//
// Live sandboxed runs (sandbox plan v2 section 5.5, SBX-UPD-1): a restart
// with a live sandboxed run answers 409 live_sandboxed_runs with the runs.
// The hook announces them on LIVE_RUNS_EVENT, and the banner (mounted on
// every page) opens LiveSandboxRunsDialog, whose two answers come back
// through answerLiveRuns. The GET report also carries a pending restart and
// a deferred update's question; both fields are absent with no live run.
export type LiveSandboxRun = {
  run_id: string;
  tool: string;
  backend: string;
  age_seconds: number;
  native_resume: boolean;
};

export type RestartStatus = {
  available: boolean;
  proxy_port?: number;
  proxy_recent_requests?: number;
  window_s?: number;
  live_sandboxed_runs?: LiveSandboxRun[];
  live_run_update_policy?: string;
  restart_pending?: boolean;
  restart_pending_since?: string;
  update_deferred_live_sandbox?: boolean;
  update_question?: boolean;
  update_pending?: boolean;
};

// The restart route's live-run answers (dashapi.LiveRuns*).
export type LiveRunsAnswer = "end" | "when_finished" | "cancel" | "end_only" | "apply_when_finished";

// LIVE_RUNS_EVENT carries the runs of a refused restart to the dialog host.
export const LIVE_RUNS_EVENT = "observer:live-sandboxed-runs";

// liveRunsFromError returns the runs of a 409 live_sandboxed_runs refusal,
// or null for any other error.
export function liveRunsFromError(e: unknown): LiveSandboxRun[] | null {
  if (!(e instanceof ApiError) || e.status !== 409) return null;
  try {
    const body = JSON.parse(e.body) as { error?: string; runs?: LiveSandboxRun[] };
    return body.error === "live_sandboxed_runs" && Array.isArray(body.runs) ? body.runs : null;
  } catch {
    return null;
  }
}

// postLiveRunsAnswer sends one answer to the restart route.
export function postLiveRunsAnswer(answer: LiveRunsAnswer) {
  return fetchJSON<Record<string, unknown>>("/api/admin/restart", undefined, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ live_runs: answer }),
  });
}

export function useDaemonRestart() {
  const [restarting, setRestarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const restartAtRef = useRef<number>(0);
  // The running process's started_at, read just before the restart.
  const beforeRef = useRef<string | null>(null);

  // While a restart is in flight, wait for the new process and reload into it.
  useEffect(() => {
    if (!restarting) return;
    const ac = new AbortController();
    void waitForNewProcess((startedAt) => isNewProcess(startedAt, beforeRef.current, restartAtRef.current), {
      signal: ac.signal,
      sleep: (ms) => new Promise((resolve) => window.setTimeout(resolve, ms)),
      probe: (signal) => fetchJSON<StatusSnapshot>("/api/status", undefined, { signal, cache: "no-store" }),
    }).then((ok) => {
      if (ok) window.location.reload();
    });
    return () => ac.abort();
  }, [restarting]);

  // markStart records what the reconnect wait compares against: the click
  // time and, when the daemon answers, its current started_at.
  async function markStart() {
    restartAtRef.current = Date.now();
    beforeRef.current = null;
    try {
      const st = await fetchJSON<StatusSnapshot>("/api/status", undefined, { cache: "no-store" });
      beforeRef.current = st.started_at ?? null;
    } catch {
      // No status read: fall back to the click time.
    }
  }

  // restart optionally asks first (the shared confirmDialog, never a native
  // window.confirm); returns nothing - observe `restarting`/`error`. The
  // dialog's proxy line comes from the live-traffic probe (restartConfirm.ts).
  async function restart(confirm?: RestartConfirm) {
    if (confirm) {
      let st: RestartStatus | null = null;
      try {
        st = await fetchJSON<RestartStatus>("/api/admin/restart");
      } catch {
        // Status probe unavailable (older daemon, read-only surface): fall
        // back to the generic warning rather than blocking the restart.
      }
      if (st?.live_sandboxed_runs && st.live_sandboxed_runs.length > 0) {
        // The live-run question replaces the plain confirm.
        window.dispatchEvent(new CustomEvent(LIVE_RUNS_EVENT, { detail: st.live_sandboxed_runs }));
        return;
      }
      // What a restart would drop (U-27): an admission policy applied live
      // that never reached config.
      const unsaved = await probeUnsavedLive((path) => fetchJSON<unknown>(path));
      const ok = await confirmDialog({
        title: confirm.title,
        body: restartConfirmBody(confirm.lead, st, unsaved),
        confirmLabel: "Restart daemon",
        tone: "danger",
      });
      if (!ok) return;
    }
    setError(null);
    await markStart();
    try {
      await fetchJSON("/api/admin/restart", undefined, { method: "POST" });
      setRestarting(true);
    } catch (e) {
      const runs = liveRunsFromError(e);
      if (runs) {
        // Live sandboxed runs: ask, never end them silently.
        window.dispatchEvent(new CustomEvent(LIVE_RUNS_EVENT, { detail: runs }));
        return;
      }
      setError(
        e instanceof Error && e.message
          ? e.message.replace(/^\d+\s*/, "")
          : "restart failed",
      );
    }
  }

  // answerLiveRuns sends the dialog's answer. "end" restarts (the reconnect
  // overlay follows); the others leave the daemon running. It returns
  // whether the answer was accepted, with `error` set when not.
  async function answerLiveRuns(answer: LiveRunsAnswer): Promise<boolean> {
    setError(null);
    if (answer === "end") await markStart();
    try {
      await postLiveRunsAnswer(answer);
      if (answer === "end") setRestarting(true);
      return true;
    } catch (e) {
      setError(e instanceof Error && e.message ? e.message.replace(/^\d+\s*/, "") : "the answer was not accepted");
      return false;
    }
  }

  return { restarting, error, restart, answerLiveRuns };
}
