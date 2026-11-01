import { useEffect, useRef, useState } from "react";
import { useApi } from "@/lib/useApi";
import { ApiError, fetchJSON } from "@/lib/api";
import type { StatusSnapshot } from "@/lib/types";

// useDaemonRestart owns the on-demand daemon-restart flow shared by the
// RestartPendingBanner and the Settings → Health control: POST
// /api/admin/restart (the daemon runs its graceful shutdown + self re-exec),
// then poll /api/status until the NEW process answers (started_at advances past
// the click) and reload into it. The backend returns 501 when RestartFunc is
// nil (standalone `observer dashboard`, not `observer start`) — surfaced as
// `error` so callers can render honest copy.
//
// Proxy-route honesty (dashboard-config-management plan §3.3 item 3): before
// the confirm dialog, GET /api/admin/restart reports how many proxied API
// turns landed in the last minute. The daemon IS the proxy on its port, so a
// restart drops in-flight proxy requests; the dialog says so with the number
// instead of a vague warning. It never automates the route OFF/ON dance —
// scripts/restart-daemon.sh stays the belt-and-braces path and is named.
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

  // Poll status only while a restart is in flight; fast so the overlay clears
  // promptly once the new process is up.
  const status = useApi<StatusSnapshot>(
    restarting ? "/api/status" : null,
    undefined,
    [restarting],
    { refreshMs: 1500 },
  );

  useEffect(() => {
    if (!restarting || !status.data?.started_at) return;
    const startedAt = new Date(status.data.started_at).getTime();
    if (Number.isFinite(startedAt) && startedAt > restartAtRef.current) {
      window.location.reload();
    }
  }, [restarting, status.data?.started_at]);

  // restart optionally gates on a window.confirm message; returns nothing —
  // observe `restarting`/`error`. The live-traffic line is appended to the
  // confirm copy when the daemon reports proxied requests in the last minute.
  async function restart(confirmMessage?: string) {
    if (confirmMessage) {
      let message = confirmMessage;
      try {
        const st = await fetchJSON<RestartStatus>("/api/admin/restart");
        if (st.live_sandboxed_runs && st.live_sandboxed_runs.length > 0) {
          // The live-run question replaces the plain confirm.
          window.dispatchEvent(new CustomEvent(LIVE_RUNS_EVENT, { detail: st.live_sandboxed_runs }));
          return;
        }
        const n = st.proxy_recent_requests ?? 0;
        if (n > 0) {
          message +=
            `\n\nA coding session is routing through this daemon right now (${n} request${n === 1 ? "" : "s"} in the last minute). ` +
            "Restarting drops in-flight proxy requests. The daemon re-execs in place, so the gap is typically under a second." +
            "\n\nHaving trouble? scripts/restart-daemon.sh performs the route-off → restart → route-on sequence from a shell.";
        } else {
          message += "\n\nNo proxied requests in the last minute - no coding session should notice.";
        }
      } catch {
        // Status probe unavailable (older daemon, read-only surface): fall
        // back to the generic warning rather than blocking the restart.
        message += "\n\nAn active proxied coding session may drop one in-flight request.";
      }
      if (!window.confirm(message)) return;
    }
    setError(null);
    restartAtRef.current = Date.now();
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
    if (answer === "end") restartAtRef.current = Date.now();
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
