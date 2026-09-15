import { useEffect, useRef, useState } from "react";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
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
type RestartStatus = {
  available: boolean;
  proxy_port?: number;
  proxy_recent_requests?: number;
  window_s?: number;
};

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
      setError(
        e instanceof Error && e.message
          ? e.message.replace(/^\d+\s*/, "")
          : "restart failed",
      );
    }
  }

  return { restarting, error, restart };
}
