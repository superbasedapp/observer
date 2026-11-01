import { useEffect, useRef, useState } from "react";
import { useApi } from "@/lib/useApi";
import type { StatusSnapshot } from "@/lib/types";
import {
  LIVE_RUNS_EVENT,
  useDaemonRestart,
  type LiveSandboxRun,
  type RestartStatus,
} from "@/lib/useDaemonRestart";
import { LiveSandboxRunsDialogView, type LiveRunsQuestionMode } from "@/components/LiveSandboxRunsDialog";
import { liveRestartPollMs } from "@/lib/liveRestartPoll";
import { isRemoteView } from "@/lib/remote";
import { RestartOverlay } from "@/components/RestartOverlay";
import { RestartPendingBar } from "@shared/primitives/RestartOverlay";
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
//
// Live sandboxed runs (sandbox plan v2 section 5.5, SBX-UPD-1): this banner
// is also the host of LiveSandboxRunsDialog. A refused restart (from here,
// Settings or anywhere else) arrives on LIVE_RUNS_EVENT; a pending "restart
// when they finish", a pending "apply when they finish" and an update that
// is waiting for live runs each get a strip with its action. With
// live_run_update_policy = ask_immediately the update's question opens at
// once; with defer it waits in its strip.
export function RestartPendingBanner() {
  const [pending, setPending] = useState<RestartPending | null>(
    getRestartPending,
  );
  const { restarting, error: restartErr, restart, answerLiveRuns } = useDaemonRestart();
  const [question, setQuestion] = useState<{ runs: LiveSandboxRun[]; mode: LiveRunsQuestionMode } | null>(null);
  const [busy, setBusy] = useState(false);
  const askedRef = useRef(false);
  // The restart report is an owner-local route: read it on this machine's
  // own dashboard only, never through a remote view. It is read once when
  // the banner mounts and polled only while a sandboxed run is live or a
  // restart or update waits (liveRestartPollMs); with nothing live it is not
  // polled (SBX-UPD audit finding 5).
  const [livePollMs, setLivePollMs] = useState(0);
  const live = useApi<RestartStatus>(isRemoteView() ? null : "/api/admin/restart", undefined, [question == null], { refreshMs: livePollMs });
  const liveRuns = live.data?.live_sandboxed_runs ?? [];
  useEffect(() => {
    setLivePollMs(liveRestartPollMs(live.data));
  }, [live.data]);

  useEffect(() => {
    const onRuns = (e: Event) => {
      const runs = (e as CustomEvent<LiveSandboxRun[]>).detail;
      if (Array.isArray(runs) && runs.length > 0) setQuestion({ runs, mode: "restart" });
    };
    window.addEventListener(LIVE_RUNS_EVENT, onRuns);
    return () => window.removeEventListener(LIVE_RUNS_EVENT, onRuns);
  }, []);

  // ask_immediately: a deferred update opens its question once.
  useEffect(() => {
    const d = live.data;
    if (!d?.update_question || d.update_pending || askedRef.current || liveRuns.length === 0) return;
    askedRef.current = true;
    setQuestion({ runs: liveRuns, mode: "update" });
  }, [live.data, liveRuns]);

  async function answer(kind: "end" | "later") {
    if (!question) return;
    setBusy(true);
    let ok: boolean;
    if (question.mode === "restart") {
      ok = await answerLiveRuns(kind === "end" ? "end" : "when_finished");
    } else {
      // Ending the runs lets the waiting apply run at once.
      ok = (kind === "end" ? await answerLiveRuns("end_only") : true) && (await answerLiveRuns("apply_when_finished"));
    }
    setBusy(false);
    if (ok) setQuestion(null);
  }

  async function cancelPending() {
    await answerLiveRuns("cancel");
    live.reload();
  }

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

  const dialog = question ? (
    <LiveSandboxRunsDialogView
      runs={question.runs}
      mode={question.mode}
      busy={busy}
      error={restartErr}
      onEnd={() => void answer("end")}
      onWhenFinished={() => void answer("later")}
      onClose={() => setQuestion(null)}
    />
  ) : null;
  const n = liveRuns.length;
  const runsLabel = n === 1 ? "1 sandboxed run" : `${n} sandboxed runs`;
  const liveStrips = (
    <>
      {live.data?.restart_pending && (
        <RestartPendingBar
          message={<>The restart waits for {runsLabel} to finish, then runs.</>}
          actions={
            <button type="button" onClick={() => void cancelPending()} className={STRIP_BUTTON}>
              cancel
            </button>
          }
        />
      )}
      {live.data?.update_pending && (
        <RestartPendingBar
          message={<>An update applies when {runsLabel} finish.</>}
          actions={
            <button type="button" onClick={() => void cancelPending()} className={STRIP_BUTTON}>
              cancel
            </button>
          }
        />
      )}
      {live.data?.update_deferred_live_sandbox && !live.data.update_pending && n > 0 && (
        <RestartPendingBar
          message={<>An update is waiting: applying it ends {runsLabel}.</>}
          actions={
            <button type="button" onClick={() => setQuestion({ runs: liveRuns, mode: "update" })} className={STRIP_ACCENT}>
              decide
            </button>
          }
        />
      )}
      {dialog}
    </>
  );

  if (!pending) return liveStrips;
  return (
    <>
    {liveStrips}
    <RestartPendingBar
      error={restartErr}
      message={
        pending.keys && pending.keys.length > 0 ? (
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
        )
      }
      actions={
        <>
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
        </>
      }
    />
    </>
  );
}

const STRIP_BUTTON = "shrink-0 rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-fg-2 hover:bg-bg-3";
const STRIP_ACCENT = "shrink-0 rounded-2 border border-accent/50 bg-accent/15 px-2 py-0.5 text-accent hover:bg-accent/25";
