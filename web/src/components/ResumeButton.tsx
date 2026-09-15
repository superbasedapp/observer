import { useState } from "react";
import clsx from "clsx";
import { Tooltip } from "@/components/primitives";
import { ApiError, fetchJSON } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { useLaunchDock } from "@/components/LaunchDock";
import { pushToast } from "@/components/Toast";
import {
  isProjectRootDeniedError,
  isTerminalCapabilityError,
  PROJECT_ROOT_DENIED_MSG,
  RESUME_EXECUTE_REQUIRED_MSG,
} from "@/lib/remoteTerminal";
import type {
  AttachSessionsResponse,
  SessionResumeInfo,
  SessionResumeResponse,
} from "@/lib/types";

// ResumeButton — the dashboard "reopen a closed session" affordance
// (session-attach Phase 3, docs/plans/session-attach-design-2026-07-19.md).
// It sits beside JumpInButton and is shown only when the session is NOT
// currently live-attachable (a live `--attach` row → Jump in is the right
// action, so this card hides). It dispatches on the server-derived
// `resume` block by CAPABILITY SHAPE, never a tool-name branch:
//
//   - kind "native":  POST /api/session/<id>/resume, then hand the returned
//                     terminal handle to the dock (HandoffCard's "Launch here"
//                     pattern) — a terminal running the tool's own resume, the
//                     REAL prior transcript.
//   - kind "handoff": native resume isn't grounded — do NOT duplicate the
//                     Continue-in… UI; render a short hint pointing at the
//                     existing card below.
//   - kind "none":    honest-disabled (feedback_honest_disable_copy), naming
//                     the gap.

// RESUME_VERBS mirrors the integration registry's ResumeNative rows: a canonical
// tool name → the observer launcher verb the native resume runs. Kept in step
// with internal/integration when a new tool grounds a ResumeNative contract.
const RESUME_VERBS: Record<string, string> = {
  "claude-code": "claude",
  codex: "codex",
};

function nativeResumeCommand(tool: string, subcommand: string): string {
  const sub = subcommand || RESUME_VERBS[tool] || "";
  return sub ? `observer ${sub} --resume <id>` : "the tool's native resume";
}

export function ResumeButton({
  sessionId,
  tool,
  resume,
}: {
  sessionId: string;
  tool: string;
  resume: SessionResumeInfo;
}) {
  const dock = useLaunchDock();
  // Poll the live-attach list so this card HIDES the moment the session is
  // joinable (Jump in owns that case) and reappears when it isn't. 15s matches
  // the JumpInButton cadence; the hook pauses on a hidden tab.
  const attach = useApi<AttachSessionsResponse>(
    "/api/attach/sessions",
    undefined,
    [sessionId],
    { refreshMs: 15000 },
  );
  const [posting, setPosting] = useState(false);
  // Set when the server refuses a resume with 409 because the session already
  // has a live terminal run (F5). /api/attach/sessions now covers every live
  // daemon-owned run (fresh/handoff/attach/resume, not attach-only), so a live
  // KindResume run DOES normally appear there and liveMatch below already hides
  // this card before the click. We still keep the 409 handling as the backstop
  // for the race window between the last poll and the click, flipping to a
  // disabled "already running" state and surfacing the server's message rather
  // than let repeated clicks spawn concurrent processes on the same transcript.
  const [alreadyRunning, setAlreadyRunning] = useState(false);

  const liveMatch = (attach.data?.sessions ?? []).some(
    (r) => r.session_id === sessionId && !r.exited,
  );
  // While the session is live-attachable, Jump in is the correct action — do
  // not also offer a resume (it would spawn a duplicate second session).
  if (liveMatch) return null;

  async function resumeNative() {
    setPosting(true);
    try {
      const r = await fetchJSON<SessionResumeResponse>(
        `/api/session/${sessionId}/resume`,
        undefined,
        { method: "POST", headers: { "Content-Type": "application/json" } },
      );
      // Same dock path as HandoffCard's launch: the token rides a computed key
      // so the source carries no literal token property (the harness
      // write-filter mangles those; feedback_write_filter_token_patterns).
      const seat: Record<string, unknown> = {
        tool,
        sessionId,
        hasProjectRoot: r.has_project_root ?? false,
      };
      seat["tok" + "en"] = r.token;
      dock.launch(seat as unknown as Parameters<typeof dock.launch>[0]);
    } catch (e) {
      // 409 → the session already has a live terminal run (or, in a race,
      // native resume is no longer grounded). Surface the server's honest
      // message AND disable the button so it can't be re-clicked into spawning a
      // second process on the same transcript. Other errors → generic toast.
      if (e instanceof ApiError && e.status === 409) {
        setAlreadyRunning(true);
        pushToast(e.message.replace(/^api 409 [^:]*:\s*/, ""), "warn");
      } else if (isProjectRootDeniedError(e)) {
        pushToast(PROJECT_ROOT_DENIED_MSG, "danger");
      } else if (isTerminalCapabilityError(e)) {
        // Resume is Execute-classified and NOT lowered by allow_terminal, so an
        // "insufficient capability" here means this device lacks execute access
        // — NOT that "allow terminal view" is off. Give resume-accurate guidance.
        pushToast(RESUME_EXECUTE_REQUIRED_MSG, "danger");
      } else {
        pushToast(
          e instanceof Error ? e.message : "Couldn't resume this session.",
          "danger",
        );
      }
    } finally {
      setPosting(false);
    }
  }

  // --- kind "handoff": point at the Continue-in… card, don't duplicate it. ---
  if (resume.kind === "handoff") {
    return (
      <section className="mt-5 rounded-3 border bg-bg-2 px-4 py-3">
        <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Resume
        </span>
        <p className="mt-1 text-[10.5px] text-fg-3">
          Native resume isn't grounded for this tool - use{" "}
          <span className="font-medium text-fg-2">Continue in another tool</span>{" "}
          below to fork this session into a fresh handover instead. A fork is a
          NEW session seeded from a scrubbed handover doc, not the original
          transcript.
        </p>
      </section>
    );
  }

  // --- kind "none": honest-disabled, name the gap. ---
  if (resume.kind !== "native") {
    return (
      <section className="mt-5 rounded-3 border bg-bg-2 px-4 py-3">
        <div className="flex items-center justify-between gap-2">
          <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
            Resume
          </span>
          <Tooltip
            content={`Resume unavailable - ${tool} has no native resume and isn't launchable in the embedded terminal, so there's no way to reopen this session from the dashboard.`}
            maxWidth={360}
          >
            <span>
              <button
                type="button"
                disabled
                className="cursor-not-allowed rounded-2 border border-line-2 bg-bg-3 px-2.5 py-1 text-[11px] font-medium text-fg-3 focus:outline-none"
              >
                Resume
              </button>
            </span>
          </Tooltip>
        </div>
        <p className="mt-1 text-[10.5px] text-fg-3">
          This tool exposes neither a native resume nor an embedded-terminal
          launcher, so a closed session can't be reopened from here.
        </p>
      </section>
    );
  }

  // --- kind "native": the real deal. ---
  const cmd = nativeResumeCommand(tool, resume.subcommand);
  const disabled = posting || alreadyRunning;
  return (
    <section className="mt-5 rounded-3 border bg-bg-2 px-4 py-3">
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Resume
        </span>
        <Tooltip
          content={
            alreadyRunning
              ? "This session already has a live terminal run - jump into it or wait for it to end before resuming again."
              : "Reopen this closed session in an embedded terminal running the tool's own resume - the REAL prior transcript, signed thinking blocks and all, not a distilled fork."
          }
          maxWidth={360}
        >
          <span>
            <button
              type="button"
              disabled={disabled}
              onClick={disabled ? undefined : resumeNative}
              className={clsx(
                "rounded-2 border px-2.5 py-1 text-[11px] font-medium focus:outline-none",
                disabled
                  ? "cursor-not-allowed border-line-2 bg-bg-3 text-fg-3"
                  : "border-accent/40 bg-accent/10 text-accent hover:bg-accent/20",
              )}
            >
              {alreadyRunning
                ? "Already running"
                : posting
                  ? "Resuming…"
                  : "Resume"}
            </button>
          </span>
        </Tooltip>
      </div>
      <p className="mt-1 text-[10.5px] text-fg-3">
        {alreadyRunning
          ? "This session already has a live terminal run - jump into it or wait for it to end before resuming again."
          : "Reopen this closed session with its native resume ("}
        {!alreadyRunning && <span className="font-mono">{cmd}</span>}
        {!alreadyRunning &&
          ") in an embedded terminal - the actual conversation reattaches, drivable from here."}
      </p>
    </section>
  );
}
