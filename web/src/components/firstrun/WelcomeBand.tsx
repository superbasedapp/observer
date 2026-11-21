import { useCallback, useEffect, useState } from "react";
import { Compass, History, Sparkles, TerminalSquare, X } from "lucide-react";
import { Button, Icon } from "@/components/primitives";
import { useLaunchDock } from "@/components/LaunchDock";
import { useTour } from "@/components/tour/TourProvider";
import { GlanceCard, RevealProgress, revealToolNames } from "@/components/firstrun/HistoryReveal";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { isRemoteView } from "@/lib/remote";
import { CONNECT_STATUS_PATH, type ConnectStatus } from "@/lib/connect";
import { accountOf } from "@/lib/getStarted";
import { useConnectHandoff } from "@/lib/useConnectHandoff";
import type { EnrolmentStatus } from "@/lib/types";
import { FIRST_RUN_PATH, FIRST_RUN_POLL_MS, openFirstRun, shouldPoll, type FirstRunResponse } from "@/lib/firstRun";
import {
  FIRST_RUN_GLANCE_PATH,
  doorOf,
  honestLine,
  readBandDismissed,
  revealPhase,
  startAgentTool,
  writeBandDismissed,
  type GlanceResponse,
} from "@/lib/firstRunDoors";

// WelcomeBand - the top of Overview on a first visit (local dashboard
// first-run design, docs/plans/local-dashboard-first-run-options-2026-11-18.md
// section 8, steps 0 and 1). Two doors:
//
//   - history (door B leads): the reveal of what the watcher is reading,
//     settling into "your AI coding at a glance", with Start a coding agent
//     and Take the 60-second tour.
//   - fresh (door A leads): Start a coding agent is primary; the tour and the
//     sample data are secondary.
//
// "Start a coding agent" opens the existing New terminal dialog through the
// launch dock (preselecting the most-used tool found here). "See what we
// found" opens the existing first-run capture dialog. Hidden while the
// installer's ?connecting=1 hand-off waits (no decisions then), for a
// remote viewer (launching is owner-local and the reads are too), and once
// "Not now" is pressed in this browser. lib/firstRunDoors.ts decides
// everything; this file renders it.

function storage(): Storage | null {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

/**
 * WelcomeBand. `embedded` is its place inside the one getting-started
 * surface (first-run plan revision 2, 3.6 and 7.1, GetStartedSurface): the
 * surface draws the frame and owns Hide, so the band drops its own border
 * and "Not now" and ignores an earlier "Not now" in this browser.
 */
export function WelcomeBand({ embedded = false }: { embedded?: boolean } = {}) {
  const remote = isRemoteView();
  const [storedDismissed, setDismissed] = useState(() => readBandDismissed(storage()));
  const dismissed = embedded ? false : storedDismissed;

  // The hand-off decides first: the same status reads the Get started panel
  // takes (shared cache), folded the same way.
  const status = useApi<ConnectStatus>(remote ? null : CONNECT_STATUS_PATH, undefined, [], { refreshMs: 30000 });
  const enrolment = useApi<EnrolmentStatus>(remote ? null : "/api/enrolment/status", undefined, [], { refreshMs: 30000 });
  const { phase: handoffPhase } = useConnectHandoff(accountOf(status.data, enrolment.data, null));
  const handoffActive = handoffPhase === "waiting" || handoffPhase === "expired";

  // The shell's brief read (shared cache) answers first; the full read adds
  // the tools and projects, and is read again every few seconds while the
  // watcher's first pass still moves.
  const brief = useApi<FirstRunResponse>(remote || dismissed ? null : FIRST_RUN_PATH, { brief: "1" });
  const [moving, setMoving] = useState(true);
  const full = useApi<FirstRunResponse>(remote || dismissed || handoffActive ? null : FIRST_RUN_PATH, undefined, [], {
    refreshMs: moving ? FIRST_RUN_POLL_MS : 0,
  });
  useEffect(() => {
    if (full.data) setMoving(shouldPoll(full.data));
  }, [full.data]);
  const data = full.data ?? brief.data;

  const door = remote ? "hidden" : doorOf({ brief: data, handoffActive, dismissed });
  const phase = revealPhase(data);
  const settledHistory = door === "history" && phase === "settled";

  // Obs lands only when the reveal finished in front of the person.
  const [sawReveal, setSawReveal] = useState(false);
  useEffect(() => {
    if (door === "history" && phase === "revealing") setSawReveal(true);
  }, [door, phase]);

  const glance = useApi<GlanceResponse>(settledHistory ? FIRST_RUN_GLANCE_PATH : null);

  const dock = useLaunchDock();
  const { startTour } = useTour();
  const startAgent = useCallback(() => {
    const tool = startAgentTool(full.data?.tools);
    if (tool) dock.openNewTerminalFor(tool);
    else dock.openNewTerminal();
  }, [dock, full.data?.tools]);
  const notNow = useCallback(() => {
    setDismissed(true);
    writeBandDismissed(storage());
  }, []);

  if (door === "hidden") return null;

  const line = honestLine(door, data, revealToolNames(full.data));
  const history = door === "history";
  const title = !history
    ? "Welcome to Observer"
    : phase === "revealing"
      ? "Reading your AI coding history"
      : "Your AI coding at a glance";

  return (
    <section
      aria-labelledby="sb-welcome-title"
      data-testid="welcome-band"
      data-door={door}
      className={embedded ? "sb-fade-up" : "sb-fade-up rounded-3 border border-accent/30 bg-bg-1 p-4 sm:p-5"}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 id="sb-welcome-title" className="flex items-center gap-2 text-[14px] font-semibold text-fg-0">
            <Icon icon={history ? History : Sparkles} size={14} className="shrink-0 text-accent" />
            {title}
          </h2>
          <p className="mt-0.5 text-[12px] text-fg-2" aria-live="polite">
            {line}{" "}
            {history && (
              <button
                type="button"
                onClick={openFirstRun}
                className="font-medium text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
              >
                See what we found
              </button>
            )}
          </p>
          {!history && (
            <p className="mt-1 text-[11.5px] text-fg-3">
              Observer shows what your coding agents do: sessions, tokens, cost and guardrails, all on this machine.
              Start one here and watch it work.
            </p>
          )}
        </div>
        {!embedded && (
        <button
          type="button"
          onClick={notNow}
          aria-label="Not now: hide this welcome"
          title="Not now"
          className="sb-press shrink-0 rounded-2 p-1 text-fg-3 hover:bg-bg-3 hover:text-fg-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
        >
          <Icon icon={X} size={14} />
        </button>
        )}
      </div>

      {history && (
        <div className="mt-4">
          {phase === "revealing" ? (
            <RevealProgress data={full.data ?? brief.data} />
          ) : (
            <GlanceCard glance={glance.data} loading={glance.loading} error={glance.error} landed={sawReveal} />
          )}
        </div>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <Button variant={history ? "secondary" : "primary"} size="sm" iconLeft={TerminalSquare} onClick={startAgent}>
          Start a coding agent
        </Button>
        <Button variant={history ? "primary" : "ghost"} size="sm" iconLeft={Compass} onClick={startTour}>
          {history ? "Take the 60-second tour" : "Take the tour"}
        </Button>
        {!history && <SampleDataLink sessions={data?.sessions ?? 0} />}
      </div>
    </section>
  );
}

/** The existing sample-data offer: only while nothing is captured. */
function SampleDataLink({ sessions }: { sessions: number }) {
  const demo = useApi<{ available: boolean; active: boolean }>(sessions === 0 ? "/api/demo" : null);
  const [seeding, setSeeding] = useState(false);
  if (!demo.data?.available || demo.data.active) return null;
  const startDemo = async () => {
    setSeeding(true);
    try {
      await fetchJSON("/api/demo/start", undefined, { method: "POST" });
      window.location.reload();
    } catch {
      setSeeding(false);
    }
  };
  return (
    <span className="text-[11.5px] text-fg-3">
      or{" "}
      <button
        type="button"
        onClick={() => void startDemo()}
        disabled={seeding}
        className="font-medium text-accent hover:underline disabled:opacity-60"
      >
        {seeding ? "Loading the sample..." : "explore with sample data"}
      </button>
      . Your real data stays untouched.
    </span>
  );
}
