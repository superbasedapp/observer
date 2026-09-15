import { useMemo, useRef } from "react";
import { Link } from "react-router-dom";
import { SlideOver } from "@/components/primitives";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { SessionDetailPanel } from "@/components/SessionDetailPanel";
import { useApi } from "@/lib/useApi";
import { useNowTick } from "@/lib/useNowTick";
import { toolMeta } from "@/lib/tools";
import {
  fmtElapsed,
  parseLinkError,
  terminalLinkPath,
  type TerminalSessionLink,
} from "@/lib/cockpit";

// TerminalSessionModal — what the terminal's "⊙ Session" control now opens
// (Task 9). It resolves the terminal→session link and then shows the FULL
// session detail slide-over over the terminal workspace, rather than the lite
// vitals popover that used to be the only thing reachable from here.
//
// WHY A SLIDE-OVER OVER THE TERMINAL, NOT A NAVIGATION. The whole point of the
// terminal workspace is that the run keeps running; routing to /sessions would
// unmount the workspace's React subtree. The panel is presented as a modal
// layer instead, and the terminal is still there when it closes.
//
// Z-ORDER. The terminal workspace is itself an overlay stack — the expanded
// terminal's backdrop is z-80 and the floating project/session panels live in
// the bounded band [90,110]. A page-level slide-over (z-40/50) would render
// UNDERNEATH all of it. 112 clears the band while staying below the guided
// tour (z-120/130) and the terminal's own right-click menu (z-200).
export const TERMINAL_OVERLAY_Z = 112;

// LITE FALLBACK — kept for the no-session case ONLY. Not every launch
// correlates: a run can be too young (the tool has not written its first
// transcript record), or its shape may never correlate at all. There is no
// session id to open a detail panel for, and inventing one would be a lie —
// so this branch says what is happening and offers the live vitals panel,
// which is designed to work without a correlated session.
export default function TerminalSessionModal({
  token,
  onClose,
  onOpenVitals,
}: {
  token: string;
  onClose: () => void;
  /**
   * Opens the floating per-terminal vitals cockpit for this token. Offered from
   * both branches: while uncorrelated it is the only thing that can show
   * anything at all, and once correlated it is the way to keep vitals on screen
   * NEXT TO the terminal after this modal is dismissed (a 1680px slide-over
   * covers the terminal; the cockpit docks beside it).
   */
  onOpenVitals: () => void;
}) {
  // Honest elapsed floor before a session start time is known — the link wire
  // carries no launch timestamp, so the earliest instant we can attest to is
  // when this component mounted.
  const mountMs = useRef<number>(Date.now()).current;
  // Ticking clock so the "Waiting Ns" display in the uncorrelated branch below
  // actually advances. A bare Date.now() read at render time only updates on
  // the next poll-driven render (every 4s here) — worse, once linkError/data
  // settle into a steady uncorrelated state nothing re-renders this component
  // AT ALL between polls, so the elapsed readout can visibly freeze (observed
  // live as a permanently-stuck "Waiting 0s"). Same fix, same primitive, as
  // cockpit/CockpitContent.tsx's WaitingState.
  const now = useNowTick(1000);

  // Poll fast (4s) while hunting for a correlation, slow (15s) once we have
  // one, and NEVER stop: a first correlation can be a weak activity match that
  // a later authoritative out-of-band handshake RE-POINTS to a different
  // session. Same contract as the cockpit panel — see SessionCockpitPanel.
  const correlatedRef = useRef(false);
  const link = useApi<TerminalSessionLink>(
    terminalLinkPath(token),
    undefined,
    [token],
    { refreshMs: correlatedRef.current ? 15000 : 4000 },
  );
  const resolved = link.data ?? null;
  const linkError = useMemo(() => parseLinkError(link.error), [link.error]);

  const tool = resolved?.tool ?? "";
  // LATCH THE CORRELATION. A poll that comes back uncorrelated (or fails) must
  // not tear the open detail panel down and rebuild it: the panel holds live
  // view state — the active tab, which tabs have been mounted, expanded message
  // rows — and all of it dies with the unmount. A LATER correlated answer
  // naming a DIFFERENT session still re-points, which is the whole reason this
  // poll never stops (a weak activity match can be superseded by an
  // authoritative out-of-band handshake).
  const latchedRef = useRef("");
  const fresh = resolved?.correlated && resolved.session_id ? resolved.session_id : "";
  if (fresh && fresh !== latchedRef.current) latchedRef.current = fresh;
  const sessionId = latchedRef.current;
  const correlated = sessionId !== "";
  correlatedRef.current = correlated;

  if (correlated) {
    return (
      // This modal mounts ABOVE the route-level RouteErrorBoundary (it opens
      // over whatever page is active), so without its own boundary a single
      // render throw inside the panel unwinds the entire dashboard root —
      // the exact failure the 2026-08-29 e2e investigation instrumented
      // (ResumeButton throwing on a malformed detail reply took out the
      // terminal, dock, and page). Keyed on the session id so switching
      // sessions resets a tripped boundary.
      <ErrorBoundary key={sessionId}>
        <SessionDetailPanel
          sessionId={sessionId}
          open
          // The forward-looking hero band. This panel was opened from a RUNNING
          // terminal, which is the one context where "how much context is left
          // and what will the next message cost" outranks the totals.
          liveHero
          // This modal is not route state: it opens over WHATEVER page the
          // operator is on, by terminal token, and four of those pages keep their
          // own (closed) SessionDetailPanel mounted with a `?tab=` cleanup effect.
          // Sharing the URL slot with them made every tab click here snap back to
          // Overview one commit later. Local tab state instead — see the prop doc.
          urlTabState={false}
          zIndex={TERMINAL_OVERLAY_Z}
          onClose={onClose}
          onPinVitals={onOpenVitals}
        />
      </ErrorBoundary>
    );
  }

  return (
    <SlideOver
      open
      onClose={onClose}
      width={560}
      zIndex={TERMINAL_OVERLAY_Z}
      title="⊙ Session"
      subtitle={tool ? `${toolMeta(tool).label} · linking…` : undefined}
    >
      <div className="p-5">
        <UncorrelatedNote
          tool={tool}
          mountMs={mountMs}
          now={now}
          loading={link.loading && !resolved}
          remoteDisabled={linkError?.code === "remote_view_disabled"}
          errored={Boolean(linkError && linkError.code !== "remote_view_disabled")}
          onOpenVitals={onOpenVitals}
        />
      </div>
    </SlideOver>
  );
}

function UncorrelatedNote({
  tool,
  mountMs,
  now,
  loading,
  remoteDisabled,
  errored,
  onOpenVitals,
}: {
  tool: string;
  mountMs: number;
  now: number;
  loading: boolean;
  remoteDisabled: boolean;
  errored: boolean;
  onOpenVitals: () => void;
}) {
  if (remoteDisabled) {
    return (
      <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
        <div className="text-[13px] font-semibold text-fg-1">
          Remote terminal view is disabled
        </div>
        <p className="mt-2 text-[12px] leading-relaxed text-fg-3">
          This dashboard is paired to a remote device, and per-terminal session view is
          turned off for remote viewers. Open this terminal from the owner-local
          dashboard, or enable remote terminal view in Settings.
        </p>
      </div>
    );
  }

  const waited = Math.max(0, Math.floor((now - mountMs) / 1000));
  const toolLabel = tool ? toolMeta(tool).label : "The tool";
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
      <div className="flex items-center gap-2 text-[13px] font-semibold text-fg-1">
        <span className="inline-block size-2 animate-pulse rounded-full bg-info" aria-hidden />
        No session linked to this terminal yet
      </div>
      <p className="mt-2 text-[12px] leading-relaxed text-fg-3">
        {toolLabel} is running here, but Observer has not yet matched it to a captured
        session. Observer keeps checking while the terminal is open. Some tools do not
        expose enough information to identify the session reliably. You can browse
        captured sessions below; this view opens the details when a link is found.
      </p>
      <p className="mt-2 text-[11.5px] text-fg-4">
        Waiting {fmtElapsed(waited)}
        {errored && " · the last link check failed, still retrying"}
        {loading && " · checking…"}
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={onOpenVitals}
          className="rounded-2 border border-line-2 bg-bg-3 px-2.5 py-1.5 text-[11.5px] text-fg-1 hover:bg-bg-4"
        >
          Open the live vitals panel
        </button>
        <Link
          to="/sessions"
          className="text-[11.5px] text-accent hover:underline"
        >
          Browse all sessions
        </Link>
      </div>
      <p className="mt-3 text-[11px] leading-relaxed text-fg-4">
        Some launches never auto-link - a plain shell has no session, and a few run
        shapes cannot be matched. The vitals panel works either way.
      </p>
    </div>
  );
}
