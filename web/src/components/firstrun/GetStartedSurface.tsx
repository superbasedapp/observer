// GetStartedSurface - the ONE getting-started surface at the top of Overview
// (first-run plan revision 2, sections 3.6 and 7.1; decision 14). It replaced
// five stacked cards (the welcome band, Get started, Milestones, the
// components pointer and the AI Apps card) with one container whose body is
// the track the daemon chose:
//
//   - AI coding agents: the existing WelcomeBand (history reveal, Start a
//     coding agent) and the existing GetStarted steps, composed, not
//     rewritten (both take an `embedded` prop);
//   - AI apps: AppsTrack (one consent, the waiting card, the first trace);
//   - Both: the two side by side (stacked on a phone), coding first.
//
// The track is read from GET /api/firstrun "plane" (internal/planechoice,
// lane POLISH-F1). There is no rule table here: row 4 shows the coding track
// with the one-line switch, row 3 a quiet "Add AI Apps" line, and a daemon
// without the plane block shows the coding track as before. Hide is the
// daemon-kept snooze the Get started panel always used; it folds the surface
// to a one-line strip, and Settings > General "Show the getting-started steps
// again" (or the strip's Show) brings it back.

import { useCallback, useState } from "react";
import clsx from "clsx";
import { Button } from "@/components/primitives";
import { GetStarted } from "@/components/GetStarted";
import { WelcomeBand } from "@/components/firstrun/WelcomeBand";
import { AppsTrack } from "@/components/apps/AppsTrack";
import { useApi } from "@/lib/useApi";
import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import { isRemoteView } from "@/lib/remote";
import { CONNECT_STATUS_PATH, type ConnectStatus } from "@/lib/connect";
import { useConnectHandoff } from "@/lib/useConnectHandoff";
import { withArrivalIntent } from "@/lib/connectHandoff";
import type { EnrolmentStatus } from "@/lib/types";
import { PRODUCT_NAMES } from "@shared/lib/productNames";
import {
  FIRST_RUN_PATH,
  FIRST_RUN_SEEN_PATH,
  focusRequestInit,
  type FirstRunResponse,
  type PlaneChoice,
} from "@/lib/firstRun";
import {
  GET_STARTED_SNOOZE_KEY,
  SURFACE_SHOWN_AGAIN_KEY,
  accountOf,
  snoozeRequestInit,
  surfaceFold,
  surfaceLayout,
  type SurfaceLayout,
} from "@/lib/getStarted";

function readShownAgain(): string | null {
  try {
    return globalThis.localStorage?.getItem(SURFACE_SHOWN_AGAIN_KEY) ?? null;
  } catch {
    return null;
  }
}

/** showGettingStartedAgain is Settings' "Show the getting-started steps
 *  again": a Hide older than now no longer folds the surface, and the
 *  welcome band's own "Not now" is forgotten too. */
export function showGettingStartedAgain(): void {
  try {
    globalThis.localStorage?.setItem(SURFACE_SHOWN_AGAIN_KEY, new Date().toISOString());
    globalThis.localStorage?.removeItem("sb_welcome_band_dismissed");
  } catch {
    // Storage unavailable: nothing was folded in this browser either.
  }
}

/** postFocus stores the track choice on the daemon (POST /api/firstrun/seen
 *  {"focus"}), the same write as Settings > General. */
export async function postFocus(choice: PlaneChoice, token?: string): Promise<void> {
  const t = token || (await localConfirmHeaders())["X-Observer-Confirm"] || "";
  await fetchJSON(FIRST_RUN_SEEN_PATH, undefined, focusRequestInit(choice, t));
}

export function GetStartedSurface({ sessions }: { sessions: number | null }) {
  const remote = isRemoteView();
  const brief = useApi<FirstRunResponse>(FIRST_RUN_PATH, { brief: "1" });
  // The installer's ?connecting=1 hand-off decides first (as WelcomeBand and
  // GetStarted already do): its card stands in for everything.
  const status = useApi<ConnectStatus>(remote ? null : CONNECT_STATUS_PATH, undefined, [], { refreshMs: 30000 });
  const enrolment = useApi<EnrolmentStatus>(remote ? null : "/api/enrolment/status", undefined, [], {
    refreshMs: 30000,
  });
  const { handoff, phase: handoffPhase } = useConnectHandoff(accountOf(status.data, enrolment.data, null));
  const handoffActive = handoffPhase === "waiting" || handoffPhase === "expired";

  const [snoozedNow, setSnoozedNow] = useState<string | null>(null);
  const [shownAgain, setShownAgain] = useState<string | null>(readShownAgain);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const reload = brief.reload;
  const onChanged = useCallback(() => reload(), [reload]);

  const choose = useCallback(
    async (c: PlaneChoice) => {
      setBusy(true);
      setErr("");
      try {
        await postFocus(c, brief.data?.confirm_token);
        reload();
      } catch (e: unknown) {
        setErr(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
    },
    [brief.data?.confirm_token, reload],
  );

  const hide = useCallback(async () => {
    setSnoozedNow(new Date().toISOString());
    try {
      const token = brief.data?.confirm_token || (await localConfirmHeaders())["X-Observer-Confirm"] || "";
      await fetchJSON(FIRST_RUN_SEEN_PATH, undefined, snoozeRequestInit(token));
    } catch {
      // Folded for this page view; it may come back on a reload.
    }
  }, [brief.data?.confirm_token]);

  const show = useCallback(() => {
    showGettingStartedAgain();
    setShownAgain(new Date().toISOString());
    setSnoozedNow(null);
  }, []);

  // A remote viewer, and the hand-off, get today's panel unchanged: the
  // switch and the AI Apps consent are owner-local writes.
  if (remote || handoffActive) return <GetStarted sessions={sessions} />;

  const data = brief.data;
  // The installer's `--apps` hand-off opens the AI apps track for this visit
  // (FR-M18); the view only, nothing is recorded or turned on.
  const layout = withArrivalIntent(surfaceLayout(data?.plane), handoff);
  const snoozedAt = snoozedNow ?? data?.snoozed?.[GET_STARTED_SNOOZE_KEY] ?? null;
  if (surfaceFold(snoozedAt, shownAgain) === "folded") {
    return <FoldedStrip layout={layout} onShow={show} />;
  }

  const both = layout.columns.length > 1;
  return (
    <section
      aria-labelledby="sb-surface-title"
      data-testid="get-started-surface"
      data-track={layout.track}
      data-tour="get-started"
      className="space-y-4 rounded-3 border border-accent/30 bg-bg-1 p-4 sm:p-5"
    >
      <SurfaceHeader layout={layout} busy={busy} onChoose={(c) => void choose(c)} onHide={() => void hide()} />
      {err && <p className="text-[11.5px] text-danger">{err}</p>}
      <div className={clsx(both && "grid gap-5 lg:grid-cols-2")}>
        {layout.columns.includes("coding") && (
          <div className="min-w-0 space-y-4" data-testid="surface-coding">
            {both && <ColumnTitle>{PRODUCT_NAMES.first_run_coding}</ColumnTitle>}
            <WelcomeBand embedded />
            <GetStarted sessions={sessions} embedded narrow={both} />
          </div>
        )}
        {layout.columns.includes("apps") && (
          <div
            className={clsx(
              "min-w-0 space-y-3",
              both && "border-t border-line-1 pt-4 lg:border-l lg:border-t-0 lg:pl-5 lg:pt-0",
            )}
            data-testid="surface-apps"
          >
            {both && <ColumnTitle>{PRODUCT_NAMES.first_run_apps}</ColumnTitle>}
            <AppsTrack
              apps={data?.apps}
              loaded={data != null || brief.error != null}
              codingHistory={data?.plane?.coding_history ?? (sessions ?? 0) > 0}
              onChanged={onChanged}
            />
          </div>
        )}
      </div>
      {layout.offerApps && <OfferLine busy={busy} onAdd={() => void choose("both")} />}
      {layout.switchBack && <SwitchBackLine busy={busy} onChoose={(c) => void choose(c)} />}
    </section>
  );
}

function ColumnTitle({ children }: { children: React.ReactNode }) {
  return <p className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">{children}</p>;
}

/** SurfaceHeader: the title, the row-4 switch and Hide. Pure props. */
export function SurfaceHeader({
  layout,
  busy,
  onChoose,
  onHide,
}: {
  layout: SurfaceLayout;
  busy: boolean;
  onChoose: (c: PlaneChoice) => void;
  onHide: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
      <h2 id="sb-surface-title" className="text-[14px] font-semibold text-fg-0">
        Get started
      </h2>
      {/* On a phone the switch takes its own row under the title; from sm
          up it sits on the title line, as plan 3.6 (a) draws it. */}
      {layout.showSwitch && (
        <div className="order-last w-full sm:order-none sm:ml-auto sm:w-auto">
          <SwitchLine layout={layout} busy={busy} onChoose={onChoose} />
        </div>
      )}
      <Button size="sm" variant="ghost" onClick={onHide}>
        Hide
      </Button>
    </div>
  );
}

/** SwitchLine is row 4's one-line switch (decision 2): no question card, no
 *  Continue; ignoring it keeps AI coding agents. Disabled, with the reason,
 *  where AI Apps is not available. */
export function SwitchLine({
  layout,
  busy,
  onChoose,
}: {
  layout: SurfaceLayout;
  busy: boolean;
  onChoose: (c: PlaneChoice) => void;
}) {
  const off = layout.switchDisabled !== "";
  return (
    <span className="flex flex-wrap items-center gap-2 text-[11.5px] text-fg-2" data-testid="surface-switch">
      <span>Here for {PRODUCT_NAMES.planea_area} you build instead?</span>
      <span className="flex items-center gap-1.5">
        <Button
          size="sm"
          variant="secondary"
          disabled={off || busy}
          onClick={() => onChoose("apps")}
          title={off ? layout.switchDisabled : undefined}
        >
          Switch
        </Button>
        <Button
          size="sm"
          variant="ghost"
          disabled={off || busy}
          onClick={() => onChoose("both")}
          title={off ? layout.switchDisabled : undefined}
        >
          {PRODUCT_NAMES.first_run_both}
        </Button>
      </span>
      {off && <span className="w-full text-[10.5px] text-fg-4">{layout.switchDisabled}</span>}
    </span>
  );
}

/** OfferLine is row 3's quiet line: only where AI Apps is available. */
export function OfferLine({ busy, onAdd }: { busy: boolean; onAdd: () => void }) {
  return (
    <p className="border-t border-line-1 pt-3 text-[11.5px] text-fg-3" data-testid="surface-offer">
      Building an AI app too?{" "}
      <button
        type="button"
        onClick={onAdd}
        disabled={busy}
        className="font-medium text-accent hover:underline disabled:opacity-60"
      >
        Add {PRODUCT_NAMES.planea}
      </button>
    </p>
  );
}

/** SwitchBackLine is the AI apps track's way back (U-02): the same stored
 *  choice as the row-4 switch and Settings > General, to AI coding agents
 *  or Both. */
export function SwitchBackLine({ busy, onChoose }: { busy: boolean; onChoose: (c: PlaneChoice) => void }) {
  return (
    <p
      className="flex flex-wrap items-center gap-x-2 gap-y-1.5 border-t border-line-1 pt-3 text-[11.5px] text-fg-3"
      data-testid="surface-switch-back"
    >
      <span>Using {PRODUCT_NAMES.first_run_coding} too?</span>
      <Button size="sm" variant="ghost" disabled={busy} onClick={() => onChoose("coding")}>
        Switch to {PRODUCT_NAMES.first_run_coding}
      </Button>
      <Button size="sm" variant="ghost" disabled={busy} onClick={() => onChoose("both")}>
        {PRODUCT_NAMES.first_run_both}
      </Button>
    </p>
  );
}

/** FoldedStrip: Hide folds the surface to one line until Show. */
export function FoldedStrip({ layout, onShow }: { layout: SurfaceLayout; onShow: () => void }) {
  const what =
    layout.track === "apps"
      ? `turn on ${PRODUCT_NAMES.planea}, send your first trace, look at it`
      : layout.track === "both"
        ? `your coding agents and ${PRODUCT_NAMES.planea}`
        : "sign in, route your tools, use them as usual";
  return (
    <div
      role="note"
      data-testid="get-started-folded"
      data-track={layout.track}
      className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-3 border border-line-2 bg-bg-1 px-4 py-2 text-small text-fg-2"
    >
      <span className="min-w-0 flex-1">Get started: {what}.</span>
      <Button size="sm" variant="ghost" onClick={onShow}>
        Show
      </Button>
    </div>
  );
}
