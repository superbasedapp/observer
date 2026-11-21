// AppsTrack - the AI apps column of the one getting-started surface
// (first-run plan revision 2, sections 3.6 c to e and 7.1). Three steps:
// turn on AI Apps (one consent, no restart: POST /api/apps/enable, the one
// enable seam the CLI and the VS Code action also call), send your first
// trace (the coding-agent prompt or the SDK snippet, the prompt generated
// from the daemon's live receiver and dashboard addresses), look at it (the
// first-trace card, then a one-line strip).
//
// The daemon reports every fact (/api/firstrun "apps", GET /api/apps/status,
// lane POLISH-F1); lib/planeaFirstRun.ts's APPS_TRACK_RULES picks the card.
// A daemon without the apps block, or a process without the enable seam,
// keeps the "Your apps" card (AppsFirstRunCard), which turns on through the
// same seam and says a restart is needed only where there is no seam.
// Features a hot enable cannot start (pending_next_start) are named on the
// waiting card (FR-M01).

import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { GatedLink } from "@/components/GatedLink";
import clsx from "clsx";
import { ArrowRight, Check, Telescope } from "lucide-react";
import {
  buttonClasses,
  Callout,
  ConfirmButton,
  CopyOnClick,
  Icon,
  InlineLoading,
  LiveDot,
  ObsLanding,
  SegmentedControl,
} from "@/components/primitives";
import { AppsFirstRunCard, SdkSnippet } from "@/components/apps/AppsFirstRunCard";
import { useApi } from "@/lib/useApi";
import { localConfirmHeaders } from "@/lib/api";
import { refreshAfterAppsChange } from "@/lib/useComponents";
import { useMachineTail } from "@/lib/appExplorerViews";
import { fmtCompact, fmtCostFine, fmtRelative } from "@/lib/format";
import { useNowTick } from "@/lib/useNowTick";
import { PRODUCT_NAMES } from "@shared/lib/productNames";
import { SDK_CATALOG } from "@shared/lib/sdkCatalog";
import { provenanceText } from "@shared/components/planea/costSource";
import type { ConfigResponse } from "@/lib/types";
import type { AppTraceRow, AppTracesResult } from "@/lib/planeaApi";
import {
  APPS_ENABLE_PATH,
  APPS_STATUS_PATH,
  appsRequestInit,
  type AppsEnableReport,
  type FirstRunApps,
} from "@/lib/firstRun";
import {
  APPS_HOME_PATH,
  FIRST_TRACE_OPENED_KEY,
  OBS_BUILDS,
  WAITING_POLL_MS,
  agentPrompt,
  appsSteps,
  appsTrackPhase,
  configuredReceiver,
  consentChanges,
  consentLines,
  enableResult,
  pendingLine,
  receiverAddress,
  sendTabs,
  showWaitingHelp,
  waitingHelp,
  type AppsTrackPhase,
  type SendTab,
} from "@/lib/planeaFirstRun";

type AppsStatusResponse = FirstRunApps & { confirm_token?: string };

function readOpened(): string | null {
  try {
    return globalThis.localStorage?.getItem(FIRST_TRACE_OPENED_KEY) ?? null;
  } catch {
    return null;
  }
}

function writeOpened(id: string): void {
  try {
    globalThis.localStorage?.setItem(FIRST_TRACE_OPENED_KEY, id);
  } catch {
    // Storage unavailable: the first-trace card shows again next visit.
  }
}

/** The live tail's filters while waiting: any trace. */
const NO_FILTERS: Record<string, string> = {};

/** The phases in which the column reads the daemon every few seconds. */
const POLLING: ReadonlySet<AppsTrackPhase> = new Set(["waiting", "bind_failed"]);

export function AppsTrack({
  apps,
  loaded,
  codingHistory,
  onChanged,
}: {
  /** The apps block of the first-run read (undefined from an older daemon). */
  apps: FirstRunApps | null | undefined;
  loaded: boolean;
  /** The plane block's coding_history: decides which send tab leads. */
  codingHistory: boolean;
  /** Re-read the first-run state after a change (the track may move). */
  onChanged: () => void;
}) {
  const [poll, setPoll] = useState(false);
  const status = useApi<AppsStatusResponse>(loaded && apps ? APPS_STATUS_PATH : null, undefined, [], {
    refreshMs: poll ? WAITING_POLL_MS : 0,
  });
  const live: FirstRunApps | null | undefined = status.data ?? apps;
  const [openedTrace, setOpenedTrace] = useState<string | null>(readOpened);
  const phase = appsTrackPhase({ loaded, apps: live, openedTrace });
  useEffect(() => setPoll(POLLING.has(phase)), [phase]);
  // U-07: while waiting, the machine's live trace tail (server-sent events,
  // polling when the stream is refused) tells the card the moment a trace
  // lands, so it re-reads the status at once instead of on the next poll.
  const tail = useMachineTail(NO_FILTERS, phase === "waiting");
  const tailed = tail.rows.length;
  const reloadStatus = status.reload;
  useEffect(() => {
    if (tailed > 0) reloadStatus();
  }, [tailed, reloadStatus]);

  // A trace landed (or the track changed): the surface re-reads its plane.
  const traceId = live?.latest_trace?.trace_id ?? null;
  useEffect(() => {
    if (traceId) onChanged();
  }, [traceId, onChanged]);

  const cfg = useApi<ConfigResponse>(phase === "consent" || phase === "bind_failed" ? "/api/config" : null);
  const receiver = receiverAddress(live, configuredReceiver(cfg.data?.config));

  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<AppsEnableReport | null>(null);
  const turnOn = useCallback(async () => {
    setBusy(true);
    setReport(null);
    try {
      const token = status.data?.confirm_token || (await localConfirmHeaders())["X-Observer-Confirm"] || "";
      const res = await fetch(APPS_ENABLE_PATH, { ...appsRequestInit(token), credentials: "same-origin" });
      const text = await res.text();
      let body: AppsEnableReport | null = null;
      try {
        body = JSON.parse(text) as AppsEnableReport;
      } catch {
        body = null;
      }
      if (res.status === 404) {
        setReport({ outcome: "old_daemon", ok: false, message: "This daemon cannot turn AI Apps on in place: restart the daemon to finish." });
      } else {
        setReport(body ?? { outcome: "error", ok: false, message: text.trim() || `HTTP ${res.status}` });
      }
    } catch (e: unknown) {
      setReport({ outcome: "error", ok: false, message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
      // FR-M10: the component state and the routes probe at once, so the AI
      // Apps links and /api/obs reads work now, not on the next 30 s poll.
      refreshAfterAppsChange();
      status.reload();
      onChanged();
    }
  }, [status, onChanged]);

  const markOpened = useCallback((id: string) => {
    writeOpened(id);
    setOpenedTrace(id);
  }, []);

  if (phase === "legacy") return <AppsFirstRunCard variant="overview" />;

  return (
    <div className="space-y-3" data-testid="apps-track" data-phase={phase}>
      <AppsTrackHeader phase={phase} />
      <AppsTrackBody
        phase={phase}
        apps={live}
        receiver={receiver}
        dashboard={typeof window !== "undefined" ? window.location.origin : ""}
        codingHistory={codingHistory}
        busy={busy}
        report={report}
        onEnable={() => void turnOn()}
        onOpened={markOpened}
      />
    </div>
  );
}

/** The track's title and its three steps (plan 7.1). */
export function AppsTrackHeader({ phase }: { phase: AppsTrackPhase }) {
  const steps = appsSteps(phase);
  return (
    <div>
      <h3 className="flex items-center gap-2 text-[13px] font-semibold text-fg-0">
        <Icon icon={Telescope} size={14} className="shrink-0 text-accent" />
        Get started with {PRODUCT_NAMES.planea}
      </h3>
      <ol className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11.5px]" aria-label="Steps">
        {steps.map((s) => (
          <li key={s.n} className={clsx("flex items-center gap-1.5", s.done ? "text-success" : "text-fg-2")}>
            <span
              aria-hidden
              className={clsx(
                "grid h-4 w-4 place-items-center rounded-pill border text-[10px] font-semibold",
                s.done ? "border-success/40 bg-success-soft" : "border-line-3 bg-bg-3",
              )}
            >
              {s.done ? <Icon icon={Check} size={10} /> : s.n}
            </span>
            {s.title}
            {s.done && <span className="sr-only">(done)</span>}
          </li>
        ))}
      </ol>
    </div>
  );
}

export type AppsTrackBodyProps = {
  phase: AppsTrackPhase;
  apps: FirstRunApps | null | undefined;
  receiver: string;
  dashboard: string;
  codingHistory: boolean;
  busy: boolean;
  report: AppsEnableReport | null;
  onEnable: () => void;
  onOpened: (traceId: string) => void;
};

/** AppsTrackBody renders one phase; pure props, so tests render it. */
export function AppsTrackBody(p: AppsTrackBodyProps) {
  switch (p.phase) {
    case "loading":
      return <InlineLoading label="Checking this machine..." />;
    case "unavailable":
      return <UnavailableCard apps={p.apps} />;
    case "consent":
      return <ConsentCard {...p} />;
    case "bind_failed":
      return (
        <div className="space-y-3">
          <WaitingCard {...p} />
          <ConsentCard {...p} retry />
        </div>
      );
    case "waiting":
      return <WaitingCard {...p} />;
    case "first_trace":
      return <FirstTraceCard apps={p.apps} onOpened={p.onOpened} />;
    case "glance":
      return <GlanceStrip apps={p.apps} />;
    default:
      return null;
  }
}

function UnavailableCard({ apps }: { apps: FirstRunApps | null | undefined }) {
  const notInBuild = apps?.available.reason === "not_in_build";
  return (
    <Callout tone={notInBuild ? "info" : "warn"} title={notInBuild ? "Not in this edition" : "Not available here"}>
      {apps?.available.text || `${PRODUCT_NAMES.planea} cannot be turned on on this machine.`}{" "}
      {notInBuild ? (
        <>Editions that include it: {OBS_BUILDS.join(", ")}.</>
      ) : (
        <Link to="/settings/components?component=obs" className="text-accent hover:underline">
          Settings &gt; Components
        </Link>
      )}
    </Callout>
  );
}

/** ConsentCard is plan 3.6 (c): one click, the confirm step, the one
 *  consent sentence the daemon builds, and "What changes" behind a fold. */
export function ConsentCard({
  apps,
  receiver,
  busy,
  report,
  onEnable,
  retry = false,
}: AppsTrackBodyProps & { retry?: boolean }) {
  const lines = consentLines(apps, receiver);
  const result = enableResult(report);
  return (
    <div className="space-y-2 rounded-2 border border-line-2 bg-bg-2 p-3 text-[12px]" data-testid="apps-consent">
      {!retry && (
        <>
          <p className="font-semibold text-fg-0">See your own AI apps here</p>
          <p className="text-fg-2">Traces, sessions, cost and evals of the LLM apps you build.</p>
        </>
      )}
      <div className="flex flex-wrap items-center gap-3">
        <ConfirmButton
          variant="primary"
          armedVariant="primary"
          size="sm"
          onConfirm={onEnable}
          disabled={busy}
          loading={busy}
          confirmLabel="Turn on?"
          armedNote={lines.slice(0, 2).join(" ")}
        >
          {retry ? "Try again" : `Turn on ${PRODUCT_NAMES.planea}`}
        </ConfirmButton>
      </div>
      {!retry && (
        <ul className="space-y-0.5 text-fg-3">
          {lines.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      )}
      {!retry && (
        <details className="text-[11.5px] text-fg-3">
          <summary className="cursor-pointer text-fg-2 hover:text-fg-1">What changes</summary>
          <ul className="mt-1 list-disc space-y-0.5 pl-5">
            {consentChanges(apps).map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </details>
      )}
      {result && (
        <p role="status" className={result.tone === "success" ? "text-success" : "text-danger"}>
          {result.text}
        </p>
      )}
    </div>
  );
}

/** WaitingCard is plan 3.6 (d): the two ways to send a trace, the live
 *  "waiting" line, and the help after two minutes (at once on a refusal). */
export function WaitingCard({ apps, receiver, dashboard, codingHistory, phase }: AppsTrackBodyProps) {
  const tabs = sendTabs(codingHistory);
  const [tab, setTab] = useState<SendTab>(tabs[0]);
  const [openedAt] = useState(() => Date.now());
  const now = useNowTick(10_000);
  const prompt = useMemo(() => agentPrompt({ receiver, dashboard, sdks: SDK_CATALOG }), [receiver, dashboard]);
  const helpShown = showWaitingHelp(openedAt, now, apps);
  const failed = phase === "bind_failed";
  const waits = pendingLine(apps?.pending_next_start);
  return (
    <div className="space-y-3 rounded-2 border border-line-2 bg-bg-2 p-3 text-[12px]" data-testid="apps-waiting">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="font-semibold text-fg-0">Send your first trace</p>
        {failed ? (
          <span className="flex items-center gap-1.5 text-[11px] text-danger">
            <LiveDot tone="danger" still size="sm" /> receiver not listening
          </span>
        ) : (
          <span className="flex items-center gap-1.5 text-[11px] text-fg-3">
            <LiveDot tone="accent" size="sm" /> waiting for a trace
          </span>
        )}
      </div>
      <SegmentedControl
        options={tabs.map((t) => ({ value: t, label: t === "agent" ? "Let your coding agent do it" : "Do it yourself" }))}
        value={tab}
        onChange={setTab}
      />
      {tab === "agent" ? (
        <div className="space-y-1.5" data-testid="apps-agent-prompt">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-fg-2">Paste this into Claude Code, Codex or Cursor in your app&apos;s folder:</p>
            <CopyOnClick value={prompt} ariaLabel="Copy the prompt" className="text-[11px] text-accent">
              Copy the prompt
            </CopyOnClick>
          </div>
          <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-2 border border-line-2 bg-bg-3 p-3 text-[11px] leading-relaxed text-fg-1">
            {prompt}
          </pre>
        </div>
      ) : (
        <SdkSnippet receiver={receiver} />
      )}
      <p className="text-[11px] text-fg-3">This page updates by itself when the first trace arrives.</p>
      {waits && (
        <p className="text-[11px] text-fg-2" data-testid="apps-pending-next-start">
          {waits}
        </p>
      )}
      {helpShown && (
        <div className="space-y-1" data-testid="apps-waiting-help">
          <p className="text-[11.5px] font-medium text-fg-1">Not seeing it after 2 minutes?</p>
          <ul className="list-disc space-y-0.5 pl-5 text-[11px]">
            {waitingHelp(apps, receiver).map((l) => (
              <li key={l.text} className={l.tone === "danger" ? "text-danger" : "text-fg-3"}>
                {l.text}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/** FirstTraceCard is plan 3.6 (e): real numbers from the trace, shown once. */
export function FirstTraceCard({ apps, onOpened }: { apps: FirstRunApps | null | undefined; onOpened: (id: string) => void }) {
  const list = useApi<AppTracesResult>("/api/obs/traces", { limit: 1 });
  const row = list.data?.traces?.[0] ?? null;
  const prov = row ? list.data?.cost_provenance?.[row.trace_id] : undefined;
  // The provenance in words ("computed", "no model calls"), never the raw label.
  const provenance = prov ? provenanceText(prov).toLowerCase() : undefined;
  return <FirstTraceView row={row} latest={apps?.latest_trace ?? null} provenance={provenance} onOpened={onOpened} />;
}

export function FirstTraceView({
  row,
  latest,
  provenance,
  onOpened,
}: {
  row: AppTraceRow | null;
  latest: FirstRunApps["latest_trace"];
  provenance?: string;
  onOpened: (id: string) => void;
}) {
  const id = row?.trace_id ?? latest?.trace_id ?? "";
  const facts = row
    ? [
        row.root_name,
        row.service || latest?.service,
        `${row.span_count} span${row.span_count === 1 ? "" : "s"}`,
        row.model,
        `${fmtCompact(row.total_tokens)} tokens`,
        // fmtCostFine: a real sub-cent cost reads "<$0.0001" or "$0.0127",
        // never "$0.0000" (U-08).
        row.cost_usd == null
          ? provenance === "no model calls"
            ? "no model calls"
            : "cost not priced"
          : `${fmtCostFine(row.cost_usd, row.total_tokens)}${provenance ? ` (${provenance})` : ""}`,
      ]
    : [latest?.name, latest?.service];
  return (
    <div className="space-y-2 rounded-2 border border-success/30 bg-success-soft p-3 text-[12px]" data-testid="apps-first-trace">
      <div className="flex items-center gap-2">
        <ObsLanding size={36} playKey={id} />
        <p className="font-semibold text-fg-0">Your first trace</p>
      </div>
      <p className="text-fg-2">{facts.filter(Boolean).join(" · ")}</p>
      <div className="flex flex-wrap items-center gap-3">
        <Link
          to={`${APPS_HOME_PATH}?trace=${encodeURIComponent(id)}`}
          onClick={() => onOpened(id)}
          className={buttonClasses({ variant: "primary", size: "md" })}
        >
          Open the trace
          <Icon icon={ArrowRight} size="sm" />
        </Link>
        <GatedLink to="/apps/scores" className="text-accent hover:underline">
          Next: score it
        </GatedLink>
        <GatedLink to="/settings?section=observability" className="text-accent hover:underline">
          Set a budget
        </GatedLink>
      </div>
    </div>
  );
}

/** GlanceStrip: once the first trace was opened, the column is one line. */
export function GlanceStrip({ apps }: { apps: FirstRunApps | null | undefined }) {
  const today = useApi<AppTracesResult>("/api/obs/traces", { days: 1, limit: 1 });
  const errors = useApi<AppTracesResult>("/api/obs/traces", { days: 1, limit: 1, status: "error" });
  return <GlanceView latest={apps?.latest_trace ?? null} today={today.data?.total ?? null} errors={errors.data?.total ?? null} />;
}

export function GlanceView({
  latest,
  today,
  errors,
}: {
  latest: FirstRunApps["latest_trace"];
  today: number | null;
  errors: number | null;
}) {
  return (
    <div
      role="note"
      data-testid="apps-glance"
      className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-[11.5px] text-fg-2"
    >
      <span className="font-medium text-fg-1">{PRODUCT_NAMES.planea_area} at a glance</span>
      {today != null && <span>{fmtCompact(today)} trace{today === 1 ? "" : "s"} today</span>}
      {errors != null && errors > 0 && <span className="text-danger">{fmtCompact(errors)} with errors</span>}
      {latest && (
        <span className="text-fg-3">
          Latest: {latest.name || latest.trace_id}
          {latest.started_at ? `, ${fmtRelative(latest.started_at)}` : ""}
        </span>
      )}
      <Link to={APPS_HOME_PATH} className="ml-auto text-accent hover:underline">
        See the traces
      </Link>
    </div>
  );
}
