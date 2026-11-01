import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, Download, History, LoaderCircle, Plug, RefreshCw, Settings2 } from "lucide-react";
import {
  Button,
  Callout,
  ChartShell,
  ErrorState,
  Meter,
  Pill,
  SegmentedControl,
  Skeleton,
  StatCard,
  ToolGlyphFrame,
  ToolStack,
  TruncatedPath,
} from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { toolMeta } from "@/lib/tools";
import { openFirstRun, progressRatio, type FirstRunResponse } from "@/lib/firstRun";
import {
  COVERAGE_FALLBACK_PATH,
  COVERAGE_HREF,
  COVERAGE_PARAMS,
  COVERAGE_PATH,
  COVERAGE_POLL_MS,
  connectedToolsHref,
  countLine,
  coverageChips,
  coverageStatus,
  coverageView,
  defaultFilter,
  filterRows,
  fmtAgo,
  isLocalOnlyRefusal,
  nextStep,
  type CoverageFilter,
  type CoverageRow,
  type CoverageView,
} from "@/lib/coverage";
import type { ToolsStatusResponse } from "@/lib/types";
import { useLaunchDock } from "@/components/LaunchDock";

// ToolCoverage - the always-available capture coverage surfaces (T-935): the
// Tools page Coverage tab (ToolCoverageSection) and the compact Overview card
// (ToolCoverageCard). Both read the first-run model with every supported tool
// listed (GET /api/firstrun?all=1, owner-local) through one shared query, so
// opening the tab after the card paints at once. A remote viewer, whom that
// route refuses, gets the Connected-tools matrix instead (GET
// /api/tools/status) with the facts it lacks shown as unknown. The pure half
// (rows, status, next step, summary) is lib/coverage.ts. Every write stays in
// Settings > Connected tools and the New terminal dialog; this only links.

function nameOf(tool: string): string {
  return toolMeta(tool).label;
}

/** useToolCoverage reads the coverage view, polling while capture moves. */
function useToolCoverage(poll: boolean): { view: CoverageView; reload: () => void; refreshing: boolean } {
  const [moving, setMoving] = useState(false);
  const primary = useApi<FirstRunResponse>(COVERAGE_PATH, COVERAGE_PARAMS, [], {
    refreshMs: poll && moving ? COVERAGE_POLL_MS : 0,
  });
  const refused = isLocalOnlyRefusal(primary);
  const fallback = useApi<ToolsStatusResponse>(refused ? COVERAGE_FALLBACK_PATH : null);
  const view = coverageView(primary, fallback, nameOf);
  const nowMoving = view.kind === "ready" && view.moving;
  useEffect(() => {
    setMoving(nowMoving);
  }, [nowMoving]);
  return {
    view,
    reload: refused ? fallback.reload : primary.reload,
    refreshing: primary.isRefreshing || fallback.isRefreshing,
  };
}

function localDashboardURL(): string {
  const port = typeof window !== "undefined" && window.location.port ? window.location.port : "8081";
  return `http://127.0.0.1:${port}`;
}

// ---------------------------------------------------------------- the tab

export function ToolCoverageSection() {
  const { view, reload, refreshing } = useToolCoverage(true);
  return (
    <ChartShell
      title="Tool coverage"
      icon={Plug}
      sub="Every AI tool SuperBased supports: whether it was found on this machine, how it is captured, and what to do next. Not affected by the date window."
      right={
        <Button variant="secondary" size="sm" iconLeft={RefreshCw} onClick={reload} loading={refreshing}>
          Refresh
        </Button>
      }
    >
      <CoverageBody view={view} onRetry={reload} retrying={refreshing} />
    </ChartShell>
  );
}

function CoverageBody({ view, onRetry, retrying }: { view: CoverageView; onRetry: () => void; retrying: boolean }) {
  switch (view.kind) {
    case "loading":
      return (
        <div className="space-y-3" aria-busy="true" aria-label="Loading tool coverage">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-16" />
            ))}
          </div>
          <Skeleton className="h-14" />
          <Skeleton className="h-14" />
          <Skeleton className="h-14" />
        </div>
      );
    case "error":
      return (
        <ErrorState
          variant="compact"
          title="Couldn't load tool coverage"
          error={view.message}
          onRetry={onRetry}
          retrying={retrying}
        />
      );
    case "local_only":
      return <LocalOnlyNote />;
    case "ready":
      return <CoverageReady view={view} />;
  }
}

function LocalOnlyNote() {
  return (
    <Callout tone="info" title="Available on this machine's dashboard">
      Tool coverage names this machine's session folders, so it is shown only on the dashboard opened on the
      machine itself, at <code className="font-mono text-fg-1">{localDashboardURL()}</code>.
    </Callout>
  );
}

function CoverageReady({ view }: { view: Extract<CoverageView, { kind: "ready" }> }) {
  const { rows, summary } = view;
  const [filter, setFilter] = useState<CoverageFilter | null>(null);
  const active = filter ?? defaultFilter(rows);
  const shown = useMemo(() => filterRows(rows, active), [rows, active]);
  return (
    <div className="space-y-4">
      <p className="text-[13px] font-semibold text-fg-0" aria-live="polite">
        {summary.headline}
      </p>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard label="Detected" value={`${summary.found} of ${summary.supported}`} sub="found on this machine" animate={false} />
        <StatCard label="Capturing" value={String(summary.capturing)} sub="a capture path is live" animate={false} />
        <StatCard
          label="Need attention"
          value={String(summary.attention)}
          warn={summary.attention > 0}
          sub={summary.attention > 0 ? "see the next step on each" : "nothing to fix"}
          animate={false}
        />
        <StatCard label="Not found" value={String(summary.notFound)} sub="supported, not on this machine" animate={false} />
      </div>
      {view.source === "remote" && (
        <Callout tone="info" title="Remote view">
          History capture, session and project counts are shown on this machine's own dashboard, at{" "}
          <code className="font-mono text-fg-1">{localDashboardURL()}</code>. Detection and capture paths below are
          live.
        </Callout>
      )}
      {view.watcherRunning === false && (
        <Callout tone="warn" title="The background watcher is not running here">
          Start SuperBased with <code className="font-mono">observer start</code> to capture past and new sessions.
        </Callout>
      )}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <SegmentedControl<CoverageFilter>
          size="sm"
          value={active}
          onChange={setFilter}
          options={[
            { value: "found", label: `Detected (${summary.found})` },
            { value: "not_found", label: `Not found (${summary.notFound})` },
            { value: "all", label: `All (${rows.length})` },
          ]}
        />
        <span className="flex flex-wrap items-center gap-3 text-[11px]">
          {view.source === "local" && (
            <button
              type="button"
              onClick={openFirstRun}
              className="inline-flex items-center gap-1 text-accent hover:underline focus:outline-none focus-visible:underline"
            >
              <History size={12} aria-hidden /> History capture
            </button>
          )}
          <Link
            to={connectedToolsHref()}
            className="inline-flex items-center gap-1 text-accent hover:underline focus:outline-none focus-visible:underline"
          >
            <Settings2 size={12} aria-hidden /> Connected tools
          </Link>
        </span>
      </div>
      {shown.length === 0 ? (
        <p className="rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-3 py-2 text-[11.5px] text-fg-3">
          {active === "found"
            ? "No supported tool was found on this machine yet."
            : "Every supported tool was found on this machine."}
        </p>
      ) : (
        <ul className="space-y-2" aria-label="Supported AI tools">
          {shown.map((r) => (
            <CoverageItem key={r.tool} r={r} />
          ))}
        </ul>
      )}
    </div>
  );
}

function CoverageItem({ r }: { r: CoverageRow }) {
  const status = coverageStatus(r);
  const step = nextStep(r);
  const moving = status.state === "reading";
  const h = r.history;
  const ratio = h ? progressRatio(h.files_found, h.files_processed, h.files_failed) : null;
  const counts = r.found ? countLine(r) : null;
  const ago = fmtAgo(r.lastSeenAt);
  return (
    <li className="rounded-3 border border-line-2 bg-bg-1 p-3">
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
        <ToolGlyphFrame tool={r.tool} size={20} />
        <span className={`min-w-0 truncate text-[12.5px] font-semibold ${r.found ? "text-fg-0" : "text-fg-2"}`}>
          {r.name}
        </span>
        <Pill variant={status.tone} icon={moving ? LoaderCircle : undefined} spin={moving} case="none">
          {status.label}
        </Pill>
        {(counts || ago) && (
          <span className="ml-auto text-[11px] tabular-nums text-fg-3">
            {counts}
            {counts && ago ? " · " : ""}
            {ago && <span title={r.lastSeenAt}>last activity {ago}</span>}
          </span>
        )}
      </div>
      {moving && h && (
        <div className="mt-2 flex items-center gap-2">
          {ratio == null ? (
            <Skeleton className="h-1.5 flex-1 rounded-pill" />
          ) : (
            <Meter ratio={ratio} label={`Past session files read for ${r.name}`} className="flex-1" />
          )}
          <span className="shrink-0 text-[11px] tabular-nums text-fg-3">
            {h.files_found > 0
              ? `${h.files_processed.toLocaleString("en-US")} of ${h.files_found.toLocaleString("en-US")} files`
              : "Looking for files"}
          </span>
        </div>
      )}
      {r.found && (
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          {coverageChips(r).map((c) => (
            <Pill key={c.key} variant={c.tone} title={c.title} case="none">
              {c.label}
            </Pill>
          ))}
        </div>
      )}
      {r.detectedPath && (
        <div className="mt-1.5 flex min-w-0 items-center gap-1 text-[10.5px] text-fg-4">
          <span className="shrink-0">Found at</span>
          <TruncatedPath value={r.detectedPath} className="min-w-0 font-mono" />
        </div>
      )}
      {step && <NextStepLine tool={r.tool} step={step} />}
    </li>
  );
}

function NextStepLine({ tool, step }: { tool: string; step: NonNullable<ReturnType<typeof nextStep>> }) {
  const navigate = useNavigate();
  const dock = useLaunchDock();
  return (
    <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5 border-t border-line-1 pt-2">
      <span className="min-w-0 flex-1 text-[11.5px] text-fg-3">{step.detail}</span>
      {step.kind === "install" && (
        <Button variant="secondary" size="sm" iconLeft={Download} onClick={() => dock.openNewTerminalFor(tool)}>
          {step.label}
        </Button>
      )}
      {step.kind === "link" && (
        <Button variant="secondary" size="sm" iconRight={ArrowRight} onClick={() => navigate(step.href)}>
          {step.label}
        </Button>
      )}
    </div>
  );
}

// ---------------------------------------------------------- the Overview card

export function ToolCoverageCard() {
  const { view, reload, refreshing } = useToolCoverage(false);
  return (
    <ChartShell
      title="Tool coverage"
      icon={Plug}
      sub="AI tools found on this machine and how many are being captured."
    >
      {view.kind === "loading" && <Skeleton className="h-14" />}
      {view.kind === "error" && (
        <ErrorState variant="compact" title="Couldn't load tool coverage" error={view.message} onRetry={reload} retrying={refreshing} />
      )}
      {view.kind === "local_only" && <LocalOnlyNote />}
      {view.kind === "ready" && <CardReady view={view} />}
    </ChartShell>
  );
}

function CardReady({ view }: { view: Extract<CoverageView, { kind: "ready" }> }) {
  const { summary, rows } = view;
  const found = rows.filter((r) => r.found).map((r) => r.tool);
  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
      <div className="min-w-0">
        <p className="text-[13px] text-fg-1">
          <span className="text-[22px] font-semibold tabular-nums text-fg-0">{summary.found}</span>
          <span className="text-fg-3"> of {summary.supported} supported tools detected</span>
        </p>
        <p className="mt-0.5 text-[12px] text-fg-3">
          <span className="font-semibold text-success">{summary.capturing} capturing</span>
          {summary.attention > 0 && (
            <>
              {" · "}
              <span className="font-semibold text-warn">
                {summary.attention} need{summary.attention === 1 ? "s" : ""} attention
              </span>
            </>
          )}
          {view.watcherRunning === false && " · the background watcher is not running"}
        </p>
      </div>
      {found.length > 0 ? (
        <ToolStack tools={found} max={8} size={22} />
      ) : (
        <span className="text-[12px] text-fg-3">Run a supported AI tool once and it shows up here.</span>
      )}
      <Link
        to={COVERAGE_HREF}
        className="ml-auto inline-flex items-center gap-1 rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-[11.5px] font-medium text-fg-1 hover:border-line-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
      >
        {summary.attention > 0 ? "See what needs attention" : "See coverage"}
        <ArrowRight size={12} aria-hidden />
      </Link>
    </div>
  );
}
