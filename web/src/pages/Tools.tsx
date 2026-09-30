import { hasNonZero } from "@shared/lib/seriesEmpty";
import { useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/DataTable";
import {
  ActionsAreaChart,
} from "@/components/charts";
import {
  ChartShell,
  PageHeader,
  Pill,
  SegmentedControl,
  StatCard,
  ToolBadge,
  ToolDot,
  Tooltip,
  Stagger,
} from "@/components/primitives";
import { HelpInd, TitleWithHelp } from "@/components/HelpInd";
import { ChartState } from "@/components/ChartState";
import { useFilters, useGranularity, windowParams } from "@/lib/filters";
import { GranControl } from "@/components/GranControl";
import { asGranularity, perBucketTitle } from "@shared/lib/granularity";
import { useApi } from "@/lib/useApi";
import {
  ACTION_CATEGORIES,
  categoryMeta,
  coverageCaption,
  expressibleCategories,
} from "@/lib/actions";
import { toolMeta, isBrowserTool } from "@/lib/tools";
import { fmtDateTime, fmtInt, fmtPct, localeDateString } from "@/lib/format";
import type {
  ActionsTimeseries,
  ToolsBreakdownResponse,
  ToolsResponse,
} from "@/lib/types";
import { navIcon } from "@/lib/nav";
import { MetricIcon } from "@/components/MetricIcon";

export function ToolsPage() {
  const { win, customRange, tool, project } = useFilters();
  const winParams = windowParams(win, customRange);
  // Chart bucket: the shared granularity rule + the viewer's `gran=`.
  const gran = useGranularity();
  const projectParam = project === "all" ? undefined : project;
  const toolParam = tool === "all" ? undefined : tool;

  // The KPI row's query carries its filters in the PATH, not in useApi's
  // `params`. That is deliberate and load-bearing.
  //
  // useApi resets its "have data for this resource" flag on a PATH change
  // only (lib/useApi.ts) — a params/deps change refetches WITHOUT ever
  // raising `loading`, on purpose, so charts don't flicker on top of valid
  // content. For a chart that trade-off is right. For a KPI tile it is not:
  // it means changing the window or project leaves the OLD window's numbers
  // on screen, relabelled with the NEW window's subtitle and with no
  // indication that anything is in flight — the tile states a number for a
  // question it has not answered yet.
  //
  // Encoding the filters in the path makes each distinct question a distinct
  // resource, which is exactly what it is, so useApi's own documented
  // path-change semantics give the tiles an honest per-question `loading`.
  // fetchJSON returns the path verbatim when `params` is undefined
  // (lib/api.ts buildUrl), so the URL is unchanged from the params form.
  //
  // The charts below deliberately KEEP the params form and their no-flicker
  // behaviour; only the tiles need this.
  const toolsPath = useMemo(() => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries({ ...winParams, project: projectParam })) {
      if (v === undefined || v === "") continue;
      qs.set(k, String(v));
    }
    const s = qs.toString();
    return s ? `/api/tools?${s}` : "/api/tools";
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [win, customRange, project]);
  const tools = useApi<ToolsResponse>(toolsPath);
  const breakdown = useApi<ToolsBreakdownResponse>(
    "/api/tools/breakdown",
    { ...winParams, tool: toolParam, project: projectParam },
    [win, customRange, tool, project],
  );
  const ts = useApi<ActionsTimeseries>(
    "/api/timeseries/actions",
    { ...winParams, ...gran.params, tool: toolParam, project: projectParam },
    [win, customRange, tool, project, gran.params],
  );
  const tsGran = asGranularity(ts.data?.bucket ?? gran.expected);

  // A summary exists only when the CURRENT request has resolved successfully.
  //
  // `tools.loading` is honest per-question thanks to the path encoding above,
  // so it covers both the first load and every filter change. `tools.error`
  // is the other half: useApi retains the last good payload across a failed
  // refetch, so without this check a broken endpoint would leave four
  // confident KPIs on screen indefinitely with nothing saying they are no
  // longer being confirmed.
  const summary = useMemo(
    () => (tools.loading || tools.error ? null : summarize(tools.data)),
    [tools.loading, tools.error, tools.data],
  );
  const actionsSpark = useMemo<number[]>(() => {
    const series = ts.data?.series ?? [];
    return series.map((p: Record<string, unknown>) =>
      Object.entries(p)
        .filter(([k]) => k !== "bucket")
        .reduce(
          (a, [, v]) => a + (typeof v === "number" ? v : 0),
          0,
        ),
    );
  }, [ts.data]);

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("tools")}
        title="Tools"
        sub="Per-tool aggregates with charts showing when each AI client was active and what kind of work it did - four KPIs, activity-over-time stack, action-type mix per tool, and the per-tool aggregates table."
        helpId="tab.tools"
      />
      {/* 4-KPI header.

          Every tile below reads `summary`, which is null until the CURRENT
          /api/tools request resolves successfully (see above). While it is
          null the tiles render the neutral em-dash and carry NO subtitle: a
          KPI must not state a number — least of all a reassuring one like
          "100.0% · no failures" — that came from an unresolved or failed
          query rather than from the data. `loading` drives the pulse that
          says the value is still coming; the success tile additionally names
          the failure when there is one, since a blank there would read as
          "nothing to report". */}
      <Stagger className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard
          label="Total actions"
          icon={<MetricIcon metric="actions" />}
          loading={tools.loading}
          value={fmtInt(summary?.totalActions)}
          sub={summary ? `${fmtInt(summary.totalSessions)} sessions` : undefined}
          spark={actionsSpark}
          sparkColor="var(--accent)"
        />
        <StatCard
          label="Distinct tools"
          icon={<MetricIcon metric="distinctTools" />}
          loading={tools.loading}
          value={fmtInt(summary?.distinctTools)}
          sub={summary ? `${win} window` : undefined}
        />
        <StatCard
          label="Overall success"
          icon={<MetricIcon metric="successRate" />}
          loading={tools.loading}
          value={fmtPct(summary?.overallSuccess)}
          // No summary ⇒ no verdict: an unresolved query must not paint the
          // tile amber any more than it may paint it a confident 100%.
          warn={summary != null && summary.overallSuccess < 0.95}
          sub={
            summary
              ? summary.totalFailures > 0
                ? `${fmtInt(summary.totalFailures)} failures`
                : "no failures"
              : tools.error
                ? "success rate unavailable"
                : undefined
          }
        />
        <StatCard
          label="Busiest tool"
          icon={<MetricIcon metric="busiestTool" />}
          loading={tools.loading}
          value={
            summary?.busiestTool ? (
              <span className="flex items-center gap-2">
                <ToolDot tool={summary.busiestTool} size={10} />
                <span className="text-[18px] font-semibold">
                  {toolMeta(summary.busiestTool).label}
                </span>
              </span>
            ) : (
              "-"
            )
          }
          sub={
            summary?.busiestTool
              ? `${fmtInt(summary.busiestCount)} actions`
              : undefined
          }
        />
      </Stagger>

      {/* Activity + Mix side-by-side */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ChartShell
          title={<TitleWithHelp text="Activity over time" helpId="chart.tools_activity" />}
          sub={`${perBucketTitle("Actions", tsGran)}, stacked by tool · ${win}`}
          right={<GranControl served={ts.data} />}
        >
          <ChartState
            loading={ts.loading && !ts.data}
            error={ts.error}
            denied={ts.denied}
            deniedPermission={ts.deniedPermission}
            empty={!hasNonZero(ts.data?.series, ["total"])}
            emptyHint="No actions in window."
            height={300}
          >
            {ts.data && <ActionsAreaChart data={ts.data.series} granularity={tsGran} />}
          </ChartState>
        </ChartShell>

        <ChartShell
          title={<TitleWithHelp text="Action-type mix per tool" helpId="chart.tools_breakdown" />}
          sub="What each tool actually does - 100% horizontal stack per tool over the canonical action categories, plus a capture-depth row so shallow adapters aren't misread."
        >
          <ChartState
            loading={breakdown.loading && !breakdown.data}
            error={breakdown.error}
            denied={breakdown.denied}
            deniedPermission={breakdown.deniedPermission}
            empty={!breakdown.data?.tools.length}
            emptyHint="No actions to break down."
            height={300}
          >
            {breakdown.data && <ActionMixPanel data={breakdown.data} />}
          </ChartState>
        </ChartShell>
      </div>

      {/* Per-tool aggregates */}
      <ChartShell
        title="Per-tool aggregates"
        sub="Action volume, success rate, distinct sessions, first/last seen - sorted by volume DESC."
      >
        <ChartState
          loading={tools.loading && !tools.data}
          error={tools.error}
          denied={tools.denied}
          deniedPermission={tools.deniedPermission}
          empty={!tools.data?.tools.length}
          emptyHint="No tools active in window."
          height={160}
        >
          {tools.data && <PerToolTable rows={tools.data.tools} />}
        </ChartState>
      </ChartShell>

      {/* Browser chatbots grouping — the opt-in *-web browser-extension rail.
          Rendered only when at least one *-web tool is active. Tokens/cost
          for these rows are ALWAYS estimates (§9), so the section carries a
          mandatory "est." banner + per-row badge. */}
      <BrowserChatbotsCard rows={tools.data?.tools ?? []} loading={tools.loading} />
    </div>
  );
}

// --------------------------------------------------------------- helpers

// summarize folds the /api/tools rows into the four KPI numbers, or returns
// null when the query has not resolved.
//
// The null return is load-bearing, not a style choice. This used to
// substitute a zero-value object for an absent response, which made the KPI
// row render `0 actions / 0 tools / 100.0% "no failures" / —` for the entire
// (multi-second, on a large corpus) life of the in-flight request — four
// confident factual claims about a database nobody had read yet, the
// "100.0% no failures" one being both the loudest and the most wrong. An
// absent summary has no numbers in it, so the tiles cannot state any.
function summarize(data?: ToolsResponse | null): {
  totalActions: number;
  distinctTools: number;
  totalSessions: number;
  totalFailures: number;
  overallSuccess: number;
  busiestTool: string;
  busiestCount: number;
} | null {
  if (!data) return null;
  const totalActions = data.tools.reduce((a, t) => a + t.action_count, 0);
  const totalFailures = data.tools.reduce((a, t) => a + t.failure_count, 0);
  const totalSessions = data.tools.reduce((a, t) => a + t.session_count, 0);
  const busiest = data.tools.reduce(
    (acc, t) => (t.action_count > acc.count ? { tool: t.tool, count: t.action_count } : acc),
    { tool: "", count: 0 },
  );
  return {
    totalActions,
    distinctTools: data.tools.length,
    totalSessions,
    totalFailures,
    overallSuccess: totalActions > 0 ? 1 - totalFailures / totalActions : 1,
    busiestTool: busiest.tool,
    busiestCount: busiest.count,
  };
}

// --------------------------------------------------------------- ActionMix

function ActionMixPanel({ data }: { data: ToolsBreakdownResponse }) {
  // Each row gets its own 100% stacked bar with one segment per CANONICAL
  // CATEGORY (taxonomy plan §4's like-to-like surface), not per raw
  // action_type. The categories come from the API in tooltax's display
  // order and every bar uses that same order, so two adapters' bars are
  // comparable left-to-right — which was never true of the old per-type
  // bars, where each tool sorted its own segments by size and no two
  // tools' segments lined up.
  //
  // The legend below the panel is a SINGLE shared legend — mirrors
  // the legacy Chart.js single-instance behavior. Collected across
  // every tool row, ordered by total share.
  //
  // `display` toggles the right-aligned per-tool caption + legend
  // between % share (default) and raw count, mirroring design's
  // mix-mode toggle (`design/page-tools.jsx:84-85`).
  const [display, setDisplay] = useState<"share" | "count">("share");
  const rows = data.tools;
  // The API sends the canonical order; ACTION_CATEGORIES (the generated
  // mirror of the same tooltax call) is the fallback for an older daemon.
  const categories = data.categories?.length ? data.categories : ACTION_CATEGORIES;
  const sharedLegend = useMemo(() => {
    const tot: Record<string, number> = {};
    let grandTotal = 0;
    for (const t of rows) {
      for (const [category, n] of Object.entries(t.by_category ?? {})) {
        tot[category] = (tot[category] ?? 0) + n;
        grandTotal += n;
      }
    }
    return Object.entries(tot)
      .sort((a, b) => b[1] - a[1])
      .map(([category, n]) => ({
        category,
        n,
        share: grandTotal > 0 ? n / grandTotal : 0,
      }));
  }, [rows]);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-end">
        <SegmentedControl<"share" | "count">
          options={[
            { value: "share", label: "%" },
            { value: "count", label: "count" },
          ]}
          value={display}
          onChange={setDisplay}
          size="sm"
        />
      </div>
      <ul className="space-y-2">
        {rows.map((t) => {
          const byCategory = t.by_category ?? {};
          const present = categories
            .map((c) => [c, byCategory[c] ?? 0] as const)
            .filter(([, n]) => n > 0);
          const top = [...present].sort((a, b) => b[1] - a[1])[0];
          return (
            <li
              key={t.tool}
              className="rounded-2 border border-line-2 bg-bg-3 px-3 py-2"
            >
              <div className="mb-1.5 flex items-baseline justify-between gap-2">
                <span className="flex items-center gap-2">
                  <ToolBadge tool={t.tool} />
                  <span className="text-[11px] text-fg-3">
                    {fmtInt(t.total)} actions · {present.length} categories ·{" "}
                    {Object.keys(t.by_type).length} types
                  </span>
                </span>
                <span className="text-[10px] text-fg-3">
                  top:{" "}
                  <span className="text-fg-2">
                    {top ? categoryMeta(top[0]).label : "-"}
                  </span>{" "}
                  ({display === "share"
                    ? fmtPct((top?.[1] ?? 0) / Math.max(1, t.total))
                    : fmtInt(top?.[1] ?? 0)})
                </span>
              </div>
              <div className="flex h-3 w-full overflow-hidden rounded-pill bg-bg-3">
                {present.map(([category, n]) => {
                  const pct = (n / Math.max(1, t.total)) * 100;
                  if (pct < 0.5) return null;
                  const meta = categoryMeta(category);
                  return (
                    <Tooltip
                      key={category}
                      content={`${meta.label}: ${fmtInt(n)} (${fmtPct(n / Math.max(1, t.total))})`}
                    >
                      <span
                        style={{
                          width: `${pct}%`,
                          background: meta.colorVar,
                          opacity: 0.75,
                        }}
                      />
                    </Tooltip>
                  );
                })}
              </div>
              <CoverageDepthRow row={t} categories={categories} />
            </li>
          );
        })}
      </ul>
      {sharedLegend.length > 0 && (
        <div className="border-t border-line-1 pt-2">
          <ul className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10.5px] text-fg-2">
            {sharedLegend.map(({ category, n, share }) => {
              const meta = categoryMeta(category);
              return (
                <Tooltip
                  key={category}
                  content={`${fmtInt(n)} (${fmtPct(share)})`}
                >
                  <li
                    tabIndex={0}
                    className="flex cursor-help items-center gap-1.5 focus:outline-none"
                  >
                    <span
                      aria-hidden
                      className="h-2 w-2 rounded-pill"
                      style={{ background: meta.colorVar }}
                    />
                    <span>{meta.label}</span>
                    <span className="font-mono tabular-nums text-fg-3">
                      {display === "share" ? fmtPct(share) : fmtInt(n)}
                    </span>
                  </li>
                </Tooltip>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}

// --------------------------------------------------- CoverageDepthRow

// CoverageDepthRow is the taxonomy plan §4 "coverage-depth honesty" row.
//
// Capture depth varies wildly across adapters (claude-code declares a
// vocabulary spanning 8 canonical categories; a dozen adapters declare
// 2-3), so a thin action-mix bar can mean either "this agent only edits
// files" or "this adapter's logs only ever tell us about file edits".
// Without this row the mix panel compares PARSERS and looks like it is
// comparing agents.
//
// Three dot states, in one fixed canonical order per tool so the rows
// line up vertically:
//   solid  — observed in this window (count in the tooltip)
//   ring   — the adapter's declared vocabulary covers it, none seen here
//   faint  — outside the adapter's declared vocabulary: this capture
//            cannot express it at all, so an empty slot is not a verdict
//            on the agent
//
// A tool tooltax has no rows for at all gets the honest-zero caption
// ("capture depth not mapped") instead of a fabricated denominator.
function CoverageDepthRow({
  row,
  categories,
}: {
  row: ToolsBreakdownResponse["tools"][number];
  categories: string[];
}) {
  const byCategory = row.by_category ?? {};
  const declared = expressibleCategories(row.tool);
  const declaredSet = new Set<string>(declared ?? []);
  const observedCount =
    row.coverage?.observed_categories ??
    Object.values(byCategory).filter((n) => n > 0).length;
  const mapped = row.coverage?.vocabulary_declared ?? declared !== null;
  // The caption is built by a pure function in lib/actions so the
  // formatting rule has one owner and can be executed in isolation. The
  // rule that matters: observed categories and the declared vocabulary
  // span are two SEPARATE statements, never a ratio — observed can
  // legitimately exceed the span (the shared mcp__ rule and harness
  // failure/meta events are not part of any adapter's declared
  // vocabulary), which used to render as "9 of 8 capturable categories".
  const caption = coverageCaption({
    observed_categories: observedCount,
    expressible_categories: row.coverage?.expressible_categories ?? declaredSet.size,
    observed_beyond_declared: row.coverage?.observed_beyond_declared,
    canonical_categories: row.coverage?.canonical_categories || categories.length,
    vocabulary_declared: mapped,
  });

  return (
    <div className="mt-1.5 flex items-center gap-2">
      <span className="flex items-center gap-1">
        {categories.map((c) => {
          const n = byCategory[c] ?? 0;
          const meta = categoryMeta(c);
          const state =
            n > 0 ? "observed" : declaredSet.has(c) ? "expressible" : "absent";
          const title =
            state === "observed"
              ? `${meta.label}: ${fmtInt(n)} in window`
              : state === "expressible"
                ? `${meta.label}: this adapter can report it - none in window`
                : mapped
                  ? `${meta.label}: outside this adapter's captured vocabulary`
                  : `${meta.label}: capture depth not mapped for this adapter`;
          return (
            <Tooltip key={c} content={title}>
              <span
                tabIndex={0}
                aria-label={title}
                className="h-2 w-2 rounded-pill focus:outline-none"
                style={
                  state === "observed"
                    ? { background: meta.colorVar }
                    : state === "expressible"
                      ? {
                          border: `1px solid ${meta.colorVar}`,
                          opacity: 0.7,
                        }
                      : {
                          background: "var(--line-2)",
                          opacity: 0.45,
                        }
                }
              />
            </Tooltip>
          );
        })}
      </span>
      <Tooltip content={caption.title}>
        <span
          tabIndex={0}
          className="cursor-help text-[10px] text-fg-3 focus:outline-none"
        >
          {caption.seen}
          <span className="text-fg-4"> · {caption.span}</span>
          {caption.note && (
            <span className="text-fg-4"> · {caption.note}</span>
          )}
        </span>
      </Tooltip>
    </div>
  );
}

// --------------------------------------------------------------- PerToolTable

type ToolRow = ToolsResponse["tools"][number];

// timeValue turns an ISO timestamp into a sortable epoch-ms value.
function timeValue(iso: string): number {
  const t = new Date(iso).getTime();
  return Number.isFinite(t) ? t : -Infinity;
}

// ActionsBarCell is the per-tool actions count with its share bar, shared by
// the per-tool table and the browser-chatbots card.
function ActionsBarCell({ row, maxActions }: { row: ToolRow; maxActions: number }) {
  const pct = (row.action_count / maxActions) * 100;
  const meta = toolMeta(row.tool);
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-[120px] overflow-hidden rounded-pill bg-bg-3">
        <span
          style={{
            display: "block",
            height: "100%",
            width: `${pct}%`,
            background: meta.colorVar,
            opacity: 0.75,
          }}
        />
      </div>
      <span className="tabular-nums text-fg-1">{fmtInt(row.action_count)}</span>
    </div>
  );
}

// DateCell is a compact date with the full timestamp in a tooltip.
function DateCell({ iso }: { iso: string }) {
  return (
    <Tooltip content={fmtDateTime(iso)}>
      <span tabIndex={0} className="cursor-help text-fg-3 focus:outline-none">
        {fmtCompactDate(iso)}
      </span>
    </Tooltip>
  );
}

// perToolColumns: every column sorts by its raw value; the server order
// (busiest first) is kept until a header is clicked.
function perToolColumns(maxActions: number): ColumnDef<ToolRow, unknown>[] {
  return [
    {
      id: "tool",
      header: () => <>Tool<HelpInd id="column.tools.tool" /></>,
      accessorKey: "tool",
      cell: ({ row }) => <ToolBadge tool={row.original.tool} />,
    },
    {
      id: "actions",
      header: () => <>Actions<HelpInd id="column.tools.actions" /></>,
      accessorFn: (t) => t.action_count,
      cell: ({ row }) => <ActionsBarCell row={row.original} maxActions={maxActions} />,
    },
    {
      id: "failures",
      header: () => <>Failures<HelpInd id="column.tools.failures" /></>,
      accessorFn: (t) => t.failure_count,
      meta: { align: "right" },
      cell: ({ row }) =>
        row.original.failure_count > 0 ? (
          <span className="text-danger">{fmtInt(row.original.failure_count)}</span>
        ) : (
          <span className="text-fg-4">-</span>
        ),
    },
    {
      id: "success_rate",
      header: () => <>Success rate<HelpInd id="column.tools.success_rate" /></>,
      accessorFn: (t) => t.success_rate,
      cell: ({ row }) => {
        const t = row.original;
        const succPct = Math.max(0, Math.min(1, t.success_rate)) * 100;
        const succColor =
          t.success_rate >= 0.95
            ? "var(--success)"
            : t.success_rate >= 0.8
              ? "var(--warn)"
              : "var(--danger)";
        return (
          <div className="flex items-center gap-2">
            <div className="h-1.5 w-[100px] overflow-hidden rounded-pill bg-bg-3">
              <span
                style={{
                  display: "block",
                  height: "100%",
                  width: `${succPct}%`,
                  background: succColor,
                }}
              />
            </div>
            <span
              className={`tabular-nums ${
                t.success_rate < 0.9 ? "text-warn" : "text-fg-1"
              }`}
            >
              {fmtPct(t.success_rate)}
            </span>
          </div>
        );
      },
    },
    {
      id: "sessions",
      header: () => <>Sessions<HelpInd id="column.tools.sessions" /></>,
      accessorFn: (t) => t.session_count,
      meta: { align: "right" },
      cell: ({ row }) => <span className="text-fg-2">{fmtInt(row.original.session_count)}</span>,
    },
    {
      id: "first_seen",
      header: () => <>First seen<HelpInd id="column.tools.first_seen" /></>,
      accessorFn: (t) => timeValue(t.first_seen),
      cell: ({ row }) => <DateCell iso={row.original.first_seen} />,
    },
    {
      id: "last_seen",
      header: () => <>Last seen<HelpInd id="column.tools.last_seen" /></>,
      accessorFn: (t) => timeValue(t.last_seen),
      cell: ({ row }) => <DateCell iso={row.original.last_seen} />,
    },
  ];
}

function PerToolTable({ rows }: { rows: ToolsResponse["tools"] }) {
  const maxActions = Math.max(1, ...rows.map((r) => r.action_count));
  const columns = useMemo(() => perToolColumns(maxActions), [maxActions]);
  return (
    <DataTable<ToolRow>
      data={rows}
      columns={columns}
      rowKey={(t) => t.tool}
      minWidth={760}
    />
  );
}

function fmtCompactDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return localeDateString(d, "en-US", {
    month: "short",
    day: "numeric",
    year: "2-digit",
  });
}

// ------------------------------------------------------- BrowserChatbotsCard

// EstPill is the mandatory "est." label for browser-rail token/cost figures
// (§9): all five *-web surfaces estimate tokens client-side; none returns an
// authoritative count. Rendered wherever a browser token/cost figure appears.
function EstPill() {
  return (
    <Pill
      className="ml-1 align-middle"
      title="Browser-chatbot tokens & cost are ESTIMATES - no target UI returns authoritative counts."
    >
      est.
    </Pill>
  );
}

// BrowserChatbotsCard is an ADDITIVE grouping for the browser-extension rail.
// It filters the per-tool rows to the *-web tools (isBrowserTool) and renders
// a per-site breakdown. It surfaces nothing when no browser rail is active,
// so a coding-only install never sees it.
function BrowserChatbotsCard({
  rows,
  loading,
}: {
  rows: ToolsResponse["tools"];
  loading: boolean;
}) {
  const browserRows = useMemo(
    () => rows.filter((r) => isBrowserTool(r.tool)),
    [rows],
  );
  const maxActions = Math.max(1, ...browserRows.map((r) => r.action_count));
  const browserColumns = useMemo<ColumnDef<ToolRow, unknown>[]>(
    () => [
      {
        id: "site",
        header: "Site",
        accessorKey: "tool",
        cell: ({ row }) => <ToolBadge tool={row.original.tool} />,
      },
      {
        id: "turns",
        header: "Turns",
        accessorFn: (t) => t.action_count,
        cell: ({ row }) => <ActionsBarCell row={row.original} maxActions={maxActions} />,
      },
      {
        id: "sessions",
        header: "Sessions",
        accessorFn: (t) => t.session_count,
        meta: { align: "right" },
        cell: ({ row }) => <span className="text-fg-2">{fmtInt(row.original.session_count)}</span>,
      },
      {
        id: "last_seen",
        header: "Last seen",
        accessorFn: (t) => timeValue(t.last_seen),
        cell: ({ row }) => <DateCell iso={row.original.last_seen} />,
      },
    ],
    [maxActions],
  );
  if (!loading && browserRows.length === 0) return null;
  return (
    <ChartShell
      title={
        <span className="flex items-center gap-2">
          Browser chatbots
          <EstPill />
        </span>
      }
      sub="Opt-in browser-extension rail (ChatGPT / Claude / Perplexity / Gemini / Copilot web). Tokens & cost are always estimates."
    >
      <ChartState
        loading={loading && browserRows.length === 0}
        error={null}
        empty={browserRows.length === 0}
        emptyHint="No browser-chatbot turns captured - install the browser extension to observe web AI usage."
        height={120}
      >
        <DataTable<ToolRow>
          data={browserRows}
          columns={browserColumns}
          rowKey={(t) => t.tool}
          minWidth={560}
        />
      </ChartState>
    </ChartShell>
  );
}

