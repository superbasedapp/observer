import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/DataTable";
import {
  ChartShell,
  DensityBar,
  EmptyState,
  HeroStat,
  Icon,
  PageHeader,
  StatCard,
  ToolBadge,
  Tooltip,
  Stagger,
} from "@/components/primitives";
import { CopyOnClick } from "@/components/CopyOnClick";
import { HelpInd } from "@/components/HelpInd";
import { ChartState } from "@/components/ChartState";
import { useFilters, windowParams } from "@/lib/filters";
import { useApi } from "@/lib/useApi";
import { fmtCompact, fmtInt, fmtUSD } from "@/lib/format";
import type { DiscoverResponse } from "@/lib/types";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { navIcon } from "@/lib/nav";
import { MetricIcon } from "@/components/MetricIcon";

export function DiscoveryPage() {
  const { win, customRange, tool, project } = useFilters();
  const winParams = windowParams(win, customRange);
  const projectParam = project === "all" ? undefined : project;
  const toolParam = tool === "all" ? undefined : tool;

  const [stalePage, setStalePage] = useState(1);
  const [repeatedPage, setRepeatedPage] = useState(1);

  const data = useApi<DiscoverResponse>(
    "/api/discover",
    {
      ...winParams,
      project: projectParam,
      tool: toolParam,
      stale_page: stalePage,
      stale_limit: 20,
      repeated_page: repeatedPage,
      repeated_limit: 20,
    },
    [win, customRange, tool, project, stalePage, repeatedPage],
  );

  const summary = data.data?.summary;
  const rate = data.data?.blended_input_rate_per_million ?? 0;

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("discovery")}
        title="Discovery"
        sub="Wasted-effort signals - same-session stale re-reads, repeated no-change commands, and cross-tool file overlap. Surfaces the moments where the model lost track of what it already knew."
        helpId="tab.discovery"
      />
      {/* Design 1.24: HeroStat (danger) for Estimated waste +
          4 smaller StatCards on the right (Stale re-reads / Tokens
          wasted / Affected files / Repeated commands). */}
      <Stagger className="grid grid-cols-1 gap-3 xl:grid-cols-[1.4fr_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)]">
        <HeroStat
          label={`Estimated waste - last ${win}`}
          helpId="metric.stale_count"
          icon={<MetricIcon metric="waste" />}
          loading={data.loading}
          value={
            summary
              ? fmtUSD(estWasteUSD(summary.est_wasted_tokens, rate))
              : "-"
          }
          sub={
            summary ? (
              <>
                {fmtInt(summary.stale_read_count)} re-reads ·{" "}
                {fmtInt(data.data?.stale_total ?? 0)} unique files
                {summary.cross_thread_stale_count > 0 && (
                  <>
                    {" "}· {fmtInt(summary.cross_thread_stale_count)}{" "}
                    cross-thread reads (same-session reads excluded)
                  </>
                )}
              </>
            ) : (
              "no waste detected in window"
            )
          }
          variant="danger"
        />
        <StatCard
          label="Stale re-reads"
          helpId="metric.stale_count"
          icon={<MetricIcon metric="staleRereads" />}
          loading={data.loading}
          value={summary ? fmtInt(summary.stale_read_count) : "-"}
          sub={
            summary?.cross_thread_stale_count
              ? `${fmtInt(summary.cross_thread_stale_count)} cross-thread`
              : "same-session only"
          }
        />
        <StatCard
          label="Tokens wasted"
          helpId="metric.stale_count"
          icon={<MetricIcon metric="tokens" />}
          loading={data.loading}
          value={summary ? fmtCompact(summary.est_wasted_tokens) : "-"}
          sub={
            summary
              ? `${fmtUSD(rate)}/M blended input rate`
              : undefined
          }
        />
        <StatCard
          label="Affected files"
          icon={<MetricIcon metric="files" />}
          loading={data.loading}
          value={fmtInt(data.data?.stale_total)}
          sub="distinct files with stale re-reads"
        />
        <StatCard
          label="Repeated commands"
          helpId="metric.no_change_reruns"
          icon={<MetricIcon metric="commands" />}
          loading={data.loading}
          value={summary ? fmtInt(summary.repeated_command_groups) : "-"}
          sub={
            summary?.cross_tool_file_count
              ? `+ ${fmtInt(summary.cross_tool_file_count)} cross-tool files`
              : "distinct command groups"
          }
        />
      </Stagger>

      {/* Stale re-reads */}
      <ChartShell
        title="Top files re-read"
        sub={`Same-session reads where the prior read became stale (file changed in between). Top ${fmtInt(data.data?.stale_total)} files in window.`}
        right={
          data.data && data.data.stale_total > 0 ? (
            <Pagination
              page={data.data.stale_page}
              total={data.data.stale_total}
              limit={data.data.stale_limit}
              onPage={setStalePage}
            />
          ) : null
        }
      >
        <ChartState
          loading={data.loading && !data.data}
          error={data.error}
          denied={data.denied}
          deniedPermission={data.deniedPermission}
          empty={!data.data?.stale_reads?.length}
          emptyHint="No stale re-reads detected - files weren't re-read after intervening edits."
          height={200}
        >
          {data.data?.stale_reads && (
            <StaleReadsTable rows={data.data.stale_reads} rate={rate} />
          )}
        </ChartState>
      </ChartShell>

      {/* Repeated commands */}
      <ChartShell
        title="Repeated commands"
        sub={`Commands run multiple times within a project. ${fmtInt(data.data?.repeated_total)} groups in window.`}
        right={
          data.data && data.data.repeated_total > 0 ? (
            <Pagination
              page={data.data.repeated_page}
              total={data.data.repeated_total}
              limit={data.data.repeated_limit}
              onPage={setRepeatedPage}
            />
          ) : null
        }
      >
        <ChartState
          loading={data.loading && !data.data}
          error={data.error}
          denied={data.denied}
          deniedPermission={data.deniedPermission}
          empty={!data.data?.repeated_commands?.length}
          emptyHint="No repeated commands detected."
          height={200}
        >
          {data.data?.repeated_commands && (
            <RepeatedCommandsTable rows={data.data.repeated_commands} />
          )}
        </ChartState>
      </ChartShell>

      {/* Cross-tool overlap */}
      <ChartShell
        title="Cross-tool overlap"
        sub="Files touched by 2+ AI clients in this window - SuperBased's unique multi-tool value prop."
      >
        <ChartState
          loading={data.loading && !data.data}
          error={data.error}
          denied={data.denied}
          deniedPermission={data.deniedPermission}
          empty={false /* render the CrossToolEmpty CTA shell instead */}
          height={140}
        >
          {data.data?.cross_tool_files?.length ? (
            <CrossToolTable rows={data.data.cross_tool_files} />
          ) : (
            <CrossToolEmpty />
          )}
        </ChartState>
      </ChartShell>
    </div>
  );
}

function estWasteUSD(tokens: number, ratePerMillion: number): number {
  return (tokens * ratePerMillion) / 1_000_000;
}

// ---------------------------------------------------------------- panels

type StaleReadRow = NonNullable<DiscoverResponse["stale_reads"]>[number];
type RepeatedCommandRow = NonNullable<DiscoverResponse["repeated_commands"]>[number];
type CrossToolRow = NonNullable<DiscoverResponse["cross_tool_files"]>[number];

// ProjectCell is the project basename with the full root in a tooltip,
// shared by all three Discovery tables.
function ProjectCell({ project, maxWidthClass }: { project: string; maxWidthClass: string }) {
  return (
    <Tooltip
      content={<span className="break-all font-mono">{project}</span>}
      maxWidth={420}
    >
      <span
        tabIndex={0}
        className={`block ${maxWidthClass} cursor-help truncate font-mono text-fg-3 focus:outline-none`}
      >
        {basename(project)}
      </span>
    </Tooltip>
  );
}

// The stale-reads and repeated-commands lists are SERVER-paginated and
// server-ranked, so their columns do not sort: a client sort would only
// reorder the current page and misrepresent the ranking.
function staleReadColumns(rate: number, maxReads: number): ColumnDef<StaleReadRow, unknown>[] {
  return [
    {
      id: "file",
      header: () => <>File<HelpInd id="column.discover.file" /></>,
      enableSorting: false,
      cell: ({ row }) => (
        <CopyOnClick
          value={row.original.file_path}
          className="block max-w-[320px] font-mono text-fg-1"
        >
          <Tooltip
            content={<span className="break-all font-mono">{row.original.file_path}</span>}
            maxWidth={420}
          >
            <span tabIndex={0} className="block cursor-help truncate focus:outline-none">
              {shortPath(row.original.file_path)}
            </span>
          </Tooltip>
        </CopyOnClick>
      ),
    },
    {
      id: "project",
      header: "Project",
      enableSorting: false,
      cell: ({ row }) => <ProjectCell project={row.original.project} maxWidthClass="max-w-[180px]" />,
    },
    {
      id: "density",
      header: () => <>Reads density<HelpInd id="column.discover.reads" /></>,
      enableSorting: false,
      cell: ({ row }) => {
        const r = row.original;
        const stalePct = r.total_reads > 0 ? (r.stale_count / r.total_reads) * 100 : 0;
        // Segment breakdown: cross-thread stale (danger red), same-
        // session stale (warn orange), fresh reads (accent teal).
        // cross_thread_stale_count is reported as a SUBSET of
        // stale_count by /api/discover, so subtract before slicing
        // to avoid double-counting.
        const sameSessionStale = Math.max(0, r.stale_count - r.cross_thread_stale_count);
        const fresh = Math.max(0, r.total_reads - r.stale_count);
        return (
          <div className="flex items-center gap-2">
            <DensityBar
              total={r.total_reads}
              max={maxReads}
              segments={[
                {
                  value: r.cross_thread_stale_count,
                  color: "var(--danger)",
                  label: `${fmtInt(r.cross_thread_stale_count)} cross-thread stale`,
                },
                {
                  value: sameSessionStale,
                  color: "var(--warn)",
                  label: `${fmtInt(sameSessionStale)} same-session stale`,
                },
                {
                  value: fresh,
                  color: "var(--accent)",
                  label: `${fmtInt(fresh)} fresh reads`,
                },
              ]}
              title={`reads ${fmtInt(r.total_reads)} · stale ${fmtInt(r.stale_count)} (${stalePct.toFixed(0)}% of reads)`}
            />
            <span className="font-mono text-[10px] text-fg-3 tabular-nums">
              {stalePct.toFixed(0)}%
            </span>
          </div>
        );
      },
    },
    {
      id: "reads",
      header: () => <>Reads<HelpInd id="column.discover.reads" /></>,
      enableSorting: false,
      meta: { align: "right" },
      cell: ({ row }) => <span className="text-fg-2">{fmtInt(row.original.total_reads)}</span>,
    },
    {
      id: "stale",
      header: () => <>Stale<HelpInd id="column.discover.stale" /></>,
      enableSorting: false,
      meta: { align: "right" },
      cell: ({ row }) => <span className="text-warn">{fmtInt(row.original.stale_count)}</span>,
    },
    {
      id: "cross_thread",
      header: "Cross-thread",
      enableSorting: false,
      meta: { align: "right" },
      cell: ({ row }) =>
        row.original.cross_thread_stale_count > 0 ? (
          <span className="text-danger">{fmtInt(row.original.cross_thread_stale_count)}</span>
        ) : (
          <span className="text-fg-3">-</span>
        ),
    },
    {
      id: "est_tokens",
      header: () => <>Est. tokens<HelpInd id="column.discover.wasted" /></>,
      enableSorting: false,
      meta: { align: "right" },
      cell: ({ row }) => <span className="text-fg-2">{fmtCompact(row.original.est_wasted_tokens)}</span>,
    },
    {
      id: "est_waste",
      header: () => <>Est. waste $<HelpInd id="column.discover.wasted" /></>,
      enableSorting: false,
      meta: { align: "right" },
      cell: ({ row }) => (
        <span className="text-fg-0">{fmtUSD(estWasteUSD(row.original.est_wasted_tokens, rate))}</span>
      ),
    },
  ];
}

function StaleReadsTable({
  rows,
  rate,
}: {
  rows: StaleReadRow[];
  rate: number;
}) {
  const maxReads = Math.max(1, ...rows.map((r) => r.total_reads));
  const columns = useMemo(() => staleReadColumns(rate, maxReads), [rate, maxReads]);
  return (
    <DataTable<StaleReadRow>
      data={rows}
      columns={columns}
      rowKey={(r) => `${r.project}|${r.file_path}`}
      minWidth={860}
    />
  );
}


function repeatedCommandColumns(maxRuns: number): ColumnDef<RepeatedCommandRow, unknown>[] {
  return [
    {
      id: "command",
      header: () => <>Command<HelpInd id="column.discover.command" /></>,
      enableSorting: false,
      cell: ({ row }) => (
        <CopyOnClick
          value={row.original.command}
          className="block max-w-[360px] font-mono text-fg-1"
        >
          <Tooltip
            content={<span className="break-all font-mono">{row.original.command}</span>}
            maxWidth={420}
          >
            <span tabIndex={0} className="block cursor-help truncate focus:outline-none">
              {row.original.command}
            </span>
          </Tooltip>
        </CopyOnClick>
      ),
    },
    {
      id: "project",
      header: "Project",
      enableSorting: false,
      cell: ({ row }) => <ProjectCell project={row.original.project} maxWidthClass="max-w-[180px]" />,
    },
    {
      id: "frequency",
      header: () => <>Frequency<HelpInd id="column.discover.runs" /></>,
      enableSorting: false,
      cell: ({ row }) => {
        const r = row.original;
        const noChangePct = r.total_runs > 0 ? r.no_change_reruns / r.total_runs : 0;
        const freqPct = (r.total_runs / maxRuns) * 100;
        return (
          <div className="flex items-center gap-2">
            <Tooltip content={`runs ${fmtInt(r.total_runs)} · no-change ${fmtInt(r.no_change_reruns)} (${(noChangePct * 100).toFixed(0)}%)`}>
              <div
                tabIndex={0}
                className="relative h-2 w-[140px] overflow-hidden rounded-pill bg-bg-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
              >
                <span
                  className="absolute inset-y-0 left-0 block"
                  style={{
                    width: `${freqPct}%`,
                    background: noChangePct > 0.5 ? "var(--warn)" : "var(--accent)",
                  }}
                />
              </div>
            </Tooltip>
            <span className="font-mono text-[10px] text-fg-3 tabular-nums">
              {(noChangePct * 100).toFixed(0)}%
            </span>
          </div>
        );
      },
    },
    {
      id: "runs",
      header: () => <>Runs<HelpInd id="column.discover.runs" /></>,
      enableSorting: false,
      meta: { align: "right" },
      cell: ({ row }) => <span className="text-fg-2">{fmtInt(row.original.total_runs)}</span>,
    },
    {
      id: "no_change",
      header: () => <>No-change<HelpInd id="column.discover.no_change_reruns" /></>,
      enableSorting: false,
      meta: { align: "right" },
      cell: ({ row }) => {
        const r = row.original;
        const noChangePct = r.total_runs > 0 ? r.no_change_reruns / r.total_runs : 0;
        return (
          <span
            className={
              noChangePct > 0.5 ? "text-warn" : noChangePct > 0 ? "text-fg-2" : "text-fg-4"
            }
          >
            {r.no_change_reruns > 0
              ? `${fmtInt(r.no_change_reruns)} (${Math.round(noChangePct * 100)}%)`
              : "-"}
          </span>
        );
      },
    },
    {
      id: "failures",
      header: () => <>Failures<HelpInd id="column.discover.failed" /></>,
      enableSorting: false,
      meta: { align: "right" },
      cell: ({ row }) =>
        row.original.failed_runs > 0 ? (
          <span className="text-danger">{fmtInt(row.original.failed_runs)}</span>
        ) : (
          <span className="text-fg-4">-</span>
        ),
    },
  ];
}

function RepeatedCommandsTable({ rows }: { rows: RepeatedCommandRow[] }) {
  const maxRuns = Math.max(1, ...rows.map((r) => r.total_runs));
  const columns = useMemo(() => repeatedCommandColumns(maxRuns), [maxRuns]);
  return (
    <DataTable<RepeatedCommandRow>
      data={rows}
      columns={columns}
      rowKey={(r) => r.command_hash}
      minWidth={820}
    />
  );
}


function CrossToolEmpty() {
  return (
    <div className="rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-6 py-6">
      <EmptyState
        variant="inline"
        className="mx-auto max-w-[640px] py-0"
        illustration="connect"
        illustrationSize={112}
        title="No cross-tool overlap detected"
        body="This surface lights up when 2+ AI clients work on the same files in the same window. Wire up another tool to start seeing where they overlap. The MCP server lets each tool query what others have done."
      >
        <div className="mt-1 flex flex-wrap items-center justify-center gap-2">
          <Tooltip content="Open Settings → Hooks to configure Cursor">
            <Link
              to="/settings"
              className="flex h-7 items-center gap-1.5 rounded-2 border border-line-2 bg-bg-2 px-3 text-caption text-fg-2 hover:bg-bg-3 hover:text-fg-0"
            >
              Configure Cursor
            </Link>
          </Tooltip>
          <Tooltip content="Open Settings → Hooks to configure Codex">
            <Link
              to="/settings"
              className="flex h-7 items-center gap-1.5 rounded-2 border border-line-2 bg-bg-2 px-3 text-caption text-fg-2 hover:bg-bg-3 hover:text-fg-0"
            >
              Configure Codex
            </Link>
          </Tooltip>
          <a
            href="https://superbased.app/docs/guides/mcp-server"
            target="_blank"
            rel="noreferrer"
            className="flex h-7 items-center gap-1.5 rounded-2 border border-accent/40 bg-accent-soft px-3 text-[11px] font-medium text-accent hover:bg-accent-soft/80"
          >
            Learn about MCP cross-tool ↗
          </a>
        </div>
      </EmptyState>
    </div>
  );
}

// The cross-tool list is not paginated, so its columns sort client-side.
const CROSS_TOOL_COLUMNS: ColumnDef<CrossToolRow, unknown>[] = [
  {
    id: "file",
    header: "File",
    accessorKey: "file_path",
    cell: ({ row }) => (
      <Tooltip
        content={<span className="break-all font-mono">{row.original.file_path}</span>}
        maxWidth={420}
      >
        <span
          tabIndex={0}
          className="block max-w-[360px] cursor-help truncate font-mono text-fg-1 focus:outline-none"
        >
          {shortPath(row.original.file_path)}
        </span>
      </Tooltip>
    ),
  },
  {
    id: "project",
    header: "Project",
    accessorKey: "project",
    cell: ({ row }) => <ProjectCell project={row.original.project} maxWidthClass="max-w-[200px]" />,
  },
  {
    id: "tools",
    header: "Tools",
    accessorFn: (r) => r.tools.length,
    cell: ({ row }) => (
      <div className="flex flex-wrap gap-1">
        {row.original.tools.map((t) => (
          <ToolBadge key={t} tool={t} />
        ))}
      </div>
    ),
  },
  {
    id: "accesses",
    header: "Accesses",
    accessorFn: (r) => r.accesses,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-1">{fmtInt(row.original.accesses)}</span>,
  },
];

function CrossToolTable({ rows }: { rows: CrossToolRow[] }) {
  return (
    <DataTable<CrossToolRow>
      data={rows}
      columns={CROSS_TOOL_COLUMNS}
      rowKey={(r) => `${r.project}|${r.file_path}`}
      minWidth={680}
      // The cross-tool list is not paginated server-side; batch its rows.
      incrementalRows={100}
    />
  );
}


function Pagination({
  page,
  limit,
  total,
  onPage,
}: {
  page: number;
  limit: number;
  total: number;
  onPage: (n: number) => void;
}) {
  const maxPage = Math.max(1, Math.ceil(total / limit));
  return (
    <div className="flex items-center gap-1 text-[11px] text-fg-3">
      <button
        type="button"
        onClick={() => onPage(Math.max(1, page - 1))}
        disabled={page <= 1}
        aria-label="Previous page"
        className="grid h-6 w-6 place-items-center rounded-1 border border-line-2 bg-bg-2 hover:bg-bg-3 disabled:opacity-30"
      >
        <Icon icon={ChevronLeft} size="xs" />
      </button>
      <span className="px-1 tabular-nums">
        {page}/{maxPage}
      </span>
      <button
        type="button"
        onClick={() => onPage(Math.min(maxPage, page + 1))}
        disabled={page >= maxPage}
        aria-label="Next page"
        className="grid h-6 w-6 place-items-center rounded-1 border border-line-2 bg-bg-2 hover:bg-bg-3 disabled:opacity-30"
      >
        <Icon icon={ChevronRight} size="xs" />
      </button>
    </div>
  );
}

function shortPath(p: string): string {
  // Show /a/b/.../leaf-2/leaf-1 when long.
  if (p.length < 60) return p;
  const parts = p.split("/").filter(Boolean);
  if (parts.length <= 3) return p;
  return ".../" + parts.slice(-3).join("/");
}

function basename(p: string): string {
  if (!p) return "-";
  const parts = p.split("/").filter(Boolean);
  return parts[parts.length - 1] || p;
}

export type { DiscoverResponse };
