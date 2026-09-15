import { useState } from "react";
import {
  ChartShell,
  DensityBar,
  HeroStat,
  PageHeader,
  StatCard,
  ToolBadge,
  Tooltip,
} from "@/components/primitives";
import { CopyOnClick } from "@/components/CopyOnClick";
import { HelpInd } from "@/components/HelpInd";
import {
  AlertIcon,
  BoltIcon,
  CoinsIcon,
  DatabaseIcon,
  LayersIcon,
} from "@/components/icons";
import { ChartState } from "@/components/ChartState";
import { useFilters, windowParams } from "@/lib/filters";
import { useApi } from "@/lib/useApi";
import { fmtCompact, fmtInt, fmtUSD } from "@/lib/format";
import type { DiscoverResponse } from "@/lib/types";

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
    <div className="space-y-6 p-6">
      <PageHeader
        title="Discovery"
        sub="Wasted-effort signals - same-session stale re-reads, repeated no-change commands, and cross-tool file overlap. Surfaces the moments where the model lost track of what it already knew."
        helpId="tab.discovery"
      />
      {/* Design 1.24: HeroStat (danger) for Estimated waste +
          4 smaller StatCards on the right (Stale re-reads / Tokens
          wasted / Affected files / Repeated commands). */}
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[1.4fr_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)]">
        <HeroStat
          label={`Estimated waste - last ${win}`}
          helpId="metric.stale_count"
          icon={<CoinsIcon />}
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
          icon={<AlertIcon />}
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
          icon={<DatabaseIcon />}
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
          icon={<LayersIcon />}
          loading={data.loading}
          value={fmtInt(data.data?.stale_total)}
          sub="distinct files with stale re-reads"
        />
        <StatCard
          label="Repeated commands"
          helpId="metric.no_change_reruns"
          icon={<BoltIcon />}
          loading={data.loading}
          value={summary ? fmtInt(summary.repeated_command_groups) : "-"}
          sub={
            summary?.cross_tool_file_count
              ? `+ ${fmtInt(summary.cross_tool_file_count)} cross-tool files`
              : "distinct command groups"
          }
        />
      </div>

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

function StaleReadsTable({
  rows,
  rate,
}: {
  rows: NonNullable<DiscoverResponse["stale_reads"]>;
  rate: number;
}) {
  const maxReads = Math.max(1, ...rows.map((r) => r.total_reads));
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[860px] text-left text-[11.5px]">
        <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <tr className="border-b border-line-2">
            <th className="py-1.5 pl-2 font-medium">File<HelpInd id="column.discover.file" /></th>
            <th className="py-1.5 font-medium">Project</th>
            <th className="py-1.5 font-medium">Reads density<HelpInd id="column.discover.reads" /></th>
            <th className="py-1.5 text-right font-medium">Reads<HelpInd id="column.discover.reads" /></th>
            <th className="py-1.5 text-right font-medium">Stale<HelpInd id="column.discover.stale" /></th>
            <th className="py-1.5 text-right font-medium">Cross-thread</th>
            <th className="py-1.5 text-right font-medium">Est. tokens<HelpInd id="column.discover.wasted" /></th>
            <th className="py-1.5 text-right font-medium">Est. waste $<HelpInd id="column.discover.wasted" /></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const stalePct =
              r.total_reads > 0 ? (r.stale_count / r.total_reads) * 100 : 0;
            // Segment breakdown: cross-thread stale (danger red), same-
            // session stale (warn orange), fresh reads (accent teal).
            // cross_thread_stale_count is reported as a SUBSET of
            // stale_count by /api/discover, so subtract before slicing
            // to avoid double-counting.
            const sameSessionStale = Math.max(
              0,
              r.stale_count - r.cross_thread_stale_count,
            );
            const fresh = Math.max(0, r.total_reads - r.stale_count);
            return (
              <tr
                key={`${r.project}|${r.file_path}`}
                className="border-b border-line-1 last:border-b-0 hover:bg-bg-3/40"
              >
                <td className="py-1.5 pl-2">
                  <CopyOnClick
                    value={r.file_path}
                    className="block max-w-[320px] font-mono text-fg-1"
                  >
                    <Tooltip
                      content={<span className="break-all font-mono">{r.file_path}</span>}
                      maxWidth={420}
                    >
                      <span tabIndex={0} className="block cursor-help truncate focus:outline-none">
                        {shortPath(r.file_path)}
                      </span>
                    </Tooltip>
                  </CopyOnClick>
                </td>
                <td className="py-1.5 font-mono text-fg-3">
                  <Tooltip
                    content={<span className="break-all font-mono">{r.project}</span>}
                    maxWidth={420}
                  >
                    <span
                      tabIndex={0}
                      className="block max-w-[180px] cursor-help truncate focus:outline-none"
                    >
                      {basename(r.project)}
                    </span>
                  </Tooltip>
                </td>
                <td className="py-1.5">
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
                </td>
                <td className="py-1.5 text-right tabular-nums text-fg-2">
                  {fmtInt(r.total_reads)}
                </td>
                <td className="py-1.5 text-right tabular-nums text-warn">
                  {fmtInt(r.stale_count)}
                </td>
                <td className="py-1.5 text-right tabular-nums text-fg-3">
                  {r.cross_thread_stale_count > 0 ? (
                    <span className="text-danger">
                      {fmtInt(r.cross_thread_stale_count)}
                    </span>
                  ) : (
                    "-"
                  )}
                </td>
                <td className="py-1.5 text-right tabular-nums text-fg-2">
                  {fmtCompact(r.est_wasted_tokens)}
                </td>
                <td className="py-1.5 text-right tabular-nums text-fg-0">
                  {fmtUSD(estWasteUSD(r.est_wasted_tokens, rate))}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function RepeatedCommandsTable({
  rows,
}: {
  rows: NonNullable<DiscoverResponse["repeated_commands"]>;
}) {
  const maxRuns = Math.max(1, ...rows.map((r) => r.total_runs));
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[820px] text-left text-[11.5px]">
        <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <tr className="border-b border-line-2">
            <th className="py-1.5 pl-2 font-medium">Command<HelpInd id="column.discover.command" /></th>
            <th className="py-1.5 font-medium">Project</th>
            <th className="py-1.5 font-medium">Frequency<HelpInd id="column.discover.runs" /></th>
            <th className="py-1.5 text-right font-medium">Runs<HelpInd id="column.discover.runs" /></th>
            <th className="py-1.5 text-right font-medium">No-change<HelpInd id="column.discover.no_change_reruns" /></th>
            <th className="py-1.5 text-right font-medium">Failures<HelpInd id="column.discover.failed" /></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const noChangePct = r.total_runs > 0 ? r.no_change_reruns / r.total_runs : 0;
            const freqPct = (r.total_runs / maxRuns) * 100;
            return (
              <tr
                key={r.command_hash}
                className="border-b border-line-1 last:border-b-0 hover:bg-bg-3/40"
              >
                <td className="py-1.5 pl-2">
                  <CopyOnClick
                    value={r.command}
                    className="block max-w-[360px] font-mono text-fg-1"
                  >
                    <Tooltip
                      content={<span className="break-all font-mono">{r.command}</span>}
                      maxWidth={420}
                    >
                      <span tabIndex={0} className="block cursor-help truncate focus:outline-none">
                        {r.command}
                      </span>
                    </Tooltip>
                  </CopyOnClick>
                </td>
                <td className="py-1.5 font-mono text-fg-3">
                  <Tooltip
                    content={<span className="break-all font-mono">{r.project}</span>}
                    maxWidth={420}
                  >
                    <span
                      tabIndex={0}
                      className="block max-w-[180px] cursor-help truncate focus:outline-none"
                    >
                      {basename(r.project)}
                    </span>
                  </Tooltip>
                </td>
                <td className="py-1.5">
                  <div className="flex items-center gap-2">
                    <div
                      className="relative h-2 w-[140px] overflow-hidden rounded-pill bg-bg-3"
                      title={`runs ${fmtInt(r.total_runs)} · no-change ${fmtInt(r.no_change_reruns)} (${(noChangePct * 100).toFixed(0)}%)`}
                    >
                      <span
                        className="absolute inset-y-0 left-0 block"
                        style={{
                          width: `${freqPct}%`,
                          background:
                            noChangePct > 0.5 ? "var(--warn)" : "var(--accent)",
                        }}
                      />
                    </div>
                    <span className="font-mono text-[10px] text-fg-3 tabular-nums">
                      {(noChangePct * 100).toFixed(0)}%
                    </span>
                  </div>
                </td>
                <td className="py-1.5 text-right tabular-nums text-fg-2">
                  {fmtInt(r.total_runs)}
                </td>
                <td className="py-1.5 text-right tabular-nums">
                  <span
                    className={
                      noChangePct > 0.5
                        ? "text-warn"
                        : noChangePct > 0
                          ? "text-fg-2"
                          : "text-fg-4"
                    }
                  >
                    {r.no_change_reruns > 0
                      ? `${fmtInt(r.no_change_reruns)} (${Math.round(noChangePct * 100)}%)`
                      : "-"}
                  </span>
                </td>
                <td className="py-1.5 text-right tabular-nums">
                  {r.failed_runs > 0 ? (
                    <span className="text-danger">{fmtInt(r.failed_runs)}</span>
                  ) : (
                    <span className="text-fg-4">-</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function CrossToolEmpty() {
  return (
    <div className="rounded-2 border border-dashed border-line-2 bg-bg-3/40 px-6 py-8">
      <div className="mx-auto max-w-[640px] text-center">
        <div className="text-[12.5px] font-semibold text-fg-1">
          No cross-tool overlap detected
        </div>
        <p className="mx-auto mt-1 max-w-[520px] text-[11.5px] text-fg-3">
          This surface lights up when 2+ AI clients work on the same files
          in the same window. Wire up another tool to start seeing where
          they overlap. The MCP server lets each tool query what others
          have done.
        </p>
        <div className="mt-4 flex flex-wrap items-center justify-center gap-2">
          <Tooltip content="Open Settings → Hooks to configure Cursor">
            <a
              href="/settings"
              className="flex h-7 items-center gap-1.5 rounded-2 border border-line-2 bg-bg-2 px-3 text-[11px] text-fg-2 hover:bg-bg-3 hover:text-fg-0"
            >
              Configure Cursor
            </a>
          </Tooltip>
          <Tooltip content="Open Settings → Hooks to configure Codex">
            <a
              href="/settings"
              className="flex h-7 items-center gap-1.5 rounded-2 border border-line-2 bg-bg-2 px-3 text-[11px] text-fg-2 hover:bg-bg-3 hover:text-fg-0"
            >
              Configure Codex
            </a>
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
      </div>
    </div>
  );
}

function CrossToolTable({
  rows,
}: {
  rows: NonNullable<DiscoverResponse["cross_tool_files"]>;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[680px] text-left text-[11.5px]">
        <thead className="text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <tr className="border-b border-line-2">
            <th className="py-1.5 pl-2 font-medium">File</th>
            <th className="py-1.5 font-medium">Project</th>
            <th className="py-1.5 font-medium">Tools</th>
            <th className="py-1.5 text-right font-medium">Accesses</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr
              key={`${r.project}|${r.file_path}`}
              className="border-b border-line-1 last:border-b-0 hover:bg-bg-3/40"
            >
              <td className="py-1.5 pl-2 font-mono text-fg-1">
                <Tooltip
                  content={<span className="break-all font-mono">{r.file_path}</span>}
                  maxWidth={420}
                >
                  <span
                    tabIndex={0}
                    className="block max-w-[360px] cursor-help truncate focus:outline-none"
                  >
                    {shortPath(r.file_path)}
                  </span>
                </Tooltip>
              </td>
              <td className="py-1.5 font-mono text-fg-3">
                <Tooltip
                  content={<span className="break-all font-mono">{r.project}</span>}
                  maxWidth={420}
                >
                  <span
                    tabIndex={0}
                    className="block max-w-[200px] cursor-help truncate focus:outline-none"
                  >
                    {basename(r.project)}
                  </span>
                </Tooltip>
              </td>
              <td className="py-1.5">
                <div className="flex flex-wrap gap-1">
                  {r.tools.map((t) => (
                    <ToolBadge key={t} tool={t} />
                  ))}
                </div>
              </td>
              <td className="py-1.5 text-right tabular-nums text-fg-1">
                {fmtInt(r.accesses)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
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
        className="grid h-6 w-6 place-items-center rounded-1 border border-line-2 bg-bg-2 hover:bg-bg-3 disabled:opacity-30"
      >
        ‹
      </button>
      <span className="px-1 tabular-nums">
        {page}/{maxPage}
      </span>
      <button
        type="button"
        onClick={() => onPage(Math.min(maxPage, page + 1))}
        disabled={page >= maxPage}
        className="grid h-6 w-6 place-items-center rounded-1 border border-line-2 bg-bg-2 hover:bg-bg-3 disabled:opacity-30"
      >
        ›
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
