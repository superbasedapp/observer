import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import {
  ChartShell,
  EmptyState,
  ErrorState,
  HeroStat,
  InlineLoading,
  ModelId,
  PageHeader,
  Pill,
  Stagger,
  Table,
  Tooltip,
} from "@/components/primitives";
import { DataTable } from "@/components/DataTable";
import { useApi } from "@/lib/useApi";
import { fmtDateOnly, fmtDateTime, fmtDuration, fmtInt, fmtUSD } from "@/lib/format";
import type { VocabTable } from "@shared/lib/vocabEntry";
import { VocabPill } from "@shared/lib/vocabPill";
import { navIcon } from "@/lib/nav";
import { MetricIcon } from "@/components/MetricIcon";

// Benchmarks page (docs/plans/benchmarks-harness-plan-2026-07-11.md §4.1):
// the read-only surface over the CLI-driven harness×model rig. Run list →
// run detail (comparison matrix with success ± Wilson CI, expected cost per
// successful completion, non-inferiority verdicts, per-task grid, raw cost
// dots). Every stats figure is sourced from the same internal/benchmark
// ComputeReport the CLI `benchmark report` runs — the page only renders it.
// Honest throughout: all configs shown, N at every level, CI width prominent,
// verdicts suppressed below the pre-registered sample floor, and an empty
// state that names the exact command to produce data.

type RunSummary = {
  run_id: string;
  spec_name: string;
  spec_hash: string;
  status: string;
  started_at: string;
  finished_at?: string;
  planned_cells: number;
  completed_cells: number;
  spend_usd: number;
  judge_spend_usd: number;
  configs: number;
  tasks: number;
  repeats: number;
  harnesses: string[];
  models: string[];
};
type RunsResponse = { runs: RunSummary[] | null; total: number };

type Interval = { point: number; lo: number; hi: number };
type ConfigReport = {
  config_id: string;
  harness: string;
  model: string;
  n_planned: number;
  n_executed: number;
  n_scored: number;
  n_passed: number;
  n_sessions: number;
  n_tasks: number;
  success_rate: number;
  success_ci: Interval;
  model_eligible_rate: number;
  model_eligible_ci: Interval;
  total_spend_usd: number;
  mean_cost_per_attempt_usd: number;
  sd_cost_usd: number;
  median_cost_usd: number;
  iqr_lo_usd: number;
  iqr_hi_usd: number;
  cost_per_success_usd: number | null;
  mean_wall_ms: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_read_pct: number;
};
type Comparison = {
  candidate: string;
  baseline: string;
  success_diff_ci: Interval;
  paired_delta: Interval;
  paired_tasks: number;
  cheaper: boolean;
  cost_per_success_delta_usd: number;
  verdict: string;
};
type TaskCell = { attempts: number; scored: number; passed: number };
type TaskRow = { task_id: string; cells: Record<string, TaskCell> };
type RunDetail = {
  run_id: string;
  spec_name: string;
  spec_hash: string;
  status: string;
  started_at: string;
  finished_at?: string;
  baseline_config: string;
  noninferiority_margin: number;
  price_disclaimer: string;
  total_spend_usd: number;
  judge_spend_usd: number;
  planned_cells: number;
  completed_cells: number;
  repeats: number;
  min_sample: number;
  configs: ConfigReport[] | null;
  comparisons: Comparison[] | null;
  status_census: Record<string, number>;
  warnings?: string[] | null;
  cost_dots: Record<string, number[]>;
  tasks: TaskRow[] | null;
};

// VERDICT - the ONE presentation row per candidate-vs-baseline verdict
// (tone + label); glyph from VOCAB_ICONS.benchmarkVerdict.
const VERDICT: VocabTable = {
  candidate_cheaper_noninferior: { tone: "success", label: "cheaper · non-inferior" },
  candidate_worse: { tone: "danger", label: "worse" },
  no_detected_difference: { tone: "neutral", label: "no detected difference" },
  inconclusive: { tone: "warn" },
  insufficient_distinct_tasks: { tone: "warn", label: "too few distinct tasks" },
};

// RUN_STATUS - a benchmark run's status; running is in flight (spins).
// Glyph from VOCAB_ICONS.benchmarkRun.
const RUN_STATUS: VocabTable = {
  completed: { tone: "success" },
  running: { tone: "info", spin: true },
  budget_stop: { tone: "warn" },
  aborted: { tone: "danger" },
  error: { tone: "danger" },
};

export function BenchmarksPage() {
  const [params, setParams] = useSearchParams();
  const run = params.get("run") ?? "";
  const setRun = (id: string) => {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (id) next.set("run", id);
        else next.delete("run");
        return next;
      },
      { replace: false },
    );
  };
  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("benchmarks")}
        title="Benchmarks"
        sub="Harness × model comparisons grounded in billed-token truth - success ± Wilson CI, expected cost per successful completion, and non-inferiority verdicts over a pinned task corpus. Runs are launched from the CLI (observer benchmark run); this page reads the results."
      />
      {run ? <RunDetailView runID={run} onBack={() => setRun("")} /> : <RunListView onOpen={setRun} />}
    </div>
  );
}

// RUN_COLUMNS: the run list. The server returns newest first; that order
// holds until a header is clicked.
const RUN_COLUMNS: ColumnDef<RunSummary, unknown>[] = [
  {
    id: "spec",
    header: "Spec",
    accessorFn: (r) => r.spec_name,
    cell: ({ row }) => (
      <>
        <span className="font-semibold text-fg-1">{row.original.spec_name}</span>
        <code className="ml-1.5 rounded-1 bg-bg-3 px-1 font-mono text-micro text-fg-3">
          {row.original.run_id}
        </code>
      </>
    ),
  },
  {
    id: "status",
    header: "Status",
    accessorFn: (r) => r.status,
    cell: ({ row }) => <VocabPill vocab="benchmarkRun" table={RUN_STATUS} value={row.original.status} />,
  },
  {
    id: "matrix",
    header: "Matrix",
    enableSorting: false,
    cell: ({ row }) => (
      <span className="whitespace-nowrap tabular-nums text-fg-2">
        {row.original.configs}×{row.original.tasks}
        <span className="text-fg-3"> ·{row.original.repeats}rep</span>
      </span>
    ),
  },
  {
    id: "cells",
    header: "Cells",
    accessorFn: (r) => r.completed_cells,
    cell: ({ row }) => (
      <span className="whitespace-nowrap tabular-nums text-fg-2">
        {row.original.completed_cells}/{row.original.planned_cells}
      </span>
    ),
  },
  {
    id: "spend",
    header: "Spend",
    accessorFn: (r) => r.spend_usd,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{fmtUSD(row.original.spend_usd)}</span>,
  },
  {
    id: "started",
    header: "Started",
    accessorFn: (r) => r.started_at,
    cell: ({ row }) => (
      <span className="whitespace-nowrap text-fg-3">{fmtDateTime(row.original.started_at)}</span>
    ),
  },
  {
    id: "harnesses",
    header: "Harnesses",
    enableSorting: false,
    cell: ({ row }) => (
      <span className="font-mono text-[11px] text-fg-3">{row.original.harnesses.join(", ")}</span>
    ),
  },
];

// configColumnsFor builds the per-config report columns; the baseline id
// is the one piece of run state a cell needs (the "baseline" pill).
function configColumnsFor(baseline: string): ColumnDef<ConfigReport, unknown>[] {
  return [
    {
      id: "config",
      header: "Config",
      accessorFn: (c) => c.config_id,
      cell: ({ row }) => (
        <span className="font-mono text-[11px] text-fg-1">
          {row.original.config_id}
          {row.original.config_id === baseline && (
            <>
              {" "}
              <Pill variant="info">baseline</Pill>
            </>
          )}
        </span>
      ),
    },
    {
      id: "model",
      header: "Model",
      accessorFn: (c) => c.model,
      cell: ({ row }) => (
        <span className="text-[11px]">
          <ModelId model={row.original.model} className="min-w-0" />
        </span>
      ),
    },
    {
      id: "success",
      header: "Success (95% CI)",
      // No attempts is unknown, not 0% - it sorts last either way.
      accessorFn: (c) => (c.n_executed === 0 ? undefined : c.success_rate),
      sortUndefined: "last",
      cell: ({ row }) => {
        const c = row.original;
        const wide = c.success_ci.hi - c.success_ci.lo > 0.5;
        return c.n_executed === 0 ? (
          <span className="text-fg-3">no attempts</span>
        ) : (
          <span className="whitespace-nowrap tabular-nums text-fg-1">
            {(c.success_rate * 100).toFixed(0)}%{" "}
            <span className={wide ? "text-warn" : "text-fg-3"}>
              [{(c.success_ci.lo * 100).toFixed(0)}–{(c.success_ci.hi * 100).toFixed(0)}]
            </span>
          </span>
        );
      },
    },
    {
      id: "n",
      header: "N pl/ex/sc/pass",
      enableSorting: false,
      cell: ({ row }) => (
        <span className="whitespace-nowrap tabular-nums text-fg-2">
          {row.original.n_planned}/{row.original.n_executed}/{row.original.n_scored}/{row.original.n_passed}
        </span>
      ),
    },
    {
      id: "cost_per_success",
      header: "Cost / success",
      accessorFn: (c) => c.cost_per_success_usd ?? undefined,
      sortUndefined: "last",
      meta: { align: "right" },
      cell: ({ row }) =>
        row.original.cost_per_success_usd == null ? (
          <Tooltip content="No successful attempts - cost per success is undefined (censored)">
            <span tabIndex={0} className="cursor-help text-fg-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring">
              n/a
            </span>
          </Tooltip>
        ) : (
          <span className="text-fg-2">{fmtUSD(row.original.cost_per_success_usd)}</span>
        ),
    },
    {
      id: "mean_cost",
      header: "Mean $",
      accessorFn: (c) => c.mean_cost_per_attempt_usd,
      meta: { align: "right" },
      cell: ({ row }) => <span className="text-fg-2">{fmtUSD(row.original.mean_cost_per_attempt_usd)}</span>,
    },
    {
      id: "cache",
      header: "Cache %",
      accessorFn: (c) => c.cache_read_pct,
      meta: { align: "right" },
      cell: ({ row }) => <span className="text-fg-2">{row.original.cache_read_pct.toFixed(0)}%</span>,
    },
    {
      id: "wall",
      header: "Mean wall",
      accessorFn: (c) => (c.mean_wall_ms > 0 ? c.mean_wall_ms : undefined),
      sortUndefined: "last",
      cell: ({ row }) => (
        <span className="whitespace-nowrap tabular-nums text-fg-2">
          {row.original.mean_wall_ms > 0 ? fmtDuration(row.original.mean_wall_ms) : "-"}
        </span>
      ),
    },
  ];
}

const COMPARISON_COLUMNS: ColumnDef<Comparison, unknown>[] = [
  {
    id: "candidate",
    header: "Candidate",
    accessorFn: (c) => c.candidate,
    cell: ({ row }) => <span className="font-mono text-[11px] text-fg-1">{row.original.candidate}</span>,
  },
  {
    id: "verdict",
    header: "Verdict",
    accessorFn: (c) => c.verdict,
    cell: ({ row }) => <VocabPill vocab="benchmarkVerdict" table={VERDICT} value={row.original.verdict} />,
  },
  {
    id: "diff",
    header: "Δ success (95% CI)",
    accessorFn: (c) => c.success_diff_ci.point,
    cell: ({ row }) => {
      const ci = row.original.success_diff_ci;
      return (
        <span className="whitespace-nowrap tabular-nums text-fg-2">
          {signed(ci.point * 100)}pp [{signed(ci.lo * 100)}, {signed(ci.hi * 100)}]
        </span>
      );
    },
  },
  {
    id: "paired",
    header: "Paired Δ",
    accessorFn: (c) => c.paired_delta.point,
    cell: ({ row }) => (
      <span className="whitespace-nowrap tabular-nums text-fg-2">
        {signed(row.original.paired_delta.point * 100)}pp
        <span className="text-fg-3"> ({row.original.paired_tasks} tasks)</span>
      </span>
    ),
  },
  {
    id: "cheaper",
    header: "Cheaper",
    accessorFn: (c) => (c.cheaper ? 1 : 0),
    cell: ({ row }) => <span className="text-fg-2">{row.original.cheaper ? "yes" : "no"}</span>,
  },
  {
    id: "delta_cost",
    header: "Δ $/success",
    accessorFn: (c) => c.cost_per_success_delta_usd,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{signed(row.original.cost_per_success_delta_usd, true)}</span>,
  },
];

function RunListView({ onOpen }: { onOpen: (id: string) => void }) {
  const runs = useApi<RunsResponse>("/api/benchmarks", { limit: 100 }, []);
  const rows = runs.data?.runs ?? [];
  const latest = rows[0];

  return (
    <>
      <Stagger className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <HeroStat
          label="Benchmark runs"
          icon={<MetricIcon metric="benchmarkRuns" />}
          loading={runs.loading}
          value={runs.data ? fmtInt(runs.data.total) : "-"}
          sub="node-local, CLI-driven - never leaves this machine"
        />
        <HeroStat
          label="Latest run"
          icon={<MetricIcon metric="latestRun" />}
          loading={runs.loading}
          stale={runs.isStale}
          value={latest ? latest.spec_name : "-"}
          sub={latest ? `${latest.completed_cells}/${latest.planned_cells} cells · ${fmtDateOnly(latest.started_at)}` : "no runs yet"}
        />
        <HeroStat
          label="Latest spend"
          icon={<MetricIcon metric="spend" />}
          loading={runs.loading}
          stale={runs.isStale}
          value={latest ? fmtUSD(latest.spend_usd) : "-"}
          sub="estimated list price, not invoiced"
        />
      </Stagger>

      <ChartShell title="Runs">
        {runs.loading ? (
          <InlineLoading block />
        ) : runs.error && !runs.data ? (
          <ErrorState className="py-6" title="Couldn't load benchmark runs" error={runs.error} onRetry={runs.reload} />
        ) : rows.length === 0 ? (
          <EmptyState
            variant="inline"
            illustration="setup"
            title="No benchmark runs yet"
            body={
              <>
                Run a spec to populate this page:{" "}
                <code className="rounded-1 bg-bg-3 px-1 font-mono">observer benchmark run &lt;spec.toml&gt;</code>
              </>
            }
          >
            <p className="text-[12px] leading-relaxed text-fg-3">
              Dry-run by default; add <code className="rounded-1 bg-bg-3 px-1 font-mono">--confirm-spend</code> to
              drive the harnesses. Report from the CLI with{" "}
              <code className="rounded-1 bg-bg-3 px-1 font-mono">observer benchmark report &lt;run-id&gt;</code>.
            </p>
          </EmptyState>
        ) : (
          <DataTable<RunSummary>
            data={rows}
            columns={RUN_COLUMNS}
            rowKey={(r) => r.run_id}
            onRowClick={(r) => onOpen(r.run_id)}
            minWidth={720}
          />
        )}
      </ChartShell>
    </>
  );
}

function RunDetailView({ runID, onBack }: { runID: string; onBack: () => void }) {
  const detail = useApi<RunDetail>(`/api/benchmarks/${encodeURIComponent(runID)}`, undefined, [runID]);
  const d = detail.data;
  const configs = d?.configs ?? [];
  const comparisons = d?.comparisons ?? [];
  const tasks = d?.tasks ?? [];
  const configColumns = useMemo(() => configColumnsFor(d?.baseline_config ?? ""), [d?.baseline_config]);

  return (
    <>
      <div className="flex flex-wrap items-center gap-2 text-[12px]">
        <button
          type="button"
          onClick={onBack}
          className="rounded-2 border border-line-1 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-1 hover:border-line-2 hover:text-fg-0"
        >
          ← All runs
        </button>
        <a
          href={`/api/benchmarks/${encodeURIComponent(runID)}/export`}
          target="_blank"
          rel="noreferrer"
          className="rounded-2 border border-line-1 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-1 hover:border-line-2 hover:text-fg-0"
        >
          Export JSON
        </a>
        <code className="rounded-1 bg-bg-2 px-1 font-mono text-[11px] text-fg-3">{runID}</code>
      </div>

      {detail.loading && !d ? (
        <InlineLoading block />
      ) : detail.error ? (
        <ChartShell title="Run detail">
          <ErrorState
            className="py-6"
            title="Could not load this run - it may have been deleted (observer benchmark delete)."
            error={detail.error}
            onRetry={detail.reload}
          />
        </ChartShell>
      ) : d ? (
        <>
          <ChartShell
            title={
              <span className="inline-flex flex-wrap items-center gap-2">
                {d.spec_name}
                <VocabPill vocab="benchmarkRun" table={RUN_STATUS} value={d.status} />
              </span>
            }
            sub={
              <>
                Baseline <code className="font-mono text-fg-1">{d.baseline_config}</code> · non-inferiority margin{" "}
                {d.noninferiority_margin > 0 ? `${(d.noninferiority_margin * 100).toFixed(0)}pp` : "none declared"} ·
                sample floor {d.min_sample} · {d.completed_cells}/{d.planned_cells} cells · total spend{" "}
                <span className="font-semibold text-fg-1">{fmtUSD(d.total_spend_usd)}</span>{" "}
                <span className="text-fg-3">({d.price_disclaimer})</span>
              </>
            }
          >
            {configs.length === 0 ? (
              <p className="py-4 text-center text-[12px] text-fg-3">No config rows - the run produced no attempts.</p>
            ) : (
              <DataTable<ConfigReport>
                data={configs}
                columns={configColumns}
                rowKey={(c) => c.config_id}
                rowClassName={() => "align-top"}
                minWidth={820}
              />
            )}
            <p className="mt-2 text-[11px] leading-snug text-fg-3">
              Success uses a Wilson score interval (correct at small repeats); a wide CI (highlighted) means the N is
              too small to rank. Cost is skewed - see the raw per-attempt dots below.
            </p>
          </ChartShell>

          {comparisons.length > 0 && (
            <ChartShell
              title="Comparisons vs baseline"
              sub="Non-inferiority verdicts against the pre-registered margin - never a bare 'parity'. The verdict uses the unpaired independent-proportions (Newcombe) Δ-success CI below; the Paired Δ column is a separate task-blocked diagnostic and does not drive the verdict."
            >
              <DataTable<Comparison>
                data={comparisons}
                columns={COMPARISON_COLUMNS}
                rowKey={(cmp) => cmp.candidate}
                minWidth={640}
              />
            </ChartShell>
          )}

          <ChartShell title="Cost per attempt (raw)" sub="Every attempt's snapshot billed cost - dots, never hidden.">
            <div className="space-y-2.5">
              {configs.map((c) => (
                <div key={c.config_id} className="flex flex-wrap items-center gap-2">
                  <span className="w-40 shrink-0 truncate font-mono text-[11px] text-fg-2" title={c.config_id}>
                    {c.config_id}
                  </span>
                  <CostDots samples={d.cost_dots?.[c.config_id] ?? []} />
                </div>
              ))}
            </div>
          </ChartShell>

          {tasks.length > 0 && (
            <ChartShell title="Per-task results" sub="Pass count / attempts per task × config - the block structure behind the paired analysis.">
              <Table
                minWidth={Math.max(320, 160 + configs.length * 96)}
                head={
                  <tr>
                    <th className="py-1.5 pr-3 font-medium">Task</th>
                    {configs.map((c) => (
                      <th key={c.config_id} className="py-1.5 pr-3 text-right font-mono font-medium">
                        {c.config_id}
                      </th>
                    ))}
                  </tr>
                }
              >
                {tasks.map((t) => (
                  <tr key={t.task_id} className="border-b border-line-1/60 last:border-0">
                    <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-1">{t.task_id}</td>
                    {configs.map((c) => {
                      const cell = t.cells[c.config_id];
                      if (!cell || cell.attempts === 0) {
                        return (
                          <td key={c.config_id} className="py-1.5 pr-3 text-right text-fg-3">
                            -
                          </td>
                        );
                      }
                      const pass = cell.passed === cell.attempts;
                      return (
                        <td
                          key={c.config_id}
                          className={`py-1.5 pr-3 text-right tabular-nums ${pass ? "text-success" : cell.passed === 0 ? "text-danger" : "text-fg-2"}`}
                        >
                          {cell.passed}/{cell.attempts}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </Table>
            </ChartShell>
          )}

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <ChartShell title="Status census" sub="Every terminal attempt status - nothing dropped from the denominator.">
              {Object.keys(d.status_census ?? {}).length === 0 ? (
                <p className="py-2 text-[12px] text-fg-3">No attempts recorded.</p>
              ) : (
                <div className="space-y-1">
                  {Object.entries(d.status_census)
                    .sort((a, b) => b[1] - a[1])
                    .map(([s, n]) => (
                      <div key={s} className="flex items-center justify-between text-[12px]">
                        <code className="font-mono text-[11px] text-fg-2">{s}</code>
                        <span className="tabular-nums text-fg-1">{fmtInt(n)}</span>
                      </div>
                    ))}
                </div>
              )}
            </ChartShell>

            <ChartShell title="Warnings" sub="Honesty guards from the analysis pass.">
              {(d.warnings ?? []).length === 0 ? (
                <p className="py-2 text-[12px] text-fg-3">None - no sample-floor, wide-CI, or flaky-setup flags.</p>
              ) : (
                <ul className="space-y-1.5">
                  {(d.warnings ?? []).map((wmsg, i) => (
                    <li key={i} className="flex items-baseline gap-1.5 text-[11.5px] text-fg-2">
                      <Pill variant="warn">warn</Pill>
                      <span>{wmsg}</span>
                    </li>
                  ))}
                </ul>
              )}
            </ChartShell>
          </div>
        </>
      ) : null}
    </>
  );
}

// CostDots renders each attempt's cost as a dot positioned by value across the
// config's own min..max range — the dataviz "raw attempt dots" over a hidden
// aggregate. A single attempt renders one centered dot; zero renders a hint.
function CostDots({ samples }: { samples: number[] }) {
  if (samples.length === 0) {
    return <span className="text-[11px] text-fg-3">no attempts</span>;
  }
  const min = Math.min(...samples);
  const max = Math.max(...samples);
  const span = max - min;
  return (
    <div className="relative h-4 min-w-[160px] flex-1">
      <div className="absolute top-1/2 h-px w-full -translate-y-1/2 bg-line-1" />
      {samples.map((v, i) => {
        const pct = span > 0 ? ((v - min) / span) * 100 : 50;
        return (
          <span
            key={i}
            title={fmtUSD(v)}
            className="absolute top-1/2 h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-pill border border-accent/40 bg-accent/60"
            style={{ left: `${pct}%` }}
          />
        );
      })}
      <span className="absolute -bottom-4 left-0 text-[10px] tabular-nums text-fg-3">{fmtUSD(min)}</span>
      {span > 0 && (
        <span className="absolute -bottom-4 right-0 text-[10px] tabular-nums text-fg-3">{fmtUSD(max)}</span>
      )}
    </div>
  );
}

function signed(n: number, usd = false): string {
  const s = n >= 0 ? "+" : "";
  return usd ? `${s}${fmtUSD(n)}` : `${s}${n.toFixed(1)}`;
}

