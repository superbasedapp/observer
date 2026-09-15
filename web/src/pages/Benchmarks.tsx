import { type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { HeroStat, PageHeader, Pill } from "@/components/primitives";
import { PercentIcon } from "@/components/icons";
import { useApi } from "@/lib/useApi";
import { fmtDateOnly, fmtDateTime, fmtDuration, fmtInt, fmtUSD } from "@/lib/format";

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

const VERDICT_VARIANT: Record<string, "success" | "warn" | "danger" | "neutral"> = {
  candidate_cheaper_noninferior: "success",
  candidate_worse: "danger",
  no_detected_difference: "neutral",
  inconclusive: "warn",
  insufficient_distinct_tasks: "warn",
};
const VERDICT_LABEL: Record<string, string> = {
  candidate_cheaper_noninferior: "cheaper · non-inferior",
  candidate_worse: "worse",
  no_detected_difference: "no detected difference",
  inconclusive: "inconclusive",
  insufficient_distinct_tasks: "too few distinct tasks",
};

function statusVariant(s: string): "success" | "info" | "warn" | "danger" | "neutral" {
  switch (s) {
    case "completed":
      return "success";
    case "running":
      return "info";
    case "budget_stop":
      return "warn";
    case "aborted":
    case "error":
      return "danger";
    default:
      return "neutral";
  }
}

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
    <div className="space-y-4 p-5">
      <PageHeader
        title="Benchmarks"
        sub="Harness × model comparisons grounded in billed-token truth - success ± Wilson CI, expected cost per successful completion, and non-inferiority verdicts over a pinned task corpus. Runs are launched from the CLI (observer benchmark run); this page reads the results."
      />
      {run ? <RunDetailView runID={run} onBack={() => setRun("")} /> : <RunListView onOpen={setRun} />}
    </div>
  );
}

function RunListView({ onOpen }: { onOpen: (id: string) => void }) {
  const runs = useApi<RunsResponse>("/api/benchmarks", { limit: 100 }, []);
  const rows = runs.data?.runs ?? [];
  const latest = rows[0];

  return (
    <>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <HeroStat
          label="Benchmark runs"
          icon={<PercentIcon />}
          loading={runs.loading}
          value={runs.data ? fmtInt(runs.data.total) : "-"}
          sub="node-local, CLI-driven - never leaves this machine"
        />
        <HeroStat
          label="Latest run"
          loading={runs.loading}
          value={latest ? latest.spec_name : "-"}
          sub={latest ? `${latest.completed_cells}/${latest.planned_cells} cells · ${fmtDateOnly(latest.started_at)}` : "no runs yet"}
        />
        <HeroStat
          label="Latest spend"
          loading={runs.loading}
          value={latest ? fmtUSD(latest.spend_usd) : "-"}
          sub="estimated list price, not invoiced"
        />
      </div>

      <Section title="Runs">
        {runs.loading ? (
          <Loading />
        ) : rows.length === 0 ? (
          <div className="py-10 text-center text-[12px] leading-relaxed text-fg-3">
            <p className="text-[13px] font-semibold text-fg-2">No benchmark runs yet</p>
            <p className="mt-1">
              Run a spec to populate this page:{" "}
              <code className="rounded-1 bg-bg-2 px-1 font-mono">observer benchmark run &lt;spec.toml&gt;</code>
            </p>
            <p className="mt-1 text-fg-3">
              Dry-run by default; add <code className="rounded-1 bg-bg-2 px-1 font-mono">--confirm-spend</code> to
              drive the harnesses. Report from the CLI with{" "}
              <code className="rounded-1 bg-bg-2 px-1 font-mono">observer benchmark report &lt;run-id&gt;</code>.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                  <th className="py-1.5 pr-3 font-semibold">Spec</th>
                  <th className="py-1.5 pr-3 font-semibold">Status</th>
                  <th className="py-1.5 pr-3 font-semibold">Matrix</th>
                  <th className="py-1.5 pr-3 font-semibold">Cells</th>
                  <th className="py-1.5 pr-3 text-right font-semibold">Spend</th>
                  <th className="py-1.5 pr-3 font-semibold">Started</th>
                  <th className="py-1.5 font-semibold">Harnesses</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr
                    key={r.run_id}
                    onClick={() => onOpen(r.run_id)}
                    className="cursor-pointer border-b border-line-1/60 transition-colors hover:bg-bg-2/60"
                  >
                    <td className="py-1.5 pr-3">
                      <span className="font-semibold text-fg-1">{r.spec_name}</span>
                      <code className="ml-1.5 rounded-1 bg-bg-2 px-1 font-mono text-[10px] text-fg-3">
                        {r.run_id}
                      </code>
                    </td>
                    <td className="py-1.5 pr-3">
                      <Pill variant={statusVariant(r.status)}>{r.status}</Pill>
                    </td>
                    <td className="whitespace-nowrap py-1.5 pr-3 tabular-nums text-fg-2">
                      {r.configs}×{r.tasks}
                      <span className="text-fg-3"> ·{r.repeats}rep</span>
                    </td>
                    <td className="whitespace-nowrap py-1.5 pr-3 tabular-nums text-fg-2">
                      {r.completed_cells}/{r.planned_cells}
                    </td>
                    <td className="whitespace-nowrap py-1.5 pr-3 text-right tabular-nums text-fg-2">
                      {fmtUSD(r.spend_usd)}
                    </td>
                    <td className="whitespace-nowrap py-1.5 pr-3 text-fg-3">
                      {fmtDateTime(r.started_at)}
                    </td>
                    <td className="py-1.5 font-mono text-[11px] text-fg-3">{r.harnesses.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </>
  );
}

function RunDetailView({ runID, onBack }: { runID: string; onBack: () => void }) {
  const detail = useApi<RunDetail>(`/api/benchmarks/${encodeURIComponent(runID)}`, undefined, [runID]);
  const d = detail.data;
  const configs = d?.configs ?? [];
  const comparisons = d?.comparisons ?? [];
  const tasks = d?.tasks ?? [];

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
        <Loading />
      ) : detail.error ? (
        <Section title="Run detail">
          <p className="py-6 text-center text-[12px] text-danger">
            Could not load this run - it may have been deleted (
            <code className="font-mono">observer benchmark delete</code>). {detail.error.message}
          </p>
        </Section>
      ) : d ? (
        <>
          <Section
            title={
              <span className="inline-flex flex-wrap items-center gap-2">
                {d.spec_name}
                <Pill variant={statusVariant(d.status)}>{d.status}</Pill>
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
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[12px]">
                  <thead>
                    <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                      <th className="py-1.5 pr-3 font-semibold">Config</th>
                      <th className="py-1.5 pr-3 font-semibold">Model</th>
                      <th className="py-1.5 pr-3 font-semibold">Success (95% CI)</th>
                      <th className="py-1.5 pr-3 font-semibold">N pl/ex/sc/pass</th>
                      <th className="py-1.5 pr-3 text-right font-semibold">Cost / success</th>
                      <th className="py-1.5 pr-3 text-right font-semibold">Mean $</th>
                      <th className="py-1.5 pr-3 text-right font-semibold">Cache %</th>
                      <th className="py-1.5 font-semibold">Mean wall</th>
                    </tr>
                  </thead>
                  <tbody>
                    {configs.map((c) => {
                      const wide = c.success_ci.hi - c.success_ci.lo > 0.5;
                      return (
                        <tr key={c.config_id} className="border-b border-line-1/60 align-top">
                          <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-1">
                            {c.config_id}
                            {c.config_id === d.baseline_config && (
                              <>
                                {" "}
                                <Pill variant="info">baseline</Pill>
                              </>
                            )}
                          </td>
                          <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-2">{c.model}</td>
                          <td className="whitespace-nowrap py-1.5 pr-3 tabular-nums">
                            {c.n_executed === 0 ? (
                              <span className="text-fg-3">no attempts</span>
                            ) : (
                              <span className="text-fg-1">
                                {(c.success_rate * 100).toFixed(0)}%{" "}
                                <span className={wide ? "text-warn" : "text-fg-3"}>
                                  [{(c.success_ci.lo * 100).toFixed(0)}–{(c.success_ci.hi * 100).toFixed(0)}]
                                </span>
                              </span>
                            )}
                          </td>
                          <td className="whitespace-nowrap py-1.5 pr-3 tabular-nums text-fg-2">
                            {c.n_planned}/{c.n_executed}/{c.n_scored}/{c.n_passed}
                          </td>
                          <td className="whitespace-nowrap py-1.5 pr-3 text-right tabular-nums text-fg-2">
                            {c.cost_per_success_usd == null ? (
                              <span className="text-fg-3" title="No successful attempts - cost per success is undefined (censored)">
                                n/a
                              </span>
                            ) : (
                              fmtUSD(c.cost_per_success_usd)
                            )}
                          </td>
                          <td className="whitespace-nowrap py-1.5 pr-3 text-right tabular-nums text-fg-2">
                            {fmtUSD(c.mean_cost_per_attempt_usd)}
                          </td>
                          <td className="py-1.5 pr-3 text-right tabular-nums text-fg-2">
                            {c.cache_read_pct.toFixed(0)}%
                          </td>
                          <td className="whitespace-nowrap py-1.5 tabular-nums text-fg-2">
                            {c.mean_wall_ms > 0 ? fmtDuration(c.mean_wall_ms) : "-"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            <p className="mt-2 text-[11px] leading-snug text-fg-3">
              Success uses a Wilson score interval (correct at small repeats); a wide CI (highlighted) means the N is
              too small to rank. Cost is skewed - see the raw per-attempt dots below.
            </p>
          </Section>

          {comparisons.length > 0 && (
            <Section
              title="Comparisons vs baseline"
              sub="Non-inferiority verdicts against the pre-registered margin - never a bare 'parity'. The verdict uses the unpaired independent-proportions (Newcombe) Δ-success CI below; the Paired Δ column is a separate task-blocked diagnostic and does not drive the verdict."
            >
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[12px]">
                  <thead>
                    <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                      <th className="py-1.5 pr-3 font-semibold">Candidate</th>
                      <th className="py-1.5 pr-3 font-semibold">Verdict</th>
                      <th className="py-1.5 pr-3 font-semibold">Δ success (95% CI)</th>
                      <th className="py-1.5 pr-3 font-semibold">Paired Δ</th>
                      <th className="py-1.5 pr-3 font-semibold">Cheaper</th>
                      <th className="py-1.5 text-right font-semibold">Δ $/success</th>
                    </tr>
                  </thead>
                  <tbody>
                    {comparisons.map((cmp) => (
                      <tr key={cmp.candidate} className="border-b border-line-1/60">
                        <td className="py-1.5 pr-3 font-mono text-[11px] text-fg-1">{cmp.candidate}</td>
                        <td className="py-1.5 pr-3">
                          <Pill variant={VERDICT_VARIANT[cmp.verdict] ?? "neutral"}>
                            {VERDICT_LABEL[cmp.verdict] ?? cmp.verdict}
                          </Pill>
                        </td>
                        <td className="whitespace-nowrap py-1.5 pr-3 tabular-nums text-fg-2">
                          {signed(cmp.success_diff_ci.point * 100)}pp [{signed(cmp.success_diff_ci.lo * 100)},{" "}
                          {signed(cmp.success_diff_ci.hi * 100)}]
                        </td>
                        <td className="whitespace-nowrap py-1.5 pr-3 tabular-nums text-fg-2">
                          {signed(cmp.paired_delta.point * 100)}pp
                          <span className="text-fg-3"> ({cmp.paired_tasks} tasks)</span>
                        </td>
                        <td className="py-1.5 pr-3 text-fg-2">{cmp.cheaper ? "yes" : "no"}</td>
                        <td className="whitespace-nowrap py-1.5 text-right tabular-nums text-fg-2">
                          {signed(cmp.cost_per_success_delta_usd, true)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          )}

          <Section title="Cost per attempt (raw)" sub="Every attempt's snapshot billed cost - dots, never hidden.">
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
          </Section>

          {tasks.length > 0 && (
            <Section title="Per-task results" sub="Pass count / attempts per task × config - the block structure behind the paired analysis.">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[12px]">
                  <thead>
                    <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                      <th className="py-1.5 pr-3 font-semibold">Task</th>
                      {configs.map((c) => (
                        <th key={c.config_id} className="py-1.5 pr-3 text-right font-mono text-[10px] font-semibold">
                          {c.config_id}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {tasks.map((t) => (
                      <tr key={t.task_id} className="border-b border-line-1/60">
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
                  </tbody>
                </table>
              </div>
            </Section>
          )}

          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <Section title="Status census" sub="Every terminal attempt status - nothing dropped from the denominator.">
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
            </Section>

            <Section title="Warnings" sub="Honesty guards from the analysis pass.">
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
            </Section>
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
            className="absolute top-1/2 h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-full border border-accent/40 bg-accent/60"
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

// Section mirrors the Routing/Security page card shape.
function Section({
  title,
  sub,
  right,
  children,
}: {
  title: ReactNode;
  sub?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-3 border border-line-1 bg-bg-1 p-4">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h2 className="text-[13px] font-semibold text-fg-0">{title}</h2>
          {sub && <p className="mt-0.5 max-w-3xl text-[11.5px] leading-snug text-fg-3">{sub}</p>}
        </div>
        {right && <div className="flex flex-wrap items-center gap-2">{right}</div>}
      </div>
      {children}
    </section>
  );
}

function Loading() {
  return <div className="py-8 text-center text-[12px] text-fg-3">Loading…</div>;
}
