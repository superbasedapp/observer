import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { FlaskConical } from "lucide-react";
import { ChartShell, DataTable, EmptyState, PageHeader, SlideOver, StatCard, StatStrip, TableSkeleton, ErrorState, InlineLoading } from "@/components/primitives";
import { VocabPill } from "@shared/lib/vocabPill";
import { JOB_STATUS } from "@shared/lib/sessionVocab";
import { VocabDefPill } from "@shared/primitives/VocabDefPill";
import { EVAL_VERDICT } from "@shared/lib/obsVocab";
import { ScorerChips, evalScoreColumns, type PlaneAEvalScore } from "@shared/components/planea/evals";
import { compact, dateTime, num, pct1 } from "@shared/lib/displayFormat";
import { GatedLink } from "@/components/GatedLink";
import { useApi } from "@/lib/useApi";
import { navIcon } from "@/lib/nav";
import type { AppEvalDataset, AppEvalRun, AppEvalRunDetail } from "@/lib/planeaApi";
import { AppsGate, ReadState } from "@/components/apps/AppsChrome";
import { AppReviewQueues } from "@/components/apps/AppReviewQueues";
import { AppsMetricIcon } from "@/components/apps/AppsMetricIcon";

// Your apps > Evals (Plane A lane B5, plan W2-5, node parity for W3-2): the
// machine's eval datasets and runs (GET /api/obs/eval/datasets, /runs,
// /run/{id}; experiments posted by the SDK land here as runs,
// contracts/experiments.md section 6). A run opens its per-item scores in
// the shared eval-score columns.

export function AppEvalsPage() {
  const [sp, setSp] = useSearchParams();
  const runId = sp.get("run");
  const datasets = useApi<{ datasets: AppEvalDataset[] }>("/api/obs/eval/datasets");
  const runs = useApi<{ runs: AppEvalRun[] }>("/api/obs/eval/runs", { limit: 200 });
  const open = (id: string | null) => {
    const next = new URLSearchParams(sp);
    if (id) next.set("run", id);
    else next.delete("run");
    setSp(next, { replace: true });
  };
  const dsColumns = useMemo<ColumnDef<AppEvalDataset, any>[]>(
    () => [
      {
        accessorKey: "name",
        header: "Dataset",
        cell: (c) => (
          <div className="min-w-0">
            <div className="font-medium text-fg-1">{c.row.original.name}</div>
            {c.row.original.description && <div className="truncate text-[11px] text-fg-3">{c.row.original.description}</div>}
          </div>
        ),
      },
      { accessorKey: "item_count", header: "Items", cell: (c) => num(c.row.original.item_count), meta: { align: "right" } },
      { accessorKey: "created_at", header: "Created", cell: (c) => dateTime(c.row.original.created_at), meta: { align: "right" } },
    ],
    [],
  );
  const runColumns = useMemo<ColumnDef<AppEvalRun, any>[]>(
    () => [
      { accessorKey: "name", header: "Run", cell: (c) => <span className="font-medium text-fg-1">{c.row.original.name || `run ${c.row.original.id}`}</span> },
      { accessorKey: "dataset_name", header: "Dataset" },
      { accessorKey: "scorers", header: "Scorers", cell: (c) => <ScorerChips scorers={c.row.original.scorers} /> },
      { accessorKey: "status", header: "Status", cell: (c) => <VocabPill vocab="jobStatus" table={JOB_STATUS} value={c.row.original.status} /> },
      {
        id: "pass",
        header: "Passed",
        cell: (c) => (c.row.original.total > 0 ? `${c.row.original.passed}/${c.row.original.total} (${pct1(c.row.original.passed / c.row.original.total)})` : "-"),
        meta: { align: "right" },
      },
      { accessorKey: "mean_score", header: "Mean score", cell: (c) => c.row.original.mean_score.toFixed(3), meta: { align: "right", mono: true } },
      { accessorKey: "started_at", header: "Started", cell: (c) => dateTime(c.row.original.started_at), meta: { align: "right" } },
    ],
    [],
  );
  const runRows = runs.data?.runs ?? [];
  const dsRows = datasets.data?.datasets ?? [];
  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("app-evals")}
        title="Evals"
        sub="Datasets of your apps' traces and the eval runs scored against them, including the SDK's experiments."
      />
      <AppsGate>
        <StatStrip cols={3} ariaLabel="Evals summary" className="">
          <StatCard label="Datasets" icon={<AppsMetricIcon metric="datasets" />} loading={datasets.loading} value={compact(dsRows.length)} />
          <StatCard label="Runs" icon={<AppsMetricIcon metric="runs" />} loading={runs.loading} value={compact(runRows.length)} />
          <StatCard
            label="Items scored"
            icon={<AppsMetricIcon metric="items" />}
            loading={runs.loading}
            value={compact(runRows.reduce((s, r) => s + r.total, 0))}
          />
        </StatStrip>
        <ChartShell title="Runs">
          <ReadState error={runs.error} onRetry={runs.reload} feature="Eval runs" />
          {runs.loading && !runs.data ? (
            <TableSkeleton rows={6} />
          ) : !runs.error && runRows.length === 0 ? (
            <EmptyState
              variant="inline"
              icon={FlaskConical}
              title="No eval runs yet"
              body="Run an experiment from the SDK: each run and its scores land here."
            />
          ) : (
            !runs.error && <DataTable data={runRows} columns={runColumns} rowKey={(r) => String(r.id)} onRowClick={(r) => open(String(r.id))} zebra minWidth={900} />
          )}
        </ChartShell>
        <ChartShell title="Datasets">
          <ReadState error={datasets.error} onRetry={datasets.reload} feature="Datasets" />
          {datasets.loading && !datasets.data ? (
            <TableSkeleton rows={4} />
          ) : !datasets.error && dsRows.length === 0 ? (
            <EmptyState variant="inline" title="No datasets yet" body="An experiment from the SDK creates its dataset here." />
          ) : (
            !datasets.error && <DataTable data={dsRows} columns={dsColumns} rowKey={(r) => String(r.id)} zebra minWidth={620} />
          )}
        </ChartShell>
        <AppReviewQueues />
      </AppsGate>
      <SlideOver open={runId !== null} onClose={() => open(null)} width={880} bodyClassName="p-5" title="Eval run" subtitle={runId ?? undefined}>
        {runId && <RunDetail key={runId} id={runId} />}
      </SlideOver>
    </div>
  );
}

function RunDetail({ id }: { id: string }) {
  const q = useApi<AppEvalRunDetail>(`/api/obs/eval/run/${encodeURIComponent(id)}`);
  const columns = useMemo(
    () =>
      evalScoreColumns<PlaneAEvalScore & { item_id: number }>((s) => (
        <GatedLink
          to={`/apps/traces?trace=${encodeURIComponent(s.trace_id)}`}
          managed={<span className="font-mono text-[11px] text-fg-3">{(s.span_id || s.trace_id).slice(0, 10)}</span>}
          className="font-mono text-[11px] text-accent hover:underline"
        >
          {(s.span_id || s.trace_id).slice(0, 10)}
        </GatedLink>
      )),
    [],
  );
  if (q.error) return <ErrorState error={q.error} onRetry={q.reload} />;
  if (!q.data) return <InlineLoading label="Loading the run..." />;
  const { run, scores } = q.data;
  const rows = scores.map((s) => ({
    item_id: s.item_id,
    trace_id: s.trace_id,
    span_id: s.span_id,
    scorer_name: s.scorer,
    score: s.score,
    passed: s.passed,
    rationale: s.rationale,
    reviewed: false,
  }));
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-[12px] text-fg-2">
        <span className="font-medium text-fg-1">{run.name || `run ${run.id}`}</span>
        <span className="text-fg-3">·</span>
        <span>{run.dataset_name}</span>
        <span className="text-fg-3">·</span>
        <VocabDefPill of={EVAL_VERDICT} value={run.total > 0 && run.passed === run.total ? "pass" : "fail"}>
          {run.passed}/{run.total} passed
        </VocabDefPill>
        <span className="text-fg-3">·</span>
        <span>{dateTime(run.started_at)}</span>
      </div>
      <DataTable data={rows} columns={columns} rowKey={(r) => `${r.item_id}:${r.scorer_name}`} zebra minWidth={760} />
    </div>
  );
}
