import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { Star } from "lucide-react";
import { ChartShell, ComboChip, DataTable, EmptyState, PageHeader, Select, TableSkeleton, type ComboOption } from "@/components/primitives";
import { VocabDefPill } from "@shared/primitives/VocabDefPill";
import { vocabView } from "@shared/lib/vocabDef";
import { SCORE_KIND, SCORE_SOURCE } from "@shared/lib/obsVocab";
import { compact, dateTime, pct1 } from "@shared/lib/displayFormat";
import { GatedLink } from "@/components/GatedLink";
import { useApi } from "@/lib/useApi";
import { navIcon } from "@/lib/nav";
import type { AppScore, AppScoreSummaryRow, AppScoresResult } from "@/lib/planeaApi";
import { AppsGate, ReadState } from "@/components/apps/AppsChrome";

// Your apps > Scores (Plane A lane B5, node parity for W3-1): scores and user
// feedback on your apps' traces, as the SDK's score() / feedback() and the
// OTel gen_ai.evaluation.result event write them on this machine. Routes are
// lane B7's (contracts/scores.md section 6): GET /api/obs/scores/summary and
// GET /api/obs/scores. Comments are shown as stored (content stays local).

// The Source filter's choices: every SCORE_SOURCE value, by its label.
const SOURCE_OPTIONS = [
  { value: "", label: "Any source" },
  ...Object.keys(SCORE_SOURCE.entries).map((v) => {
    const label = vocabView(SCORE_SOURCE, v).label;
    return { value: v, label: label.charAt(0).toUpperCase() + label.slice(1) };
  }),
];

function fmtNum(v: number | null | undefined): string {
  return typeof v === "number" && Number.isFinite(v) ? (Math.abs(v) >= 100 ? compact(v) : v.toFixed(3)) : "-";
}

export function AppScoresPage() {
  const [sp, setSp] = useSearchParams();
  const name = sp.get("name") ?? "";
  const source = sp.get("source") ?? "";
  const set = (k: string, v: string) => {
    const next = new URLSearchParams(sp);
    if (v) next.set(k, v);
    else next.delete(k);
    setSp(next, { replace: true });
  };
  const summary = useApi<{ summary?: AppScoreSummaryRow[]; rows?: AppScoreSummaryRow[] }>("/api/obs/scores/summary");
  const listParams: Record<string, string | number> = { limit: 200 };
  if (name) listParams.name = name;
  if (source) listParams.source = source;
  const list = useApi<AppScoresResult>("/api/obs/scores", listParams, [name, source]);
  const sumRows = summary.data?.summary ?? summary.data?.rows ?? [];
  // The Score filter picks a name the summary lists (never typed); a name
  // from a link that the summary no longer lists stays selectable.
  const nameOptions = useMemo<ComboOption[]>(() => {
    const names = [...new Set(sumRows.map((r) => r.name))].sort();
    if (name && !names.includes(name)) names.unshift(name);
    return [{ value: "", label: "Any score", searchable: "any all" }, ...names.map((n) => ({ value: n, label: n, searchable: n.toLowerCase() }))];
  }, [sumRows, name]);

  const sumColumns = useMemo<ColumnDef<AppScoreSummaryRow, any>[]>(
    () => [
      {
        accessorKey: "name",
        header: "Score",
        cell: (c) => (
          <button type="button" className="font-medium text-accent hover:underline" onClick={() => set("name", c.row.original.name)}>
            {c.row.original.name}
          </button>
        ),
      },
      { accessorKey: "source", header: "Source", cell: (c) => <VocabDefPill of={SCORE_SOURCE} value={c.row.original.source} /> },
      { accessorKey: "kind", header: "Kind", cell: (c) => <VocabDefPill of={SCORE_KIND} value={c.row.original.kind} /> },
      { accessorKey: "count", header: "Count", cell: (c) => compact(c.row.original.count), meta: { align: "right" } },
      {
        id: "value",
        header: "Value",
        cell: (c) => {
          const r = c.row.original;
          if (r.kind === "boolean") return r.true_rate != null ? `${pct1(r.true_rate)} true` : "-";
          if (r.kind === "categorical") return (r.top_values ?? []).slice(0, 3).map((t) => `${t.value} (${t.count})`).join(", ") || "-";
          return `mean ${fmtNum(r.mean)} · p50 ${fmtNum(r.p50)} · ${fmtNum(r.min)}..${fmtNum(r.max)}`;
        },
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [sp],
  );
  const listColumns = useMemo<ColumnDef<AppScore, any>[]>(
    () => [
      { accessorKey: "name", header: "Score", cell: (c) => <span className="font-medium text-fg-1">{c.row.original.name}</span> },
      { accessorKey: "value", header: "Value", cell: (c) => <span className="font-mono text-[12px]">{c.row.original.value}</span> },
      { accessorKey: "source", header: "Source", cell: (c) => <VocabDefPill of={SCORE_SOURCE} value={c.row.original.source} /> },
      {
        id: "scorer",
        header: "Scorer",
        cell: (c) => {
          const s = c.row.original.scorer;
          return s?.name ? `${s.name}${s.version ? ` v${s.version}` : ""}` : "-";
        },
      },
      {
        id: "trace",
        header: "Trace",
        cell: (c) => (
          <GatedLink
            to={`/apps/traces?trace=${encodeURIComponent(c.row.original.trace_id)}`}
            managed={<span className="font-mono text-[11px] text-fg-3">{(c.row.original.span_id || c.row.original.trace_id).slice(0, 10)}</span>}
            className="font-mono text-[11px] text-accent hover:underline"
          >
            {(c.row.original.span_id || c.row.original.trace_id).slice(0, 10)}
          </GatedLink>
        ),
      },
      {
        id: "comment",
        header: "Comment",
        cell: (c) =>
          c.row.original.comment ? (
            <span className="block max-w-md truncate text-[11px] text-fg-3" title={c.row.original.comment}>
              {c.row.original.comment}
            </span>
          ) : c.row.original.comment_present ? (
            <span className="text-[11px] italic text-fg-4">stored as a hash only</span>
          ) : (
            <span className="text-fg-4">-</span>
          ),
      },
      { accessorKey: "created_at", header: "When", cell: (c) => dateTime(c.row.original.created_at), meta: { align: "right" } },
    ],
    [],
  );
  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("app-scores")}
        title="Scores"
        sub="Scores and user feedback on your apps' traces, from the SDK, your eval runs and OpenTelemetry evaluation events."
      />
      <AppsGate>
        <ChartShell title="Summary">
          <ReadState error={summary.error} onRetry={summary.reload} feature="Scores" />
          {summary.loading && !summary.data ? (
            <TableSkeleton rows={4} />
          ) : !summary.error && sumRows.length === 0 ? (
            <EmptyState
              variant="inline"
              icon={Star}
              title="No scores yet"
              body="Send one with the SDK's score or feedback call, or run an eval: the scores land here."
            />
          ) : (
            !summary.error && <DataTable data={sumRows} columns={sumColumns} rowKey={(r) => `${r.name}:${r.source}:${r.kind}`} zebra minWidth={720} />
          )}
        </ChartShell>
        <ChartShell
          title="Newest scores"
          stale={list.isStale}
          right={
            <div className="flex flex-wrap items-center gap-2">
              <ComboChip label="Score" value={name} onChange={(v) => set("name", v)} options={nameOptions} popoverWidth={260} />
              <Select aria-label="Source" className="w-auto" value={source} onChange={(e) => set("source", e.target.value)} options={SOURCE_OPTIONS} />
            </div>
          }
        >
          {list.error ? null : list.loading && !list.data ? (
            <TableSkeleton rows={6} />
          ) : (list.data?.scores.length ?? 0) === 0 ? (
            <EmptyState variant="inline" title="No scores match" body="Clear the score or source filter to see every score." />
          ) : (
            <DataTable data={list.data?.scores ?? []} columns={listColumns} rowKey={(r) => r.id} zebra minWidth={900} />
          )}
          <ReadState error={list.error} onRetry={list.reload} feature="Scores" />
        </ChartShell>
      </AppsGate>
    </div>
  );
}
