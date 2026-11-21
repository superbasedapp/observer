import type { ReactNode } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { TooltipSpan } from "../../primitives/Tooltip";
import { VocabDefPill as VocabPill } from "../../primitives/VocabDefPill";
import { shortDate } from "../../lib/displayFormat";
import { DATASET_SOURCE, EVAL_VERDICT } from "../../lib/obsVocab";
import { Gauge } from "lucide-react";
import { Pill } from "../../primitives/Pill";
import { parseScorers, scorerLabel } from "./scorers";

// evals - the pure Plane A eval and dataset table columns (B5-0,
// 2026-11-19), promoted from web2/src/pages/obs/Datasets.tsx and
// EvalRunDetail.tsx. The links are slots (the org links into its router, the
// node into its own), so these never import a router.

/** One dataset row (org dataset list; the node's eval datasets). */
export interface PlaneADatasetRow {
  dataset_id: string;
  name: string;
  description: string;
  source: string;
  item_count: number;
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
}

/** One scorer result on an eval run's item. */
export interface PlaneAEvalScore {
  trace_id: string;
  span_id?: string;
  scorer_name: string;
  score: number;
  passed: boolean;
  rationale?: string;
  reviewed: boolean;
}

/** datasetColumns: name (via renderName), items, source, updated, created. */
export function datasetColumns<R extends PlaneADatasetRow>(renderName: (row: R) => ReactNode): ColumnDef<R, any>[] {
  return [
    {
      accessorKey: "name",
      header: "Name",
      cell: ({ row }) => (
        <div className="min-w-0">
          {renderName(row.original)}
          {row.original.description && (
            <div className="truncate text-[11px] text-fg-3">{row.original.description}</div>
          )}
        </div>
      ),
    },
    {
      accessorKey: "item_count",
      header: "Items",
      cell: ({ row }) => row.original.item_count.toLocaleString(),
      meta: { align: "right" },
    },
    {
      id: "source",
      header: "Source",
      cell: ({ row }) => <VocabPill of={DATASET_SOURCE} value={row.original.source} />,
    },
    {
      accessorKey: "updated_at",
      header: "Updated",
      cell: ({ row }) => (
        row.original.updated_by ? (
          <TooltipSpan content={`by ${row.original.updated_by}`}>{shortDate(row.original.updated_at)}</TooltipSpan>
        ) : (
          <span>{shortDate(row.original.updated_at)}</span>
        )
      ),
      meta: { align: "right" },
    },
    {
      accessorKey: "created_at",
      header: "Created",
      cell: ({ row }) => (
        row.original.created_by ? (
          <TooltipSpan content={`by ${row.original.created_by}`}>{shortDate(row.original.created_at)}</TooltipSpan>
        ) : (
          <span>{shortDate(row.original.created_at)}</span>
        )
      ),
      meta: { align: "right" },
    },
  ];
}

/** evalScoreColumns: item (via renderTraceLink when it has a trace), scorer,
 *  verdict, score, reviewed, rationale. */
export function evalScoreColumns<R extends PlaneAEvalScore>(renderTraceLink: (row: R) => ReactNode): ColumnDef<R, any>[] {
  return [
    {
      id: "item",
      header: "Item",
      cell: ({ row }) => {
        const s = row.original;
        return s.trace_id ? (
          renderTraceLink(s)
        ) : (
          <span className="font-mono text-[11px] text-fg-3">-</span>
        );
      },
    },
    {
      accessorKey: "scorer_name",
      header: "Scorer",
      cell: ({ row }) => <span className="font-mono text-[11px] text-fg-2">{row.original.scorer_name}</span>,
    },
    {
      id: "verdict",
      header: "Verdict",
      cell: ({ row }) => <VocabPill of={EVAL_VERDICT} value={row.original.passed ? "pass" : "fail"} />,
    },
    {
      accessorKey: "score",
      header: "Score",
      cell: ({ row }) => row.original.score.toFixed(3),
      meta: { align: "right", mono: true },
    },
    {
      id: "review",
      header: "Reviewed",
      cell: ({ row }) => (row.original.reviewed ? <VocabPill of={EVAL_VERDICT} value="reviewed" /> : <span className="text-fg-4">-</span>),
    },
    {
      id: "rationale",
      header: "Rationale",
      cell: ({ row }) =>
        row.original.rationale ? (
          <span className="block max-w-md truncate text-[11px] text-fg-3" title={row.original.rationale}>
            {row.original.rationale}
          </span>
        ) : (
          <span className="text-fg-4">-</span>
        ),
    },
  ];
}

/** ScorerChips draws an eval run's scorers as chips ("exact_match v1") from
 *  any stored shape (parseScorers); none reads as a dash, never raw JSON. */
export function ScorerChips({ scorers }: { scorers: unknown }) {
  const list = parseScorers(scorers);
  if (list.length === 0) return <span className="text-fg-4">-</span>;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {list.map((s, i) => (
        <Pill key={`${s.name}:${s.version ?? ""}:${i}`} variant="neutral" icon={Gauge} case="none" className="font-mono">
          {scorerLabel(s)}
        </Pill>
      ))}
    </span>
  );
}
