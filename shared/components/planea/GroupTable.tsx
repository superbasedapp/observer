import { useMemo } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Layers } from "lucide-react";
import { compact, dateTime, ms } from "../../lib/displayFormat";
import { InlineEmpty as Empty, PanelCard as Card } from "../../primitives/Panel";
import { TableSkeleton } from "../../primitives/Skeleton";
import { Button } from "../../primitives/Button";
import { DataTable } from "../../primitives/DataTable";
// Aggregate cells: a sum of priced spans, said so in the tooltip (W4-2).
import { PlaneAAggregateCost as Money } from "./costCell";

// GroupTable — the shared, dumb/presentational group-rollup table used by
// both the Traces tab (api.obsTraceGroups) and the Spans tab
// (api.obsSpanGroups) on the org, and the node's Your apps pages (promoted
// from web2/src/pages/obs/GroupTable.tsx, B5-0). Callers map their server
// rows onto GroupDisplayRow (web2 keeps traceGroupToRow/spanGroupToRow) so
// this component never has to know which grouping produced them.

/** The tooltip of an unpriced group's cost cell. */
const UNPRICED_GROUP_TITLE = "No span in this group has a price, so there is no cost to show.";

export interface GroupDisplayRow {
  key: string; // group_key — '' for the honest untagged/no-user/no-session bucket
  label: string;
  count: number;
  errorCount: number;
  tokens: number;
  /** Summed cost of the group's priced spans; null when none is priced, so
   *  the cell reads "Unpriced", never $0.00 (FR-M06). */
  costUsd: number | null;
  avgCostPerTrace?: number | null;
  avgDurationMs?: number;
  p95DurationMs: number;
  lastActivity?: string;
}

export function GroupTable({
  rows,
  countLabel,
  loading,
  truncatedGroups,
  showAvgCostPerTrace,
  showAvgDuration,
  showLastActivity,
  onViewGroup,
  viewLabel = "View",
  note,
}: {
  rows: GroupDisplayRow[];
  // Column header for the count column ("Traces" | "Spans").
  countLabel: string;
  loading?: boolean;
  // Server truncates to its top-N-by-cost groups; when > 0, a note explains
  // the cap rather than silently under-reporting.
  truncatedGroups?: number;
  showAvgCostPerTrace?: boolean;
  showAvgDuration?: boolean;
  showLastActivity?: boolean;
  // When present, renders a per-row action button; omit to render a
  // read-only table.
  onViewGroup?: (row: GroupDisplayRow) => void;
  viewLabel?: string;
  // A server note on how the totals add up (the machine's explorer groups
  // say when one trace counts in full under several groups, FR-M06).
  note?: string;
}) {
  const columns = useMemo<ColumnDef<GroupDisplayRow, any>[]>(() => {
    const cols: ColumnDef<GroupDisplayRow, any>[] = [
      {
        accessorKey: "label",
        header: "Group",
        cell: (c) => <span className="font-medium text-fg-1">{c.row.original.label}</span>,
      },
      {
        accessorKey: "count",
        header: countLabel,
        cell: (c) => compact(c.row.original.count),
        meta: { align: "right" },
      },
      {
        accessorKey: "errorCount",
        header: "Errors",
        cell: (c) => (
          <span className={c.row.original.errorCount > 0 ? "font-semibold text-danger" : "text-fg-3"}>
            {c.row.original.errorCount}
          </span>
        ),
        meta: { align: "right" },
      },
      {
        accessorKey: "tokens",
        header: "Tokens",
        cell: (c) => compact(c.row.original.tokens),
        meta: { align: "right" },
      },
      {
        accessorKey: "costUsd",
        header: "Cost",
        cell: (c) =>
          c.row.original.costUsd == null ? (
            <span className="text-fg-3" title={UNPRICED_GROUP_TITLE}>
              Unpriced
            </span>
          ) : (
            <Money usd={c.row.original.costUsd} tokens={c.row.original.tokens} />
          ),
        meta: { align: "right", mono: true },
      },
    ];
    if (showAvgCostPerTrace) {
      cols.push({
        id: "avgCostPerTrace",
        header: "Avg cost/trace",
        cell: (c) =>
          c.row.original.avgCostPerTrace != null ? (
            <Money usd={c.row.original.avgCostPerTrace} />
          ) : (
            "-"
          ),
        meta: { align: "right", mono: true },
      });
    }
    if (showAvgDuration) {
      cols.push({
        id: "avgDurationMs",
        header: "Avg duration",
        cell: (c) => (c.row.original.avgDurationMs != null ? ms(c.row.original.avgDurationMs) : "-"),
        meta: { align: "right" },
      });
    }
    cols.push({
      accessorKey: "p95DurationMs",
      header: "p95 duration",
      cell: (c) => ms(c.row.original.p95DurationMs),
      meta: { align: "right" },
    });
    if (showLastActivity) {
      cols.push({
        id: "lastActivity",
        header: "Last activity",
        cell: (c) => (c.row.original.lastActivity ? dateTime(c.row.original.lastActivity) : "-"),
        meta: { align: "right" },
      });
    }
    if (onViewGroup) {
      cols.push({
        id: "view",
        header: "",
        // A group with no key (the "no end user" bucket) has nothing to
        // filter by, so it gets no drill-in button.
        cell: (c) =>
          c.row.original.key ? (
            <Button
              size="sm"
              variant="ghost"
              onClick={(e) => {
                e.stopPropagation();
                onViewGroup(c.row.original);
              }}
            >
              {viewLabel}
            </Button>
          ) : null,
      });
    }
    return cols;
  }, [countLabel, showAvgCostPerTrace, showAvgDuration, showLastActivity, onViewGroup, viewLabel]);

  return (
    <Card className="p-3">
      {loading && rows.length === 0 ? (
        <TableSkeleton rows={6} />
      ) : rows.length === 0 ? (
        <Empty icon={Layers} message="No groups in this window." />
      ) : (
        <>
          <DataTable
            data={rows}
            columns={columns}
            rowKey={(r) => r.key}
            initialSort={[{ id: "costUsd", desc: true }]}
            zebra
            minWidth={760}
            loading={loading}
          />
          {note && <p className="mt-2 text-[11px] text-fg-3">{note}</p>}
          {!!truncatedGroups && truncatedGroups > 0 && (
            <p className="mt-2 text-[11px] text-fg-3">
              Showing the top {rows.length} groups by cost. {truncatedGroups} more group
              {truncatedGroups === 1 ? "" : "s"} not shown.
            </p>
          )}
        </>
      )}
    </Card>
  );
}
