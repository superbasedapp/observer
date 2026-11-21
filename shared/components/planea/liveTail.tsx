import { useMemo } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Eraser, Pause, Play, Radio } from "lucide-react";
import { dateTime, ms } from "../../lib/displayFormat";
import { TRACE_STATUS } from "../../lib/obsVocab";
import { Button } from "../../primitives/Button";
import { DataTable } from "../../primitives/DataTable";
import { LiveDot, type LiveTone } from "../../primitives/LiveDot";
import { InlineEmpty } from "../../primitives/Panel";
import { VocabDefPill as VocabPill } from "../../primitives/VocabDefPill";
import { ErrorCountBadge, ModelCell } from "./chips";
import { ServiceCell } from "./identity";
import { PlaneAMoney } from "./money";
import type { PlaneATailRow } from "./explorerViewsModel";

// The Plane A explorer's live tail (W5-4, lane C9): the traces that arrived
// after a cursor and match the explorer's filters, on the org by polling
// GET /api/org/obs/live-tail and on the machine by server-sent events from
// GET /api/obs/explorer/tail/stream (or polling /api/obs/explorer/tail).
// Contract: docs/plans/plane-a-sdk-buildout/contracts/alerts.md "Live tail".
// Pure: the rows come in through props; the app holds the cursor, the
// polling or stream, and the buffer (mergeTail). Drawn with the shared
// Button, LiveDot, DataTable and the trace status vocabulary (design pass
// 2026-11-21: it used hand-rolled buttons, a plain table and the raw status).

export type PlaneATailState = "live" | "paused" | "reconnecting" | "stopped";

// TAIL_STATE: one row per connection state (label, dot tone, ping).
const TAIL_STATE: Record<PlaneATailState, { label: string; tone: LiveTone; still: boolean }> = {
  live: { label: "Live", tone: "success", still: false },
  paused: { label: "Paused", tone: "idle", still: true },
  reconnecting: { label: "Reconnecting...", tone: "warn", still: false },
  stopped: { label: "Stopped", tone: "idle", still: true },
};

// LiveTailPanel renders the tail buffer, newest first, with a pause switch
// and the connection state. onOpen opens a trace in the app's inspector.
export function LiveTailPanel<R extends PlaneATailRow>({
  rows,
  state,
  onTogglePause,
  onClear,
  onOpen,
  note,
}: {
  rows: R[];
  state: PlaneATailState;
  onTogglePause: () => void;
  onClear: () => void;
  onOpen?: (traceId: string) => void;
  note?: string;
}) {
  const st = TAIL_STATE[state];
  const columns = useMemo<ColumnDef<R, any>[]>(
    () => [
      {
        id: "trace",
        header: "Trace",
        cell: (c) => (
          <span className="block max-w-[240px] truncate font-medium text-fg-1" title={c.row.original.trace_id}>
            {c.row.original.root_name || c.row.original.trace_id}
          </span>
        ),
      },
      {
        id: "status",
        header: "Status",
        cell: (c) => (
          <span className="inline-flex items-center gap-1">
            {c.row.original.status ? <VocabPill of={TRACE_STATUS} value={c.row.original.status} /> : <span className="text-fg-4">-</span>}
            <ErrorCountBadge count={c.row.original.error_count} />
          </span>
        ),
      },
      { id: "model", header: "Model", cell: (c) => <ModelCell model={c.row.original.model} provider={c.row.original.provider} /> },
      { id: "service", header: "Service", cell: (c) => <ServiceCell row={c.row.original} /> },
      {
        id: "cost",
        header: "Cost",
        // No cost on the row is "not priced", never a zero.
        cell: (c) =>
          c.row.original.cost_usd == null ? (
            <span className="text-fg-4">-</span>
          ) : (
            <PlaneAMoney usd={c.row.original.cost_usd} tokens={c.row.original.total_tokens} />
          ),
        meta: { align: "right", mono: true },
      },
      { id: "duration", header: "Duration", cell: (c) => ms(c.row.original.duration_ms ?? 0), meta: { align: "right" } },
      {
        id: "started",
        header: "Started",
        cell: (c) => (c.row.original.started_at ? dateTime(c.row.original.started_at) : "-"),
        meta: { align: "right" },
      },
    ],
    [],
  );
  return (
    <div className="space-y-2" aria-label="Live tail">
      <div className="flex flex-wrap items-center gap-2 text-[12px]">
        <span role="status" className={`inline-flex items-center gap-1.5 ${state === "live" ? "text-success" : "text-fg-3"}`}>
          <LiveDot tone={st.tone} still={st.still} size="sm" />
          {st.label}
        </span>
        <Button size="sm" variant="secondary" iconLeft={state === "paused" ? Play : Pause} onClick={onTogglePause}>
          {state === "paused" ? "Resume" : "Pause"}
        </Button>
        <Button size="sm" variant="ghost" iconLeft={Eraser} onClick={onClear} disabled={rows.length === 0}>
          Clear
        </Button>
        <span className="text-fg-3">
          {rows.length} trace{rows.length === 1 ? "" : "s"}
        </span>
        {note && <span className="text-[11px] text-fg-3">{note}</span>}
      </div>
      {rows.length === 0 ? (
        <InlineEmpty icon={Radio} message="Waiting for new traces that match the filters" />
      ) : (
        <DataTable
          data={rows}
          columns={columns}
          rowKey={(r) => r.trace_id}
          onRowClick={onOpen ? (r) => onOpen(r.trace_id) : undefined}
          zebra
          minWidth={640}
        />
      )}
    </div>
  );
}
