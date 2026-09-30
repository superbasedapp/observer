import type { ColumnDef } from "@tanstack/react-table";
import { ToolBadge } from "@/components/primitives";
import { DataTable } from "@/components/DataTable";
import { ChartState } from "@/components/ChartState";
import { useApi } from "@/lib/useApi";
import { fmtInt, fmtTaskUSD } from "@/lib/format";
import type { TaskCostBucket, TaskRollup } from "@/lib/types";

// TasksTab — this project's task-tracking rollup (plan §3.5 TasksTab),
// reusing the shape of the Analysis page's task-tracking section
// (pages/Analysis.tsx TaskRollupSection) over the SAME /api/tasks endpoint,
// scoped by the numeric project_id this panel already has (rather than the
// root-path `project` filter most other pages use).

export function TasksTab({ projectId, days }: { projectId: number; days: number }) {
  const rollup = useApi<TaskRollup>(
    "/api/tasks",
    { project_id: projectId, days },
    [projectId, days],
  );
  const data = rollup.data;

  return (
    <ChartState
      loading={rollup.loading && !rollup.data}
      error={rollup.error}
      denied={rollup.denied}
      deniedPermission={rollup.deniedPermission}
      empty={!rollup.loading && (!data || data.sessions_with_tasks === 0)}
      emptyHint="No sessions in this window used a todo/plan tool - most don't; this is the normal case, not a gap."
      height={160}
    >
      {data && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <TaskKpi label="Sessions" value={fmtInt(data.sessions_with_tasks)} />
            <TaskKpi label="Created" value={fmtInt(data.counts.created)} />
            <TaskKpi label="Completed" value={fmtInt(data.counts.completed)} />
            <TaskKpi label="Cancelled" value={fmtInt(data.counts.cancelled)} />
            <TaskKpi label="Never activated" value={fmtInt(data.counts.never_activated)} />
            <TaskKpi label="Still open" value={fmtInt(data.counts.still_open)} />
          </div>

          {data.by_tool.length > 0 && (
            <DataTable<TaskRollup["by_tool"][number]>
              data={data.by_tool}
              columns={TOOL_COLUMNS}
              rowKey={(t) => t.tool}
              minWidth={440}
            />
          )}

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <TaskBucketCard label="Attributed to one task" bucket={data.attributed_single} />
            <TaskBucketCard label="Between tasks" bucket={data.between_tasks} />
            <TaskBucketCard label="Shared (2+ tasks)" bucket={data.shared} />
          </div>

          {data.cost_note && <p className="text-[10.5px] text-fg-4">{data.cost_note}</p>}
        </div>
      )}
    </ChartState>
  );
}

type ToolRow = TaskRollup["by_tool"][number];

// TOOL_COLUMNS is the per-tool breakdown; numbers sort by their raw value,
// and an unpriced tool sorts below every priced one on the Cost column.
const TOOL_COLUMNS: ColumnDef<ToolRow, unknown>[] = [
  {
    id: "tool",
    header: "Tool",
    accessorKey: "tool",
    cell: ({ row }) => <ToolBadge tool={row.original.tool} />,
  },
  {
    id: "sessions",
    header: "Sessions",
    accessorFn: (t) => t.sessions,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{fmtInt(row.original.sessions)}</span>,
  },
  {
    id: "tasks",
    header: "Tasks",
    accessorFn: (t) => t.tasks,
    meta: { align: "right" },
    cell: ({ row }) => <span className="text-fg-2">{fmtInt(row.original.tasks)}</span>,
  },
  {
    id: "cost",
    header: "Cost",
    accessorFn: (t) => (t.unpriced ? -1 : t.cost_usd),
    meta: { align: "right" },
    cell: ({ row }) =>
      row.original.unpriced ? (
        <span className="text-fg-3">unpriced</span>
      ) : (
        <span className="text-fg-1">{fmtTaskUSD(row.original.cost_usd)}</span>
      ),
  },
];

function TaskKpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 px-3 py-2">
      <div className="text-[10px] font-medium uppercase tracking-[0.05em] text-fg-3">{label}</div>
      <div className="mt-0.5 tabular-nums text-[15px] font-semibold text-fg-1">{value}</div>
    </div>
  );
}

function TaskBucketCard({ label, bucket }: { label: string; bucket: TaskCostBucket }) {
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 px-3 py-2">
      <div className="text-[10px] font-medium uppercase tracking-[0.05em] text-fg-3">{label}</div>
      <div className="mt-0.5 tabular-nums text-[14px] font-semibold text-fg-1">
        {bucket.unpriced ? <span className="text-fg-3">unpriced</span> : fmtTaskUSD(bucket.cost_usd)}
      </div>
      <div className="mt-0.5 text-[10.5px] text-fg-3">{fmtInt(bucket.actions_count)} actions</div>
    </div>
  );
}
