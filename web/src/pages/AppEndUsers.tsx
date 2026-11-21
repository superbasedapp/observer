import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { UsersRound } from "lucide-react";
import { ChartShell, DataTable, EmptyState, PageHeader, StatCard, StatStrip, TableSkeleton } from "@/components/primitives";
import { MetricIcon } from "@/components/MetricIcon";
import { PlaneAMoney } from "@shared/components/planea/money";
import { compact, dateTime, ms, pct1 } from "@shared/lib/displayFormat";
import { useHrefGate } from "@/lib/governance";
import { useApi } from "@/lib/useApi";
import { navIcon } from "@/lib/nav";
import type { AppEndUserRow, AppEndUsersResult } from "@/lib/planeaApi";
import { APPS_HEADER_CLASS, AppsGate, ReadState, WindowPicker, useAppsWindow } from "@/components/apps/AppsChrome";
import { AppsMetricIcon } from "@/components/apps/AppsMetricIcon";

// Your apps > End users (Plane A lane B5, plan W2-5, W3-4 node parity): spend,
// errors and latency per end user of your apps (GET /api/obs/end-users,
// contracts/node-routes.md). The end user is personal data, stored as sent;
// it leaves this machine only when the app's data also goes to the
// organization (the SDK destination, or an AI apps share). The columns
// extend the shared
// EndUserSpendCard's (cost, share, tokens, traces) with errors and latency.

export function AppEndUsersPage() {
  const [days, setDays] = useAppsWindow();
  const navigate = useNavigate();
  // A row opens the Traces page, which a managed machine may hide.
  const tracesShown = useHrefGate()("/apps/traces") === "shown";
  const q = useApi<AppEndUsersResult>("/api/obs/end-users", { days }, [days]);
  const columns = useMemo<ColumnDef<AppEndUserRow, any>[]>(
    () => [
      { accessorKey: "end_user", header: "End user", cell: (c) => <span className="text-fg-1">{c.row.original.end_user}</span> },
      {
        accessorKey: "cost_usd",
        header: "Cost",
        cell: (c) => <PlaneAMoney usd={c.row.original.cost_usd} tokens={c.row.original.total_tokens} />,
        meta: { align: "right", mono: true },
      },
      { accessorKey: "cost_share", header: "Share", cell: (c) => pct1(c.row.original.cost_share), meta: { align: "right" } },
      { accessorKey: "total_tokens", header: "Tokens", cell: (c) => compact(c.row.original.total_tokens), meta: { align: "right" } },
      { accessorKey: "traces", header: "Traces", cell: (c) => compact(c.row.original.traces), meta: { align: "right" } },
      {
        accessorKey: "error_traces",
        header: "Errors",
        cell: (c) => (
          <span className={c.row.original.error_traces > 0 ? "font-semibold text-danger" : "text-fg-3"}>{c.row.original.error_traces}</span>
        ),
        meta: { align: "right" },
      },
      { accessorKey: "p50_ms", header: "p50", cell: (c) => ms(c.row.original.p50_ms), meta: { align: "right" } },
      { accessorKey: "p95_ms", header: "p95", cell: (c) => ms(c.row.original.p95_ms), meta: { align: "right" } },
      { accessorKey: "sessions", header: "Sessions", cell: (c) => compact(c.row.original.sessions), meta: { align: "right" } },
      { accessorKey: "last_at", header: "Last seen", cell: (c) => dateTime(c.row.original.last_at), meta: { align: "right" } },
    ],
    [],
  );
  const d = q.data;
  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("app-end-users")}
        title="End users"
        className={APPS_HEADER_CLASS}
        sub="Which of your apps' users drive spend, errors and latency. End users are personal data, stored as sent."
        helpId="glossary.apps_end_user"
        right={<WindowPicker days={days} onChange={setDays} />}
      />
      <AppsGate>
        <ReadState error={q.error} onRetry={q.reload} feature="End users" />
        {!q.error && (
          <>
            <StatStrip cols={3} ariaLabel="End users summary" className="">
              <StatCard label="End users" icon={<AppsMetricIcon metric="endUsers" />} loading={q.loading} value={d ? compact(d.end_users.length) : "-"} stale={q.isStale} />
              <StatCard
                label="Cost"
                icon={<MetricIcon metric="spend" />}
                loading={q.loading}
                value={d ? <PlaneAMoney usd={d.total_cost_usd} /> : "-"}
                stale={q.isStale}
              />
              <StatCard
                label="Traces without an end user"
                icon={<AppsMetricIcon metric="traces" />}
                loading={q.loading}
                value={d ? compact(d.no_end_user_traces) : "-"}
                sub={d && d.no_end_user_traces > 0 ? <PlaneAMoney usd={d.no_end_user_cost_usd} /> : undefined}
                stale={q.isStale}
              />
            </StatStrip>
            <ChartShell title="By end user" stale={q.isStale}>
              {q.loading && !d ? (
                <TableSkeleton rows={8} />
              ) : (d?.end_users.length ?? 0) === 0 ? (
                <EmptyState
                  variant="inline"
                  icon={UsersRound}
                  title="No end users in this window"
                  body="An app names the user behind a request with the SDK's user option."
                />
              ) : (
                <DataTable
                  data={d?.end_users ?? []}
                  columns={columns}
                  rowKey={(r) => r.end_user}
                  onRowClick={
                    tracesShown ? (r) => navigate(`/apps/traces?days=${days}&end_user=${encodeURIComponent(r.end_user)}`) : undefined
                  }
                  initialSort={[{ id: "cost_usd", desc: true }]}
                  zebra
                  minWidth={900}
                />
              )}
            </ChartShell>
          </>
        )}
      </AppsGate>
    </div>
  );
}
