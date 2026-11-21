import { useMemo } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { MessageSquareText } from "lucide-react";
import { ChartShell, DataTable, EmptyState, PageHeader, Pagination, TableSkeleton } from "@/components/primitives";
import { ErrorCountBadge } from "@shared/components/planea/chips";
import { EndUserCell, ServiceCell } from "@shared/components/planea/identity";
import { PlaneAMoney } from "@shared/components/planea/money";
import { compact, dateTime } from "@shared/lib/displayFormat";
import { useHrefGate } from "@/lib/governance";
import { useApi } from "@/lib/useApi";
import { navIcon } from "@/lib/nav";
import type { AppSessionRow, AppSessionsResult } from "@/lib/planeaApi";
import { APPS_HEADER_CLASS, AppsGate, ReadState, WindowPicker, useAppsWindow } from "@/components/apps/AppsChrome";

// Your apps > Sessions (Plane A lane B5, plan W2-5): the app's sessions on
// this machine (GET /api/obs/sessions, contracts/node-routes.md). A row opens
// the Traces page filtered to that session.

const PAGE = 50;

export function AppSessionsPage() {
  const [days, setDays] = useAppsWindow();
  const [sp, setSp] = useSearchParams();
  const navigate = useNavigate();
  // A row opens the Traces page, which a managed machine may hide.
  const tracesShown = useHrefGate()("/apps/traces") === "shown";
  const page = Math.max(1, Number(sp.get("page")) || 1);
  const q = useApi<AppSessionsResult>("/api/obs/sessions", { days, limit: PAGE, offset: (page - 1) * PAGE }, [days, page]);
  const columns = useMemo<ColumnDef<AppSessionRow, any>[]>(
    () => [
      {
        accessorKey: "session_id",
        header: "Session",
        cell: (c) => <span className="block max-w-[220px] truncate font-mono text-[11px] text-fg-1">{c.row.original.session_id}</span>,
      },
      { id: "end_user", header: "End user", cell: (c) => <EndUserCell row={c.row.original} /> },
      { id: "service", header: "Service", cell: (c) => <ServiceCell row={c.row.original} /> },
      {
        accessorKey: "trace_count",
        header: "Traces",
        cell: (c) => (
          <span className="inline-flex items-center gap-1">
            {compact(c.row.original.trace_count)}
            <ErrorCountBadge count={c.row.original.error_count} />
          </span>
        ),
        meta: { align: "right" },
      },
      { accessorKey: "total_tokens", header: "Tokens", cell: (c) => compact(c.row.original.total_tokens), meta: { align: "right" } },
      {
        accessorKey: "total_cost",
        header: "Cost",
        cell: (c) => <PlaneAMoney usd={c.row.original.total_cost} tokens={c.row.original.total_tokens} />,
        meta: { align: "right", mono: true },
      },
      { accessorKey: "first_at", header: "First", cell: (c) => dateTime(c.row.original.first_at), meta: { align: "right" } },
      { accessorKey: "last_at", header: "Last", cell: (c) => dateTime(c.row.original.last_at), meta: { align: "right" } },
    ],
    [],
  );
  const rows = q.data?.sessions ?? [];
  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("app-sessions")}
        title="Sessions"
        className={APPS_HEADER_CLASS}
        sub="Your apps' conversations and runs, grouped by the session id the app reported. Open one to see its traces."
        right={<WindowPicker days={days} onChange={setDays} />}
      />
      <AppsGate>
        <ChartShell
          title="Sessions"
          stale={q.isStale}
          sub={
            q.data
              ? `${compact(q.data.total)} sessions; ${compact(q.data.unsessioned)} traces without a session id${q.data.truncated ? " (window truncated to the newest traces)" : ""}`
              : undefined
          }
        >
          <ReadState error={q.error} onRetry={q.reload} feature="Sessions" />
          {q.loading && !q.data ? (
            <TableSkeleton rows={8} />
          ) : !q.error && rows.length === 0 ? (
            <EmptyState
              variant="inline"
              icon={MessageSquareText}
              title="No sessions in this window"
              body="An app groups its traces into a session with the SDK's session option."
            />
          ) : (
            !q.error && (
              <>
                <DataTable
                  data={rows}
                  columns={columns}
                  rowKey={(r) => r.session_id}
                  onRowClick={
                    tracesShown ? (r) => navigate(`/apps/traces?days=${days}&session_id=${encodeURIComponent(r.session_id)}`) : undefined
                  }
                  zebra
                  minWidth={900}
                />
                <Pagination
                  page={page}
                  limit={PAGE}
                  total={q.data?.total ?? rows.length}
                  onPage={(p) => {
                    const next = new URLSearchParams(sp);
                    next.set("page", String(p));
                    setSp(next, { replace: true });
                  }}
                  loading={q.isStale}
                />
              </>
            )
          )}
        </ChartShell>
      </AppsGate>
    </div>
  );
}
