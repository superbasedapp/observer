import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { CircleDot, Group, MessageSquareText, Server, Spline, UsersRound } from "lucide-react";
import {
  ActiveFilterChips,
  ChartShell,
  ComboChip,
  DataTable,
  EmptyState,
  Icon,
  PageHeader,
  Pagination,
  TableSkeleton,
  Toggle,
  type ComboOption,
  type FilterChip,
} from "@/components/primitives";
import { VocabDefPill } from "@shared/primitives/VocabDefPill";
import { TRACE_STATUS } from "@shared/lib/obsVocab";
import { ErrorCountBadge, ModelCell } from "@shared/components/planea/chips";
import { EndUserCell, ServiceCell } from "@shared/components/planea/identity";
import { GroupTable, type GroupDisplayRow } from "@shared/components/planea/GroupTable";
import { PlaneATraceCostCell } from "@shared/components/planea/costCell";
import { ExplorerSearchInput, explorerValueOptions } from "@shared/components/planea/explorerFilters";
import { compact, dateTime, ms } from "@shared/lib/displayFormat";
import { useApi } from "@/lib/useApi";
import { navIcon } from "@/lib/nav";
import type { AppExplorerGroups, AppTraceRow, AppTracesResult } from "@/lib/planeaApi";
import { APPS_HEADER_CLASS, AppsGate, ReadState, WindowPicker, useAppsWindow } from "@/components/apps/AppsChrome";
import { AppTraceInspector } from "@/components/apps/AppTraceInspector";
import { AdmissionMarkPill } from "@/components/apps/AdmissionMarkPill";
import { SdkSnippet } from "@/components/apps/AppsFirstRunCard";
import { SavedViewsBar } from "@shared/components/planea/savedViews";
import { LiveTailPanel } from "@shared/components/planea/liveTail";
import { viewDraft, type PlaneASavedView } from "@shared/components/planea/explorerViewsModel";
import { deleteMachineView, listMachineViews, saveMachineView, useMachineTail } from "@/lib/appExplorerViews";

// Your apps > Traces (Plane A lane B5, plan W2-5, D17): the machine's trace
// explorer over GET /api/obs/traces (filters, contracts/node-routes.md), the
// shared Plane A cells, and the shared trace inspector opened in place
// (?trace=). "Group by" reads lane B9's GET /api/obs/explorer/groups
// (contracts/alerts.md) into the shared GroupTable. Lane C9 (W5-4) adds the
// saved views bar (/api/obs/explorer/views, the shared SavedViewsBar) and the
// Live switch: the shared LiveTailPanel fed by the SSE tail.
//
// The filter row is the design system's (design pass 2026-11-21): one row of
// chips at chip height (search, ComboChip pickers over the values the
// machine lists, a Live switch), the active filters as removable chips under
// it, the saved views at its end. End user, service and session are picked
// from what the machine saw in the window, never typed.

const PAGE = 50;

const STATUS_OPTIONS: ComboOption[] = [
  { value: "", label: "Any status", searchable: "any all" },
  { value: "error", label: "With errors", searchable: "error errors failed" },
  { value: "ok", label: "No errors", searchable: "ok no error fine" },
];

const GROUP_BY: ComboOption[] = [
  { value: "", label: "No grouping", searchable: "none no grouping flat" },
  { value: "user", label: "End user", searchable: "end user" },
  { value: "session", label: "Session", searchable: "session" },
  { value: "service", label: "Service", searchable: "service" },
  { value: "environment", label: "Environment", searchable: "environment env" },
  { value: "release", label: "Release", searchable: "release version" },
  { value: "model", label: "Model", searchable: "model" },
  { value: "tag", label: "Tag", searchable: "tag" },
];

// The group-by modes whose groups are a trace filter on this page (the
// group key is the filter's value), for the group table's View traces.
const DRILL_PARAM: Record<string, string> = { user: "end_user", service: "service", session: "session_id" };

const optionLabel = (opts: ComboOption[], v: string) => String(opts.find((o) => o.value === v)?.label ?? v);

/** useFieldValues lists the values the machine saw for one field in the
 *  window (the explorer's group-by read), for a filter chip's options. */
function useFieldValues(by: "user" | "service" | "session", days: number): string[] {
  const q = useApi<AppExplorerGroups>("/api/obs/explorer/groups", { by, days }, [by, days]);
  return useMemo(() => (q.data?.groups ?? []).map((g) => g.group_key).filter(Boolean), [q.data]);
}

export function AppTracesPage() {
  const [days, setDays] = useAppsWindow();
  const [sp, setSp] = useSearchParams();
  const set = (k: string, v: string) => {
    const next = new URLSearchParams(sp);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== "trace" && k !== "page") next.delete("page");
    setSp(next, { replace: true });
  };
  const status = sp.get("status") ?? "";
  const endUser = sp.get("end_user") ?? "";
  const service = sp.get("service") ?? "";
  const session = sp.get("session_id") ?? "";
  const search = sp.get("q") ?? "";
  const groupBy = sp.get("by") ?? "";
  const page = Math.max(1, Number(sp.get("page")) || 1);
  const live = sp.get("live") === "1";
  const users = useFieldValues("user", days);
  const services = useFieldValues("service", days);
  const sessions = useFieldValues("session", days);
  // The URL filters under the explorer's names (contracts/alerts.md): what a
  // saved view stores and what the tail filters on.
  const explorerFilters = useMemo(
    () => ({ status, user: endUser, service, q: search }),
    [status, endUser, service, search],
  );
  const tail = useMachineTail(explorerFilters, live);
  const [views, setViews] = useState<PlaneASavedView[]>([]);
  const [viewErr, setViewErr] = useState("");
  const [viewBusy, setViewBusy] = useState(false);
  const loadViews = useCallback(() => {
    listMachineViews()
      .then(setViews)
      .catch(() => setViews([]));
  }, []);
  useEffect(loadViews, [loadViews]);
  const applyView = (v: PlaneASavedView) => {
    const next = new URLSearchParams();
    const map: Record<string, string> = { status: "status", user: "end_user", service: "service", q: "q" };
    for (const [k, val] of Object.entries(v.filters)) if (map[k]) next.set(map[k], val);
    if (v.page === "groups" && v.group_by) next.set("by", v.group_by);
    next.set("view", v.id);
    if (live) next.set("live", "1");
    setSp(next, { replace: true });
  };
  const viewAction = async (fn: () => Promise<unknown>) => {
    setViewBusy(true);
    setViewErr("");
    try {
      await fn();
      loadViews();
    } catch (e) {
      setViewErr(e instanceof Error ? e.message : String(e));
    } finally {
      setViewBusy(false);
    }
  };
  // One removable chip per filter in effect (the grouping and Live are
  // views, shown by their own controls, not filters).
  const clearAll = () => {
    const next = new URLSearchParams(sp);
    for (const k of ["status", "end_user", "service", "session_id", "q", "page", "view"]) next.delete(k);
    setSp(next, { replace: true });
  };
  const chips: FilterChip[] = [
    ...(search ? [{ label: <>search: {search}</>, onClear: () => set("q", "") }] : []),
    ...(status ? [{ label: <>status: {optionLabel(STATUS_OPTIONS, status).toLowerCase()}</>, onClear: () => set("status", "") }] : []),
    ...(endUser ? [{ label: <>end user: {endUser}</>, onClear: () => set("end_user", "") }] : []),
    ...(service ? [{ label: <>service: {service}</>, onClear: () => set("service", "") }] : []),
    ...(session ? [{ label: <>session: {session}</>, onClear: () => set("session_id", "") }] : []),
  ];

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("app-traces")}
        className={APPS_HEADER_CLASS}
        title="Traces"
        sub="Every trace your apps sent to this machine. Open one to see its spans, timeline and content."
        right={<WindowPicker days={days} onChange={setDays} />}
      />
      <AppsGate>
        <section className="space-y-2" aria-label="Trace filters">
          <div className="flex flex-wrap items-center gap-2">
            <ExplorerSearchInput value={search} onSubmit={(v) => set("q", v)} placeholder="Search trace id or name" />
            <ComboChip label="Status" icon={<Icon icon={CircleDot} size={11} />} value={status} onChange={(v) => set("status", v)} options={STATUS_OPTIONS} popoverWidth={220} />
            <ComboChip
              label="End user"
              icon={<Icon icon={UsersRound} size={11} />}
              value={endUser}
              onChange={(v) => set("end_user", v)}
              options={explorerValueOptions(users, endUser, "Any end user")}
              popoverWidth={260}
              emptyHint="No end user in this window."
            />
            <ComboChip
              label="Service"
              icon={<Icon icon={Server} size={11} />}
              value={service}
              onChange={(v) => set("service", v)}
              options={explorerValueOptions(services, service, "Any service")}
              popoverWidth={260}
            />
            <ComboChip
              label="Session"
              icon={<Icon icon={MessageSquareText} size={11} />}
              value={session}
              onChange={(v) => set("session_id", v)}
              options={explorerValueOptions(sessions, session, "Any session")}
              popoverWidth={280}
              disabled={!!groupBy || live}
              triggerTooltip={groupBy || live ? "The session filter applies to the trace list only." : undefined}
            />
            <span className="mx-1 hidden h-4 w-px bg-line-2 sm:block" aria-hidden />
            <ComboChip label="Group by" icon={<Icon icon={Group} size={11} />} value={groupBy} onChange={(v) => set("by", v)} options={GROUP_BY} popoverWidth={220} />
            <Toggle on={live} onChange={(on) => set("live", on ? "1" : "")} label="Live" />
          </div>
          <ActiveFilterChips chips={chips} onClearAll={clearAll} />
          <SavedViewsBar
            views={views}
            selectedId={sp.get("view") ?? undefined}
            onApply={applyView}
            busy={viewBusy}
            error={viewErr}
            onSave={(name) =>
              void viewAction(() => saveMachineView(viewDraft(name, groupBy ? "groups" : "traces", explorerFilters, groupBy, [])))
            }
            onDelete={(v) => void viewAction(() => deleteMachineView(v.id))}
          />
        </section>
        {live ? (
          <ChartShell title="Live tail" sub="New traces that match the filters, as they arrive on this machine.">
            <LiveTailPanel rows={tail.rows} state={tail.state} onTogglePause={tail.togglePause} onClear={tail.clear} onOpen={(id) => set("trace", id)} />
          </ChartShell>
        ) : groupBy ? (
          <Groups
            by={groupBy}
            days={days}
            status={status}
            endUser={endUser}
            service={service}
            q={search}
            onView={
              DRILL_PARAM[groupBy]
                ? (key) => {
                    // A group of a filterable field opens its traces: the
                    // field's filter set, the grouping off.
                    const next = new URLSearchParams(sp);
                    next.set(DRILL_PARAM[groupBy], key);
                    for (const k of ["by", "page", "view"]) next.delete(k);
                    setSp(next, { replace: true });
                  }
                : undefined
            }
          />
        ) : (
          <TraceList
            days={days}
            filters={{ status, end_user: endUser, service, session_id: session, q: search }}
            filtered={chips.length > 0}
            page={page}
            onPage={(p) => set("page", String(p))}
            onOpen={(id) => set("trace", id)}
          />
        )}
      </AppsGate>
      <AppTraceInspector traceId={sp.get("trace")} onClose={() => set("trace", "")} />
    </div>
  );
}

function TraceList({
  days,
  filters,
  filtered,
  page,
  onPage,
  onOpen,
}: {
  days: number;
  filters: Record<string, string>;
  filtered: boolean;
  page: number;
  onPage: (p: number) => void;
  onOpen: (id: string) => void;
}) {
  const params: Record<string, string | number> = { days, limit: PAGE, offset: (page - 1) * PAGE };
  for (const [k, v] of Object.entries(filters)) if (v) params[k] = v;
  const q = useApi<AppTracesResult>("/api/obs/traces", params, [days, page, JSON.stringify(filters)]);
  const columns = useMemo<ColumnDef<AppTraceRow, any>[]>(
    () => [
      {
        accessorKey: "root_name",
        header: "Trace",
        cell: (c) => (
          <span className="block max-w-[240px] truncate font-medium text-fg-1" title={c.row.original.trace_id}>
            {c.row.original.root_name || c.row.original.trace_id}
          </span>
        ),
      },
      {
        accessorKey: "status",
        header: "Status",
        cell: (c) => (
          <span className="inline-flex items-center gap-1">
            <VocabDefPill of={TRACE_STATUS} value={c.row.original.status} />
            <ErrorCountBadge count={c.row.original.error_count} />
            <AdmissionMarkPill mark={c.row.original.admission} />
          </span>
        ),
      },
      { id: "end_user", header: "End user", cell: (c) => <EndUserCell row={c.row.original} /> },
      { id: "service", header: "Service", cell: (c) => <ServiceCell row={c.row.original} /> },
      { id: "model", header: "Model", cell: (c) => <ModelCell model={c.row.original.model} provider={c.row.original.provider} /> },
      { accessorKey: "span_count", header: "Spans", cell: (c) => compact(c.row.original.span_count), meta: { align: "right" } },
      { accessorKey: "total_tokens", header: "Tokens", cell: (c) => compact(c.row.original.total_tokens), meta: { align: "right" } },
      {
        accessorKey: "cost_usd",
        header: "Cost",
        cell: (c) => (
          <PlaneATraceCostCell
            usd={c.row.original.cost_usd}
            tokens={c.row.original.total_tokens}
            provenance={q.data?.cost_provenance?.[c.row.original.trace_id]}
          />
        ),
        meta: { align: "right", mono: true },
      },
      { accessorKey: "duration_ms", header: "Duration", cell: (c) => ms(c.row.original.duration_ms), meta: { align: "right" } },
      { accessorKey: "started_at", header: "Started", cell: (c) => dateTime(c.row.original.started_at), meta: { align: "right" } },
    ],
    [q.data],
  );
  const rows = q.data?.traces ?? [];
  return (
    <ChartShell title="Traces" sub={q.data ? `${compact(q.data.total ?? rows.length)} in the window` : undefined} stale={q.isStale}>
      <ReadState error={q.error} onRetry={q.reload} feature="Traces" />
      {q.loading && !q.data ? (
        <TableSkeleton rows={8} />
      ) : !q.error && rows.length === 0 ? (
        filtered ? (
          <EmptyState variant="inline" icon={Spline} title="No traces match the filters" body="Clear a filter above, or widen the window." />
        ) : (
          <div className="space-y-3" data-testid="apps-traces-empty">
            <EmptyState variant="inline" icon={Spline} title="No traces in this window" body="Send one from your app with the SDK:" />
            <SdkSnippet />
          </div>
        )
      ) : (
        !q.error && (
          <>
            <DataTable data={rows} columns={columns} rowKey={(r) => r.trace_id} onRowClick={(r) => onOpen(r.trace_id)} zebra minWidth={980} />
            <Pagination page={page} limit={PAGE} total={q.data?.total ?? rows.length} onPage={onPage} loading={q.isStale} />
          </>
        )
      )}
    </ChartShell>
  );
}

function Groups({
  by,
  days,
  status,
  endUser,
  service,
  q: search,
  onView,
}: {
  by: string;
  days: number;
  status: string;
  endUser: string;
  service: string;
  q: string;
  onView?: (groupKey: string) => void;
}) {
  const params: Record<string, string | number> = { by, days };
  if (status) params.status = status;
  if (endUser) params.user = endUser;
  if (service) params.service = service;
  if (search) params.q = search;
  const q = useApi<AppExplorerGroups>("/api/obs/explorer/groups", params, [by, days, status, endUser, service, search]);
  const rows: GroupDisplayRow[] = (q.data?.groups ?? []).map((g) => ({
    key: g.group_key,
    label: g.label,
    count: g.trace_count,
    errorCount: g.error_count,
    tokens: g.total_tokens,
    costUsd: g.total_cost_usd,
    avgCostPerTrace: g.avg_cost_per_trace,
    p95DurationMs: g.p95_duration_ms,
    lastActivity: g.last_at,
  }));
  if (q.error) return <ReadState error={q.error} onRetry={q.reload} feature="Grouping" />;
  return (
    <GroupTable
      rows={rows}
      countLabel="Traces"
      loading={q.loading}
      truncatedGroups={q.data?.truncated_groups}
      note={q.data?.note}
      showAvgCostPerTrace
      showLastActivity
      onViewGroup={onView ? (r) => r.key && onView(r.key) : undefined}
      viewLabel="View traces"
    />
  );
}
