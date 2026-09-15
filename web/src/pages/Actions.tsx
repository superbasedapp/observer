import { useEffect, useMemo, useRef, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import clsx from "clsx";
import {
  ActiveFilterChips,
  ChartShell,
  type FilterChip,
  PageHeader,
  Pill,
  SegmentedControl,
  ToolBadge,
  Tooltip,
} from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { CopyOnClick } from "@/components/CopyOnClick";
import { DataTable, Pagination } from "@/components/DataTable";
import { ChartState } from "@/components/ChartState";
import { SessionDetailPanel } from "@/components/SessionDetailPanel";
import { useFilters, windowParams } from "@/lib/filters";
import { useApi } from "@/lib/useApi";
import { fmtDateOnly, fmtDateTime, fmtShortId } from "@/lib/format";
import {
  actionMeta,
  mcpIdentity,
  KNOWN_ACTION_TYPES,
  KNOWN_EFFORT_LEVELS,
  KNOWN_PERMISSION_MODES,
} from "@/lib/actions";
import type {
  ActionListRow,
  ActionsDayCountsResponse,
  ActionsResponse,
} from "@/lib/types";

type View = "table" | "timeline";

const PAGE_LIMIT = 50;
// Timeline view scans a wider slice than the Table page because
// 50 rows clustered in the most recent hour collapse to a single
// pixel on a multi-day axis. /api/actions caps at 500 server-side
// (intArg ceiling); take the full budget for Timeline.
const TIMELINE_LIMIT = 500;

export function ActionsPage() {
  const { win, customRange, tool, project } = useFilters();
  const winParams = windowParams(win, customRange);
  const toolParam = tool === "all" ? undefined : tool;
  const projectParam = project === "all" ? undefined : project;

  const [page, setPage] = useState(1);
  const [view, setView] = useState<View>("table");
  const [actionType, setActionType] = useState("");
  const [effortLevel, setEffortLevel] = useState("");
  const [permissionMode, setPermissionMode] = useState("");
  const [isInterrupt, setIsInterrupt] = useState(false);
  const [assistantText, setAssistantText] = useState(false);
  const [sessionFilter, setSessionFilter] = useState("");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  // Timeline day selector — null means "show every loaded action"
  // (the most-recent slice). Set when the user clicks a chip on the
  // day strip; the actions fetch then filters server-side by date.
  // Default to today on first entry into Timeline view; users can
  // click "All" to clear the filter, or pick any other day.
  const [pickedDay, setPickedDay] = useState<string | null>(null);
  // Track whether we've auto-defaulted on this Timeline entry so
  // clearing to "All" doesn't get clobbered back to today by the
  // auto-default effect below.
  const timelineEntered = useRef(false);
  useEffect(() => {
    if (view === "timeline") {
      if (!timelineEntered.current) {
        timelineEntered.current = true;
        setPickedDay(todayIsoDate());
      }
    } else {
      // Leaving Timeline — reset both the entered flag and the picked
      // day so the next Timeline entry re-defaults to today.
      timelineEntered.current = false;
      setPickedDay(null);
    }
  }, [view]);
  // Live-tail control — when unpaused, useApi refresh fires every
  // 5s so the firehose stays current; pausing freezes the view so
  // the operator can read through without rows shifting underfoot.
  const [paused, setPaused] = useState(false);
  const [tailNonce, setTailNonce] = useState(0);
  useEffect(() => {
    // Live-tail is a Table-view affordance — the firehose only
    // makes sense for a streaming most-recent list. Timeline is
    // retrospective navigation; ticking every 5s caused fetches to
    // abort each other and surfaced as "loading forever" when the
    // network roundtrip exceeded the tick interval.
    if (paused || view === "timeline") return;
    const t = window.setInterval(() => setTailNonce((n) => n + 1), 5_000);
    return () => window.clearInterval(t);
  }, [paused, view]);

  // Reset page when any filter changes — including the Timeline
  // day pick. Switching from "Apr 23 (2275)" to "May 15 (4173)"
  // should re-anchor at page 1, not preserve the prior page
  // offset that may be past the new day's row count.
  const filterKey = `${win}|${tool}|${project}|${actionType}|${effortLevel}|${permissionMode}|${isInterrupt}|${assistantText}|${sessionFilter}|${pickedDay ?? ""}`;
  useMemo(() => setPage(1), [filterKey]);

  const actions = useApi<ActionsResponse>(
    "/api/actions",
    {
      page,
      limit: view === "timeline" ? TIMELINE_LIMIT : PAGE_LIMIT,
      // Window filter — same window contract as the Sessions page.
      // Without it the header's window selector was a no-op here
      // (only the Timeline day-counts strip honored it).
      ...winParams,
      tool: toolParam,
      project: projectParam,
      action_type: actionType || undefined,
      effort_level: effortLevel || undefined,
      permission_mode: permissionMode || undefined,
      is_interrupt: isInterrupt ? 1 : undefined,
      assistant_text: assistantText ? 1 : undefined,
      session_id: sessionFilter || undefined,
      // Timeline day filter — both bounds set to the picked day so
      // the server returns just that day's actions. No-op when the
      // user hasn't picked yet (Timeline default shows the latest
      // slice; Table view ignores pickedDay via the useEffect above).
      from_date: pickedDay || undefined,
      to_date: pickedDay || undefined,
    },
    [
      page,
      view,
      win,
      customRange,
      tool,
      project,
      actionType,
      effortLevel,
      permissionMode,
      isInterrupt,
      tailNonce,
      assistantText,
      sessionFilter,
      pickedDay,
    ],
  );

  // Day-count strip for the Timeline view — populates every day in
  // the configured Window so chips remain selectable even when they
  // lie outside the most-recent 500-row slice. Fetched only when
  // Timeline is active to keep the Table view fast.
  const dayCounts = useApi<ActionsDayCountsResponse>(
    view === "timeline" ? "/api/actions/day-counts" : null,
    {
      ...winParams,
      tool: toolParam,
      project: projectParam,
    },
    [view, win, customRange, tool, project],
  );

  const columns = useMemo<ColumnDef<ActionListRow, unknown>[]>(
    () => [
      {
        id: "timestamp",
        header: () => <>Time<HelpInd id="column.actions.when" /></>,
        accessorKey: "timestamp",
        cell: ({ row }) => (
          <Tooltip content={fmtDateTime(row.original.timestamp)}>
            <span tabIndex={0} className="cursor-help text-fg-2 focus:outline-none">
              {relativeTime(row.original.timestamp)}
            </span>
          </Tooltip>
        ),
      },
      {
        id: "tool",
        header: () => <>Tool<HelpInd id="column.actions.tool" /></>,
        accessorKey: "tool",
        cell: ({ row }) => <ToolBadge tool={row.original.tool} />,
      },
      {
        id: "action_type",
        header: () => <>Type<HelpInd id="column.actions.type" /></>,
        accessorKey: "action_type",
        cell: ({ row }) => <ActionTypeBadge type={row.original.action_type} />,
      },
      {
        id: "target",
        header: () => <>Target / message<HelpInd id="column.actions.target" /></>,
        accessorKey: "target",
        cell: ({ row }) =>
          row.original.target ? (
            <Tooltip
              content={<span className="break-all font-mono">{row.original.target}</span>}
              maxWidth={420}
            >
              <span
                tabIndex={0}
                className="block max-w-[240px] cursor-help truncate font-mono text-[11px] text-fg-2 focus:outline-none"
              >
                {row.original.target}
              </span>
            </Tooltip>
          ) : (
            <span className="text-fg-4">-</span>
          ),
      },
      {
        id: "success",
        header: () => <>Status<HelpInd id="column.actions.ok" /></>,
        accessorKey: "success",
        cell: ({ row }) =>
          row.original.success ? (
            row.original.is_interrupt ? (
              <Pill variant="warn">interrupt</Pill>
            ) : (
              <span className="text-fg-4">·</span>
            )
          ) : (
            <Pill variant="danger">fail</Pill>
          ),
      },
      {
        id: "effort",
        header: () => <>Effort<HelpInd id="column.actions.effort" /></>,
        accessorKey: "effort_level",
        cell: ({ row }) =>
          row.original.effort_level ? (
            <Pill>{row.original.effort_level}</Pill>
          ) : (
            <span className="text-fg-4">-</span>
          ),
      },
      {
        id: "source",
        header: () => <>Source<HelpInd id="column.actions.source" /></>,
        accessorKey: "source_file",
        cell: ({ row }) => {
          const sf = row.original.source_file;
          if (!sf) return <span className="text-fg-4">-</span>;
          // Short-display: just the filename. Hover reveals the full path.
          const i = sf.lastIndexOf("/");
          const tail = i >= 0 ? sf.slice(i + 1) : sf;
          return (
            <Tooltip
              content={<span className="break-all font-mono">{sf}</span>}
              maxWidth={420}
            >
              <span
                tabIndex={0}
                className="max-w-[180px] cursor-help truncate font-mono text-[10.5px] text-fg-3 focus:outline-none"
              >
                {tail}
              </span>
            </Tooltip>
          );
        },
      },
      {
        id: "content",
        header: () => <>Content<HelpInd id="column.actions.content" /></>,
        accessorKey: "excerpt",
        cell: ({ row }) =>
          row.original.excerpt ? (
            <Tooltip
              content={
                <span className="block max-h-[200px] overflow-y-auto whitespace-pre-wrap break-words font-mono">
                  {row.original.excerpt}
                </span>
              }
              maxWidth={420}
            >
              <span
                tabIndex={0}
                className="block max-w-[200px] cursor-help truncate font-mono text-[10.5px] text-fg-2 focus:outline-none"
              >
                {row.original.excerpt}
              </span>
            </Tooltip>
          ) : (
            <span className="text-fg-4">-</span>
          ),
      },
      {
        id: "session",
        header: () => <>Session<HelpInd id="column.actions.session" /></>,
        accessorKey: "session_id",
        cell: ({ row }) => (
          <span className="inline-flex items-center gap-1.5">
            <Tooltip content={`Open session ${row.original.session_id}`}>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedSession(row.original.session_id);
                }}
                className="font-mono text-[11px] text-accent hover:text-accent-strong hover:underline"
              >
                {fmtShortId(row.original.session_id, 8)}
              </button>
            </Tooltip>
            <CopyOnClick value={row.original.session_id}>
              <span className="text-[9px] text-fg-4">copy</span>
            </CopyOnClick>
          </span>
        ),
      },
    ],
    [],
  );

  const anyFilter =
    !!actionType ||
    !!effortLevel ||
    !!permissionMode ||
    isInterrupt ||
    assistantText ||
    !!sessionFilter;

  function clearAll() {
    setActionType("");
    setEffortLevel("");
    setPermissionMode("");
    setIsInterrupt(false);
    setAssistantText(false);
    setSessionFilter("");
  }

  return (
    <div className="grid min-h-0 grid-cols-1 lg:h-full lg:grid-cols-[220px_minmax(0,1fr)]">
      <FilterRail
        actionType={actionType}
        setActionType={setActionType}
        effortLevel={effortLevel}
        setEffortLevel={setEffortLevel}
        permissionMode={permissionMode}
        setPermissionMode={setPermissionMode}
        isInterrupt={isInterrupt}
        setIsInterrupt={setIsInterrupt}
        assistantText={assistantText}
        setAssistantText={setAssistantText}
        sessionFilter={sessionFilter}
        setSessionFilter={setSessionFilter}
        anyFilter={anyFilter}
        clearAll={clearAll}
      />

      <div className="min-w-0 space-y-4 overflow-y-auto p-6">
        <PageHeader
          title="Actions"
          sub="The flat firehose - every recorded tool-call action across the window, filterable by tool, type, effort, and permission. Row-click expands inline detail; the session pill opens the session slide-over."
          helpId="tab.actions"
        />
        <ChartShell
          title={
            <span className="flex items-center gap-2">
              Event log
              <LiveTailIndicator
                paused={paused}
                onToggle={() => setPaused((p) => !p)}
              />
            </span>
          }
          sub={
            actions.data
              ? `${actions.data.total.toLocaleString()} matching · row-click expands details · session pill opens slide-over`
              : "Loading…"
          }
          right={
            <SegmentedControl<View>
              options={[
                { value: "table", label: "Table" },
                { value: "timeline", label: "Timeline" },
              ]}
              value={view}
              onChange={setView}
              size="sm"
            />
          }
        >
          {anyFilter && (
            <ActiveFilterChips
              className="mb-3"
              chips={buildActionChips({
                actionType,
                setActionType,
                effortLevel,
                setEffortLevel,
                permissionMode,
                setPermissionMode,
                isInterrupt,
                setIsInterrupt,
                assistantText,
                setAssistantText,
                sessionFilter,
                setSessionFilter,
              })}
              onClearAll={clearAll}
            />
          )}
          {view === "timeline" ? (
            <>
              <TimelineView
                rows={actions.loading ? [] : actions.data?.rows ?? []}
                dayCounts={dayCounts.data?.cells ?? []}
                pickedDay={pickedDay}
                onPickDay={setPickedDay}
                onPickSession={setSelectedSession}
                loading={actions.loading || dayCounts.loading}
              />

              {actions.data && (
                <Pagination
                  page={actions.data.page}
                  limit={actions.data.limit}
                  total={actions.data.total}
                  onPage={setPage}
                  loading={actions.loading}
                />
              )}
            </>
          ) : (
            <>
              <ChartState
                loading={actions.loading && !actions.data}
                error={actions.error}
                empty={
                  !actions.loading &&
                  actions.data != null &&
                  !actions.data.rows.length
                }
                emptyHint="No actions match these filters."
                height={240}
              >
                <DataTable<ActionListRow>
                  data={actions.data?.rows ?? []}
                  columns={columns}
                  rowKey={(r) => String(r.id)}
                  minWidth={880}
                  loading={actions.loading}
                  onRowClick={(r) =>
                    setExpandedId((cur) => (cur === r.id ? null : r.id))
                  }
                />
              </ChartState>

              {/* Expanded detail for the last-clicked row */}
              {expandedId != null &&
                actions.data?.rows.find((r) => r.id === expandedId) && (
                  <ExpandedDetail
                    row={actions.data.rows.find((r) => r.id === expandedId)!}
                    onClose={() => setExpandedId(null)}
                  />
                )}

              {actions.data && (
                <Pagination
                  page={actions.data.page}
                  limit={actions.data.limit}
                  total={actions.data.total}
                  onPage={setPage}
                  loading={actions.loading}
                />
              )}
            </>
          )}
        </ChartShell>
      </div>

      <SessionDetailPanel
        sessionId={selectedSession}
        open={selectedSession != null}
        onClose={() => setSelectedSession(null)}
        onOpenSession={(id) => setSelectedSession(id)}
      />
    </div>
  );
}

function FilterRail({
  actionType,
  setActionType,
  effortLevel,
  setEffortLevel,
  permissionMode,
  setPermissionMode,
  isInterrupt,
  setIsInterrupt,
  assistantText,
  setAssistantText,
  sessionFilter,
  setSessionFilter,
  anyFilter,
  clearAll,
}: {
  actionType: string;
  setActionType: (s: string) => void;
  effortLevel: string;
  setEffortLevel: (s: string) => void;
  permissionMode: string;
  setPermissionMode: (s: string) => void;
  isInterrupt: boolean;
  setIsInterrupt: (b: boolean) => void;
  assistantText: boolean;
  setAssistantText: (b: boolean) => void;
  sessionFilter: string;
  setSessionFilter: (s: string) => void;
  anyFilter: boolean;
  clearAll: () => void;
}) {
  return (
    <aside className="flex h-full min-h-0 flex-col gap-4 overflow-y-auto border-r border-line-1 bg-bg-1 p-4">
      <div className="flex items-baseline justify-between gap-2">
        <h2 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">
          Filters
        </h2>
        {anyFilter && (
          <button
            type="button"
            onClick={clearAll}
            className="text-[10.5px] text-accent hover:text-accent-strong"
          >
            Clear all
          </button>
        )}
      </div>

      <FacetGroup label="Action type">
        <FacetRow
          label="All"
          active={!actionType}
          onClick={() => setActionType("")}
        />
        {KNOWN_ACTION_TYPES.map((t) => {
          const meta = actionMeta(t);
          return (
            <FacetRow
              key={t}
              label={meta.label}
              active={actionType === t}
              onClick={() => setActionType(t)}
              dotColor={meta.colorVar}
            />
          );
        })}
      </FacetGroup>

      <FacetGroup label="Effort">
        <FacetRow
          label="All"
          active={!effortLevel}
          onClick={() => setEffortLevel("")}
        />
        {KNOWN_EFFORT_LEVELS.map((e) => (
          <FacetRow
            key={e}
            label={e}
            active={effortLevel === e}
            onClick={() => setEffortLevel(e)}
          />
        ))}
      </FacetGroup>

      <FacetGroup label="Permission">
        <FacetRow
          label="All"
          active={!permissionMode}
          onClick={() => setPermissionMode("")}
        />
        {KNOWN_PERMISSION_MODES.map((p) => (
          <FacetRow
            key={p}
            label={p}
            active={permissionMode === p}
            onClick={() => setPermissionMode(p)}
          />
        ))}
      </FacetGroup>

      <FacetGroup label="Misc">
        <FacetToggle
          on={isInterrupt}
          onChange={setIsInterrupt}
          label="Interrupted"
        />
        <FacetToggle
          on={assistantText}
          onChange={setAssistantText}
          label="AI messages"
        />
      </FacetGroup>

      <FacetGroup label="Session id">
        <input
          type="search"
          placeholder="Exact match…"
          value={sessionFilter}
          onChange={(e) => setSessionFilter(e.target.value)}
          className="h-7 w-full rounded-2 border border-line-2 bg-bg-2 px-2 font-mono text-[11px] text-fg-1 placeholder:font-sans placeholder:text-fg-4 focus:border-accent focus:outline-none"
        />
      </FacetGroup>
    </aside>
  );
}

function FacetGroup({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <div className="mb-1.5 px-1 text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">
        {label}
      </div>
      <div className="flex flex-col gap-0.5">{children}</div>
    </div>
  );
}

function FacetRow({
  label,
  active,
  onClick,
  dotColor,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  dotColor?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={clsx(
        "flex items-center gap-2 rounded-2 px-2 py-1 text-left text-[11.5px] transition-colors",
        active
          ? "bg-bg-3 text-fg-0"
          : "text-fg-2 hover:bg-bg-2 hover:text-fg-1",
      )}
    >
      {dotColor && (
        <span
          className="h-1.5 w-1.5 rounded-pill"
          style={{ background: dotColor }}
        />
      )}
      <span className="truncate">{label}</span>
    </button>
  );
}

function FacetToggle({
  on,
  onChange,
  label,
}: {
  on: boolean;
  onChange: (b: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={() => onChange(!on)}
      className={clsx(
        "flex items-center gap-2 rounded-2 px-2 py-1 text-left text-[11.5px] transition-colors",
        on
          ? "bg-accent-soft text-accent"
          : "text-fg-2 hover:bg-bg-2 hover:text-fg-1",
      )}
    >
      <span
        className={clsx(
          "h-1.5 w-1.5 rounded-pill",
          on ? "bg-accent" : "bg-fg-4",
        )}
      />
      {label}
    </button>
  );
}

// TimelineView — day strip on top (sourced from the window-wide
// /api/actions/day-counts so every day in the configured Window is
// selectable, not just days that fit in the most-recent 500 slice),
// vertical timeline body below. Body mirrors
// design/claude-design-screenshots/capture-2026-05-16T14-46-58-929Z
// — a continuous vertical line on the left with a colored dot
// marker per event and a rich card on the right carrying tool
// badge, raw_tool_name, action-type, #id, target, excerpt, status
// pills, and source/session deep-links.
function TimelineView({
  rows,
  dayCounts,
  pickedDay,
  onPickDay,
  onPickSession,
  loading,
}: {
  rows: ActionListRow[];
  dayCounts: { day: string; count: number }[];
  pickedDay: string | null;
  onPickDay: (day: string | null) => void;
  onPickSession: (sessionId: string) => void;
  loading?: boolean;
}) {
  // Newest first inside the visible set so the timeline reads top
  // (most recent) → bottom (oldest).
  const sortedRows = useMemo(() => {
    return [...rows].sort((a, b) => {
      const ta = new Date(a.timestamp).getTime();
      const tb = new Date(b.timestamp).getTime();
      return tb - ta;
    });
  }, [rows]);

  return (
    <div className="flex flex-col gap-3">
      <TimelineDayAxis
        cells={dayCounts}
        picked={pickedDay}
        onPick={onPickDay}
      />

      {rows.length === 0 ? (
        <div className="grid h-[200px] place-items-center rounded-3 border border-dashed border-line-2 bg-bg-3/40 text-[11px] text-fg-3">
          {loading ? (
            <span className="inline-flex items-center gap-2 text-fg-2">
              <span className="inline-block h-3 w-3 animate-spin rounded-full border border-line-3 border-t-accent" />
              Loading…
            </span>
          ) : pickedDay ? (
            `No actions on ${pickedDay}. Pick another day from the strip above.`
          ) : (
            "No actions match these filters."
          )}
        </div>
      ) : (
        <VerticalTimeline rows={sortedRows} onPickSession={onPickSession} />
      )}
    </div>
  );
}

// TimelineDayAxis — horizontal strip of day chips across the
// configured Window. Each chip carries the day's date, action
// count, and a density bar height-scaled to the busiest day in the
// strip. An "All" chip on the left resets the filter and shows the
// most-recent-N slice.
function TimelineDayAxis({
  cells,
  picked,
  onPick,
}: {
  cells: { day: string; count: number }[];
  picked: string | null;
  onPick: (day: string | null) => void;
}) {
  const total = cells.reduce((a, c) => a + c.count, 0);
  const maxCount = Math.max(1, ...cells.map((c) => c.count));
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 px-3 py-2.5">
      <div className="mb-1.5 flex items-baseline justify-between text-[10.5px] text-fg-3">
        <span className="font-semibold uppercase tracking-[0.06em]">
          Timeline · click a day to filter
        </span>
        <span className="font-mono">
          {total.toLocaleString()} actions across {cells.length} day
          {cells.length === 1 ? "" : "s"}
        </span>
      </div>
      <div className="flex items-end gap-1 overflow-x-auto pb-1">
        <Tooltip content="Show the most-recent actions across all days in the window" maxWidth={300}>
          <button
            type="button"
            onClick={() => onPick(null)}
            className={clsx(
              "flex shrink-0 flex-col items-center justify-end gap-1 rounded-2 border px-2 py-1.5 text-[10px] transition-colors",
              picked == null
                ? "border-accent bg-accent-soft text-accent"
                : "border-line-2 bg-bg-2 text-fg-2 hover:bg-bg-3",
            )}
          >
            <span className="h-[28px] w-[3px] rounded-pill bg-fg-3/40" />
            <span className="font-semibold uppercase tracking-[0.06em]">All</span>
          </button>
        </Tooltip>
        {cells.map((c) => {
          const heightPct = Math.max(8, (c.count / maxCount) * 100);
          const isActive = picked === c.day;
          const date = new Date(c.day + "T00:00:00Z");
          const monthDay = date.toLocaleDateString("en-US", {
            month: "short",
            day: "numeric",
            timeZone: "UTC",
          });
          return (
            <Tooltip
              key={c.day}
              content={`${fmtDateOnly(c.day)} · ${c.count} action${c.count === 1 ? "" : "s"}`}
            >
              <button
                type="button"
                onClick={() => onPick(c.day)}
                className={clsx(
                  "flex w-[64px] shrink-0 flex-col items-center justify-end gap-1 rounded-2 border px-1 py-1.5 transition-all",
                  isActive
                    ? "border-accent bg-accent-soft text-accent"
                    : "border-line-2 bg-bg-2 text-fg-2 hover:-translate-y-0.5 hover:border-accent/60 hover:bg-bg-3",
                )}
              >
                <span
                  className={clsx(
                    "w-[6px] rounded-pill",
                    isActive ? "bg-accent" : "bg-accent/55",
                  )}
                  style={{ height: `${heightPct * 0.32}px` }}
                />
                <span className="font-mono text-[9.5px] tabular-nums">
                  {c.count}
                </span>
                <span className="text-[10px] uppercase tracking-[0.04em]">
                  {monthDay}
                </span>
              </button>
            </Tooltip>
          );
        })}
      </div>
    </div>
  );
}

// VerticalTimeline — per-row flex layout with three columns:
// timestamp (80px), rail (16px with a continuous center line + dot
// marker per row), and the rich Event Log card (flex-1). Each row's
// rail segment is full-height so consecutive rows produce a visually
// continuous vertical line behind the dot markers. Matches the
// design pattern in capture-2026-05-16T14-46-58-929Z.png.
function VerticalTimeline({
  rows,
  onPickSession,
}: {
  rows: ActionListRow[];
  onPickSession: (sessionId: string) => void;
}) {
  return (
    <ol className="rounded-3 border border-line-2 bg-bg-2 px-3 py-3">
      {rows.map((r, i) => (
        <TimelineEntry
          key={r.id}
          row={r}
          onPickSession={onPickSession}
          isFirst={i === 0}
          isLast={i === rows.length - 1}
        />
      ))}
    </ol>
  );
}

// TimelineEntry — one row of the vertical timeline. Three-column
// flex: timestamp on the left, rail (with center line + dot) in
// the middle, rich card on the right. The rail line is per-row,
// but the top/bottom flush together create a continuous illusion;
// the first row's rail starts mid-row and the last row's ends
// mid-row so the line caps cleanly at the dot markers.
function TimelineEntry({
  row,
  onPickSession,
  isFirst,
  isLast,
}: {
  row: ActionListRow;
  onPickSession: (sessionId: string) => void;
  isFirst: boolean;
  isLast: boolean;
}) {
  const meta = actionMeta(row.action_type);
  const ts = new Date(row.timestamp);
  const hhmmss = ts.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
  const monthDay = ts.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });
  return (
    <li className="flex items-stretch gap-3 py-2">
      <Tooltip content={fmtDateTime(row.timestamp)}>
        <div
          tabIndex={0}
          className="shrink-0 cursor-help pt-2 text-right font-mono text-[10.5px] tabular-nums text-fg-3 focus:outline-none"
          style={{ width: 80 }}
        >
          <span className="block text-fg-2">{hhmmss}</span>
          <span className="block text-[9.5px] text-fg-4">{monthDay}</span>
        </div>
      </Tooltip>
      <div className="relative shrink-0" style={{ width: 16 }} aria-hidden>
        {/* Vertical line segment. Top half hidden on the first row,
            bottom half hidden on the last row, so the rail caps
            cleanly at the dot markers without trailing past them. */}
        <span
          className="absolute left-1/2 w-px -translate-x-1/2 bg-line-2"
          style={{
            top: isFirst ? "16px" : 0,
            bottom: isLast ? "calc(100% - 16px)" : 0,
          }}
        />
        {/* Dot marker on the rail at the entry's "row anchor" — the
            same vertical offset as the timestamp's first line so
            scanning the rail aligns with reading the timestamps. */}
        <span
          className={clsx(
            "absolute left-1/2 top-[10px] block h-3 w-3 -translate-x-1/2 rounded-full ring-2 ring-bg-2",
            !row.success && "ring-danger",
          )}
          style={{ background: meta.colorVar }}
        />
      </div>
      <div className="min-w-0 flex-1">
        <EventLogCard row={row} onPickSession={onPickSession} />
      </div>
    </li>
  );
}

// EventLogCard — vertical rich entry. Mirrors design/claude-design-
// screenshots/capture-2026-05-16T14-46-58-929Z.png: header carries
// ToolBadge + raw_tool_name + #id + action-type pill on the left,
// target on the right; body holds either the FTS5 excerpt OR a
// summary block built from target + raw_tool_name when no excerpt
// is available — so every entry shows substantive detail, not just
// failures. Footer carries status / effort / permission / source +
// session deep-link.
function EventLogCard({
  row,
  onPickSession,
}: {
  row: ActionListRow;
  onPickSession: (sessionId: string) => void;
}) {
  const sf = row.source_file ?? "";
  const sfTail =
    sf.lastIndexOf("/") >= 0 ? sf.slice(sf.lastIndexOf("/") + 1) : sf;
  // Detail body — prefer the FTS5 excerpt, fall back to target so
  // every entry surfaces *some* readable content. Failures also
  // render the error message in a danger-tinted block alongside.
  const detailBody =
    row.excerpt && row.excerpt.trim().length > 0
      ? row.excerpt
      : row.target && row.target.trim().length > 0
        ? row.target
        : null;
  return (
    <article className="rounded-3 border border-line-2 bg-bg-1 p-3.5 transition-colors hover:border-line-3">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <ToolBadge tool={row.tool} />
          {(() => {
            const mcp = mcpIdentity(row);
            if (mcp) {
              return (
                <CopyOnClick value={row.raw_tool_name || row.target || ""} title="MCP tool call">
                  <span className="inline-flex items-center gap-1 rounded-pill border border-accent/40 bg-accent/10 px-2 py-0.5 font-mono text-[10px] font-medium leading-none text-accent">
                    <span className="uppercase tracking-[0.06em] opacity-80">MCP</span>
                    <span className="max-w-[200px] truncate">
                      {mcp.server}
                      {mcp.tool ? ` / ${mcp.tool}` : ""}
                    </span>
                  </span>
                </CopyOnClick>
              );
            }
            return row.raw_tool_name ? (
              <Tooltip content={<span className="break-all font-mono">{row.raw_tool_name}</span>} maxWidth={360}>
                <span
                  tabIndex={0}
                  className="max-w-[180px] cursor-help truncate font-mono text-[11px] text-fg-1 focus:outline-none"
                >
                  {row.raw_tool_name}
                </span>
              </Tooltip>
            ) : null;
          })()}
          <ActionTypeBadge type={row.action_type} />
          <CopyOnClick value={String(row.id)}>
            <span className="font-mono text-[10.5px] text-fg-4">#{row.id}</span>
          </CopyOnClick>
        </div>
        {row.target && (
          <CopyOnClick value={row.target}>
            <span
              className="block max-w-[260px] truncate font-mono text-[10.5px] text-fg-2"
            >
              {row.target}
            </span>
          </CopyOnClick>
        )}
      </header>

      {detailBody && (
        <pre className="mt-2 max-h-[160px] overflow-auto whitespace-pre-wrap break-words rounded-2 bg-bg-2 px-3 py-2 font-mono text-[11px] leading-snug text-fg-1">
          {detailBody}
        </pre>
      )}

      {row.error_message && (
        <pre className="mt-2 max-h-[120px] overflow-auto whitespace-pre-wrap break-words rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 font-mono text-[11px] text-danger">
          {row.error_message}
        </pre>
      )}

      <footer className="mt-2 flex flex-wrap items-center gap-1.5 text-[10.5px] text-fg-3">
        {row.success ? (
          row.is_interrupt ? (
            <Pill variant="warn">interrupted</Pill>
          ) : (
            <Pill>ok</Pill>
          )
        ) : (
          <Pill variant="danger">fail</Pill>
        )}
        {row.effort_level && <Pill>effort: {row.effort_level}</Pill>}
        {row.permission_mode && (
          <Pill>permission: {row.permission_mode}</Pill>
        )}
        {row.stop_reason && <Pill>stop: {row.stop_reason}</Pill>}
        {row.service_tier &&
          !["standard", "default", "auto"].includes(row.service_tier) && (
            <Pill>tier: {row.service_tier}</Pill>
          )}
        {sf && (
          <Tooltip content={<span className="break-all font-mono">{sf}</span>} maxWidth={420}>
            <span
              tabIndex={0}
              className="ml-auto max-w-[200px] cursor-help truncate font-mono text-[10.5px] text-fg-4 focus:outline-none"
            >
              {sfTail}
            </span>
          </Tooltip>
        )}
        <Tooltip content={`Open session ${row.session_id}`}>
          <button
            type="button"
            onClick={() => onPickSession(row.session_id)}
            className={clsx(
              "font-mono text-[10.5px] text-accent hover:text-accent-strong hover:underline",
              !sf && "ml-auto",
            )}
          >
            session {fmtShortId(row.session_id, 10)}
          </button>
        </Tooltip>
      </footer>
    </article>
  );
}

function ActionTypeBadge({ type }: { type: string }) {
  const meta = actionMeta(type);
  return (
    <Tooltip content={`${meta.label} · category: ${meta.category}`}>
      <span
        tabIndex={0}
        className="inline-flex cursor-help items-center gap-1 rounded-pill border px-2 py-0.5 text-[10.5px] font-medium focus:outline-none"
        style={{
          borderColor: `color-mix(in srgb, ${meta.colorVar} 35%, transparent)`,
          background: `color-mix(in srgb, ${meta.colorVar} 12%, transparent)`,
          color: meta.colorVar,
        }}
      >
        <span
          className="h-1 w-1 rounded-full"
          style={{ background: meta.colorVar }}
        />
        {meta.label}
      </span>
    </Tooltip>
  );
}

function ExpandedDetail({
  row,
  onClose,
}: {
  row: ActionListRow;
  onClose: () => void;
}) {
  return (
    <div className="mt-2 rounded-2 border border-line-2 bg-bg-3/60 p-3 text-[11.5px]">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
            Action #{row.id}
          </div>
          <div className="font-mono text-fg-2">
            {row.raw_tool_name || "(no raw tool name)"}
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="text-[11px] text-fg-3 hover:text-fg-1"
        >
          Hide ×
        </button>
      </div>
      <dl className="mt-2 grid grid-cols-1 gap-x-4 gap-y-1 md:grid-cols-2">
        <DetailRow label="Timestamp" value={row.timestamp} mono />
        <DetailRow
          label="Message ID"
          value={row.message_id || "-"}
          mono
        />
        <DetailRow
          label="Project"
          value={row.project || "(none)"}
          mono
        />
        <DetailRow
          label="Permission"
          value={row.permission_mode || "-"}
        />
        <DetailRow label="Effort" value={row.effort_level || "-"} />
        <DetailRow
          label="Status"
          value={row.success ? "success" : "failure"}
        />
      </dl>
      {row.target && (
        <>
          <div className="mt-3 text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
            Target / message
          </div>
          <pre className="mt-1 max-h-[160px] overflow-auto whitespace-pre-wrap rounded-1 bg-bg-1 px-2 py-1.5 font-mono text-[11px] text-fg-1">
            {row.target}
          </pre>
        </>
      )}
      {row.error_message && (
        <>
          <div className="mt-3 text-[10px] font-semibold uppercase tracking-[0.06em] text-danger">
            Error
          </div>
          <pre className="mt-1 max-h-[120px] overflow-auto whitespace-pre-wrap rounded-1 border border-danger/30 bg-danger-soft px-2 py-1.5 font-mono text-[11px] text-danger">
            {row.error_message}
          </pre>
        </>
      )}
    </div>
  );
}

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex gap-2">
      <dt className="w-[100px] shrink-0 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
        {label}
      </dt>
      <Tooltip
        content={<span className="break-all">{String(value)}</span>}
        maxWidth={420}
      >
        <dd
          tabIndex={0}
          className={`min-w-0 cursor-help truncate focus:outline-none ${mono ? "font-mono text-fg-2" : "text-fg-1"}`}
        >
          {value}
        </dd>
      </Tooltip>
    </div>
  );
}

// LiveTailIndicator — small status pill next to the Event log title.
// When unpaused, animates a pulsing green dot to signal the firehose
// is refreshing on a 5s cadence. Click toggles to a paused state with
// a Resume CTA — design's `page-actions.jsx:135-137` calls for the
// pause control in the card head.
function LiveTailIndicator({
  paused,
  onToggle,
}: {
  paused: boolean;
  onToggle: () => void;
}) {
  return (
    <Tooltip content={paused ? "Resume live tail" : "Pause live tail"}>
    <button
      type="button"
      onClick={onToggle}
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-pill border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.04em] transition-colors",
        paused
          ? "border-warn/40 bg-warn-soft text-warn hover:bg-warn-soft/80"
          : "border-success/40 bg-success-soft text-success hover:bg-success-soft/80",
      )}
    >
      <span
        aria-hidden
        className={clsx(
          "h-1.5 w-1.5 rounded-full",
          paused ? "bg-warn" : "animate-pulse bg-success",
        )}
      />
      {paused ? "paused" : "live"}
    </button>
    </Tooltip>
  );
}

// buildActionChips — page-local mapping from Actions filter state to
// the generic FilterChip shape consumed by `<ActiveFilterChips />`.
function buildActionChips(props: {
  actionType: string;
  setActionType: (s: string) => void;
  effortLevel: string;
  setEffortLevel: (s: string) => void;
  permissionMode: string;
  setPermissionMode: (s: string) => void;
  isInterrupt: boolean;
  setIsInterrupt: (b: boolean) => void;
  assistantText: boolean;
  setAssistantText: (b: boolean) => void;
  sessionFilter: string;
  setSessionFilter: (s: string) => void;
}): FilterChip[] {
  const chips: FilterChip[] = [];
  if (props.actionType)
    chips.push({
      label: `type: ${props.actionType}`,
      onClear: () => props.setActionType(""),
    });
  if (props.effortLevel)
    chips.push({
      label: `effort: ${props.effortLevel}`,
      onClear: () => props.setEffortLevel(""),
    });
  if (props.permissionMode)
    chips.push({
      label: `permission: ${props.permissionMode}`,
      onClear: () => props.setPermissionMode(""),
    });
  if (props.isInterrupt)
    chips.push({
      label: "interrupted",
      onClear: () => props.setIsInterrupt(false),
    });
  if (props.assistantText)
    chips.push({
      label: "AI assistant text only",
      onClear: () => props.setAssistantText(false),
    });
  if (props.sessionFilter)
    chips.push({
      label: `session: ${fmtShortId(props.sessionFilter, 10)}`,
      title: `Remove filter (session ${props.sessionFilter})`,
      onClear: () => props.setSessionFilter(""),
    });
  return chips;
}

// todayIsoDate — UTC-anchored YYYY-MM-DD for "today" so it pairs
// cleanly with the day-counts response, which buckets server-side
// by substr(timestamp, 1, 10) (also UTC since timestamps are
// stored in RFC3339Nano).
function todayIsoDate(): string {
  const d = new Date();
  return d.toISOString().slice(0, 10);
}

function relativeTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "-";
  const ms = Date.now() - t;
  if (ms < 0) return "future";
  const s = ms / 1000;
  if (s < 60) return `${Math.round(s)}s ago`;
  const m = s / 60;
  if (m < 60) return `${Math.round(m)}m ago`;
  const h = m / 60;
  if (h < 24) return `${Math.round(h)}h ago`;
  const d = h / 24;
  if (d < 14) return `${Math.round(d)}d ago`;
  return `${Math.round(d / 7)}w ago`;
}
