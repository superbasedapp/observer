import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import clsx from "clsx";
import {
  CalendarDays,
  Check,
  CornerDownRight,
  Info,
  List,
  Pencil,
  Star,
  StickyNote,
  Table2,
  Bot,
  X,
  type LucideIcon,
} from "lucide-react";
import { useSearchParams } from "react-router-dom";
import type { ColumnDef, SortingState } from "@tanstack/react-table";
import {
  ActiveFilterChips,
  ChartShell,
  type FilterChip,
  GlyphBadge,
  Icon,
  LiveDot,
  ModelMark,
  PageHeader,
  Pill,
  SegmentedControl,
  SlideOver,
  SurfaceBadge,
  type SurfaceKind,
  ExecutionLocationBadge,
  EXECUTION_FILTER_OPTIONS,
  type ExecutionFilterValue,
  TokenBar,
  ToolBadge,
  Tooltip,
} from "@/components/primitives";
import { AnchoredPopover } from "@/components/primitives/AnchoredPopover";
import { shortModel } from "@/lib/models";
import { orgIntelSessionsBanner, orgPlaneEnrichAction, SESSION_ENRICH_PLANE_COPY, sessionEffectiveTitle, sessionEnrichPlane, type OrgIntelStatusResponse } from "@/lib/orgIntel";
import { HelpInd } from "@/components/HelpInd";
import { CopyOnClick } from "@/components/CopyOnClick";
import { CommandJobButton } from "@/components/CommandJobButton";
import { Summary } from "@/components/Summary";
import { DataTable, Pagination } from "@/components/DataTable";
import { ChartState } from "@/components/ChartState";
import { SessionDetailPanel } from "@/components/SessionDetailPanel";
import { TagPill } from "@/components/TagPill";
import { FavoriteStar, RatingChip, TagEditor } from "@/components/TagEditor";
import { postSessionTags } from "@/lib/api";
import { useFilters, windowDaysApprox, windowParams } from "@/lib/filters";
import { useApi } from "@/lib/useApi";
import { pushToast } from "@/components/Toast";
import { cloudFetchEvents } from "@/lib/cloud";
import type { CloudStatusWithDigestPlan } from "@/lib/cloud";
import { CloudDigestCard } from "@/components/CloudDigestCard";
import { CloudEnrichmentSummary } from "@/components/CloudEnrichmentSummary";
import { OrgSessionsBannerView } from "@/components/OrgSessionsBanner";
import { CloudRow } from "@/components/sessiondetail/CloudRow";
import { OrgIntelCard } from "@/components/sessiondetail/OrgIntelCard";
import { cloudProgressAction, cloudProgressMeta } from "@/lib/cloudProgress";
import { vocabIcon } from "@shared/lib/vocabIcons";
import { CodeCommentSplit } from "@shared/primitives/CodeCommentSplit";
import {
  fmtCompact,
  fmtDateTime,
  fmtDuration,
  fmtInt,
  fmtPct,
  fmtCost,
  fmtUSD,
  costLabel,
  getCostDisplayMode,
  localeString,
} from "@/lib/format";
import { csvText } from "@/lib/costExport";
import type {
  AttachSessionsResponse,
  SessionRow,
  SessionsCalendarResponse,
  SessionsResponse,
  TagRollup,
  TagRollupResponse,
} from "@/lib/types";
import {
  activeFilterCount,
  applyFilters,
  EMPTY_FILTERS,
  loadFilters,
  saveFilters,
  type SessionFilters,
  SessionsFiltersDrawer,
} from "./sessions/FiltersDrawer";
import { navIcon } from "@/lib/nav";
import { OwnAgentsView } from "./sessions/OwnAgentsView";
import { ColumnsPicker } from "./sessions/ColumnsPicker";
import { agentFromSurfaceHost } from "@/lib/ownAgents";
import {
  ENRICH_TONE_CLASS,
  SORT_OPTIONS,
  inlineFacets,
  loadColumnOverrides,
  matchSortOption,
  parentSessionId,
  projectName,
  resolveSessionColumns,
  rowTagCount,
  saveColumnOverrides,
  sessionColumn,
  sessionTokenTotal,
  shortSessionId,
  sortButtonLabel,
  type ColumnOverrides,
  type ColumnStorage,
  type EnrichVariant,
  type SessionColumnId,
} from "@/lib/sessionColumns";

// One glyph per sessions section card title (the ChartShell `icon` slot): the
// chart or table shape the section shows, never decoration.
const SECTION_ICONS = {
  allSessions: List,
} satisfies Record<string, LucideIcon>;

const PAGE_LIMIT = 50;

// selectLiveRunIds / selectActiveIds narrow the two liveness polls to the id
// lists the table reads (useApi `select`), so a poll that changes nothing
// the table shows keeps the sets, the column defs and every row as they are.
function selectLiveRunIds(d: AttachSessionsResponse): string[] {
  const out: string[] = [];
  for (const r of d.sessions ?? []) {
    if (r.session_id && !r.exited) out.push(r.session_id);
  }
  return out;
}

function selectActiveIds(d: { active_ids?: string[] }): string[] {
  return (d.active_ids ?? []).filter((id) => !!id);
}
// SESSIONS_POLL_MS is the list poll (see the useApi call below).
const SESSIONS_POLL_MS = 30_000;

// The Sort menu (SORT_OPTIONS) and the column table live in
// lib/sessionColumns. The menu reaches the sorts that have no visible header:
// rating (no column), and the four token buckets the Tokens column sums.
// Header clicks drive the same `sorting` state.

// browserStorage is localStorage, or null where reading it throws (a
// private window, blocked site data). The column choices degrade to the
// defaults; nothing else depends on it.
function browserStorage(): ColumnStorage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

type View = "table" | "calendar" | "agents";

// SURFACE_FILTER_OPTIONS backs the toolbar's Client dropdown — one row per
// value of the closed capture-surface vocabulary (SurfaceBadge's
// SurfaceKind), walked as data rather than hand-written <option>s so a new
// kind is one row here. "" = no filter. The filter is SERVER-side
// (`surface=` on /api/sessions), like tags/favorites and unlike the drawer:
// the drawer only sees the loaded page, and a client filter there would
// silently hide matching sessions on other pages.
const SURFACE_FILTER_OPTIONS: ReadonlyArray<{ value: SurfaceKind | ""; label: string }> = [
  { value: "", label: "Client: any" },
  { value: "cli", label: "cli - terminal" },
  { value: "ide", label: "ide - editor / plugin" },
  { value: "desktop", label: "desktop - desktop app" },
  { value: "sdk", label: "sdk - programmatic" },
  { value: "web", label: "web - browser" },
  { value: "mobile", label: "mobile - phone app" },
];

export function SessionsPage() {
  const { win, customRange, tool, model, project, query: globalQuery } = useFilters();
  const winParams = windowParams(win, customRange);
  // CalendarView needs a plain day-count for its grid span; sub-day
  // windows round up to a day.
  const calendarDays = windowDaysApprox(win, customRange);
  const toolParam = tool === "all" ? undefined : tool;
  const modelParam = model === "all" ? undefined : model;
  const projectParam = project === "all" ? undefined : project;

  const [view, setView] = useState<View>("table");
  const [enrichmentSession, setEnrichmentSession] = useState<SessionRow | null>(null);
  const [page, setPage] = useState(1);
  // Server-side sort. The table is controlled (manualSorting): a header click
  // updates this state, which feeds sort_by/sort_dir into the fetch so the
  // server orders the WHOLE filtered set before paging. Without this, sorting
  // reordered only the loaded page (e.g. "cost desc" showed the priciest of
  // the visible 20, not the priciest session overall).
  const [sorting, setSorting] = useState<SortingState>([
    { id: "started_at", desc: true },
  ]);
  const sortBy = sorting[0]?.id ?? "started_at";
  const sortDir = sorting[0]?.desc === false ? "asc" : "desc";
  // The menu row for the current sort, when one matches. The button names
  // any other sort by its column (a header sort on a column that may now be
  // hidden), so the order on screen is always explained.
  const sortOption = matchSortOption(sortBy, sortDir === "desc");
  const sortLabel = sortButtonLabel(sortBy, sortDir === "desc").replace(
    "Total $",
    costLabel("Total $", "Total tokens"),
  );

  // Column choices (lib/sessionColumns): the viewer's explicit on/off per
  // column, remembered in this browser. The fit rule below drops default
  // columns that do not fit the card's measured width.
  const [colOverrides, setColOverrides] = useState<ColumnOverrides>(() =>
    loadColumnOverrides(browserStorage()),
  );
  useEffect(() => {
    saveColumnOverrides(browserStorage(), colOverrides);
  }, [colOverrides]);
  // fitRef wraps the table; its width is what the columns must fit. Read
  // before paint (layout effect) so the first frame is already fitted, and
  // again whenever the card resizes.
  const fitRef = useRef<HTMLDivElement | null>(null);
  const [fitWidth, setFitWidth] = useState<number | null>(null);
  const [localQuery, setLocalQuery] = useState("");
  // pickedDay is set when the user clicks a CalendarView cell — drives
  // a server-side from_date/to_date filter on /api/sessions so the
  // refetch returns that day's sessions regardless of pagination
  // position. Local substring filtering against the loaded page can't
  // see sessions from days outside the current page (e.g. clicking a
  // calendar cell from a month ago when the table only has the most
  // recent page-50 loaded).
  const [pickedDay, setPickedDay] = useState<string | null>(null);
  // Deep-linkable detail panel: /sessions?session=<id> opens it directly
  // (the Suggestions page links session-scoped suggestions here). The URL
  // is the source of truth so back/forward and copy-paste both work.
  const [searchParams, setSearchParams] = useSearchParams();
  const selected = searchParams.get("session");
  const watch = searchParams.get("watch") === "1";
  const setSelected = (id: string | null) => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (id) {
          next.set("session", id);
        } else {
          next.delete("session");
          // Closing the panel drops watch mode too, so a re-open from a
          // row click starts in normal (non-tail-follow) mode.
          next.delete("watch");
        }
        return next;
      },
      { replace: true },
    );
  };
  // setWatch opens the detail panel directly in watch mode (read-only
  // tail-follow) — used by the "live · watch" pill on bare sessions.
  const setWatch = (id: string) => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.set("session", id);
        next.set("watch", "1");
        return next;
      },
      { replace: true },
    );
  };
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [sortMenuOpen, setSortMenuOpen] = useState(false);
  const sortTriggerRef = useRef<HTMLButtonElement | null>(null);
  const [filters, setFilters] = useState<SessionFilters>(() => loadFilters());
  useEffect(() => {
    saveFilters(filters);
  }, [filters]);
  const drawerCount = activeFilterCount(filters);

  // Session classification (docs/plans/session-classification-tags-plan-2026-07-31.md).
  // tagFilters + favoriteOnly are SERVER-side params, deliberately NOT part of
  // the drawer's client-side applyFilters: that path only sees the loaded page,
  // so a tag filter there would silently hide matching sessions on other pages.
  // Nothing is persisted — the server owns tags/favorites, and the filter is a
  // transient view choice.
  const [tagFilters, setTagFilters] = useState<string[]>([]);
  const [favoriteOnly, setFavoriteOnly] = useState(false);
  // surfaceFilter is the Client dropdown's value: one closed-vocabulary kind
  // or "" for any. Server-side (all pages) and transient, exactly like
  // favoriteOnly — the stamp is the server's fact, the filter a view choice.
  const [surfaceFilter, setSurfaceFilter] = useState<SurfaceKind | "">("");
  // agentHost is the Own agents view's pick: one own agent's stored
  // surface_host ("agent:<name>"). It narrows the table SERVER-side to that
  // agent's custom-agent sessions (tool + surface_host), all pages, and is
  // transient like the Client dropdown. null = no agent filter.
  const [agentHost, setAgentHost] = useState<string | null>(null);
  // ranFilter is the "Where it ran" dropdown's value (execution_location on
  // /api/sessions, node migration 240): local / vendor_cloud /
  // customer_worker / unknown, or "" for anywhere. Server-side and transient,
  // exactly like surfaceFilter.
  const [ranFilter, setRanFilter] = useState<ExecutionFilterValue>("");
  const tagKey = tagFilters.join(",");
  // annotations holds per-session optimistic overrides for the
  // classification fields, merged over the fetched rows. Each entry is
  // replaced by the server's post-mutation truth on success and reverted on
  // failure, so it never drifts from the backend.
  const [annotations, setAnnotations] = useState<
    Record<
      string,
      { tags?: string[]; favorite?: boolean; has_note?: boolean; rating?: number; title?: string }
    >
  >({});
  const addTagFilter = (tag: string) => {
    setTagFilters((cur) => (cur.includes(tag) ? cur : [...cur, tag]));
  };
  // toggleTagFilter is what the Tags panel's pills use: they render their
  // own selected state (aria-pressed), so a second click on a selected pill
  // has to mean "deselect" — an add-only handler left the operator with no
  // way to drop a tag from the pill itself. Row pills and the detail panel
  // keep the add-only handler: those pills carry no selected state, so
  // toggling there would silently clear a filter the operator can't see.
  const toggleTagFilter = (tag: string) => {
    setTagFilters((cur) =>
      cur.includes(tag) ? cur.filter((t) => t !== tag) : [...cur, tag],
    );
  };

  // Reset page when filters change (incl. picked calendar day).
  const filterKey = `${win}|${tool}|${project}|${model}|${pickedDay ?? ""}|${sortBy}|${sortDir}|${tagKey}|${favoriteOnly}|${surfaceFilter}|${agentHost ?? ""}|${ranFilter}`;
  const lastKey = useMemo(() => filterKey, [filterKey]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useMemo(() => setPage(1), [lastKey]);

  // The detail drawer and the enrichment panel are modal (scrim + scroll
  // lock): while either is open, nothing behind them is visible to refresh.
  const tableCovered = selected != null || enrichmentSession !== null;
  const sessions = useApi<SessionsResponse>(
    "/api/sessions",
    {
      page,
      limit: PAGE_LIMIT,
      // An own-agent pick names its tool outright (the global tool filter
      // would otherwise hide every custom-agent session).
      tool: agentHost ? "custom-agent" : toolParam,
      surface_host: agentHost ?? undefined,
      model: modelParam,
      project: projectParam,
      ...winParams,
      from_date: pickedDay ?? undefined,
      to_date: pickedDay ?? undefined,
      sort_by: sortBy,
      sort_dir: sortDir,
      // Repeated `tag=` params (AND semantics, server-side) + favorite=1.
      tag: tagFilters.length > 0 ? tagFilters : undefined,
      favorite: favoriteOnly ? 1 : undefined,
      // Capture-surface kind, exact match server-side; "" is dropped by
      // buildUrl so "any" sends nothing.
      surface: surfaceFilter || undefined,
      // Where it ran; "" (anywhere) is dropped by buildUrl.
      execution_location: ranFilter || undefined,
    },
    [
      page,
      win,
      customRange,
      tool,
      project,
      model,
      pickedDay,
      sortBy,
      sortDir,
      tagKey,
      favoriteOnly,
      surfaceFilter,
      agentHost,
      ranFilter,
    ],
    // Live-capture refresh: every 30 s while the tab is visible and the
    // table is not covered by a modal panel. Lets fresh Antigravity-CLI .pb
    // files (and any other in-progress session) appear without a manual
    // reload. It was 5 s, but on a large database one /api/sessions costs
    // several seconds server-side, so a 5 s poll kept a request permanently
    // in flight and re-rendered the table on every settle. The per-row live
    // signal does not depend on this cadence: the "live" pills come from the
    // cheap /api/live + /api/attach/sessions polls below. While the session
    // drawer (or the enrichment panel) covers the table, the poll pauses;
    // on close the query cache revalidates at once if the list is overdue.
    { refreshMs: tableCovered ? 0 : SESSIONS_POLL_MS },
  );

  // Per-day rollup over the full window — drives the Calendar view
  // so the grid carries real data across the configured Window, not
  // just whatever's in the most recent 50 rows of the table page.
  // Fetched only when Calendar view is active to avoid the cost on
  // the default Table view.
  const calendar = useApi<SessionsCalendarResponse>(
    view === "calendar" ? "/api/sessions/calendar" : null,
    {
      tool: toolParam,
      model: modelParam,
      project: projectParam,
      ...winParams,
    },
    [view, win, customRange, tool, model, project],
  );

  // Live attach sessions (session-attach Phase 2): polled every 15s WHILE the
  // page is visible (P2-4a) so a "live · joinable" chip clears when the child
  // exits and appears when a new daemon-owned terminal run lands — the badge
  // must not stay stuck live on a one-shot snapshot. useApi pauses the loop when
  // the tab is hidden and clears the interval on unmount. Drives the
  // informational chip on rows whose session id has a live daemon-owned terminal
  // run bound to it — /api/attach/sessions now covers every live kind
  // (fresh/handoff/attach/resume), not attach-only, so a dashboard-launched
  // "new terminal" session gets the chip too once the correlation sweep links
  // it (~10-30s after launch). A dashboard without the attach seam 503s →
  // empty set → no chips.
  // Paused while the table is covered (see tableCovered); resumes, with an
  // immediate revalidation when overdue, the moment the panel closes.
  //
  // Only the ids of running runs are read, selected BY VALUE: the payload
  // carries per-run fields that move on every poll, and a new liveSet
  // rebuilds the column defs and re-renders every row.
  const liveRunIds = useApi<AttachSessionsResponse, string[]>(
    "/api/attach/sessions",
    undefined,
    [],
    { refreshMs: tableCovered ? 0 : 15000, select: selectLiveRunIds },
  ).data;
  const liveSet = useMemo(() => new Set(liveRunIds ?? []), [liveRunIds]);

  // Canonical liveness for BARE (non-attachable) sessions: /api/live
  // marks a session active if any row landed in the last 15 minutes.
  // Polled at 15s (matching the attach cadence, NOT Live.tsx's 5s — this
  // table lists many rows). Drives the read-only "live · watch" chip on
  // rows that are running but weren't launched with `--attach`.
  // ids_only mode: EVERY active session id in the window (the card-view
  // default caps at the newest 8, which would silently drop the ninth
  // concurrent session's "live · watch" pill).
  const activeIds = useApi<{ active_ids?: string[] }, string[]>(
    "/api/live",
    { window_minutes: 15, ids_only: 1 },
    [],
    { refreshMs: tableCovered ? 0 : 15000, select: selectActiveIds },
  ).data;
  const activeSet = useMemo(() => new Set(activeIds ?? []), [activeIds]);

  // Tag vocabulary + per-tag rollup. Drives the Tags panel and is reloaded
  // after every classification mutation so counts/cost stay honest.
  const tagRollup = useApi<TagRollupResponse>("/api/sessions/tags", undefined, []);

  // Cloud Intelligence background-by-default (value-upgrade plan §W3,
  // 2026-09-15): the developer's own enrichment policy (`observer cloud
  // enable`) drives whether this page polls for freshly-arrived AI titles,
  // and the honest "waiting on provider" banner reads the last sync's
  // outcome. 30s cadence, paused while the tab is hidden (useApi's default).
  const cloudStatus = useApi<CloudStatusWithDigestPlan>(
    "/api/cloud/status",
    undefined,
    [],
    { refreshMs: 30000 },
  );
  const cloudSignedIn = !!cloudStatus.data?.sign_in?.signed_in;
  const cloudProviderWaiting = cloudStatus.data?.provider_state === "waiting";
  const [cloudBannerDismissed, setCloudBannerDismissed] = useState(false);
  // The org plane's status (ruling Q6): when the listed sessions are on the
  // org plane, the banner above the table describes org enrichment instead of
  // personal sign-in.
  const orgIntelStatus = useApi<OrgIntelStatusResponse>("/api/intel/status", undefined, [], { refreshMs: 300000 });

  // Polls GET /api/cloud/events every 30s while the policy is on. The FIRST
  // response only records which result ids already exist (nothing to
  // announce retroactively for a page that just opened); a later poll that
  // introduces a NEW result id raises "N session(s) named by Cloud
  // Intelligence" and reloads the table so the new title renders.
  const cloudSeenResultIdsRef = useRef<Set<string> | null>(null);
  useEffect(() => {
    if (!cloudSignedIn) return undefined;
    let cancelled = false;
    const poll = () => {
      cloudFetchEvents()
        .then((resp) => {
          if (cancelled) return;
          const results = resp.results ?? [];
          if (cloudSeenResultIdsRef.current === null) {
            cloudSeenResultIdsRef.current = new Set(results.map((res) => res.result_id));
            return;
          }
          const seen = cloudSeenResultIdsRef.current;
          const fresh = results.filter((res) => !seen.has(res.result_id));
          for (const res of results) seen.add(res.result_id);
          if (fresh.length > 0) {
            pushToast(
              `${fresh.length} session${fresh.length === 1 ? "" : "s"} named by Cloud Intelligence`,
              "success",
            );
            sessions.reload();
          }
        })
        .catch(() => {
          // Best-effort poll; a transient failure just waits for the next tick.
        });
    };
    poll();
    const id = window.setInterval(poll, 30000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cloudSignedIn]);

  const rawRows = sessions.data?.rows ?? [];
  // SERVER TRUTH WINS ON EVERY FETCH. The optimistic override map is a bridge
  // across exactly one gap — between a classification POST and the next
  // /api/sessions response — and is dropped WHOLESALE the moment a fresh page
  // lands. Without this the map was write-only: a tag added from the CLI or a
  // second device could never appear on a row that had ever been touched here,
  // and a POST whose response failed AFTER the server had already committed
  // left the reverted (wrong) value pinned forever.
  //
  // sessions.data changes identity only when the payload actually differs
  // (useApi's byte-identical guard), so idle 5s polls don't churn state — and a
  // byte-identical response carries no new server truth to adopt anyway.
  useEffect(() => {
    if (sessions.data == null) return;
    setAnnotations((cur) => (Object.keys(cur).length === 0 ? cur : {}));
  }, [sessions.data]);

  // Merge optimistic annotations over the fetched page.
  const rows = useMemo(
    () =>
      rawRows.map((r) => {
        const a = annotations[r.id];
        return a ? { ...r, ...a } : r;
      }),
    // rawRows identity is stable between polls thanks to useApi's
    // byte-identical guard, so this only recomputes on real change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [sessions.data, annotations],
  );
  const orgSessionsBanner = useMemo(
    () => orgIntelSessionsBanner(orgIntelStatus.data?.status, rows.map(sessionEnrichPlane)),
    [orgIntelStatus.data, rows],
  );

  // patchAnnotation records an optimistic (or server-confirmed) override.
  const patchAnnotation = (
    id: string,
    patch: { tags?: string[]; favorite?: boolean; has_note?: boolean; rating?: number; title?: string },
  ) => {
    setAnnotations((cur) => ({ ...cur, [id]: { ...cur[id], ...patch } }));
  };

  // toggleFavorite flips the star optimistically, then reconciles against the
  // server's reply; a failed POST reverts to the pre-click value.
  const toggleFavorite = async (row: SessionRow) => {
    const before = row.favorite === true;
    patchAnnotation(row.id, { favorite: !before });
    try {
      const r = await postSessionTags(row.id, { favorite: !before });
      patchAnnotation(row.id, {
        favorite: r.favorite,
        tags: r.tags,
        has_note: (r.note ?? "") !== "",
        rating: r.rating,
      });
      tagRollup.reload();
    } catch {
      patchAnnotation(row.id, { favorite: before });
    }
  };

  // setRating writes the 1-10 overall score optimistically (0 = clear), then
  // reconciles against the server's reply; a failed POST reverts to the
  // pre-click value.
  const setRating = async (row: SessionRow, next: number) => {
    const before = row.rating ?? 0;
    patchAnnotation(row.id, { rating: next });
    try {
      const r = await postSessionTags(row.id, { rating: next });
      patchAnnotation(row.id, {
        rating: r.rating,
        favorite: r.favorite,
        tags: r.tags,
        has_note: (r.note ?? "") !== "",
      });
    } catch {
      patchAnnotation(row.id, { rating: before });
    }
  };

  // setTitle writes the developer's own session title optimistically (""
  // clears it, falling back to the AI title), then reconciles against the
  // server's reply; a failed POST reverts to the pre-edit value. Throws on
  // failure so the inline editor can surface the error inline rather than
  // silently reverting.
  const setTitle = async (row: SessionRow, next: string) => {
    const before = row.title ?? "";
    patchAnnotation(row.id, { title: next });
    try {
      const r = await postSessionTags(row.id, { title: next });
      patchAnnotation(row.id, {
        title: r.title ?? "",
        favorite: r.favorite,
        tags: r.tags,
        has_note: (r.note ?? "") !== "",
        rating: r.rating,
      });
    } catch (e) {
      patchAnnotation(row.id, { title: before });
      throw e;
    }
  };

  const query = localQuery || globalQuery;
  const filtered = useMemo(() => {
    let out = rows;
    if (drawerCount > 0) out = applyFilters(out, filters);
    const q = query.trim().toLowerCase();
    if (q) {
      out = out.filter(
        (r) =>
          r.id.toLowerCase().includes(q) ||
          (r.project ?? "").toLowerCase().includes(q) ||
          // Typing "2026-05-16" into the search box still substring-
          // matches against started_at. Calendar day-click uses the
          // server-side from_date/to_date path via pickedDay so it
          // works across pages, not just the loaded slice.
          (r.started_at ?? "").toLowerCase().includes(q),
      );
    }
    return out;
  }, [rows, query, filters, drawerCount]);

  // Models seen in the loaded page — feeds the drawer's Models chip
  // group so the user only sees models that would actually match a
  // visible session. Deduplicated; order matches first-seen.
  const availableModels = useMemo(() => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const r of rows) {
      for (const m of r.models ?? []) {
        if (!seen.has(m)) {
          seen.add(m);
          out.push(m);
        }
      }
    }
    return out;
  }, [rows]);

  const drawerChips = useMemo<FilterChip[]>(() => {
    const c: FilterChip[] = [];
    if (filters.models.length > 0) {
      c.push({
        label: `models: ${filters.models.length}`,
        title: filters.models.join(", "),
        onClear: () => setFilters((f) => ({ ...f, models: [] })),
      });
    }
    if (filters.minCostUsd || filters.maxCostUsd) {
      c.push({
        // A cost range carried in from a shared link names dollars, which
        // the token-usage view does not show (T-204): the chip says a cost
        // filter is set and still clears it.
        label: costLabel(
          `cost: ${rangeLabel(filters.minCostUsd, filters.maxCostUsd, "$")}`,
          "cost filter set (amounts hidden)",
        ),
        onClear: () =>
          setFilters((f) => ({ ...f, minCostUsd: "", maxCostUsd: "" })),
      });
    }
    if (filters.minActions || filters.maxActions) {
      c.push({
        label: `actions: ${rangeLabel(filters.minActions, filters.maxActions, "")}`,
        onClear: () =>
          setFilters((f) => ({ ...f, minActions: "", maxActions: "" })),
      });
    }
    if (filters.duration !== "any") {
      c.push({
        label: `duration: ${durationLabel(filters.duration)}`,
        onClear: () => setFilters((f) => ({ ...f, duration: "any" })),
      });
    }
    if (filters.sidechain !== "any") {
      c.push({
        label:
          filters.sidechain === "with" ? "with sidechain" : "no sidechain",
        onClear: () => setFilters((f) => ({ ...f, sidechain: "any" })),
      });
    }
    if (filters.reliability !== "any") {
      c.push({
        label: `reliability: ${filters.reliability}`,
        onClear: () => setFilters((f) => ({ ...f, reliability: "any" })),
      });
    }
    return c;
  }, [filters]);

  // Classification chips are SEPARATE from drawerChips: these clear
  // server-side params (tag=/favorite=), not the drawer's page-local state.
  const classificationChips = useMemo<FilterChip[]>(() => {
    const c: FilterChip[] = [];
    if (favoriteOnly) {
      c.push({
        label: (
          <span className="inline-flex items-center gap-1">
            <Icon icon={Star} size={10} fill="currentColor" /> favorites
          </span>
        ),
        title: "Show all sessions again",
        onClear: () => setFavoriteOnly(false),
      });
    }
    for (const t of tagFilters) {
      c.push({
        label: `tag: ${t}`,
        title: `Stop filtering by "${t}"`,
        onClear: () => setTagFilters((cur) => cur.filter((x) => x !== t)),
      });
    }
    if (surfaceFilter) {
      c.push({
        label: `client: ${surfaceFilter}`,
        title: "Show sessions from every client again",
        onClear: () => setSurfaceFilter(""),
      });
    }
    if (agentHost) {
      c.push({
        label: `agent: ${agentFromSurfaceHost(agentHost)}`,
        title: "Show every session again",
        onClear: () => setAgentHost(null),
      });
    }
    if (ranFilter) {
      c.push({
        label: `ran: ${EXECUTION_FILTER_OPTIONS.find((o) => o.value === ranFilter)?.label.split(" - ")[0] ?? ranFilter}`,
        title: "Show sessions from everywhere again",
        onClear: () => setRanFilter(""),
      });
    }
    return c;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [favoriteOnly, tagKey, surfaceFilter, agentHost, ranFilter]);

  const showScoring = (sessions.data?.scored_count ?? 0) > 0;
  useLayoutEffect(() => {
    const el = fitRef.current;
    if (view !== "table" || !el) return undefined;
    const read = () => {
      const w = Math.floor(el.clientWidth);
      setFitWidth((cur) => (w > 0 && cur !== w ? w : cur));
    };
    read();
    if (typeof ResizeObserver === "undefined") return undefined;
    const ro = new ResizeObserver(read);
    ro.observe(el);
    return () => ro.disconnect();
  }, [view]);
  const resolvedColumns = useMemo(
    () => resolveSessionColumns({ overrides: colOverrides, scoring: showScoring, available: fitWidth }),
    [colOverrides, showScoring, fitWidth],
  );
  const shownKey = resolvedColumns.shown.join(",");
  const columns = useMemo<ColumnDef<SessionRow, unknown>[]>(
    () =>
      buildColumns(resolvedColumns.shown, resolvedColumns.flexWidth, resolvedColumns.overflow, liveSet, activeSet, setWatch, {
        onToggleFavorite: (r) => void toggleFavorite(r),
        onSetRating: (r, rating) => void setRating(r, rating),
        onTagClick: addTagFilter,
        onTagsChange: (id, tags) => {
          patchAnnotation(id, { tags });
          tagRollup.reload();
        },
        onSetTitle: (r, title) => setTitle(r, title),
      }, setEnrichmentSession),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [shownKey, resolvedColumns.flexWidth, resolvedColumns.overflow, liveSet, activeSet],
  );

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("sessions")}
        title="Sessions"
        sub="One row per AI-coding session. Click a row to see action breakdown, token buckets, cost summary, and a full messages timeline with expandable tool calls."
        helpId="tab.sessions"
        right={
          <SegmentedControl<View>
            options={[
              { value: "table", label: "Table", icon: Table2 },
              { value: "calendar", label: "Calendar", icon: CalendarDays },
              { value: "agents", label: "Own agents", icon: Bot },
            ]}
            value={view}
            onChange={setView}
            size="sm"
          />
        }
      />
      {!showScoring && sessions.data && <ScoringHintBanner onScored={() => sessions.reload()} />}
      {orgSessionsBanner && <OrgSessionsBannerView banner={orgSessionsBanner} />}
      {cloudStatus.data && (!orgSessionsBanner || orgSessionsBanner.mode === "mixed") && <CloudEnrichmentSummary data={cloudStatus.data} />}
      {cloudProviderWaiting && !cloudBannerDismissed && (
        <CloudProviderWaitingBanner onDismiss={() => setCloudBannerDismissed(true)} />
      )}

      <TagsRollupPanel
        rows={tagRollup.data?.tags ?? []}
        active={tagFilters}
        onPick={toggleTagFilter}
        onClearAll={() => setTagFilters([])}
      />

      {projectParam && <CloudDigestCard projectRoot={projectParam} />}

      <ChartShell
        title={
          <span className="flex items-baseline gap-2">
            All sessions
            {sessions.data && (
              <Pill>{fmtInt(sessions.data.total)} total</Pill>
            )}
          </span>
        }
        icon={SECTION_ICONS.allSessions}
        sub="click any row for the per-session breakdown"
        stale={sessions.isStale}
      >
        {/* The toolbar is its own wrapping row under the title (it used to
            sit in the card header, where at 1280px it squeezed the title
            into a one-word column and ran past the card edge). */}
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <input
            type="search"
            placeholder="filter by id, project…"
            value={localQuery}
            onChange={(e) => setLocalQuery(e.target.value)}
            className="h-7 w-full min-w-0 rounded-2 sm:w-[180px] border border-line-2 bg-bg-2 px-2 font-mono text-[11px] text-fg-1 placeholder:text-fg-4 focus:border-accent focus:outline-none"
          />
          <Tooltip
            content={
              surfaceFilter
                ? `Showing ${surfaceFilter} sessions only - pick "any" to show all`
                : "Filter by how the tool was driven: terminal, editor, desktop app, SDK, or browser (server-side, all pages)"
            }
            maxWidth={320}
          >
            <select
              aria-label="Filter sessions by client"
              value={surfaceFilter}
              onChange={(e) => setSurfaceFilter(e.target.value as SurfaceKind | "")}
              className={
                surfaceFilter
                  ? "h-7 max-w-[124px] rounded-2 border border-accent/50 bg-accent-soft px-2 text-[11px] text-accent focus:outline-none"
                  : "h-7 max-w-[124px] rounded-2 border border-line-2 bg-bg-2 px-2 text-[11px] text-fg-2 hover:bg-bg-3 focus:border-accent focus:outline-none"
              }
            >
              {SURFACE_FILTER_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </Tooltip>
          <Tooltip
            content={
              ranFilter
                ? "Showing sessions from one place only - pick \"anywhere\" to show all"
                : "Filter by where the agent ran: this machine, a vendor's cloud sandbox, or compute your organization runs (server-side, all pages)"
            }
            maxWidth={320}
          >
            <select
              aria-label="Filter sessions by where they ran"
              value={ranFilter}
              onChange={(e) => setRanFilter(e.target.value as ExecutionFilterValue)}
              className={
                ranFilter
                  ? "h-7 max-w-[124px] rounded-2 border border-accent/50 bg-accent-soft px-2 text-[11px] text-accent focus:outline-none"
                  : "h-7 max-w-[124px] rounded-2 border border-line-2 bg-bg-2 px-2 text-[11px] text-fg-2 hover:bg-bg-3 focus:border-accent focus:outline-none"
              }
            >
              {EXECUTION_FILTER_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </Tooltip>
          <Tooltip
            content={
              favoriteOnly
                ? "Showing favorited sessions only - click to show all"
                : "Show only sessions you starred (server-side filter, all pages)"
            }
          >
            <button
              type="button"
              aria-pressed={favoriteOnly}
              onClick={() => setFavoriteOnly((v) => !v)}
              className={
                favoriteOnly
                  ? "inline-flex items-center gap-1.5 rounded-2 border border-warn/50 bg-warn-soft px-2.5 py-1 text-[11px] text-warn"
                  : "inline-flex items-center gap-1.5 rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
              }
            >
              <Icon icon={Star} size="xs" fill={favoriteOnly ? "currentColor" : "none"} />
              Favorites
            </button>
          </Tooltip>
          <span aria-hidden className="hidden flex-1 lg:block" />
          <Tooltip
            content={
              sortOption
                ? `Sorted by ${sortOption.label.toLowerCase()} - click to change`
                : "Choose a sort order, including rating and each token type, which have no column of their own"
            }
            maxWidth={320}
          >
            <button
              ref={sortTriggerRef}
              type="button"
              aria-haspopup="menu"
              aria-expanded={sortMenuOpen}
              onClick={() => setSortMenuOpen((o) => !o)}
              className={
                sortMenuOpen
                  ? "inline-flex items-center gap-1.5 rounded-2 border border-accent/50 bg-accent-soft px-2.5 py-1 text-[11px] text-accent"
                  : "inline-flex items-center gap-1.5 rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
              }
            >
              {sortLabel}
            </button>
          </Tooltip>
          <AnchoredPopover
            open={sortMenuOpen}
            anchorRef={sortTriggerRef}
            ariaLabel="Sort sessions"
            width={220}
            onDismiss={() => setSortMenuOpen(false)}
          >
            <div role="menu" className="py-1">
              {SORT_OPTIONS.map((opt) => {
                const active =
                  opt.id === sortBy && opt.desc === (sortDir === "desc");
                return (
                  <button
                    key={`${opt.id}-${opt.desc}`}
                    type="button"
                    role="menuitemradio"
                    aria-checked={active}
                    onClick={() => {
                      setSorting([{ id: opt.id, desc: opt.desc }]);
                      setSortMenuOpen(false);
                    }}
                    className={clsx(
                      "flex w-full items-center justify-between px-3 py-1.5 text-left text-[11.5px] focus:outline-none",
                      active
                        ? "bg-accent-soft text-accent"
                        : "text-fg-2 hover:bg-bg-2 hover:text-fg-0 focus:bg-bg-2 focus:text-fg-0",
                    )}
                  >
                    {opt.label}
                    {active && <Icon icon={Check} size="xs" />}
                  </button>
                );
              })}
            </div>
          </AnchoredPopover>
          {view === "table" && (
            <ColumnsPicker
              resolved={resolvedColumns}
              overrides={colOverrides}
              scoring={showScoring}
              onChange={setColOverrides}
            />
          )}
          <Tooltip
            content={
              drawerCount > 0
                ? `${drawerCount} drawer filter${drawerCount === 1 ? "" : "s"} active - click to edit`
                : "Open the filters drawer (model, cost, duration, sidechain…)"
            }
            maxWidth={320}
          >
            <button
              type="button"
              onClick={() => setDrawerOpen(true)}
              className={
                drawerCount > 0
                  ? "inline-flex items-center gap-1.5 rounded-2 border border-accent/50 bg-accent-soft px-2.5 py-1 text-[11px] text-accent hover:bg-accent-soft/70"
                  : "inline-flex items-center gap-1.5 rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
              }
            >
              Filters
              {drawerCount > 0 && (
                <span className="rounded-pill bg-accent px-1.5 py-px font-mono text-[9.5px] font-semibold leading-none text-accent-on">
                  {drawerCount}
                </span>
              )}
            </button>
          </Tooltip>
          <Tooltip content="Download visible sessions as CSV">
            <button
              type="button"
              onClick={() => exportSessionsCsv(filtered)}
              disabled={!filtered.length}
              className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-2 hover:bg-bg-3 disabled:opacity-40"
            >
              Export
            </button>
          </Tooltip>
        </div>
        {(pickedDay ||
          drawerChips.length > 0 ||
          classificationChips.length > 0) && (
          <ActiveFilterChips
            className="mb-3"
            chips={[
              ...(pickedDay
                ? [
                    {
                      label: `day: ${pickedDay}`,
                      onClear: () => setPickedDay(null),
                    } as FilterChip,
                  ]
                : []),
              ...classificationChips,
              ...drawerChips,
            ]}
            onClearAll={() => {
              setPickedDay(null);
              setFilters(EMPTY_FILTERS);
              setTagFilters([]);
              setFavoriteOnly(false);
              setSurfaceFilter("");
              setAgentHost(null);
              setRanFilter("");
            }}
          />
        )}
        {view === "agents" ? (
          <OwnAgentsView
            onPick={(a) => {
              // Narrow the table to the picked agent's sessions, then
              // swap to it (the calendar's day-pick precedent).
              setAgentHost(a.surface_host);
              setLocalQuery("");
              setView("table");
            }}
          />
        ) : view === "calendar" ? (
          <CalendarView
            cells={calendar.data?.cells ?? []}
            loading={calendar.loading}
            windowDaysParam={calendarDays}
            onPickDay={(day) => {
              // Filter table to the picked day via a SERVER-side
              // from_date/to_date filter, then swap to table view. A
              // local substring filter against the loaded page would
              // silently miss any day outside the page-50 slice.
              setPickedDay(day);
              setLocalQuery("");
              setView("table");
            }}
          />
        ) : (
          <div ref={fitRef} className="min-w-0">
            <ChartState
              loading={sessions.loading && !sessions.data}
              error={sessions.error}
              denied={sessions.denied}
              deniedPermission={sessions.deniedPermission}
              empty={!sessions.loading && filtered.length === 0}
              emptyHint={
                pickedDay
                  ? `No sessions on ${pickedDay}. Clear the day filter to see all sessions.`
                  : query
                    ? `No sessions match "${query}". Clear the search or widen filters.`
                    : "No sessions in window. Set up your AI tools in Settings > Connected tools: each tool's Set up registers its hooks, MCP and proxy route, one confirm per write."
              }
              height={240}
            >
              <DataTable<SessionRow>
                data={filtered}
                columns={columns}
                onRowClick={(r) => setSelected(r.id)}
                rowKey={(r) => r.id}
                zebra
                // The fixed layout holds each column to its budget from
                // lib/sessionColumns, so no long path or label can widen the
                // table; Session alone takes the leftover width. The fit
                // rule already dropped what does not fit, so the table only
                // scrolls sideways when the viewer chose more columns than
                // fit (then Favorite and Session stay pinned). While it fits,
                // the wrapper clips instead of scrolling, which lets the
                // header stick to the page as it scrolls.
                layout="fixed"
                minWidth={resolvedColumns.minWidth}
                scrollX={resolvedColumns.overflow}
                stickyHeader
                loading={sessions.loading}
                sorting={sorting}
                onSortingChange={setSorting}
              />
            </ChartState>

            {sessions.data && (
              <div className="flex items-center justify-between gap-3">
                <Pagination
                  page={sessions.data.page}
                  limit={sessions.data.limit}
                  total={sessions.data.total}
                  onPage={setPage}
                  loading={sessions.loading}
                />
                {(sessions.data.page_cost_usd ?? 0) > 0 && (
                  <span className="shrink-0 pt-3 text-[11px] tabular-nums text-fg-3">
                    page cost{" "}
                    <span className="text-fg-1">
                      {fmtUSD(sessions.data.page_cost_usd ?? 0)}
                    </span>
                  </span>
                )}
              </div>
            )}
          </div>
        )}
      </ChartShell>

      <SlideOver open={enrichmentSession !== null} onClose={() => setEnrichmentSession(null)}
        title={SESSION_ENRICH_PLANE_COPY[enrichmentSession ? sessionEnrichPlane(enrichmentSession) : "personal"].drawerTitle}
        subtitle={enrichmentSession?.title || enrichmentSession?.cloud_title || enrichmentSession?.org_title || enrichmentSession?.project} width={640}>
        {enrichmentSession && sessionEnrichPlane(enrichmentSession) === "org" && <div className="space-y-4 p-4">
          <p className="text-[11.5px] leading-relaxed text-fg-3">{SESSION_ENRICH_PLANE_COPY.org.drawerNote}</p>
          <OrgIntelCard key={enrichmentSession.id} sessionId={enrichmentSession.id} />
        </div>}
        {enrichmentSession && sessionEnrichPlane(enrichmentSession) === "personal" && <div className="space-y-4 p-4">
          <p className="text-[11.5px] leading-relaxed text-fg-3">{SESSION_ENRICH_PLANE_COPY.personal.drawerNote}</p>
          <CloudRow key={enrichmentSession.id} sessionId={enrichmentSession.id} onChanged={() => { sessions.reload(); cloudStatus.reload(); }} />
          {cloudStatus.data && <details className="space-y-2">
            <Summary className="w-fit text-caption font-medium text-fg-3">Enrichment settings and allowance</Summary>
            <CloudEnrichmentSummary data={cloudStatus.data} />
          </details>}
        </div>}
      </SlideOver>

      <SessionDetailPanel
        sessionId={selected}
        open={selected != null}
        watch={watch}
        onClose={() => setSelected(null)}
        onOpenSession={(id) => setSelected(id)}
        onFilterTag={(tag) => {
          addTagFilter(tag);
          setSelected(null);
        }}
        onAnnotationChange={(id, next) => {
          patchAnnotation(id, {
            tags: next.tags,
            favorite: next.favorite,
            has_note: (next.note ?? "") !== "",
            rating: next.rating,
          });
          tagRollup.reload();
        }}
      />

      <SessionsFiltersDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        value={filters}
        onApply={(next) => {
          setFilters(next);
          setDrawerOpen(false);
        }}
        availableModels={availableModels}
      />
    </div>
  );
}

function rangeLabel(min: string, max: string, prefix: string): string {
  const lo = min.trim();
  const hi = max.trim();
  if (lo && hi) return `${prefix}${lo}-${prefix}${hi}`;
  if (lo) return `≥ ${prefix}${lo}`;
  if (hi) return `≤ ${prefix}${hi}`;
  return "-";
}

function durationLabel(d: SessionFilters["duration"]): string {
  switch (d) {
    case "short":
      return "<5m";
    case "medium":
      return "5-30m";
    case "long":
      return "30m-2h";
    case "xlong":
      return ">2h";
    default:
      return "any";
  }
}

// TagsRollupPanel — the v1 per-label analysis surface (plan §5): one row per
// tag with its session count and cost, click-through = filter the list to
// that tag. Renders NOTHING until the operator has tagged something, so an
// untouched dashboard gains no empty furniture.
function TagsRollupPanel({
  rows,
  active,
  onPick,
  onClearAll,
}: {
  rows: TagRollup[];
  active: string[];
  // Called on every pill click. The pill renders its own selected state,
  // so this handler TOGGLES: clicking a selected pill drops that tag.
  onPick: (tag: string) => void;
  onClearAll: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  if (rows.length === 0) return null;
  const sorted = [...rows].sort(
    (a, b) => b.cost_usd - a.cost_usd || b.sessions - a.sessions,
  );
  // A SELECTED tag is always rendered, even when it sorts below the
  // collapsed cut-off: otherwise the only pill that can switch that filter
  // off is hidden behind "+n more".
  const shown = expanded
    ? sorted
    : sorted.filter((r, i) => i < 8 || active.includes(r.tag));
  const totalCost = sorted.reduce((a, r) => a + r.cost_usd, 0);
  return (
    <section className="rounded-3 border border-line-2 bg-bg-2 p-3">
      <header className="mb-2 flex items-baseline justify-between gap-2">
        <h3 className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Tags
        </h3>
        <span className="flex items-baseline gap-2 font-mono text-[10.5px] text-fg-3">
          {active.length > 0 && (
            <button
              type="button"
              onClick={onClearAll}
              className="rounded-2 border border-accent/40 bg-accent-soft px-1.5 py-0.5 font-sans text-[10.5px] text-accent transition-colors hover:bg-accent-soft/70"
            >
              Clear all ({active.length})
            </button>
          )}
          <span>
            {fmtInt(sorted.length)} label{sorted.length === 1 ? "" : "s"} ·{" "}
            <span className="text-fg-1">{fmtUSD(totalCost)}</span>
          </span>
        </span>
      </header>
      <div className="flex flex-wrap gap-1.5">
        {shown.map((r) => {
          const on = active.includes(r.tag);
          return (
            <Tooltip
              key={r.tag}
              content={`${fmtInt(r.sessions)} session${r.sessions === 1 ? "" : "s"} · ${fmtUSD(r.cost_usd)} · ${fmtCompact(r.tokens)} tokens. Click to ${on ? "stop filtering by" : "filter by"} "${r.tag}".`}
            >
              <button
                type="button"
                onClick={() => onPick(r.tag)}
                aria-pressed={on}
                className={
                  "inline-flex items-center gap-1.5 rounded-2 border px-1.5 py-1 transition-colors " +
                  (on
                    ? "border-accent bg-accent-soft"
                    : "border-line-2 bg-bg-3 hover:bg-bg-4")
                }
              >
                <TagPill tag={r.tag} />
                <span className="font-mono text-[10px] tabular-nums text-fg-3">
                  {fmtInt(r.sessions)}
                </span>
                <span className="font-mono text-[10px] tabular-nums text-fg-2">
                  {fmtUSD(r.cost_usd)}
                </span>
              </button>
            </Tooltip>
          );
        })}
        {sorted.length > shown.length && (
          <button
            type="button"
            onClick={() => setExpanded(true)}
            className="rounded-2 border border-line-2 bg-bg-3 px-2 py-1 text-[10.5px] text-fg-3 hover:bg-bg-4 hover:text-fg-1"
          >
            +{sorted.length - shown.length} more
          </button>
        )}
      </div>
    </section>
  );
}

// CloudProviderWaitingBanner (value-upgrade plan §W3): shown above the table
// when the last `observer cloud sync` reported the hosted enrichment
// provider is not accepting jobs yet, so a developer who just turned Cloud
// Intelligence on understands why titles haven't appeared - nothing is lost,
// the queue just hasn't drained yet. Dismissable for the rest of this page
// load only (re-appears on a fresh load while still waiting).
function CloudProviderWaitingBanner({ onDismiss }: { onDismiss: () => void }) {
  return (
    <div className="flex items-start gap-3 rounded-3 border border-info/30 bg-info-soft/60 px-4 py-2.5 text-[11.5px]">
      <Icon icon={Info} size="md" className="mt-px shrink-0 text-info" />
      <div className="flex-1 text-fg-2">
        Cloud Intelligence: your sessions are queued. The hosted enrichment
        provider is not accepting jobs yet, so titles will appear once it is.
        Nothing is lost.
      </div>
      <button
        type="button"
        onClick={onDismiss}
        className="shrink-0 text-fg-3 hover:text-fg-1"
        aria-label="Dismiss"
      >
        <Icon icon={X} size="sm" />
      </button>
    </div>
  );
}

// ScoringHintBanner: the no-score state. "Score all now" runs `observer
// score` (the same command, as a dashboard job), which scores every session
// that has no score yet; the table reloads when it finishes.
function ScoringHintBanner({ onScored }: { onScored: () => void }) {
  return (
    <div className="flex items-start gap-3 rounded-3 border border-warn/30 bg-warn-soft/60 px-4 py-2.5 text-[11.5px]">
      <Icon icon={Info} size="md" className="mt-px shrink-0 text-warn" />
      <div className="min-w-0 flex-1 text-fg-2">
        <b className="text-fg-1">
          No session in this view has a quality score yet.
        </b>{" "}
        The running daemon scores each session once it has been idle for a
        while (30 minutes by default), and the Quality / Errors / Redundancy
        columns appear as soon as one is scored. Sessions get a 0-100 quality
        score and a redundancy index that flags repeat-work patterns.
        <CommandJobButton
          job="score"
          className="mt-2"
          confirmLabel="Score every unscored session?"
          armedNote="Writes quality scores for every session that has none yet. Local only, no model involved."
          runningLabel="Scoring…"
          doneText="Scored. The table now shows the new scores."
          onDone={onScored}
        >
          Score all now
        </CommandJobButton>
      </div>
    </div>
  );
}

// CalendarView — per-day grid heat-mapped by session count + total
// cost. Sources data from /api/sessions/calendar (server-side GROUP
// BY date(started_at) over the configured Window) so the cells
// reflect activity across the entire window, not just the most
// recent paginated slice. Days with no activity render as empty
// grey cells so the window's span is always visible. Clicking a
// day filters the table view to that day's ISO prefix.
function CalendarView({
  cells,
  loading,
  windowDaysParam,
  onPickDay,
}: {
  cells: { day: string; session_count: number; cost_usd: number }[];
  loading: boolean;
  windowDaysParam: number;
  onPickDay?: (day: string) => void;
}) {
  const byDay = useMemo(() => {
    const m = new Map<string, { count: number; cost: number }>();
    for (const c of cells) {
      m.set(c.day, { count: c.session_count, cost: c.cost_usd });
    }
    return m;
  }, [cells]);

  // Bracket the visible range to the configured Window — today back
  // `windowDaysParam` days — instead of the min/max day in the loaded
  // data. This way switching the Window to 90d always shows a 90-day
  // calendar regardless of whether earlier days had activity. Falls
  // back to a 30-day window when the caller passes a non-positive
  // value. The "all" Window passes 36500; cap the displayed span at
  // 365 so the calendar doesn't render thousands of empty cells.
  const span = clampSpanDays(windowDaysParam);
  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);
  const last = today;
  const first = new Date(today);
  first.setUTCDate(first.getUTCDate() - (span - 1));
  const start = startOfWeek(first);
  const end = endOfWeek(last);
  const gridCells: Date[] = [];
  for (let cur = start; cur <= end; cur = nextDay(cur)) gridCells.push(cur);
  const maxCost = Math.max(...[...byDay.values()].map((v) => v.cost), 0);
  const totalCost = [...byDay.values()].reduce((a, v) => a + v.cost, 0);
  const totalSessions = [...byDay.values()].reduce((a, v) => a + v.count, 0);
  // Date-range header — "May 1 – May 30" rendered above the grid so
  // the user has anchoring context. Falls back to UTC since cells
  // themselves are UTC-indexed.
  const fmtHeader = (d: Date) =>
    d.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      timeZone: "UTC",
    });

  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
      <header className="mb-3 flex flex-wrap items-baseline justify-between gap-2 border-b border-line-1 pb-2.5">
        <div className="flex items-baseline gap-2">
          <span className="text-[12px] font-semibold uppercase tracking-[0.06em] text-fg-1">
            {fmtHeader(first)} - {fmtHeader(last)}
          </span>
          <span className="font-mono text-[10.5px] text-fg-3">
            {byDay.size} active day{byDay.size === 1 ? "" : "s"}
          </span>
          {loading && (
            <LiveDot tone="info" label="Loading" className="h-2 w-2" />
          )}
        </div>
        <div className="flex items-baseline gap-3 font-mono text-[10.5px] text-fg-3">
          <span>
            {fmtInt(totalSessions)} session{totalSessions === 1 ? "" : "s"}
          </span>
          <span className="font-semibold text-fg-1">
            {fmtUSD(totalCost)}
          </span>
        </div>
      </header>
      <div className="mb-2 grid grid-cols-7 gap-1.5 text-center text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        {["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].map((d) => (
          <div key={d}>{d}</div>
        ))}
      </div>
      <div className="grid grid-cols-7 gap-1.5">
        {gridCells.map((d) => {
          const key = d.toISOString().slice(0, 10);
          const slot = byDay.get(key);
          const cost = slot?.cost ?? 0;
          // Log scale + brighter floor so even small days read.
          const intensity = maxCost > 0
            ? Math.min(1, Math.log1p(cost) / Math.log1p(maxCost))
            : 0;
          const hasData = !!slot;
          const bgPct = intensity > 0 ? (12 + intensity * 60).toFixed(0) : "0";
          return (
            <Tooltip
              key={key}
              content={
                hasData
                  ? `${key} · ${slot!.count} sessions · ${fmtUSD(cost)}`
                  : key
              }
            >
            <button
              type="button"
              onClick={hasData && onPickDay ? () => onPickDay(key) : undefined}
              disabled={!hasData}
              className={
                "group/cal relative flex h-[94px] flex-col items-stretch overflow-hidden rounded-2 border px-2 py-1.5 text-left transition-all " +
                (hasData
                  ? "cursor-pointer border-line-2 hover:-translate-y-0.5 hover:border-accent/70 hover:shadow-drawer"
                  : "cursor-default border-line-1 bg-bg-3/30 text-fg-4")
              }
              style={
                hasData
                  ? {
                      background: `linear-gradient(155deg, color-mix(in srgb, var(--accent) ${bgPct}%, var(--bg-2)) 0%, var(--bg-2) 100%)`,
                    }
                  : undefined
              }
            >
              <div className="flex items-baseline justify-between">
                <span className="font-mono text-[10.5px] font-semibold text-fg-2">
                  {d.getUTCDate()}
                </span>
                {hasData && (
                  <span
                    aria-hidden
                    className="h-1.5 w-1.5 rounded-full bg-accent opacity-90"
                  />
                )}
              </div>
              {hasData ? (
                <div className="mt-auto flex flex-col gap-0.5">
                  <span className="font-mono text-[20px] font-bold leading-none tabular-nums text-fg-0">
                    {slot!.count}
                  </span>
                  <span className="font-mono text-[10.5px] tabular-nums text-fg-2">
                    {fmtUSD(cost)}
                  </span>
                </div>
              ) : (
                <span className="mt-auto text-[10px] text-fg-4">-</span>
              )}
            </button>
            </Tooltip>
          );
        })}
      </div>
      <div className="mt-3 flex items-center justify-between gap-3 text-[10.5px] text-fg-3">
        <p>Click a day to switch to Table view filtered to that day.</p>
        <div className="flex items-center gap-1.5">
          <span className="text-fg-4">less</span>
          {[0.15, 0.35, 0.55, 0.75, 0.95].map((s) => (
            <span
              key={s}
              className="h-2.5 w-3 rounded-[2px]"
              style={{
                background: `color-mix(in srgb, var(--accent) ${(12 + s * 60).toFixed(0)}%, var(--bg-2))`,
              }}
            />
          ))}
          <span className="text-fg-4">more</span>
        </div>
      </div>
    </div>
  );
}

function clampSpanDays(n: number): number {
  if (!Number.isFinite(n) || n <= 0) return 30;
  return Math.min(365, Math.round(n));
}

function startOfWeek(d: Date): Date {
  const out = new Date(d);
  out.setUTCHours(0, 0, 0, 0);
  out.setUTCDate(out.getUTCDate() - out.getUTCDay());
  return out;
}

function endOfWeek(d: Date): Date {
  const out = new Date(d);
  out.setUTCHours(0, 0, 0, 0);
  out.setUTCDate(out.getUTCDate() + (6 - out.getUTCDay()));
  return out;
}

function nextDay(d: Date): Date {
  const out = new Date(d);
  out.setUTCDate(out.getUTCDate() + 1);
  return out;
}

// TagsCtx bundles the classification callbacks the table cells need. Passed
// as one object so buildColumns doesn't grow a fourth positional callback.
type TagsCtx = {
  onToggleFavorite: (row: SessionRow) => void;
  onSetRating: (row: SessionRow, rating: number) => void;
  onTagClick: (tag: string) => void;
  onTagsChange: (sessionId: string, tags: string[]) => void;
  // onSetTitle returns the underlying promise (rather than firing-and-
  // forgetting like the others) so the inline title editor can await it and
  // show an error instead of silently reverting.
  onSetTitle: (row: SessionRow, title: string) => Promise<void>;
};

// TAGS_CELL_WIDTH is the Tags column's budget, which rowTagCount sizes the
// pills against.
const TAGS_CELL_WIDTH = sessionColumn("tags")?.width ?? 164;

// SESSION_TITLE_MAX_LENGTH mirrors the server's <= 200-char rule
// (store.MaxTitleLen).
const SESSION_TITLE_MAX_LENGTH = 200;

// SessionTitleCell renders the Session cell's text: the EFFECTIVE title (the
// developer's own title > the AI/cloud title > the org title) over the short
// id, or the short id alone when nothing titled the session. The title is
// plain text (a click on it opens the row like any other cell, its tooltip
// carries the full title); the id is the click-to-copy target either way.
//
// A hover-revealed pencil, or a double-click on the text, opens a text
// input; Enter saves (POST /api/session/<id>/tags {title}), Escape cancels,
// and an empty save clears the title (falls back to the AI/cloud title, then
// the plain id).
function SessionTitleCell({
  row,
  onSetTitle,
}: {
  row: SessionRow;
  onSetTitle: (row: SessionRow, title: string) => Promise<void>;
}) {
  const userTitle = row.title ?? "";
  // Effective title: yours, then the personal-plane AI title, then the
  // org-plane AI title (lib/orgIntel sessionEffectiveTitle, design 3.2).
  const eff = sessionEffectiveTitle(row);
  const effectiveTitle = eff.text;
  const usingAI = eff.source === "cloud" || eff.source === "org";
  const shortId = shortSessionId(row.id);

  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(userTitle);
  const [err, setErr] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (editing) inputRef.current?.focus();
  }, [editing]);

  function openEditor() {
    setDraft(userTitle);
    setErr(null);
    setEditing(true);
  }

  async function save() {
    const value = draft.trim().slice(0, SESSION_TITLE_MAX_LENGTH);
    if (value === userTitle) {
      setEditing(false);
      return;
    }
    setErr(null);
    try {
      await onSetTitle(row, value);
      setEditing(false);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  if (editing) {
    return (
      <span className="flex min-w-0 flex-1 flex-col gap-0.5">
        <input
          ref={inputRef}
          value={draft}
          maxLength={SESSION_TITLE_MAX_LENGTH}
          placeholder="Title this session"
          onClick={(e) => e.stopPropagation()}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={() => void save()}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              void save();
            } else if (e.key === "Escape") {
              e.preventDefault();
              setEditing(false);
            }
          }}
          className="w-full rounded-1 border border-line-2 bg-bg-3 px-1 py-0.5 text-caption text-fg-1 outline-none focus:border-accent"
        />
        {err && <span className="text-[9px] text-danger">{err}</span>}
      </span>
    );
  }

  const idCopy = (className: string) => (
    <CopyOnClick value={row.id} className={className}>
      <span className="truncate">{shortId}</span>
    </CopyOnClick>
  );

  return (
    <span
      className="group/title flex min-w-0 flex-1 flex-col justify-center leading-tight"
      onDoubleClick={(e) => {
        e.stopPropagation();
        openEditor();
      }}
    >
      <span className="flex min-w-0 items-center gap-1">
        {usingAI && (
          <Pill variant="accent" className="shrink-0 whitespace-nowrap" title={eff.source === "org" ? "Title from your organization's session enrichment" : "Title from your AI summaries"}>
            {eff.source === "org" ? "org" : "AI"}
          </Pill>
        )}
        {effectiveTitle ? (
          <Tooltip
            content={
              <span className="block">
                <span className="block text-fg-0">{effectiveTitle}</span>
                <span className="block break-all font-mono text-[10.5px] text-fg-3">{row.id}</span>
              </span>
            }
            maxWidth={360}
          >
            <span tabIndex={0} className="min-w-0 truncate text-[12px] font-medium text-fg-0 focus:outline-none">
              {effectiveTitle}
            </span>
          </Tooltip>
        ) : (
          idCopy("min-w-0 font-mono text-[11px] text-accent hover:text-accent-strong")
        )}
        <Tooltip content={userTitle ? "Edit your title" : "Set your own title"}>
          <button
            type="button"
            aria-label={userTitle ? "Edit your title" : "Set your own title"}
            onClick={(e) => {
              e.stopPropagation();
              openEditor();
            }}
            className="shrink-0 text-fg-4 opacity-0 transition-opacity hover:text-accent focus:opacity-100 group-hover/title:opacity-100"
          >
            <Icon icon={Pencil} size={10} />
          </button>
        </Tooltip>
      </span>
      {effectiveTitle &&
        idCopy("mt-0.5 min-w-0 max-w-full font-mono text-[10px] text-fg-4 hover:text-accent")}
    </span>
  );
}

// EnrichButton is the Session cell's enrichment control: one icon whose
// glyph and colour say where the session's AI summaries stand, and whose
// name says what a click does ("Enrich session", "Team AI summaries",
// "Queued · view status", ...). The words, the plane and any AI title are in
// the tooltip; the click opens the enrichment panel, never the row.
function EnrichButton({ row, onEnrich }: { row: SessionRow; onEnrich: (r: SessionRow) => void }) {
  const plane = sessionEnrichPlane(row);
  const progress = row.cloud_enrichment;
  const action =
    plane === "org"
      ? orgPlaneEnrichAction(row)
      : cloudProgressAction(progress, !!row.cloud_enriched);
  const meta = cloudProgressMeta(progress);
  // The org plane has no request state on this node: a pulled-back title is
  // the only result there is.
  const variant: EnrichVariant =
    plane === "org"
      ? row.org_title
        ? "success"
        : "neutral"
      : progress
        ? meta.variant
        : row.cloud_enriched
          ? "success"
          : "neutral";
  const hasResult = plane === "org" ? !!row.org_title : !!row.cloud_enriched;
  const glyphState = progress && plane === "personal" ? progress.state : hasResult ? "complete" : "idle";
  // The AI title is worth repeating here only when the row shows another
  // (your own title wins over it).
  const aiTitle = plane === "org" ? row.org_title : row.cloud_title;
  const showAiTitle = !!aiTitle && !!row.title;
  const inFlight = plane === "personal" && meta.inFlight === true;
  return (
    <Tooltip
      content={
        <span className="block space-y-0.5">
          <span className="block font-medium text-fg-0">{action}</span>
          <span className="block text-fg-2">{SESSION_ENRICH_PLANE_COPY[plane].tooltip}</span>
          {showAiTitle && <span className="block text-fg-3">AI title: {aiTitle}</span>}
        </span>
      }
      maxWidth={320}
    >
      <button
        type="button"
        aria-label={action}
        onClick={(event) => {
          event.stopPropagation();
          onEnrich(row);
        }}
        onKeyDown={(event) => event.stopPropagation()}
        className={clsx(
          "inline-grid h-[22px] w-[22px] shrink-0 place-items-center rounded-1 transition-colors hover:bg-bg-4 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]",
          ENRICH_TONE_CLASS[variant],
        )}
      >
        <Icon
          icon={vocabIcon("cloudProgress", glyphState)}
          size={13}
          className={inFlight ? "animate-pulse" : undefined}
        />
      </button>
    </Tooltip>
  );
}

// LiveBadge is the compact "live" pill: green for a session that is running
// now. A bare session (running outside observer) is a button that opens the
// drawer in read-only watch mode; an attachable one is informational (open
// the row and Jump in). The full words ("live · watch", "live · joinable")
// are the accessible text and the tooltip; on screen the pill says "live",
// and on a phone only the dot shows, so the title keeps the room.
function LiveBadge({ joinable, onWatch }: { joinable: boolean; onWatch: () => void }) {
  const pill = (qualifier: string) => (
    <Pill variant="success" className="relative whitespace-nowrap">
      <LiveDot tone="success" size="sm" className="shrink-0" />
      <span aria-hidden className="hidden sm:inline">live</span>
      <span className="sr-only">live · {qualifier}</span>
    </Pill>
  );
  if (joinable) {
    return (
      <Tooltip content="Running as an attachable observer session - open it and click Jump in to join the live terminal.">
        <span tabIndex={0} className="relative inline-flex shrink-0 focus:outline-none">
          {pill("joinable")}
        </span>
      </Tooltip>
    );
  }
  return (
    <Tooltip content="Running outside observer - click to watch the conversation read-only; joining requires an observer-launched session.">
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          onWatch();
        }}
        onKeyDown={(e) => e.stopPropagation()}
        className="relative inline-flex shrink-0 rounded-pill focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]"
      >
        {pill("watch")}
      </button>
    </Tooltip>
  );
}

// TokenBreakdown is the Tokens cell's tooltip: every bucket the column sums,
// plus the cache-write tier split and reasoning when the row carries them.
function TokenBreakdown({ row }: { row: SessionRow }) {
  const tier1h = row.cache_creation_1h_tokens || 0;
  const tier5m = Math.max(0, row.cache_creation_tokens - tier1h);
  const lines: [string, number, string?][] = [
    ["Input", row.input_tokens],
    ["Cache read", row.cache_read_tokens],
    ["Cache write", row.cache_creation_tokens, row.cache_creation_tokens > 0 ? `5m ${fmtCompact(tier5m)} · 1h ${fmtCompact(tier1h)}` : undefined],
    ["Output", row.output_tokens, (row.reasoning_tokens ?? 0) > 0 ? `reasoning ${fmtCompact(row.reasoning_tokens ?? 0)}` : undefined],
  ];
  return (
    <span className="block min-w-[180px] space-y-0.5 text-[11px]">
      {lines.map(([label, value, note]) => (
        <span key={label} className="flex items-baseline gap-3">
          <span className="text-fg-3">{label}</span>
          {note && <span className="text-[10px] text-fg-4">{note}</span>}
          <span className="ml-auto tabular-nums text-fg-0">{fmtInt(value)}</span>
        </span>
      ))}
      <span className="mt-1 flex items-baseline gap-3 border-t border-line-2 pt-1">
        <span className="text-fg-2">Total</span>
        <span className="ml-auto font-medium tabular-nums text-fg-0">{fmtInt(sessionTokenTotal(row))}</span>
      </span>
    </span>
  );
}

// tokenCount renders a token count, or a muted dash for none.
function tokenCount(v: number) {
  return v > 0 ? (
    <span className="tabular-nums text-fg-1">{fmtCompact(v)}</span>
  ) : (
    <span className="text-fg-4">-</span>
  );
}

// buildColumns builds every column's def, then returns the ones `shown`
// names, in that order, with the width budget and flags from the one column
// table (lib/sessionColumns). Session takes `flexWidth` (the fit rule's
// answer). `pinned` (the table scrolls sideways) pins Favorite and Session.
function buildColumns(
  shown: readonly SessionColumnId[],
  flexWidth: number | null,
  pinned: boolean,
  liveSet: Set<string>,
  activeSet: Set<string>,
  onWatch: (id: string) => void,
  tagsCtx: TagsCtx,
  onEnrich: (session: SessionRow) => void,
): ColumnDef<SessionRow, unknown>[] {
  const facets = inlineFacets(shown);
  const defs: Record<SessionColumnId, ColumnDef<SessionRow, unknown>> = {
    favorite: {
      // Favorite star + a compact rating trigger sharing one narrow column.
      // Rating has no column of its own; best/worst-first lives in the Sort
      // menu. Server-sortable via sort_by=favorite (the header click).
      id: "favorite",
      header: () => <Icon icon={Star} size="xs" label="Favorites" />,
      accessorFn: (r) => (r.favorite ? 1 : 0),
      cell: ({ row }) => {
        const rating = row.original.rating ?? 0;
        return (
          <span className="flex items-center gap-1">
            <FavoriteStar
              favorite={row.original.favorite === true}
              onToggle={() => tagsCtx.onToggleFavorite(row.original)}
            />
            <RatingChip
              compact
              rating={rating}
              onRate={(next) => tagsCtx.onSetRating(row.original, next)}
              // Rated rows always show the number; unrated rows only reveal
              // the "rate" affordance on row hover/keyboard focus.
              className={
                rating > 0
                  ? undefined
                  : "opacity-0 focus:opacity-100 focus-visible:opacity-100 group-hover:opacity-100 group-focus-within:opacity-100"
              }
            />
          </span>
        );
      },
    },
    session: {
      id: "session",
      header: () => <>Session<HelpInd id="column.sessions.id" /></>,
      accessorKey: "id",
      // One fixed-height line of status: subagent glyph, the title/id
      // block (two text lines at most), then the live pill and the
      // enrichment button at the right edge. Nothing wraps, so every row is
      // the same height.
      cell: ({ row }) => {
        const r = row.original;
        const parent = parentSessionId(r.id);
        const joinable = liveSet.has(r.id);
        const live = joinable || activeSet.has(r.id);
        return (
          <span className="flex h-8 min-w-0 items-center gap-1.5">
            {parent && (
              <GlyphBadge
                icon={CornerDownRight}
                label={`Subagent session, started by ${shortSessionId(parent)}`}
              />
            )}
            <SessionTitleCell row={r} onSetTitle={tagsCtx.onSetTitle} />
            {live && <LiveBadge joinable={joinable} onWatch={() => onWatch(r.id)} />}
            <EnrichButton row={r} onEnrich={onEnrich} />
          </span>
        );
      },
    },
    tool: {
      id: "tool",
      header: () => <>Tool<HelpInd id="column.sessions.tool" /></>,
      accessorKey: "tool",
      // The badge label ellipsizes (its glyph's tooltip names the tool);
      // the client and where-it-ran ride along as glyphs while their own
      // columns are off, each with the full words in its tooltip.
      cell: ({ row }) => (
        <span className="flex min-w-0 items-center gap-1.5">
          <ToolBadge
            tool={row.original.tool}
            pip={false}
            className="min-w-0 !shrink [&>span:last-child]:min-w-0 [&>span:last-child]:truncate"
          />
          {facets.client && (
            <SurfaceBadge glyph surface={row.original.surface} host={row.original.surface_host} />
          )}
          {facets.ran && (
            <ExecutionLocationBadge
              glyph
              hideLocal
              location={row.original.execution_location}
              vendorRef={row.original.vendor_session_ref}
            />
          )}
        </span>
      ),
    },
    client: {
      // Client: the capture-surface pill (cli / ide / desktop / sdk / web +
      // host). SurfaceBadge renders NOTHING when neither field is present —
      // absent is unknown, never "cli". Not sortable: no server sort key.
      id: "client",
      header: () => <>Client<HelpInd id="column.sessions.client" /></>,
      accessorFn: (r) => r.surface ?? "",
      enableSorting: false,
      cell: ({ row }) => (
        <span className="flex min-w-0">
          <SurfaceBadge
            compact
            surface={row.original.surface}
            host={row.original.surface_host}
            className="min-w-0 max-w-full [&>span:last-child]:min-w-0 [&>span:last-child]:truncate"
          />
        </span>
      ),
    },
    ran: {
      // Ran: where the session's agent ran (node migration 240). Blank is
      // unknown, never "local". Not sortable (no server sort key).
      id: "ran",
      header: () => <>Ran<HelpInd id="column.sessions.ran" /></>,
      accessorFn: (r) => r.execution_location ?? "",
      enableSorting: false,
      cell: ({ row }) => (
        <span className="flex min-w-0">
          <ExecutionLocationBadge
            location={row.original.execution_location}
            vendorRef={row.original.vendor_session_ref}
          />
        </span>
      ),
    },
    project: {
      id: "project",
      header: () => <>Project<HelpInd id="column.sessions.project" /></>,
      accessorKey: "project",
      // The folder name reads at a glance; the full path is the tooltip.
      cell: ({ row }) => {
        const p = row.original.project;
        if (!p) return <span className="text-fg-4">none</span>;
        return (
          <Tooltip content={<span className="break-all font-mono">{p}</span>} maxWidth={420}>
            <span tabIndex={0} className="block min-w-0 cursor-help truncate text-fg-2 focus:outline-none">
              {projectName(p) || p}
            </span>
          </Tooltip>
        );
      },
    },
    tags: {
      // Tags: as many pills as fit (rowTagCount, at most two) + a "+n"
      // overflow, the note glyph, and the editor trigger, which shows on row
      // hover / focus (or while open) so untagged rows stay empty. A pill
      // click filters the list.
      id: "tags",
      header: () => <>Tags</>,
      enableSorting: false,
      cell: ({ row }) => {
        const tags = row.original.tags ?? [];
        const count = rowTagCount(tags, row.original.has_note === true, TAGS_CELL_WIDTH);
        const shownTags = tags.slice(0, count);
        const hidden = tags.slice(count);
        return (
          <span className="flex min-w-0 items-center gap-1 overflow-hidden">
            {shownTags.map((t) => (
              <TagPill key={t} tag={t} shrink onClick={tagsCtx.onTagClick} />
            ))}
            {hidden.length > 0 && (
              <Tooltip content={hidden.join(", ")}>
                <span
                  tabIndex={0}
                  className="shrink-0 cursor-help font-mono text-[10px] text-fg-3 focus:outline-none"
                >
                  +{hidden.length}
                </span>
              </Tooltip>
            )}
            {row.original.has_note && (
              <GlyphBadge icon={StickyNote} label="This session has a note. Open it to read." />
            )}
            <TagEditor
              quiet
              sessionId={row.original.id}
              tags={tags}
              className="shrink-0 opacity-0 focus-visible:opacity-100 group-hover:opacity-100 group-focus-within:opacity-100 aria-expanded:opacity-100"
              onTagsChange={(next) =>
                tagsCtx.onTagsChange(row.original.id, next)
              }
            />
          </span>
        );
      },
    },
    models: {
      id: "models",
      header: "Model(s)",
      // Not server-sortable (no single ordering key).
      enableSorting: false,
      cell: ({ row }) => {
        const ms = row.original.models ?? [];
        if (ms.length === 0) {
          return <span className="text-fg-4">-</span>;
        }
        const primary = ms[0];
        const extras = ms.slice(1);
        return (
          <Tooltip
            content={
              <span className="block whitespace-pre-line break-all font-mono">
                {ms.join("\n")}
              </span>
            }
            maxWidth={360}
          >
            <span
              tabIndex={0}
              className="flex min-w-0 cursor-help items-center gap-1.5 focus:outline-none"
            >
              {/* Family mark (no own tooltip: the cell's tooltip lists every model). */}
              <ModelMark model={primary} tooltip={false} />
              <span className="min-w-0 truncate font-mono text-[10.5px] text-fg-1">
                {shortModel(primary)}
              </span>
              {extras.length > 0 && (
                <span className="shrink-0 font-mono text-[10.5px] text-fg-3">
                  +{extras.length}
                </span>
              )}
            </span>
          </Tooltip>
        );
      },
    },
    started_at: {
      id: "started_at",
      header: () => <>Started<HelpInd id="column.sessions.started" /></>,
      accessorKey: "started_at",
      cell: ({ row }) => (
        <Tooltip content={fmtDateTime(row.original.started_at)}>
          <span
            tabIndex={0}
            className="cursor-help whitespace-nowrap font-mono text-[11px] text-fg-3 focus:outline-none"
          >
            {fmtTimestamp(row.original.started_at)}
          </span>
        </Tooltip>
      ),
    },
    elapsed: {
      id: "elapsed",
      header: () => <>Elapsed<HelpInd id="column.sessions.elapsed" /></>,
      accessorKey: "duration_seconds",
      cell: ({ row }) => (
        <span className="text-fg-2">
          {fmtDuration(row.original.duration_seconds * 1000)}
        </span>
      ),
    },
    actions: {
      id: "actions",
      header: () => <>Actions<HelpInd id="column.sessions.actions" /></>,
      accessorKey: "total_actions",
      cell: ({ row }) => (
        <span className="text-fg-1">{fmtInt(row.original.total_actions)}</span>
      ),
    },
    ai_code_lines: {
      // AI code lines (lines-of-code tracking §3.4). Server-sortable via
      // sort_by=ai_code_lines. There is deliberately NO human column and no
      // share here: with no editor capture the human side is unmeasured
      // rather than zero, and a table cell has no room for the capture
      // caveat that would make either honest.
      id: "ai_code_lines",
      header: () => (
        <Tooltip content="Code lines the agent added or modified. Comments and blank lines are excluded; deleted lines are not included. The muted percentage is the comment share: comment lines over code plus comment lines the agent wrote in code files.">
          <span>
            AI code
            <HelpInd id="column.sessions.ai_code_lines" />
          </span>
        </Tooltip>
      ),
      accessorKey: "ai_code_lines",
      cell: ({ row }) => {
        // omitempty on the wire: absent means NOT COUNTED, never zero.
        const v = row.original.ai_code_lines;
        if (v === undefined || v === null) {
          return (
            <Tooltip content="No agent code lines recorded: either this session changed no code, or its line counts have not been computed yet. Settings > Backfill > loc populates history.">
              <span tabIndex={0} className="text-fg-4 focus:outline-none">
                -
              </span>
            </Tooltip>
          );
        }
        // The comment share is server-computed (internal/loc.SplitAuthored)
        // and rendered by the one shared renderer; absent split = no suffix.
        return (
          <span className="whitespace-nowrap">
            <span className="text-fg-1">{fmtCompact(v)}</span>
            {row.original.ai_split && (
              <CodeCommentSplit
                split={row.original.ai_split}
                variant="share"
                compact
                className="ml-1 text-[10px] text-fg-3"
              />
            )}
          </span>
        );
      },
    },
    tokens: {
      // Tokens: the four billable buckets added up, with their mix as a thin
      // bar under the number. No server sort key exists for the sum, so the
      // header does not sort; the Sort menu and the per-bucket columns do.
      id: "tokens",
      header: () => <>Tokens<HelpInd id="column.sessions.tokens" /></>,
      accessorFn: (r) => sessionTokenTotal(r),
      enableSorting: false,
      cell: ({ row }) => {
        const r = row.original;
        const total = sessionTokenTotal(r);
        if (total <= 0) return <span className="text-fg-4">-</span>;
        return (
          <div className="flex flex-col items-end gap-1">
            <Tooltip content={<TokenBreakdown row={r} />} maxWidth={300}>
              <span
                tabIndex={0}
                data-tokens-cell
                className="cursor-help text-fg-1 focus:outline-none"
              >
                {fmtCompact(total)}
              </span>
            </Tooltip>
            <TokenBar
              buckets={{
                netInput: r.input_tokens,
                cacheRead: r.cache_read_tokens,
                cacheWrite: r.cache_creation_tokens,
                output: r.output_tokens,
              }}
              trackClassName="h-[3px]"
              className="max-w-[56px]"
            />
          </div>
        );
      },
    },
    input: {
      id: "input",
      header: () => <>Input<HelpInd id="column.sessions.input_tokens" /></>,
      accessorKey: "input_tokens",
      cell: ({ row }) => tokenCount(row.original.input_tokens),
    },
    cache_r: {
      id: "cache_r",
      header: () => (
        <>Cache R<HelpInd id="column.sessions.cache_read_tokens" /></>
      ),
      accessorKey: "cache_read_tokens",
      cell: ({ row }) => tokenCount(row.original.cache_read_tokens),
    },
    cache_w: {
      id: "cache_w",
      header: () => (
        <>Cache W<HelpInd id="column.sessions.cache_creation_tokens" /></>
      ),
      accessorKey: "cache_creation_tokens",
      cell: ({ row }) => {
        const total = row.original.cache_creation_tokens;
        if (total <= 0) return <span className="text-fg-4">-</span>;
        const tier1h = row.original.cache_creation_1h_tokens || 0;
        const tier5m = Math.max(0, total - tier1h);
        const pct1h = total > 0 ? (tier1h / total) * 100 : 0;
        const pct5m = total > 0 ? (tier5m / total) * 100 : 0;
        const tipBody = (
          <div className="space-y-1">
            <div className="flex items-baseline justify-between gap-4 font-mono">
              <span className="text-fg-3">5m tier</span>
              <span className="tabular-nums">
                {fmtCompact(tier5m)} <span className="text-fg-3">({pct5m.toFixed(0)}%)</span>
              </span>
            </div>
            <div className="flex items-baseline justify-between gap-4 font-mono">
              <span className="text-fg-3">1h tier</span>
              <span className="tabular-nums">
                {fmtCompact(tier1h)} <span className="text-fg-3">({pct1h.toFixed(0)}%)</span>
              </span>
            </div>
            {tier1h > 0 && (
              <div className="border-t border-line-2 pt-1 text-[10.5px] text-fg-3">
                1h tier bills at 2× input rate; 5m tier at 1.25×.
              </div>
            )}
          </div>
        );
        return (
          <Tooltip content={tipBody} maxWidth={260}>
            <span tabIndex={0} className="cursor-help text-fg-1 focus:outline-none">
              {fmtCompact(total)}
            </span>
          </Tooltip>
        );
      },
    },
    output: {
      id: "output",
      header: () => <>Output<HelpInd id="column.sessions.output_tokens" /></>,
      accessorKey: "output_tokens",
      cell: ({ row }) => tokenCount(row.original.output_tokens),
    },
    cost: {
      id: "cost",
      // Only Total $ in the table — API $ + Tool $ live on the detail panel;
      // hover shows the split. In the org's token-usage view the cell renders
      // the row's token total, so the header names tokens there too.
      header: () => <>{costLabel("Total $", "Total tok")}<HelpInd id="column.sessions.cost" /></>,
      accessorKey: "cost_usd",
      cell: ({ row }) => {
        const total = row.original.cost_usd;
        if (total <= 0) {
          return <span className="text-fg-4">-</span>;
        }
        const color =
          total >= 50
            ? "text-danger"
            : total >= 10
              ? "text-warn"
              : "text-fg-0";
        const api = row.original.ai_cost_usd;
        const tool = row.original.tool_cost_usd;
        const rowTokens = sessionTokenTotal(row.original);
        if (getCostDisplayMode() === "tokens") {
          return (
            <span className="font-semibold text-fg-0">{fmtCost(total, rowTokens)}</span>
          );
        }
        const split =
          api > 0 || tool > 0
            ? `api ${fmtUSD(api)} · tool ${fmtUSD(tool)}`
            : "";
        return (
          <Tooltip
            content={
              <span className="block whitespace-pre-line">
                {fmtUSD(total, true)}
                {split ? `\n${split}` : ""}
              </span>
            }
          >
            <span
              tabIndex={0}
              className={`cursor-help font-semibold focus:outline-none ${color}`}
            >
              {fmtCost(total, rowTokens)}
            </span>
          </Tooltip>
        );
      },
    },
    quality: {
      id: "quality",
      header: () => <>Quality<HelpInd id="column.sessions.quality" /></>,
      accessorFn: (r) => r.quality_score ?? -1,
      cell: ({ row }) =>
        row.original.quality_score != null
          ? fmtPct(row.original.quality_score)
          : <span className="text-fg-4">-</span>,
    },
    errors: {
      id: "errors",
      header: () => <>Errors<HelpInd id="column.sessions.errors" /></>,
      accessorFn: (r) => r.error_rate ?? -1,
      cell: ({ row }) =>
        row.original.error_rate != null ? (
          <span
            className={
              row.original.error_rate > 0.05 ? "text-warn" : "text-fg-2"
            }
          >
            {fmtPct(row.original.error_rate)}
          </span>
        ) : (
          <span className="text-fg-4">-</span>
        ),
    },
    redundancy: {
      id: "redundancy",
      header: () => <>Redund.<HelpInd id="column.sessions.redundancy" /></>,
      accessorFn: (r) => r.redundancy_ratio ?? -1,
      cell: ({ row }) => {
        const r = row.original;
        if (r.redundancy_ratio == null) return <span className="text-fg-4">-</span>;
        // Spec §14.1 wasteful subset rendered as
        // "0.30 (0.20 wasteful)" when present. Sessions
        // without cache_events keep the legacy single value.
        if (r.redundancy_ratio_wasteful != null) {
          return (
            <Tooltip content="total / wasteful subset">
              <span tabIndex={0} className="focus:outline-none">
                {fmtPct(r.redundancy_ratio)}
                <span className="ml-1 text-fg-3">
                  ({fmtPct(r.redundancy_ratio_wasteful)} wasteful)
                </span>
              </span>
            </Tooltip>
          );
        }
        return fmtPct(r.redundancy_ratio);
      },
    },
  };

  return shown.map((id) => {
    const spec = sessionColumn(id);
    const def = defs[id];
    return {
      ...def,
      meta: {
        ...COLUMN_META[id],
        // Session declares the fit rule's width for it (null until the card
        // is measured: no width, so it takes the leftover space).
        width: spec?.flex ? (flexWidth ?? undefined) : spec?.width,
        sticky: pinned && spec?.locked === true,
      },
    } as ColumnDef<SessionRow, unknown>;
  });
}

// COLUMN_META is each column's alignment and clipping (widths and pinning
// come from lib/sessionColumns): numbers right-aligned in tabular figures,
// and every text column clips rather than widening the table.
const COLUMN_META: Record<SessionColumnId, { align?: "right"; truncate?: boolean }> = {
  favorite: {},
  session: { truncate: true },
  tool: { truncate: true },
  client: { truncate: true },
  ran: { truncate: true },
  project: { truncate: true },
  tags: { truncate: true },
  models: { truncate: true },
  started_at: {},
  elapsed: { align: "right" },
  actions: { align: "right" },
  ai_code_lines: { align: "right" },
  tokens: { align: "right" },
  input: { align: "right" },
  cache_r: { align: "right" },
  cache_w: { align: "right" },
  output: { align: "right" },
  cost: { align: "right" },
  quality: { align: "right" },
  errors: { align: "right" },
  redundancy: { align: "right" },
};

// Format an ISO timestamp as "MMM DD HH:MM" — matches design's
// dim mono treatment for the Started column. localeString is the cached,
// byte-identical toLocaleString (one formatter, not one per cell).
function fmtTimestamp(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return localeString(d, "en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

// CSV export of the currently-visible (post-filter) Sessions table.
// Columns mirror the table 1:1 (minus Models, which the backend
// doesn't expose per-session yet).
function exportSessionsCsv(rows: SessionRow[]) {
  if (!rows.length) return;
  // The export follows the developer cost display through lib/costExport
  // (T-204): the `_usd` columns are left out in the token-usage view.
  const csv = csvText<SessionRow>(rows, [
    { header: "session_id", value: (r) => r.id },
    { header: "tool", value: (r) => r.tool },
    { header: "surface", value: (r) => r.surface },
    { header: "surface_host", value: (r) => r.surface_host },
    { header: "execution_location", value: (r) => r.execution_location },
    { header: "vendor_session_ref", value: (r) => r.vendor_session_ref },
    { header: "project", value: (r) => r.project },
    { header: "started_at", value: (r) => r.started_at },
    { header: "duration_seconds", value: (r) => r.duration_seconds },
    { header: "total_actions", value: (r) => r.total_actions },
    { header: "sidechain_action_count", value: (r) => r.sidechain_action_count },
    { header: "input_tokens", value: (r) => r.input_tokens },
    { header: "cache_read_tokens", value: (r) => r.cache_read_tokens },
    { header: "cache_creation_tokens", value: (r) => r.cache_creation_tokens },
    { header: "output_tokens", value: (r) => r.output_tokens },
    { header: "ai_cost_usd", value: (r) => r.ai_cost_usd },
    { header: "tool_cost_usd", value: (r) => r.tool_cost_usd },
    { header: "cost_usd", value: (r) => r.cost_usd },
    { header: "cost_reliability", value: (r) => r.cost_reliability },
  ]);
  const blob = new Blob([csv], {
    type: "text/csv;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sessions-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
