import { useEffect, useMemo, useRef, useState } from "react";
import clsx from "clsx";
import { Pencil } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import type { ColumnDef, SortingState } from "@tanstack/react-table";
import {
  ActiveFilterChips,
  ChartShell,
  type FilterChip,
  ModelDot,
  PageHeader,
  Pill,
  SegmentedControl,
  SlideOver,
  ToolBadge,
  Tooltip,
  TruncatedPath,
} from "@/components/primitives";
import { AnchoredPopover } from "@/components/primitives/AnchoredPopover";
import { shortModel } from "@/lib/models";
import { HelpInd } from "@/components/HelpInd";
import { CopyOnClick } from "@/components/CopyOnClick";
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
import { CloudRow } from "@/components/sessiondetail/CloudRow";
import { cloudProgressAction } from "@/lib/cloudProgress";
import {
  fmtCompact,
  fmtDateTime,
  fmtDuration,
  fmtInt,
  fmtPct,
  fmtUSD,
} from "@/lib/format";
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

const PAGE_LIMIT = 50;

// SORT_OPTIONS backs the toolbar's Sort menu. Since the Rating column was
// removed (rating is now a click-popover only, not a whole column), there is
// no clickable header left for "best/worst rated first" — this menu is how
// that server-side sort_by=rating ordering stays reachable, alongside a few
// other sorts that are handy without hunting for the right column header.
// Remaining columns (Session/Tool/Project/quality/errors/redundancy/token
// buckets…) are still sortable via a header click, which drives the same
// `sorting` state untouched by this menu.
type SortOption = { id: string; desc: boolean; label: string };
const SORT_OPTIONS: SortOption[] = [
  { id: "started_at", desc: true, label: "Started (newest first)" },
  { id: "cost", desc: true, label: "Cost (highest first)" },
  { id: "elapsed", desc: true, label: "Elapsed (longest first)" },
  { id: "actions", desc: true, label: "Actions (most first)" },
  { id: "ai_code_lines", desc: true, label: "AI code lines (most first)" },
  { id: "rating", desc: true, label: "Rating (best first)" },
  { id: "rating", desc: false, label: "Rating (worst first)" },
  { id: "favorite", desc: true, label: "Favorites first" },
];

type View = "table" | "calendar";

export function SessionsPage() {
  const { win, customRange, tool, project, query: globalQuery } = useFilters();
  const winParams = windowParams(win, customRange);
  // CalendarView needs a plain day-count for its grid span; sub-day
  // windows round up to a day.
  const calendarDays = windowDaysApprox(win, customRange);
  const toolParam = tool === "all" ? undefined : tool;
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
  // Only truthy when the current sort exactly matches one of the toolbar's
  // named options — a header click on a column the menu doesn't cover (e.g.
  // "Project") leaves the button reading plain "Sort".
  const sortOption = SORT_OPTIONS.find(
    (o) => o.id === sortBy && o.desc === (sortDir === "desc"),
  );
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
  const filterKey = `${win}|${tool}|${project}|${pickedDay ?? ""}|${sortBy}|${sortDir}|${tagKey}|${favoriteOnly}`;
  const lastKey = useMemo(() => filterKey, [filterKey]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useMemo(() => setPage(1), [lastKey]);

  const sessions = useApi<SessionsResponse>(
    "/api/sessions",
    {
      page,
      limit: PAGE_LIMIT,
      tool: toolParam,
      project: projectParam,
      ...winParams,
      from_date: pickedDay ?? undefined,
      to_date: pickedDay ?? undefined,
      sort_by: sortBy,
      sort_dir: sortDir,
      // Repeated `tag=` params (AND semantics, server-side) + favorite=1.
      tag: tagFilters.length > 0 ? tagFilters : undefined,
      favorite: favoriteOnly ? 1 : undefined,
    },
    [
      page,
      win,
      customRange,
      tool,
      project,
      pickedDay,
      sortBy,
      sortDir,
      tagKey,
      favoriteOnly,
    ],
    // Live-capture refresh: 5s while the tab is visible. Lets fresh
    // Antigravity-CLI .pb files (and any other in-progress session)
    // appear without requiring the operator to manually reload.
    { refreshMs: 5000 },
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
      project: projectParam,
      ...winParams,
    },
    [view, win, customRange, tool, project],
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
  const attach = useApi<AttachSessionsResponse>(
    "/api/attach/sessions",
    undefined,
    [],
    { refreshMs: 15000 },
  );
  const liveSet = useMemo(() => {
    const s = new Set<string>();
    for (const r of attach.data?.sessions ?? []) {
      if (r.session_id && !r.exited) s.add(r.session_id);
    }
    return s;
  }, [attach.data]);

  // Canonical liveness for BARE (non-attachable) sessions: /api/live
  // marks a session active if any row landed in the last 15 minutes.
  // Polled at 15s (matching the attach cadence, NOT Live.tsx's 5s — this
  // table lists many rows). Drives the read-only "live · watch" chip on
  // rows that are running but weren't launched with `--attach`.
  // ids_only mode: EVERY active session id in the window (the card-view
  // default caps at the newest 8, which would silently drop the ninth
  // concurrent session's "live · watch" pill).
  const live = useApi<{ active_ids?: string[] }>(
    "/api/live",
    { window_minutes: 15, ids_only: 1 },
    [],
    { refreshMs: 15000 },
  );
  const activeSet = useMemo(() => {
    const s = new Set<string>();
    for (const id of live.data?.active_ids ?? []) {
      if (id) s.add(id);
    }
    return s;
  }, [live.data]);

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
        label: `cost: ${rangeLabel(filters.minCostUsd, filters.maxCostUsd, "$")}`,
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
        label: "★ favorites",
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
    return c;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [favoriteOnly, tagKey]);

  const showScoring = (sessions.data?.scored_count ?? 0) > 0;
  const columns = useMemo<ColumnDef<SessionRow, unknown>[]>(
    () =>
      buildColumns(showScoring, liveSet, activeSet, setWatch, {
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
    [showScoring, liveSet, activeSet],
  );

  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="Sessions"
        sub="One row per AI-coding session. Click a row to see action breakdown, token buckets, cost summary, and a full messages timeline with expandable tool calls."
        helpId="tab.sessions"
        right={
          <SegmentedControl<View>
            options={[
              { value: "table", label: "Table" },
              { value: "calendar", label: "Calendar" },
            ]}
            value={view}
            onChange={setView}
            size="sm"
          />
        }
      />
      {!showScoring && sessions.data && <ScoringHintBanner />}
      {cloudStatus.data && <CloudEnrichmentSummary data={cloudStatus.data} />}
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
        sub="click any row for the per-session breakdown"
        right={
          <div className="flex items-center gap-2">
            <input
              type="search"
              placeholder="filter by id, project…"
              value={localQuery}
              onChange={(e) => setLocalQuery(e.target.value)}
              className="h-7 w-[240px] rounded-2 border border-line-2 bg-bg-2 px-2 font-mono text-[11px] text-fg-1 placeholder:text-fg-4 focus:border-accent focus:outline-none"
            />
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
                ★ Favorites
              </button>
            </Tooltip>
            <Tooltip
              content={
                sortOption
                  ? `Sorted by ${sortOption.label.toLowerCase()} - click to change`
                  : "Choose a sort order (also reaches Rating best/worst-first, which has no column any more)"
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
                Sort{sortOption ? `: ${sortOption.label}` : ""}
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
                      {active && <span aria-hidden>✓</span>}
                    </button>
                  );
                })}
              </div>
            </AnchoredPopover>
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
        }
      >
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
            }}
          />
        )}
        {view === "calendar" ? (
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
          <>
            <ChartState
              loading={sessions.loading && !sessions.data}
              error={sessions.error}
              empty={!sessions.loading && filtered.length === 0}
              emptyHint={
                pickedDay
                  ? `No sessions on ${pickedDay}. Clear the day filter to see all sessions.`
                  : query
                    ? `No sessions match "${query}". Clear the search or widen filters.`
                    : "No sessions in window. Run `observer init` to register hooks with your AI tools."
              }
              height={240}
            >
              <DataTable<SessionRow>
                data={filtered}
                columns={columns}
                onRowClick={(r) => setSelected(r.id)}
                rowKey={(r) => r.id}
                // Every column declares meta.width (COL_W), so the fixed
                // layout can hold the budget: no single long project path or
                // tool label can inflate its column and push Output / Total $
                // off the right edge. minWidth is the sum of that budget;
                // below it the wrapper scrolls, with a visible scrollbar and
                // an edge fade rather than a silently clipped table.
                layout="fixed"
                minWidth={
                  SESSIONS_MIN_WIDTH +
                  (showScoring ? SESSIONS_SCORING_WIDTH : 0)
                }
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
          </>
        )}
      </ChartShell>

      <SlideOver open={enrichmentSession !== null} onClose={() => setEnrichmentSession(null)} title="Session enrichment"
        subtitle={enrichmentSession?.title || enrichmentSession?.cloud_title || enrichmentSession?.project} width={640}>
        {enrichmentSession && <div className="space-y-4 p-4">
          <CloudRow key={enrichmentSession.id} sessionId={enrichmentSession.id} onChanged={() => { sessions.reload(); cloudStatus.reload(); }} />
          {cloudStatus.data && <details className="space-y-2">
            <summary className="w-fit cursor-pointer text-[11px] font-medium text-fg-3">Enrichment settings and allowance</summary>
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
  if (lo && hi) return `${prefix}${lo}–${prefix}${hi}`;
  if (lo) return `≥ ${prefix}${lo}`;
  if (hi) return `≤ ${prefix}${hi}`;
  return "-";
}

function durationLabel(d: SessionFilters["duration"]): string {
  switch (d) {
    case "short":
      return "<5m";
    case "medium":
      return "5–30m";
    case "long":
      return "30m–2h";
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
                    : "border-line-2 bg-bg-1 hover:bg-bg-3")
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
            className="rounded-2 border border-line-2 bg-bg-1 px-2 py-1 text-[10.5px] text-fg-3 hover:bg-bg-3 hover:text-fg-1"
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
      <span className="mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded-full border border-info/40 text-info">
        i
      </span>
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
        ×
      </button>
    </div>
  );
}

function ScoringHintBanner() {
  return (
    <div className="flex items-start gap-3 rounded-3 border border-warn/30 bg-warn-soft/60 px-4 py-2.5 text-[11.5px]">
      <span className="mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded-full border border-warn/40 text-warn">
        i
      </span>
      <div className="text-fg-2">
        <b className="text-fg-1">
          Quality / Errors / Redundancy scoring is hidden.
        </b>{" "}
        Run{" "}
        <code className="rounded-1 border border-line-3 bg-bg-3 px-1.5 py-0.5 font-mono text-[11px] text-fg-1">
          observer score
        </code>{" "}
        to populate the columns. Sessions get a 0–100 quality score and a
        redundancy index that flags repeat-work patterns.
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
            {fmtHeader(first)} – {fmtHeader(last)}
          </span>
          <span className="font-mono text-[10.5px] text-fg-3">
            {byDay.size} active day{byDay.size === 1 ? "" : "s"}
          </span>
          {loading && (
            <span
              aria-label="loading"
              className="inline-block h-2 w-2 animate-pulse rounded-full bg-accent"
            />
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

// MAX_ROW_TAGS caps how many pills a row shows before collapsing the rest
// into a "+n" affordance. Two keeps the column inside its width budget
// (COL_W.tags) without wrapping every tagged row onto three lines.
const MAX_ROW_TAGS = 2;

// COL_W is the Sessions table's width budget, in px, one entry per column.
// It exists because the table has 15 columns and the operator's report was
// that the last two (Output, Total $) fell off the right edge at default
// zoom on a ~2000px display: with auto layout a single long value (a deep
// project path, a 16-character tool label like "Open Interpreter") inflates
// its own column and pushes everything after it out of view.
//
// The table renders with layout="fixed", so these numbers are authoritative
// and any surplus container width is redistributed across them in
// proportion. Each is sized to its HEADER plus its typical value, and the
// three text columns that can hold an unbounded string (project, tool,
// models) also set meta.truncate so they clip instead of growing.
//
// Sum without the optional scoring columns: 1378px. That fits inside the
// ~1620px of table area a 1920px viewport leaves after the sidebar and the
// page/card padding, with room to spare; at 1440px the wrapper scrolls the
// last ~140px, with a visible scrollbar and an edge fade to say so.
const COL_W = {
  favorite: 44,
  session: 116,
  // 110 is the width at which the two most common labels ("Claude Code",
  // "Antigravity CLI") still read; longer ones ellipsize with the badge's
  // own tooltip carrying the full name.
  tool: 120,
  project: 132,
  tags: 116,
  models: 108,
  // 110 keeps "Sep 07, 12:31" on ONE line: at 98 it wrapped and every row
  // in the table grew a second line for it.
  started: 110,
  // The numeric columns are sized by their HEADER, not their values: the
  // label plus its help dot plus the sort caret is wider than "481.1K".
  elapsed: 80,
  actions: 80,
  aiCode: 80,
  input: 68,
  cacheR: 82,
  cacheW: 86,
  output: 78,
  cost: 78,
  quality: 68,
  errors: 66,
  redundancy: 120,
} as const;

// SESSIONS_MIN_WIDTH is the sum of COL_W: below it the DataTable wrapper
// scrolls horizontally rather than squeezing the numerics into two lines.
const SESSIONS_MIN_WIDTH =
  COL_W.favorite +
  COL_W.session +
  COL_W.tool +
  COL_W.project +
  COL_W.tags +
  COL_W.models +
  COL_W.started +
  COL_W.elapsed +
  COL_W.actions +
  COL_W.aiCode +
  COL_W.input +
  COL_W.cacheR +
  COL_W.cacheW +
  COL_W.output +
  COL_W.cost;

const SESSIONS_SCORING_WIDTH =
  COL_W.quality + COL_W.errors + COL_W.redundancy;

// SESSION_TITLE_MAX_LENGTH mirrors the server's <= 200-char rule
// (store.MaxTitleLen).
const SESSION_TITLE_MAX_LENGTH = 200;

// SessionTitleCell renders the Session column's primary text — the EFFECTIVE
// title (the developer's own title > the AI/cloud title > the plain id
// fallback) — with inline editing. The id itself never disappears: it stays
// the CopyOnClick value and the "click to copy" tooltip target, so a titled
// row is still one click from its real id.
//
// A hover-revealed pencil, or a double-click on the title, opens a text
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
  const cloudTitle = row.cloud_title ?? "";
  const effectiveTitle = userTitle || cloudTitle;
  // The primary text duplicates the cloud-enriched dot's tooltip exactly
  // when it's showing the cloud title with no user override — so the dot is
  // hidden in that one case (see the cell renderer below).
  const usingAI = userTitle === "" && cloudTitle !== "";
  const fallback = `${(row.id.split(":agent:").at(-1) ?? row.id).slice(0, 12)}…`;
  const primaryText = effectiveTitle || fallback;

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
      <span className="flex flex-col gap-0.5">
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
          className="w-full rounded-1 border border-line-2 bg-bg-1 px-1 py-0.5 text-[11px] text-fg-1 outline-none focus:border-accent"
        />
        {err && <span className="text-[9px] text-danger">{err}</span>}
      </span>
    );
  }

  return (
    <span
      className="group/title inline-flex min-w-0 max-w-full items-center gap-1"
      onDoubleClick={(e) => {
        e.stopPropagation();
        openEditor();
      }}
    >
      {usingAI && <Pill variant="accent">AI</Pill>}
      <CopyOnClick
        value={row.id}
        className="min-w-0 font-mono text-[11px] text-accent hover:text-accent-strong"
      >
        <span className="truncate">{primaryText}</span>
      </CopyOnClick>
      <button
        type="button"
        title={userTitle ? "Edit your title" : "Set your own title"}
        onClick={(e) => {
          e.stopPropagation();
          openEditor();
        }}
        className="shrink-0 opacity-0 transition-opacity hover:text-accent focus:opacity-100 group-hover/title:opacity-100"
      >
        <Pencil size={10} aria-hidden />
      </button>
    </span>
  );
}

function buildColumns(
  showScoring: boolean,
  liveSet: Set<string>,
  activeSet: Set<string>,
  onWatch: (id: string) => void,
  tagsCtx: TagsCtx,
  onEnrich: (session: SessionRow) => void,
): ColumnDef<SessionRow, unknown>[] {
  // Column order matches design/page-sessions.jsx exactly:
  // Session / Tool / Project / Model(s) / Started / Elapsed / Actions /
  // Sub / Input / Cache R / Cache W / Output / API $ / Tool $ / Total $
  // Reliability and scoring (optional) come after.
  const cols: ColumnDef<SessionRow, unknown>[] = [
    {
      // Favorite star + a compact rating trigger sharing one narrow column.
      // There is no dedicated Rating column any more (issue: rating should be
      // reachable only via a click-popover, not a whole column that's empty
      // for most rows) — server-side "best/worst first" sort now lives in the
      // toolbar's Sort menu instead of a clickable header. Still
      // server-sortable via sort_by=favorite (the header click toggles it).
      id: "favorite",
      header: () => <span title="Favorites">★</span>,
      accessorFn: (r) => (r.favorite ? 1 : 0),
      meta: { width: COL_W.favorite },
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
              // the "rate" affordance on row hover/keyboard focus so the
              // column doesn't fill up with muted placeholder icons.
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
    {
      id: "session",
      header: () => <>Session<HelpInd id="column.sessions.id" /></>,
      accessorKey: "id",
      meta: { width: COL_W.session },
      // flex-wrap, not nowrap: the id + copy affordance already fills the
      // column, so a "live" pill drops to a second line instead of pushing
      // the column (and every column after it) wider.
      cell: ({ row }) => (
        <span className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
          <SessionTitleCell row={row.original} onSetTitle={tagsCtx.onSetTitle} />
          <button type="button" className="rounded-1 border border-accent/30 px-1.5 py-0.5 text-[10px] font-medium text-accent hover:bg-accent/10"
            onClick={(event) => { event.stopPropagation(); onEnrich(row.original); }}
            onKeyDown={(event) => event.stopPropagation()}
            title="Open this session's enrichment status and controls">
            {cloudProgressAction(row.original.cloud_enrichment, !!row.original.cloud_enriched)}
          </button>
          {row.original.id.includes(":agent:") && (
            <span className="text-[10px] text-fg-3">subagent</span>
          )}
          {row.original.cloud_enriched &&
            // Cloud-enriched marker — makes an AI-summarized session spottable
            // in the list. Hidden when the primary text is ALREADY showing the
            // cloud title (no user title set): the dot would otherwise repeat
            // exactly what's already on the row. Still shown when a user title
            // is displayed instead (the dot's tooltip then surfaces the
            // DIFFERENT AI title) or when enrichment exists with no title yet.
            !(!row.original.title && row.original.cloud_title) && (
              <span
                aria-label="Cloud-enriched session"
                title={
                  row.original.cloud_title
                    ? `Cloud enrichment: ${row.original.cloud_title}`
                    : "Cloud-enriched session"
                }
                className="inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-accent"
              />
            )}
          {liveSet.has(row.original.id) ? (
            <Pill
              variant="success"
              title="Running as an attachable `observer --attach` session - open it and click Jump in to join the live terminal."
            >
              live · joinable
            </Pill>
          ) : (
            activeSet.has(row.original.id) && (
              // Bare (non-attachable) live session — offer a read-only
              // watch. stopPropagation so the pill click doesn't also
              // fire the row's open-in-normal-mode handler.
              <span
                role="button"
                tabIndex={0}
                onClick={(e) => {
                  e.stopPropagation();
                  onWatch(row.original.id);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.stopPropagation();
                    e.preventDefault();
                    onWatch(row.original.id);
                  }
                }}
                className="cursor-pointer focus:outline-none"
              >
                <Pill
                  variant="success"
                  title="Running outside observer - watch the conversation read-only; joining requires an observer-launched session"
                >
                  live · watch
                </Pill>
              </span>
            )
          )}
        </span>
      ),
    },
    {
      id: "tool",
      header: () => <>Tool<HelpInd id="column.sessions.tool" /></>,
      accessorKey: "tool",
      meta: { width: COL_W.tool, truncate: true },
      // The badge's label is the tool's display name, which runs to 16
      // characters ("Open Interpreter", "Perplexity (web)"). min-w-0 on
      // both the wrapper and the badge lets the label shrink; the arbitrary
      // child selector puts the ellipsis on the label span itself, which is
      // the only text node in the shared primitive. The badge's own tooltip
      // still carries the full name.
      cell: ({ row }) => (
        <span className="flex min-w-0">
          <ToolBadge
            tool={row.original.tool}
            className="min-w-0 [&>span:last-child]:min-w-0 [&>span:last-child]:truncate"
          />
        </span>
      ),
    },
    {
      id: "project",
      header: () => <>Project<HelpInd id="column.sessions.project" /></>,
      accessorKey: "project",
      meta: { width: COL_W.project, truncate: true },
      cell: ({ row }) =>
        row.original.project ? (
          // TruncatedPath keeps the TAIL (the basename) readable and puts
          // the ellipsis at the head; the full path stays on hover/focus.
          <TruncatedPath
            value={row.original.project}
            className="font-mono text-[11px] text-fg-3"
          />
        ) : (
          <Pill>none</Pill>
        ),
    },
    {
      // Tags: up to MAX_ROW_TAGS pills + a "+n" overflow, followed by the
      // editor trigger. Clicking a pill filters the list to that tag
      // (server-side); clicking the trigger opens the popover editor.
      id: "tags",
      header: () => <>Tags</>,
      enableSorting: false,
      meta: { width: COL_W.tags },
      cell: ({ row }) => {
        const tags = row.original.tags ?? [];
        const shown = tags.slice(0, MAX_ROW_TAGS);
        const hidden = tags.slice(MAX_ROW_TAGS);
        return (
          // No max-width: the cell already has a hard width budget, and
          // flex-wrap keeps the pills inside it instead of overflowing.
          <span className="flex flex-wrap items-center gap-1">
            {shown.map((t) => (
              <TagPill key={t} tag={t} onClick={tagsCtx.onTagClick} />
            ))}
            {hidden.length > 0 && (
              <Tooltip content={hidden.join(", ")}>
                <span
                  tabIndex={0}
                  className="cursor-help font-mono text-[10px] text-fg-3 focus:outline-none"
                >
                  +{hidden.length}
                </span>
              </Tooltip>
            )}
            {row.original.has_note && (
              <Tooltip content="This session has a note - open it to read.">
                <span
                  tabIndex={0}
                  aria-label="has note"
                  className="cursor-help text-[10px] text-fg-3 focus:outline-none"
                >
                  ✎
                </span>
              </Tooltip>
            )}
            <TagEditor
              sessionId={row.original.id}
              tags={tags}
              label={tags.length > 0 ? "edit" : "+ tag"}
              onTagsChange={(next) =>
                tagsCtx.onTagsChange(row.original.id, next)
              }
            />
          </span>
        );
      },
    },
    {
      id: "models",
      header: "Model(s)",
      // Not server-sortable (no single ordering key); keep the header inert
      // rather than offering a sort affordance the backend would ignore.
      enableSorting: false,
      meta: { width: COL_W.models, truncate: true },
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
              <ModelDot model={primary} />
              <span className="min-w-0 truncate font-mono text-[10.5px] text-fg-1">
                {shortModel(primary)}
              </span>
              {extras.length > 0 && (
                <span className="shrink-0 font-mono text-[10.5px] text-fg-3">
                  + {extras.length}
                </span>
              )}
            </span>
          </Tooltip>
        );
      },
    },
    {
      id: "started_at",
      header: () => <>Started<HelpInd id="column.sessions.started" /></>,
      accessorKey: "started_at",
      meta: { width: COL_W.started },
      cell: ({ row }) => (
        <Tooltip content={fmtDateTime(row.original.started_at)}>
          <span
            tabIndex={0}
            className="cursor-help font-mono text-[11px] text-fg-3 focus:outline-none"
          >
            {fmtTimestamp(row.original.started_at)}
          </span>
        </Tooltip>
      ),
    },
    {
      id: "elapsed",
      header: () => <>Elapsed<HelpInd id="column.sessions.elapsed" /></>,
      accessorKey: "duration_seconds",
      meta: { align: "right", width: COL_W.elapsed },
      cell: ({ row }) => (
        <span className="tabular-nums text-fg-2">
          {fmtDuration(row.original.duration_seconds * 1000)}
        </span>
      ),
    },
    {
      id: "actions",
      header: () => <>Actions<HelpInd id="column.sessions.actions" /></>,
      accessorKey: "total_actions",
      meta: { align: "right", width: COL_W.actions },
      cell: ({ row }) => (
        <span className="tabular-nums text-fg-1">
          {fmtInt(row.original.total_actions)}
        </span>
      ),
    },
    {
      // AI code lines (lines-of-code tracking §3.4). Server-sortable via
      // sort_by=ai_code_lines. There is deliberately NO human column and no
      // share here: with no editor capture the human side is unmeasured
      // rather than zero, and a table cell has no room for the capture
      // caveat that would make either honest. The share lives only where
      // /api/loc/summary supplies human_capture.
      id: "ai_code_lines",
      header: () => (
        <span title="Code lines the agent added or modified. Comments and blank lines are excluded; deleted lines are not included.">
          AI code
          <HelpInd id="column.sessions.ai_code_lines" />
        </span>
      ),
      accessorKey: "ai_code_lines",
      meta: { align: "right", mono: true, width: COL_W.aiCode },
      cell: ({ row }) => {
        // omitempty on the wire: absent means NOT COUNTED, never zero. A
        // session that was never counted is not a session that wrote no
        // code, so it gets a dash and the backfill hint instead of a 0.
        const v = row.original.ai_code_lines;
        if (v === undefined || v === null) {
          return (
            <span
              className="text-fg-4"
              title="No agent code lines recorded: either this session changed no code, or its line counts have not been computed yet. Run `observer backfill --loc` to populate history."
            >
              -
            </span>
          );
        }
        return (
          <span className="tabular-nums text-fg-1">{fmtCompact(v)}</span>
        );
      },
    },
    {
      id: "input",
      header: () => <>Input<HelpInd id="column.sessions.input_tokens" /></>,
      accessorKey: "input_tokens",
      meta: { align: "right", mono: true, width: COL_W.input },
      cell: ({ row }) =>
        row.original.input_tokens > 0 ? (
          <span className="tabular-nums text-fg-1">
            {fmtCompact(row.original.input_tokens)}
          </span>
        ) : (
          <span className="text-fg-4">-</span>
        ),
    },
    {
      id: "cache_r",
      header: () => (
        <>Cache R<HelpInd id="column.sessions.cache_read_tokens" /></>
      ),
      accessorKey: "cache_read_tokens",
      meta: { align: "right", mono: true, width: COL_W.cacheR },
      cell: ({ row }) =>
        row.original.cache_read_tokens > 0 ? (
          <span className="tabular-nums text-fg-1">
            {fmtCompact(row.original.cache_read_tokens)}
          </span>
        ) : (
          <span className="text-fg-4">-</span>
        ),
    },
    {
      id: "cache_w",
      header: () => (
        <>Cache W<HelpInd id="column.sessions.cache_creation_tokens" /></>
      ),
      accessorKey: "cache_creation_tokens",
      meta: { align: "right", mono: true, width: COL_W.cacheW },
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
            <span tabIndex={0} className="cursor-help tabular-nums text-fg-1 focus:outline-none">
              {fmtCompact(total)}
            </span>
          </Tooltip>
        );
      },
    },
    {
      id: "output",
      header: () => <>Output<HelpInd id="column.sessions.output_tokens" /></>,
      accessorKey: "output_tokens",
      meta: { align: "right", mono: true, width: COL_W.output },
      cell: ({ row }) =>
        row.original.output_tokens > 0 ? (
          <span className="tabular-nums text-fg-1">
            {fmtCompact(row.original.output_tokens)}
          </span>
        ) : (
          <span className="text-fg-4">-</span>
        ),
    },
    {
      id: "cost",
      // Only Total $ in the table — API $ + Tool $ live on the
      // SessionDetailPanel's CostStat tile per operator feedback that
      // the Sessions table had too many cost cols. Hover shows the
      // 3-way split as a tooltip so the data isn't hidden.
      header: () => <>Total $<HelpInd id="column.sessions.cost" /></>,
      accessorKey: "cost_usd",
      meta: { align: "right", width: COL_W.cost },
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
              className={`cursor-help font-semibold tabular-nums focus:outline-none ${color}`}
            >
              {fmtUSD(total)}
            </span>
          </Tooltip>
        );
      },
    },
  ];

  if (showScoring) {
    cols.push(
      {
        id: "quality",
        header: () => <>Quality<HelpInd id="column.sessions.quality" /></>,
        accessorFn: (r) => r.quality_score ?? -1,
        meta: { align: "right", width: COL_W.quality },
        cell: ({ row }) =>
          row.original.quality_score != null
            ? fmtPct(row.original.quality_score)
            : "-",
      },
      {
        id: "errors",
        header: () => <>Errors<HelpInd id="column.sessions.errors" /></>,
        accessorFn: (r) => r.error_rate ?? -1,
        meta: { align: "right", width: COL_W.errors },
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
            "-"
          ),
      },
      {
        id: "redundancy",
        header: () => <>Redund.<HelpInd id="column.sessions.redundancy" /></>,
        accessorFn: (r) => r.redundancy_ratio ?? -1,
        meta: { align: "right", width: COL_W.redundancy },
        cell: ({ row }) => {
          const r = row.original;
          if (r.redundancy_ratio == null) return "-";
          // Spec §14.1 wasteful subset rendered as
          // "0.30 (0.20 wasteful)" when present. Sessions
          // without cache_events keep the legacy single value.
          if (r.redundancy_ratio_wasteful != null) {
            return (
              <span title="total / wasteful subset (spec §14.1)">
                {fmtPct(r.redundancy_ratio)}
                <span className="ml-1 text-fg-3">
                  ({fmtPct(r.redundancy_ratio_wasteful)} wasteful)
                </span>
              </span>
            );
          }
          return fmtPct(r.redundancy_ratio);
        },
      },
    );
  }

  return cols;
}

// Format an ISO timestamp as "MMM DD HH:MM" — matches design's
// dim mono treatment for the Started column.
function fmtTimestamp(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("en-US", {
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
  const header = [
    "session_id",
    "tool",
    "project",
    "started_at",
    "duration_seconds",
    "total_actions",
    "sidechain_action_count",
    "input_tokens",
    "cache_read_tokens",
    "cache_creation_tokens",
    "output_tokens",
    "ai_cost_usd",
    "tool_cost_usd",
    "cost_usd",
    "cost_reliability",
  ].join(",");
  const lines = rows.map((r) =>
    [
      escapeCsv(r.id),
      escapeCsv(r.tool),
      escapeCsv(r.project),
      escapeCsv(r.started_at),
      r.duration_seconds,
      r.total_actions,
      r.sidechain_action_count,
      r.input_tokens,
      r.cache_read_tokens,
      r.cache_creation_tokens,
      r.output_tokens,
      r.ai_cost_usd,
      r.tool_cost_usd,
      r.cost_usd,
      escapeCsv(r.cost_reliability),
    ].join(","),
  );
  const blob = new Blob([[header, ...lines].join("\n")], {
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

function escapeCsv(s: string | undefined | null): string {
  if (!s) return "";
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
