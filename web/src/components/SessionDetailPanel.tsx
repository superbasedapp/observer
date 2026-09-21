import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { SlideOver, SurfaceBadge, TabStrip, ToolBadge, TruncatedPath, type TabDef } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { CopyOnClick } from "@/components/CopyOnClick";
import { SessionActionHeader } from "@/components/SessionActionHeader";
import { fetchJSON } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { fmtShortId } from "@/lib/format";
import type {
  SessionDetail,
  SessionMessages,
  SessionRawEvents,
  ToolCallRow,
} from "@/lib/types";
import { CacheTab } from "@/components/sessiondetail/CacheTab";
import { CostTab } from "@/components/sessiondetail/CostTab";
import { KpiBand } from "@/components/sessiondetail/KpiBand";
import { LineageBanner } from "@/components/sessiondetail/LineageBanner";
import { LiveHeroBand } from "@/components/sessiondetail/LiveHeroBand";
import { MessagesTab } from "@/components/sessiondetail/MessagesTab";
import { OverviewTab } from "@/components/sessiondetail/OverviewTab";
import { SessionEnrichmentHeader } from "@/components/sessiondetail/SessionEnrichmentHeader";
import { SystemTab } from "@/components/sessiondetail/SystemTab";
import { TasksTab } from "@/components/sessiondetail/TasksTab";
import {
  DEFAULT_MSG_DIR,
  DEFAULT_MSG_SORT,
  MESSAGES_LIMIT,
  MSG_SORT_LS_KEY,
  RAW_EVENTS_LIMIT,
  loadStoredMsgSort,
  watchFollowEdge,
  type MessageSortKey,
  type SortDir,
} from "@/components/sessiondetail/messagesModel";
import { hasRecordedUsage, sessionRecentlyActive } from "@/components/sessiondetail/shared";

// SessionDetailPanel — right-side slide-over showing one session.
//
// SHELL ONLY. This file used to be 3,760 lines holding every block. It is now
// the shell described in the 2026-08-01 design proposal, step 3: it owns the
// data fetches, the cross-block state (sort / page / watch mode / focused
// message) and the layout — a persistent action header, a KPI band, and five
// tabs. Every block's internals were MOVED VERBATIM into
// `components/sessiondetail/`, not rewritten:
//
//   KPI band + lineage  above the tabs (KpiBand.tsx, LineageBanner.tsx)
//   Overview            OverviewTab.tsx  — action breakdown, token buckets,
//                                          models used, output composition
//   Messages            MessagesTab.tsx  — message timeline + source rows
//                       MessagesTable.tsx  (the table + row internals)
//   Cost & limits       CostTab.tsx      — next-message predictor (which
//                                          already contains the 5h/weekly
//                                          limit gauge) + model-switch forecast
//   Cache               CacheTab.tsx     — cache expiry + cache stats
//   System              SystemTab.tsx    — processes
//
// Panel width is 1680px. Each historical bump unlocked another Messages
// column without horizontal scroll (880 → 1200 → 1400 → 1480 → 1680).

// ----- Tab model ---------------------------------------------------

type TabId = "overview" | "messages" | "cost" | "cache" | "tasks" | "system";

const TAB_IDS: TabId[] = [
  "overview",
  "messages",
  "cost",
  "cache",
  "tasks",
  "system",
];

// TAB_PARAM is the deep-link key. Convention copied from Settings
// (`/settings?section=<id>`): the URL is the source of truth, the default is
// omitted from the URL, and writes use { replace: true } so tab switching
// doesn't fill the back-button history. The proposal asked for
// `?session=…&tab=messages`; this is that.
const TAB_PARAM = "tab";

function isTabId(v: string | null): v is TabId {
  return v != null && (TAB_IDS as string[]).includes(v);
}

export function SessionDetailPanel({
  sessionId,
  open,
  watch = false,
  liveHero = false,
  urlTabState = true,
  zIndex,
  onPinVitals,
  onClose,
  onOpenSession,
  onFilterTag,
  onAnnotationChange,
}: {
  sessionId: string | null;
  open: boolean;
  // liveHero = prepend the four forward-looking "right now" tiles (context
  // window used / % of limit spent / next-turn cost / process·network·memory)
  // above the historical KPI band. Opt-in, because they only earn their space
  // for a session that is still running: the terminal workspace opens the panel
  // for exactly that case, the list pages do not. See LiveHeroBand.tsx.
  liveHero?: boolean;
  // urlTabState = this panel is the one the ROUTE addresses, so the active tab
  // lives in `?tab=` (deep-linkable, back/forward-safe). True for every list
  // page, which opens exactly one panel through its own `?session=`.
  //
  // FALSE for a host that is not route state. `?tab=` is a single slot per
  // route, and a list page keeps its own panel mounted at all times (closed,
  // `open={selected != null}`) with a cleanup effect that DELETES `?tab=`
  // whenever the panel is closed. So a second panel floating over that route —
  // the terminal workspace's session modal, which is opened by terminal token
  // from wherever the operator happens to be — would write `?tab=messages`,
  // have the page's closed panel delete it on the very next commit, and snap
  // straight back to Overview. That was the 2026-08-28 "tabs flip back" defect.
  // Such a panel keeps its tab in local state and never touches the URL.
  urlTabState?: boolean;
  // zIndex raises the whole slide-over above the terminal workspace's overlay
  // stack. Omitted everywhere except the terminal, which is the one host that
  // is itself an overlay — see the SlideOver prop doc.
  zIndex?: number;
  // onPinVitals, when given, offers "Pin vitals panel" alongside the live hero
  // band: this slide-over is 1680px and covers the terminal it was opened from,
  // so the terminal host uses this to hand the operator the small floating
  // cockpit that docks BESIDE the terminal instead. Absent everywhere else.
  onPinVitals?: () => void;
  // watch = open the panel in read-only "watch live" mode: the messages
  // stream tail-follows the newest page, polling faster (4s vs 8s), for
  // bare (non-attachable) live sessions. Poll-based v1 on the existing
  // /messages endpoint — no WS, no after_id cursor (noted follow-up).
  watch?: boolean;
  onClose: () => void;
  // onOpenSession navigates the host page to another session's detail —
  // reused by the codex fork/subagent lineage banner to open a parent or
  // spawned session. Absent → lineage links render non-interactive.
  onOpenSession?: (id: string) => void;
  // onFilterTag lets the host page turn a tag click into a list filter.
  // Absent (Cache/Actions/Live pages) → tag pills render inert.
  onFilterTag?: (tag: string) => void;
  // onAnnotationChange reports the server's post-mutation classification so
  // the host list can update its row without a full refetch.
  onAnnotationChange?: (
    sessionId: string,
    next: { tags: string[]; favorite: boolean; note: string; rating: number },
  ) => void;
}) {
  // watchMode is seeded from the `watch` prop but locally toggleable —
  // "Stop" in the indicator (and "Watch instead" on JumpInButton) flip it
  // without needing a URL round-trip. Re-seeds on prop / session change.
  const [watchMode, setWatchMode] = useState(watch);
  useEffect(() => {
    setWatchMode(watch);
  }, [watch, sessionId]);
  // stickToEdge drives chat-follow etiquette: auto-scroll to the newest
  // message only while the reader is pinned to the followed edge (the bottom
  // under the chronological default, the TOP under a time-descending sort —
  // see watchFollowEdge). Scrolling away releases the stick; scrolling back
  // re-engages it. Reset on session change, when (re)entering watch mode, and
  // on any SORT change — a sort change re-windows the whole timeline (it also
  // resets to page 1), and under follow="none" sorts handleScroll early-returns
  // so the flag would otherwise freeze at whatever it held when the operator
  // left the chronological order and never re-engage on the way back.
  const [stickToEdge, setStickToEdge] = useState(true);

  // ----- Tab state ------------------------------------------------
  //
  // The URL owns the active tab (see TAB_PARAM) for the ONE panel a route
  // addresses through its own `?session=`. The default is derived, not stored:
  // opening in watch mode means the operator came to read the live stream, so
  // Messages is the honest landing tab there; everything else lands on
  // Overview. An explicit ?tab= always wins over both.
  //
  // A panel that is NOT route-addressable keeps its tab in local state instead
  // (urlTabState={false}) — see the prop doc. Both code paths must run their
  // hooks unconditionally, so the URL pair and the local pair are always
  // declared; `urlTabState` only decides which one is read and written.
  const [searchParams, setSearchParams] = useSearchParams();
  const [localTab, setLocalTab] = useState<TabId | null>(null);
  const urlTab = searchParams.get(TAB_PARAM);
  const defaultTab: TabId = watch ? "messages" : "overview";
  const activeTab: TabId = urlTabState
    ? isTabId(urlTab)
      ? urlTab
      : defaultTab
    : (localTab ?? defaultTab);
  const setTab = useCallback(
    (id: TabId) => {
      if (!urlTabState) {
        setLocalTab(id);
        return;
      }
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          // Writing the default would make "no preference" and "chose the
          // default" indistinguishable, and would leave a param behind on
          // every panel open. Same rule Settings uses for ?section=.
          if (id === (watch ? "messages" : "overview")) {
            next.delete(TAB_PARAM);
          } else {
            next.set(TAB_PARAM, id);
          }
          return next;
        },
        { replace: true },
      );
    },
    [urlTabState, setSearchParams, watch],
  );
  // Drop ?tab= when the panel closes. Without this, closing while on the Cache
  // tab leaves a dangling `?tab=cache` on a page with no open panel, and the
  // NEXT session opened would silently land on Cache. Runs as an effect (i.e.
  // in a later commit than the host page's own `?session=` removal) so the two
  // URL writes can't clobber each other.
  //
  // GATED ON urlTabState, which is what makes the cleanup safe now that this
  // panel has more than one host. `?tab=` is route state, and this effect is a
  // blind delete of it — so only the instance that OWNS the route's tab param
  // may run it. A non-owning instance running this would delete a param written
  // by a different, still-open panel (see the prop doc).
  //
  // GUARDED ON hasTabParam, not just on `open`. react-router does not
  // de-duplicate a replace-navigation to an identical URL, and
  // setSearchParams' identity is not contractually stable across renders — an
  // unconditional call here would re-navigate on every mount of every page
  // that renders this panel closed, and could self-retrigger. Once the param
  // is gone hasTabParam is false and the effect is inert.
  const hasTabParam = searchParams.has(TAB_PARAM);
  useEffect(() => {
    if (!urlTabState || open || !hasTabParam) return;
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete(TAB_PARAM);
        return next;
      },
      { replace: true },
    );
  }, [urlTabState, open, hasTabParam, setSearchParams]);

  // ----- Mount policy: lazy-mount, then keep mounted ---------------
  //
  // A tab is mounted the first time it is shown and is NEVER unmounted while
  // the panel stays open — inactive tabs are hidden with `display:none`.
  //
  // WHY NOT CONDITIONAL RENDERING. Every tab except Messages owns its own
  // useApi hook (CacheExpiryCard polls /api/cache/status every 5s;
  // PredictorCard, ForecastWidget, VerbosityCard and ProcessesSection each
  // fetch on mount). useApi keeps its data in component state and resets
  // hasDataRef on unmount, so unmounting a tab would abort its in-flight
  // request, discard its data, and re-fetch with loading=true — a visible
  // reload every time you flick between tabs — plus it would drop
  // ProcessesSection's expanded/poll state and the Messages table's expanded
  // rows. Hiding keeps today's behaviour exactly.
  //
  // WHY NOT MOUNT-EVERYTHING-UP-FRONT. That is literally today's behaviour
  // (one flat scroll), so it would be safe — but it means a panel opened to
  // glance at the cost tile still starts a 5s cache poll and three one-shot
  // fetches. Lazy first mount is strictly LESS work than today and never
  // more; nothing observes a tab that was never opened.
  //
  // The latch itself lives in TabPanel (a ref), not in shell state: it needs no
  // re-render to record "this tab has been seen", and it resets for free
  // because SlideOver unmounts its whole subtree when `open` goes false
  // (AnimatePresence) — so reopening the panel is lazy again.

  // Live-capture refresh while the slide-over is open: 8s on both
  // the detail rollup and the message stream. Calmer than the 2s
  // first-pass cadence — 2s was visibly choppy because every
  // background refetch toggled useApi's loading state, blanking the
  // rendered content. With useApi's silent-refetch tweak in place,
  // 8s gives steady progress without UI churn. Pauses when the tab
  // is hidden via the default visibility gate in useApi.
  // Watch mode polls faster (4s) so the tail stays close to live; the
  // calm 8s cadence remains the default for normal reading.
  const liveRefresh = open
    ? { refreshMs: watchMode ? 4000 : 8000 }
    : undefined;
  const detail = useApi<SessionDetail>(
    sessionId ? `/api/session/${sessionId}` : null,
    undefined,
    [sessionId],
    liveRefresh,
  );
  const [msgPage, setMsgPage] = useState(1);
  // tokenDetail controls per-message token grouping:
  //   - "turn": one message row per user-turn (claudecode msg.ID for
  //     Anthropic, codex turn boundary). Tokens for all model inferences
  //     within a turn are summed into that row.
  //   - "inference": one message row per token_count event (codex
  //     v1.7.24+). Each row carries the per-inference last_token_usage.
  //     For claudecode this is identical to "turn" since the watcher
  //     already emits one row per Anthropic msg_xxx.
  // null = no explicit operator choice yet → derive the default from the
  // tool (see effectiveDetail): codex defaults to "inference" (its
  // per-inference rows are the informative grain — turn collapses them),
  // every other tool defaults to "turn". An explicit toggle pins the
  // choice. Reset to null + page 1 on session navigation.
  const [tokenDetail, setTokenDetail] = useState<"turn" | "inference" | null>(
    null,
  );
  // focusMid is the message a Processes-panel link asked to jump to; the
  // MessagesTable scrolls to + highlights the row with this message_id.
  const [focusMid, setFocusMid] = useState<string | null>(null);
  const [showRawEvents, setShowRawEvents] = useState(false);
  const [rawPage, setRawPage] = useState(1);
  // Messages-table sort. Lifted here (next to msgPage) so it survives the
  // auto-refresh poll and so it can be fed into the request params. Held as
  // one object so the click handler's updater stays pure (a nested setState
  // would double-toggle under StrictMode). Lazy-initialized from
  // localStorage (see loadStoredMsgSort) so a chosen sort survives a page
  // reload, not just a session switch.
  const [msgSort, setMsgSort] = useState<{ by: MessageSortKey; dir: SortDir }>(
    loadStoredMsgSort,
  );
  // Mirror every sort change to storage — a plain effect keyed on the
  // primitive by/dir values, not a write inside onSortMessages' updater, so
  // StrictMode's double-invoke of the updater can't double-write (the effect
  // itself is idempotent: it just reflects whatever msgSort currently is).
  // Storing the default explicitly would make "no stored preference" and
  // "operator picked the default" indistinguishable, so the default removes
  // the key instead of writing it.
  useEffect(() => {
    try {
      if (msgSort.by === DEFAULT_MSG_SORT && msgSort.dir === DEFAULT_MSG_DIR) {
        localStorage.removeItem(MSG_SORT_LS_KEY);
      } else {
        localStorage.setItem(MSG_SORT_LS_KEY, JSON.stringify(msgSort));
      }
    } catch {
      // localStorage unavailable (private mode, quota); the in-memory sort
      // still works for the CURRENT session view, but without storage the
      // session-switch effect below re-reads the (empty) store and falls
      // back to the default — an accepted limitation of storage-less mode.
    }
  }, [msgSort.by, msgSort.dir]);
  // See stickToEdge above: re-arm chat-follow on session / watch-mode / sort
  // change. Declared here because it depends on msgSort.
  useEffect(() => {
    setStickToEdge(true);
  }, [sessionId, watchMode, msgSort.by, msgSort.dir]);
  useEffect(() => {
    setMsgPage(1);
    setTokenDetail(null);
    setFocusMid(null);
    setShowRawEvents(false);
    setRawPage(1);
    // Apply the saved sort (global, not per-session — see loadStoredMsgSort)
    // rather than hardcoded defaults, so switching sessions doesn't discard
    // the operator's chosen order.
    setMsgSort(loadStoredMsgSort());
    // NOTE: the active TAB is deliberately NOT reset here. Following a lineage
    // link from a fork to its parent while reading Messages should land on the
    // parent's Messages, not bounce back to Overview — and resetting would
    // also fight the ?tab= deep link on first open (sessionId goes null → id).
  }, [sessionId]);
  // onSortMessages — click a header: a new column selects it (ascending,
  // except Time which starts descending so "newest first" is one click
  // away); clicking the active column toggles direction. Any change resets
  // to page 1, since the sort re-windows the whole timeline.
  const onSortMessages = useCallback((key: MessageSortKey) => {
    setMsgSort((s) =>
      s.by === key
        ? { by: key, dir: s.dir === "asc" ? "desc" : "asc" }
        : { by: key, dir: key === "timestamp" ? "desc" : "asc" },
    );
    setMsgPage(1);
  }, []);
  const followEdge = watchFollowEdge(msgSort.by, msgSort.dir);
  // Effective grain: an explicit toggle wins; otherwise codex defaults to
  // per-inference, everything else to turn rollup.
  const effectiveDetail: "turn" | "inference" =
    tokenDetail ?? (detail.data?.tool === "codex" ? "inference" : "turn");
  // browserSession gates the chat-bubble rendering of assistant_message /
  // user_prompt rows to browser-captured chat sessions (every browserchat
  // tool — chatgpt-web / claude-web / perplexity-web / gemini-web /
  // copilot-web — ends in "-web"). For those the response text lives in
  // raw_tool_output and IS the on-screen answer to render inline; coding-
  // agent rows keep their existing dense-table rendering untouched.
  const browserSession = (detail.data?.tool ?? "").endsWith("-web");
  const offset = (msgPage - 1) * MESSAGES_LIMIT;
  const messageParams: Record<string, string | number> = {
    limit: MESSAGES_LIMIT,
    offset,
  };
  if (effectiveDetail === "inference") {
    messageParams.detail = "inference";
  }
  // Sort travels with every request (including the auto-refresh poll) so the
  // live stream honours the operator's chosen order. Omitted entirely on the
  // default so the request stays byte-identical to the pre-sort client.
  if (msgSort.by !== DEFAULT_MSG_SORT || msgSort.dir !== DEFAULT_MSG_DIR) {
    messageParams.sort_by = msgSort.by;
    messageParams.sort_dir = msgSort.dir;
  }
  // The messages fetch stays in the SHELL, not in MessagesTab. Two reasons:
  // its `total` feeds the tab-strip count (which must be honest whether or not
  // the Messages tab is on screen), and moving it into a lazily-mounted tab
  // would have changed polling behaviour — which this split does not do.
  const messages = useApi<SessionMessages>(
    sessionId ? `/api/session/${sessionId}/messages` : null,
    messageParams,
    [sessionId, msgPage, effectiveDetail, msgSort.by, msgSort.dir],
    liveRefresh,
  );
  const rawOffset = (rawPage - 1) * RAW_EVENTS_LIMIT;
  const rawEvents = useApi<SessionRawEvents>(
    showRawEvents && sessionId ? `/api/session/${sessionId}/raw-events` : null,
    { limit: RAW_EVENTS_LIMIT, offset: rawOffset },
    [sessionId, showRawEvents, rawPage],
    undefined,
  );

  // onFocusMessage — a Processes-panel msg link: ensure the page containing the
  // message is loaded (the /messages ?locate= override returns its offset),
  // then highlight it. The highlight auto-clears after 3s.
  //
  // CROSS-TAB. Processes now lives on the System tab and the message it links
  // to on the Messages tab, so this also switches tabs — otherwise the link
  // would scroll a table the operator cannot see. The tab switch mounts
  // MessagesTable if it wasn't visited yet; its focus effect keys on focusMid
  // and so fires on that first mount.
  //
  // The probe MUST ask in the same shape as the rendered table, or the offset
  // it returns addresses a page the table never shows: the server resolves
  // ?locate= against its EFFECTIVE (post-sort, post-grain) row list, so a
  // chronological probe under an active sort — or a turn-grain probe while the
  // table is on inference grain — hands back an offset for a different row
  // set, the target row is absent from the page that loads, and the
  // scrollIntoView silently no-ops. Reuse the exact params the table's own
  // request carries, minus offset (locate replaces it).
  const onFocusMessage = useCallback(
    async (mid: string) => {
      if (!sessionId) return;
      setTab("messages");
      const onPage = messages.data?.messages.some((m) => m.message_id === mid);
      if (!onPage) {
        try {
          const sorted =
            msgSort.by !== DEFAULT_MSG_SORT || msgSort.dir !== DEFAULT_MSG_DIR;
          const r = await fetchJSON<SessionMessages>(
            `/api/session/${sessionId}/messages`,
            {
              locate: mid,
              limit: MESSAGES_LIMIT,
              // undefined params are dropped by buildUrl, so the default
              // grain / default sort still send the historical query.
              detail: effectiveDetail === "inference" ? "inference" : undefined,
              sort_by: sorted ? msgSort.by : undefined,
              sort_dir: sorted ? msgSort.dir : undefined,
            },
          );
          setMsgPage(Math.floor((r.offset ?? 0) / MESSAGES_LIMIT) + 1);
        } catch {
          /* ignore — still try to highlight on the current page */
        }
      }
      setFocusMid(mid);
    },
    [sessionId, messages.data, effectiveDetail, msgSort.by, msgSort.dir, setTab],
  );
  useEffect(() => {
    if (!focusMid) return;
    const t = setTimeout(() => setFocusMid(null), 3000);
    return () => clearTimeout(t);
  }, [focusMid]);

  // Tail-follow: in watch mode, keep the messages view pinned to the page new
  // rows land on — but only while the reader is stuck to the followed edge
  // (paginating away releases it). Which page that is depends on the sort:
  // the LAST page under the chronological default, page 1 under a
  // time-descending sort (newest first). Under any other sort a new row's
  // page is unpredictable, so we pin nothing. total is the whole-session
  // count the endpoint returns regardless of the current offset.
  const totalMsgs = messages.data?.total ?? 0;
  const lastMsgPage = Math.max(1, Math.ceil(totalMsgs / MESSAGES_LIMIT));
  const followPage = followEdge === "top" ? 1 : lastMsgPage;
  useEffect(() => {
    if (!watchMode || !stickToEdge || totalMsgs === 0) return;
    if (followEdge === "none") return;
    setMsgPage((p) => (p === followPage ? p : followPage));
  }, [watchMode, stickToEdge, totalMsgs, followPage, followEdge]);

  const onMsgPage = useCallback(
    (p: number) => {
      setMsgPage(p);
      // In watch mode, paginating off the followed page releases the
      // tail-follow stick; landing back on it re-engages. The followed page is
      // page 1 under a time-descending sort.
      if (watchMode) {
        setStickToEdge(followEdge === "top" ? p === 1 : p >= lastMsgPage);
      }
    },
    [watchMode, followEdge, lastMsgPage],
  );

  const d = detail.data;
  const tabs: TabDef<TabId>[] = useMemo(
    () => [
      { id: "overview", label: "Overview" },
      {
        id: "messages",
        label: "Messages",
        count: messages.data ? messages.data.total : null,
      },
      { id: "cost", label: "Cost & limits" },
      { id: "cache", label: "Cache" },
      { id: "tasks", label: "Tasks" },
      { id: "system", label: "System" },
    ],
    [messages.data],
  );

  return (
    <SlideOver
      open={open}
      onClose={onClose}
      width={1680}
      zIndex={zIndex}
      title={
        d ? (
          <span className="flex items-center gap-2">
            <ToolBadge tool={d.tool} />
            {/* Capture surface (migration 107). Renders nothing when the
                session carries no stamp — absence is UNKNOWN, never "cli". */}
            <SurfaceBadge surface={d.surface} host={d.surface_host} />
            {/* Captured tool/CLI version (migration 125). Rendered only
                when stamped — absence is UNKNOWN, never a fabricated
                version. */}
            {d.tool_version ? (
              <span className="font-mono text-[11px] text-fg-3" title="Tool version">
                v{d.tool_version}
              </span>
            ) : null}
            <CopyOnClick
              value={d.id}
              className="font-mono text-[12px] text-fg-2"
            >
              {d.id.slice(0, 8)}…{d.id.slice(-4)}
            </CopyOnClick>
          </span>
        ) : sessionId ? (
          <span className="font-mono text-[12px] text-fg-3" title={sessionId}>
            {fmtShortId(sessionId, 8)}
          </span>
        ) : (
          "Session detail"
        )
      }
      subtitle={
        d?.project ? (
          <TruncatedPath value={d.project} className="text-[11.5px]" />
        ) : undefined
      }
    >
      <div className="px-5 pb-5 pt-3">
        <ChartState
          loading={detail.loading && !detail.data}
          error={detail.error}
          empty={!detail.data}
          emptyHint="Loading session…"
          height={120}
        >
          {d && (
            <>
              {/* ALWAYS VISIBLE, above the tabs. The action strip: annotation
                  chips + the three session verbs (Jump in / Resume / Continue
                  in…). The KPI band and the lineage banner join it here —
                  lineage is a fact about the session's IDENTITY (this run is a
                  fork / has subagents), so putting it behind a tab would make
                  it discoverable only by accident. The design proposal's
                  mapping table omitted this block entirely; above-the-tabs is
                  the call this implementation made. */}
              <div className="space-y-5">
                {/* Cloud-enrichment title + description at the very top — the
                    "what was this session about" summary. Collapses when the
                    session has no enrichment result. */}
                <SessionEnrichmentHeader sessionId={d.id} />
                <SessionActionHeader
                  d={d}
                  watchable={watch === true || sessionRecentlyActive(d)}
                  onWatch={() => setWatchMode(true)}
                  onFilterTag={onFilterTag}
                  onAnnotationChange={onAnnotationChange}
                />
                <LineageBanner d={d} onOpenSession={onOpenSession} />
                {/* Forward-looking band FIRST when the panel was opened from a
                    live terminal: on a running session "how much room is left
                    and what does the next message cost" outranks the totals. */}
                {liveHero && (
                  <LiveHeroBand
                    sessionId={d.id}
                    detail={d}
                    onPinVitals={onPinVitals}
                  />
                )}
                <KpiBand d={d} />
                {(!hasRecordedUsage(d) || d.tokens_note) && (
                  <p role="note" className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3 text-[11.5px] text-fg-2">
                    {d.tokens_note ?? "Token usage was not captured. Token counts and cost are unknown, not zero."}
                  </p>
                )}
              </div>
            </>
          )}
        </ChartState>

        {/* The tab strip and every panel sit OUTSIDE the detail ChartState on
            purpose. Messages and Processes always rendered from their OWN
            endpoints before the split — they were visible even when
            /api/session/<id> was still loading or had errored. Putting the
            strip inside the ChartState would have made them unreachable in
            exactly that case (no strip → no way to select the tab), which is
            dropping a block in an error state. The three detail-derived tabs
            gate on `d` individually instead; the ChartState above is still the
            one place that reports the detail load / error. */}
        <TabStrip
          tabs={tabs}
          value={activeTab}
          onChange={setTab}
          idPrefix="sessdetail"
          className="mt-5"
        />

        {/* Each panel mounts on first visit and then stays mounted, hidden
            with `hidden` (display:none). See the mount-policy note above —
            unmounting would abort in-flight fetches and restart polling on
            every tab flick. */}
        <TabPanel id="overview" active={activeTab}>
          {d && <OverviewTab d={d} />}
        </TabPanel>
        <TabPanel id="cost" active={activeTab}>
          {d && <CostTab d={d} />}
        </TabPanel>
        <TabPanel id="cache" active={activeTab}>
          {d && <CacheTab d={d} />}
        </TabPanel>
        <TabPanel id="tasks" active={activeTab}>
          {d && <TasksTab d={d} />}
        </TabPanel>
        <TabPanel id="messages" active={activeTab}>
          <MessagesTab
            tool={d?.tool}
            messages={messages}
            watchMode={watchMode}
            onStopWatch={() => setWatchMode(false)}
            effectiveDetail={effectiveDetail}
            onTokenDetail={setTokenDetail}
            browserSession={browserSession}
            focusMid={focusMid}
            stickToEdge={stickToEdge}
            onStickChange={setStickToEdge}
            followEdge={followEdge}
            sortBy={msgSort.by}
            sortDir={msgSort.dir}
            onSort={onSortMessages}
            msgPage={msgPage}
            onMsgPage={onMsgPage}
            raw={{
              open: showRawEvents,
              onToggle: () => {
                setShowRawEvents((v) => !v);
                setRawPage(1);
              },
              data: rawEvents.data,
              loading: rawEvents.loading,
              error: rawEvents.error,
              page: rawPage,
              onPage: setRawPage,
            }}
          />
        </TabPanel>
        <TabPanel id="system" active={activeTab}>
          <SystemTab sessionId={sessionId} onFocusMessage={onFocusMessage} />
        </TabPanel>
      </div>
    </SlideOver>
  );
}

// TabPanel renders nothing until its tab has been visited once, then keeps its
// subtree mounted forever (hidden when inactive). `hidden` is a Tailwind
// display:none — React keeps the DOM and all component state, so useApi data,
// in-flight requests, expanded rows and scroll positions all survive a tab
// switch. Effects still run while hidden; the only measurable consequence is
// that a scrollIntoView against a display:none node no-ops, which is why
// cross-tab focus (Processes → Messages) switches the tab BEFORE setting
// focusMid rather than after.
function TabPanel({
  id,
  active,
  children,
}: {
  id: TabId;
  active: TabId;
  children: React.ReactNode;
}) {
  const isActive = id === active;
  // Monotonic mount latch: flips true the first time this tab is selected and
  // never flips back for the life of the panel.
  const mountedRef = useRef(false);
  if (isActive) mountedRef.current = true;
  if (!mountedRef.current) return null;
  return (
    <div
      id={`sessdetail-panel-${id}`}
      role="tabpanel"
      aria-labelledby={`sessdetail-tab-${id}`}
      // Both the attribute and the utility class: the attribute keeps the
      // panel out of the accessibility tree, the class guarantees display:none
      // regardless of any base-layer rule that might set `display` on a div.
      hidden={!isActive}
      className={isActive ? "mt-5" : "hidden"}
    >
      {children}
    </div>
  );
}

// Re-export `ToolCallRow` so its type is preserved if consumers need it.
export type { ToolCallRow };
