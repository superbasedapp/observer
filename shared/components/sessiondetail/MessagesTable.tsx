import {
  Fragment,
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { AnimatePresence, motion } from "framer-motion";
import { createPortal } from "react-dom";
import clsx from "clsx";
import { CopyOnClick, Pill, Tooltip } from "../../primitives";
import { actionMeta, mcpIdentity } from "../../lib/actions";
import { fmtClock, fmtCompact, fmtDuration, fmtInt } from "../../lib/format";
import type {
  ActionFullText,
  ExtraMessageColumn,
  MessageRowLike as MessageRow,
  ToolCallRowLike as ToolCallRow,
} from "../../lib/types";
import {
  DEFAULT_MSG_DIR,
  DEFAULT_MSG_SORT,
  MESSAGE_COLUMNS,
  messageRowKey,
  messageTableMinWidth,
  visibleExtraColumnIds,
  type MessageColumn,
  type MessageColumnPreset,
  type MessageSortKey,
  type SortDir,
} from "../../lib/messagesModel";
import { truncate } from "../../lib/sessionElapsed";
import { defaultRenderCost, type RenderCost } from "./cost";

// MessagesTable and its row internals (tool-call expander, diff view, browser
// chat bubbles, full-text modal). Promoted into the shared design system so
// the node (web/) and org (web2/) session-detail Messages tables share one
// implementation.
//
// The one app-coupling this component had — an /api/action/<id>/full_text
// fetch — is now injected via the `fetchFullText` prop. The node passes a
// fetchJSON-backed callback (its behaviour byte-for-byte unchanged); the org
// passes an audited-tool-bodies-backed callback, or omits it, in which case
// the expand/copy/view affordances render an honest "full text not available
// here" state instead of fetching. Two further slots keep it app-agnostic:
// `renderCost` renders the three cost columns (default: the node's fmtUSD), so
// the org can render tokens/percent through its <Money> formatter; and
// `renderRowBody` mounts arbitrary content (the org's audited-disclosure
// blocks) beneath a message row.

// FetchFullText resolves the untruncated body for one action, keyed by its id
// as a string (the node coerces its numeric action_id). Absent = no fetch: the
// affordances degrade to an honest unavailable state.
export type FetchFullText = (actionId: string) => Promise<ActionFullText>;

// RenderCost / defaultRenderCost are re-exported from ./cost so callers that
// import them alongside MessagesTable have one entry point.
export type { RenderCost } from "./cost";

// ----- Messages table ---------------------------------------------

// tokensPerSec is OUTPUT tokens per second: the turn's output_tokens
// divided by its elapsed time. Only output tokens count (input / cache
// tokens are not generated, so they don't belong in a generation-rate).
// Returns null when there's no output or no/zero timing (don't fabricate
// a rate).
// tokensPerSec is OUTPUT tokens per second. The denominator (tps_ms) is
// chosen server-side from the best available timing source — proxy
// measured response time, codex intra-turn span, or the gap-to-next
// fallback — and is absent when none applies (then we show "—").
function tokensPerSec(m: MessageRow): number | null {
  if (m.output <= 0 || m.tps_ms == null || m.tps_ms <= 0) return null;
  return m.output / (m.tps_ms / 1000);
}

// tpsBasisLabel describes which timing source backed a Tok/s value, for
// the column's tooltip.
function tpsBasisLabel(basis: MessageRow["tps_basis"]): string {
  switch (basis) {
    case "measured":
      return "measured response time (proxy)";
    case "intra-turn":
      return "intra-turn generation span";
    default:
      return "elapsed (to next message)";
  }
}

// fmtTps keeps one decimal under 10 tok/s (where precision matters) and
// rounds to a whole number above it, suffixed "/s".
function fmtTps(tps: number): string {
  return `${tps >= 10 ? Math.round(tps).toString() : tps.toFixed(1)}/s`;
}

// msgTokens is the token count behind a message's cost figure: net input +
// output + cache read + cache write. Passed to renderCost as `ctx.tokens` so
// the org's <Money> renderer keeps its token link in tokens display mode; the
// node's default renderer ignores it.
function msgTokens(m: MessageRow): number {
  return m.input + m.output + m.cache_read + m.cache_creation;
}

// SortableTh renders one Messages-table header as a control: clickable and
// keyboard-operable (Enter / Space), carrying the DataTable indicator
// convention (↑ active-ascending, ↓ active-descending, · inactive) and
// aria-sort for assistive tech. A tooltip-bearing column keeps its tooltip by
// wrapping the raw <th> — Tooltip clones its child, so it must stay a DOM
// element rather than this component.
function SortableTh({
  col,
  active,
  dir,
  onSort,
}: {
  col: (typeof MESSAGE_COLUMNS)[number];
  active: boolean;
  dir: SortDir;
  onSort: (key: MessageSortKey) => void;
}) {
  const indicator = active ? (dir === "asc" ? "↑" : "↓") : "·";
  const hint = `Sort by ${col.label}${
    active ? (dir === "asc" ? " (ascending)" : " (descending)") : ""
  }`;
  const th = (
    <th
      tabIndex={0}
      aria-sort={active ? (dir === "asc" ? "ascending" : "descending") : "none"}
      // A tooltip-bearing column gets the hint through the Tooltip below; the
      // native title= would fire a SECOND, overlapping popup on hover.
      title={col.tooltip ? undefined : hint}
      onClick={() => onSort(col.key)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSort(col.key);
        }
      }}
      className={clsx(
        "cursor-pointer select-none py-1.5 font-medium hover:text-fg-1 focus:outline-none",
        col.right && "text-right",
        col.className,
      )}
    >
      {col.label}
      <span className="ml-1 text-fg-4">{indicator}</span>
    </th>
  );
  if (!col.tooltip) return th;
  return (
    <Tooltip
      content={
        <>
          {col.tooltip}
          <span className="mt-1 block text-fg-3">{hint}.</span>
        </>
      }
      maxWidth={col.tooltipMaxWidth}
    >
      {th}
    </Tooltip>
  );
}

// ExtraTh renders one app-supplied extra column header. It mirrors SortableTh's
// sort affordance (clickable + keyboard-operable + the ↑/↓/· indicator + aria-
// sort) when the column declares a `sortKey` and an onSort handler is present;
// otherwise it is a plain, non-interactive header. The label is the column's
// `header` node verbatim.
function ExtraTh({
  col,
  active,
  dir,
  onSort,
}: {
  col: ExtraMessageColumn;
  active: boolean;
  dir: SortDir;
  onSort?: (key: MessageSortKey) => void;
}) {
  const sortable = col.sortKey != null && onSort != null;
  const indicator =
    col.sortKey != null ? (active ? (dir === "asc" ? "↑" : "↓") : "·") : null;
  return (
    <th
      tabIndex={sortable ? 0 : undefined}
      aria-sort={
        col.sortKey != null
          ? active
            ? dir === "asc"
              ? "ascending"
              : "descending"
            : "none"
          : undefined
      }
      onClick={sortable ? () => onSort?.(col.sortKey as MessageSortKey) : undefined}
      onKeyDown={
        sortable
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onSort?.(col.sortKey as MessageSortKey);
              }
            }
          : undefined
      }
      className={clsx(
        "py-1.5 font-medium",
        sortable &&
          "cursor-pointer select-none hover:text-fg-1 focus:outline-none",
      )}
    >
      {col.header}
      {indicator ? <span className="ml-1 text-fg-4">{indicator}</span> : null}
    </th>
  );
}

// CellCtx is everything a cell renderer may read: the row, the two row-level
// flags the expander needs, and the injected cost renderer.
type CellCtx = {
  m: MessageRow;
  isOpen: boolean;
  hasToolCalls: boolean;
  renderCost: RenderCost;
};

// MESSAGE_CELLS renders one <td> per column key. It exists because column
// presets made the old shape unsafe: the header was driven by MESSAGE_COLUMNS
// while the body was seventeen hand-ordered <td>s, so hiding a column would
// have had to hide "the Nth cell" — an index correspondence nothing enforced.
// Keyed renderers make header and body derive from the SAME table, so they
// cannot drift and a preset is a filter over one list rather than two.
// The cell bodies are the pre-preset markup verbatim, classNames included.
const MESSAGE_CELLS: Record<MessageSortKey, (c: CellCtx) => ReactNode> = {
  // Chronological ordinal from the server — NOT the page index, which would
  // renumber under a non-default sort.
  seq: ({ m }) => <td className="py-1 pl-3 tabular-nums text-fg-3">{m.seq}</td>,
  timestamp: ({ m }) => (
    <td className="py-1 whitespace-nowrap tabular-nums text-fg-2" title={m.timestamp}>
      {fmtClock(m.timestamp)}
    </td>
  ),
  message_id: ({ m }) => (
    <td className="py-1 font-mono text-[10.5px]">
      {m.message_id ? (
        <CopyOnClick
          value={m.message_id}
          className="text-accent hover:text-accent-strong"
        >
          {m.message_id.slice(0, 10)}…
        </CopyOnClick>
      ) : (
        <span className="text-fg-4">-</span>
      )}
    </td>
  ),
  role: ({ m }) => (
    <td className="py-1">
      <RolePill role={m.role} />
    </td>
  ),
  account: ({ m }) => (
    <td className="max-w-[230px] py-1 text-fg-2">
      <Tooltip content={<div className="space-y-1">
        <p>{m.account?.status === "conflict" ? "Different logins were observed for this message." : "Login observed at capture time; provider billing identity is unconfirmed."}</p>
        {(m.account?.evidence ?? []).map((e, i) => <p key={i} className="break-all">{e.email || e.name || e.account_id} · {e.source} · {e.stage} · {e.observed_at}</p>)}
        {(!m.account || m.account.status === "unknown") && <p>No account evidence with an exact message match.</p>}
      </div>} maxWidth={440}>
        <span tabIndex={0} className="block truncate cursor-help">{m.account?.label || "Unknown"}</span>
      </Tooltip>
    </td>
  ),
  model: ({ m }) => (
    <td className="max-w-[160px] py-1 font-mono text-fg-2">
      <div className="flex items-center gap-1">
        {m.model ? (
          <Tooltip
            content={<span className="break-all font-mono">{m.model}</span>}
            maxWidth={360}
          >
            <span
              tabIndex={0}
              className="block max-w-[120px] truncate cursor-help focus:outline-none"
            >
              {m.model}
            </span>
          </Tooltip>
        ) : (
          "-"
        )}
        {m.fast && (
          <Tooltip
            content={
              <span>
                Served in the provider's low-latency fast tier -
                Anthropic Opus 4.8 (<code>speed:&quot;fast&quot;</code>) or
                OpenAI/Codex (<code>service_tier:&quot;priority&quot;</code>).
                Billed at the model's fast-mode premium (Opus 4.8 &amp;
                gpt-5.4 2×, gpt-5.5 2.5×).
              </span>
            }
            maxWidth={320}
          >
            <span tabIndex={0} className="shrink-0 cursor-help focus:outline-none">
              <Pill variant="info" title="fast tier (premium price)">
                ⚡ fast
              </Pill>
            </span>
          </Tooltip>
        )}
        {m.service_tier &&
          !["standard", "default", "auto"].includes(m.service_tier) && (
            <Pill variant="accent" title="requested/served processing tier">
              {m.service_tier}
            </Pill>
          )}
        {m.stop_reason && (
          <Pill
            // Show every turn's stop_reason; routine completions
            // (end_turn / tool_use) stay subdued (neutral) while
            // abnormal ends (max_tokens / refusal / stop_sequence
            // / pause_turn) stand out in warn.
            variant={
              m.stop_reason === "end_turn" || m.stop_reason === "tool_use"
                ? "neutral"
                : "warn"
            }
            title="how this turn ended (stop_reason)"
          >
            {m.stop_reason}
          </Pill>
        )}
      </div>
    </td>
  ),
  effort_level: ({ m }) => (
    <td className="py-1 text-fg-2">
      {m.effort_level ? (
        <span className="font-mono text-[10.5px] uppercase tracking-tight">
          {m.effort_level}
        </span>
      ) : (
        <span className="text-fg-4">-</span>
      )}
    </td>
  ),
  input: ({ m }) => (
    <td className="py-1 text-right tabular-nums text-fg-2">
      {m.input > 0 ? fmtCompact(m.input) : "-"}
    </td>
  ),
  cache_read: ({ m }) => (
    <td className="py-1 text-right tabular-nums text-fg-2">
      {m.cache_read > 0 ? fmtCompact(m.cache_read) : "-"}
    </td>
  ),
  cache_creation: ({ m }) => (
    <td className="py-1 text-right tabular-nums text-fg-2">
      {m.cache_creation > 0 ? fmtCompact(m.cache_creation) : "-"}
    </td>
  ),
  output: ({ m }) => (
    <td className="py-1 text-right tabular-nums text-fg-2">
      {m.output > 0 ? fmtCompact(m.output) : "-"}
    </td>
  ),
  elapsed_ms: ({ m }) => (
    <td className="py-1 text-right tabular-nums text-fg-3">
      {m.elapsed_ms != null ? fmtDuration(m.elapsed_ms) : "-"}
    </td>
  ),
  tokens_per_sec: ({ m }) => {
    const tps = tokensPerSec(m);
    return (
      <td className="py-1 text-right tabular-nums text-fg-3">
        {tps != null ? (
          <Tooltip
            content={`${fmtInt(m.output)} output tokens over ${fmtDuration(
              m.tps_ms ?? 0,
            )} ${tpsBasisLabel(m.tps_basis)}`}
          >
            <span tabIndex={0} className="cursor-help focus:outline-none">
              {fmtTps(tps)}
            </span>
          </Tooltip>
        ) : (
          "-"
        )}
      </td>
    );
  },
  // Tools cell. When the expandable tool_calls array is present, the count is
  // an active expander (chevron reflects open state). When only a projected
  // tool_call_count is shipped (the org has no per-message tool_calls array),
  // the count still renders but the chevron is DISABLED with a "tool calls not
  // shipped" tooltip — the count is honest, the expansion just isn't available
  // on that surface. Zero / absent renders "-".
  tool_call_count: ({ m, isOpen, hasToolCalls }) => {
    const count = m.tool_call_count ?? 0;
    if (hasToolCalls) {
      return (
        <td className="py-1 text-right tabular-nums text-fg-2">
          <Tooltip content="Click row to expand tool calls">
            <span
              tabIndex={0}
              className="inline-flex cursor-help items-center gap-1 focus:outline-none"
            >
              {fmtInt(count)}
              <Caret open={isOpen} />
            </span>
          </Tooltip>
        </td>
      );
    }
    if (count > 0) {
      return (
        <td className="py-1 text-right tabular-nums text-fg-2">
          <Tooltip content="tool calls not shipped">
            <span
              tabIndex={0}
              className="inline-flex cursor-help items-center gap-1 text-fg-3 focus:outline-none"
            >
              {fmtInt(count)}
              <Caret open={false} disabled />
            </span>
          </Tooltip>
        </td>
      );
    }
    return <td className="py-1 text-right tabular-nums text-fg-2">-</td>;
  },
  ai_cost_usd: ({ m, renderCost }) => (
    <td className="py-1 text-right tabular-nums text-fg-1">
      {m.ai_cost_usd > 0
        ? renderCost(m.ai_cost_usd, { kind: "api", tokens: msgTokens(m) })
        : "-"}
    </td>
  ),
  tool_cost_usd: ({ m, renderCost }) => (
    <td className="py-1 text-right tabular-nums text-fg-3">
      {m.tool_cost_usd > 0 ? renderCost(m.tool_cost_usd, { kind: "tool" }) : "-"}
    </td>
  ),
  cost_usd: ({ m, renderCost }) => (
    <td className="py-1 text-right tabular-nums text-fg-0">
      {m.cost_usd > 0 ? (
        <span className="font-semibold">
          {renderCost(m.cost_usd, { kind: "total", tokens: msgTokens(m) })}
        </span>
      ) : (
        "-"
      )}
    </td>
  ),
  content: ({ m }) => (
    <td className="max-w-[320px] truncate py-1 pl-3 pr-3 text-fg-2">
      <ContentSnippet row={m} />
    </td>
  ),
};

export function MessagesTable({
  rows,
  columns = MESSAGE_COLUMNS,
  extraColumns,
  preset,
  focusMid,
  browser = false,
  watch = false,
  stick = true,
  onStickChange,
  follow = "bottom",
  sortBy = DEFAULT_MSG_SORT,
  sortDir = DEFAULT_MSG_DIR,
  onSort,
  fetchFullText,
  renderCost = defaultRenderCost,
  renderRowBody,
  expandedKeys,
  onToggleRow,
}: {
  rows: MessageRow[];
  // columns = the visible column set, already resolved from the operator's
  // preset (see messagesModel.visibleMessageColumns). Defaults to the full
  // table so this component stays drop-in for any caller that doesn't care.
  columns?: MessageColumn[];
  // extraColumns are app-supplied columns rendered AFTER the built-in columns
  // and BEFORE the Content column (the org's Src / Reasoning / TTFB / tool-
  // count columns). Each participates in preset visibility via `preset` below
  // (visibleExtraColumnIds); absent => only the built-in columns render.
  extraColumns?: ExtraMessageColumn[];
  // preset is the active column preset, used ONLY to decide which extraColumns
  // are visible (the built-in `columns` are already preset-resolved by the
  // caller). Absent => extraColumns are all shown (treated as the "all" view).
  preset?: MessageColumnPreset;
  focusMid?: string | null;
  // browser = the session is a browser-captured chat (browserchat *-web
  // tool). Turns on the chat-bubble rendering of user_prompt /
  // assistant_message rows in the expander. Absent/false for every
  // coding-agent session → rendering is unchanged.
  browser?: boolean;
  // watch = read-only tail-follow mode. Caps the table in a vertical
  // scroll region and auto-pins to the newest row while `stick`; reports
  // scroll-position changes back via onStickChange.
  watch?: boolean;
  stick?: boolean;
  onStickChange?: (atEdge: boolean) => void;
  // follow names which edge live watch-mode tracks under the active sort:
  // "bottom" (chronological ascending — newest last), "top" (chronological
  // descending — newest first), or "none" (any other sort, where a new row's
  // position is unpredictable and yanking the viewport would be hostile).
  follow?: "bottom" | "top" | "none";
  sortBy?: MessageSortKey;
  sortDir?: SortDir;
  onSort?: (key: MessageSortKey) => void;
  // fetchFullText resolves the untruncated body for one action's copy / view /
  // change affordances. Absent → those affordances render an honest
  // "full text not available here" state instead of fetching.
  fetchFullText?: FetchFullText;
  // renderCost renders the three cost columns; default is the node's fmtUSD.
  renderCost?: RenderCost;
  // renderRowBody mounts arbitrary content beneath a message row (the org's
  // audited-disclosure blocks). Return null/undefined to render nothing.
  renderRowBody?: (row: MessageRow) => ReactNode;
  // expandedKeys / onToggleRow make per-row expansion CONTROLLED. When
  // expandedKeys is provided the component reads each row's open state from it
  // and calls onToggleRow(key) on a toggle instead of mutating its internal
  // map — so a caller can share ONE expansion state between the built-in
  // tool-call expander (the Tools chevron / row click) and its own row-level
  // disclosure (the org's audited-content chip + renderRowBody). Keys are
  // messageRowKey(row) (message_id, else `seq-<n>`), the same rule the internal
  // state uses, exported so a caller need not duplicate it. Omit both props to
  // keep the internal uncontrolled state — the node's behaviour, byte-for-byte
  // unchanged.
  expandedKeys?: Set<string>;
  onToggleRow?: (key: string) => void;
}) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  // Controlled when the caller supplies expandedKeys; otherwise the internal
  // `expanded` map owns row-open state (uncontrolled — the node path).
  const controlled = expandedKeys != null;
  const toggleRow = useCallback(
    (key: string) => {
      if (controlled) onToggleRow?.(key);
      else setExpanded((s) => ({ ...s, [key]: !s[key] }));
    },
    [controlled, onToggleRow],
  );
  const scrollRef = useRef<HTMLDivElement | null>(null);
  // Scroll the focused message into view once it (and its page) are present.
  useEffect(() => {
    if (!focusMid) return;
    const el = document.getElementById(`msg-row-${focusMid}`);
    el?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [focusMid, rows]);
  // Chat-follow: after each rows update, if watching and stuck to the
  // followed edge, pin the scroll container to the newest message — the
  // BOTTOM under the chronological default, the TOP under a time-descending
  // sort. follow="none" (any non-chronological sort) never force-scrolls.
  useEffect(() => {
    if (!watch || !stick || follow === "none") return;
    const el = scrollRef.current;
    if (el) el.scrollTop = follow === "top" ? 0 : el.scrollHeight;
  }, [rows, watch, stick, follow]);
  function handleScroll() {
    if (!watch || follow === "none") return;
    const el = scrollRef.current;
    if (!el) return;
    // 40px slack so a near-edge position still counts as "stuck".
    const atEdge =
      follow === "top"
        ? el.scrollTop < 40
        : el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    onStickChange?.(atEdge);
  }
  // Split the built-in columns at the Content column so any extra columns land
  // AFTER the built-ins and BEFORE Content. When there is no Content column
  // (a custom `columns` set), extras go last.
  const contentIdx = columns.findIndex((c) => c.key === "content");
  const headCols = contentIdx >= 0 ? columns.slice(0, contentIdx) : columns;
  const tailCols = contentIdx >= 0 ? columns.slice(contentIdx) : [];
  // Which extra columns are visible under the active preset (an active-sort
  // extra column is never hidden; preset undefined => the "all" view).
  const shownExtra: ExtraMessageColumn[] = extraColumns?.length
    ? (() => {
        const ids = visibleExtraColumnIds(
          preset ?? "all",
          sortBy,
          extraColumns,
        );
        return extraColumns.filter((c) => ids.has(c.id));
      })()
    : [];
  // Column count spanned by the tool-call expander + row-body rows, and the px
  // budget the extra columns add to the table min-width.
  const totalCols = columns.length + shownExtra.length;
  const extraMinWidth = shownExtra.reduce((n, c) => n + (c.width ?? 90), 0);
  return (
    <div
      ref={scrollRef}
      onScroll={watch ? handleScroll : undefined}
      className={clsx(
        "overflow-x-auto rounded-2 border border-line-1",
        watch && "max-h-[60vh] overflow-y-auto",
      )}
    >
      {/* min-width follows the VISIBLE columns (1460px for All, ~734px for
          the default preset) so a narrow preset actually buys back the
          horizontal scroll instead of only hiding ink. */}
      <table
        className="w-full text-left text-[11px]"
        style={{ minWidth: messageTableMinWidth(columns) + extraMinWidth }}
      >
        <thead className="bg-bg-3/40 text-[10px] uppercase tracking-[0.06em] text-fg-3">
          <tr className="whitespace-nowrap border-b border-line-2">
            {headCols.map((col) => (
              <SortableTh
                key={col.key}
                col={col}
                active={sortBy === col.key}
                dir={sortDir}
                onSort={onSort ?? (() => {})}
              />
            ))}
            {shownExtra.map((ec) => (
              <ExtraTh
                key={`x-${ec.id}`}
                col={ec}
                active={ec.sortKey != null && sortBy === ec.sortKey}
                dir={sortDir}
                onSort={onSort}
              />
            ))}
            {tailCols.map((col) => (
              <SortableTh
                key={col.key}
                col={col}
                active={sortBy === col.key}
                dir={sortDir}
                onSort={onSort ?? (() => {})}
              />
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((m) => {
            // Key on row IDENTITY, never on the page index: expansion state is
            // keyed by this, and an index-derived key hands one row's expanded
            // state to whatever row later occupies that slot — which reordering
            // (sort, page, live poll) now does routinely. messageRowKey is the
            // shared rule (message_id, else the server's whole-timeline `seq`
            // ordinal), so a controlled caller keys off exactly the same value.
            const key = messageRowKey(m);
            const isOpen = expandedKeys ? expandedKeys.has(key) : !!expanded[key];
            const hasToolCalls = (m.tool_calls?.length ?? 0) > 0;
            const rowBody = renderRowBody?.(m);
            return (
              <Fragment key={key}>
                <tr
                  id={m.message_id ? `msg-row-${m.message_id}` : undefined}
                  className={clsx(
                    "whitespace-nowrap border-b border-line-1 last:border-b-0",
                    hasToolCalls && "cursor-pointer hover:bg-bg-3/40",
                    focusMid &&
                      m.message_id === focusMid &&
                      "bg-accent-soft/40 ring-2 ring-inset ring-accent-ring",
                  )}
                  onClick={() => hasToolCalls && toggleRow(key)}
                >
                  {/* One <td> per VISIBLE column, in the same table order as
                      the header above — both driven by `columns` + `shownExtra`
                      split at Content, so a preset can never desynchronise
                      header and body. */}
                  {headCols.map((col) => (
                    <Fragment key={col.key}>
                      {MESSAGE_CELLS[col.key]({ m, isOpen, hasToolCalls, renderCost })}
                    </Fragment>
                  ))}
                  {shownExtra.map((ec) => (
                    <td key={`x-${ec.id}`} className="py-1 align-top text-fg-2">
                      {ec.render(m)}
                    </td>
                  ))}
                  {tailCols.map((col) => (
                    <Fragment key={col.key}>
                      {MESSAGE_CELLS[col.key]({ m, isOpen, hasToolCalls, renderCost })}
                    </Fragment>
                  ))}
                </tr>
                {isOpen && m.tool_calls && m.tool_calls.length > 0 && (
                  <tr className="bg-bg-1">
                    {/* Spans the VISIBLE columns — a hard 17 would overflow
                        the row under any preset. */}
                    <td colSpan={totalCols} className="px-3 py-2 pl-[50px]">
                      <div className="flex flex-col gap-1.5">
                        {m.tool_calls.map((tc, j) => (
                          <ToolCallRowView
                            key={`${key}-tc-${j}`}
                            tc={tc}
                            browser={browser}
                            fetchFullText={fetchFullText}
                          />
                        ))}
                      </div>
                    </td>
                  </tr>
                )}
                {rowBody != null && rowBody !== false && (
                  <tr className="bg-bg-1">
                    <td colSpan={totalCols} className="px-3 py-2">
                      {rowBody}
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// useActionFullText caches the on-demand full-text fetch per action_id within a
// single row's lifetime. The cache is a ref (not state) because we only want
// the cached value to influence what gets copied, never to trigger re-renders.
// The fetch itself is INJECTED (fetchFullText) rather than hard-wired to a node
// endpoint; when it is absent `available` is false and fetchOnce rejects, so
// callers show an honest "not available here" state.
function useActionFullText(actionId: number, fetchFullText?: FetchFullText) {
  const cacheRef = useRef<ActionFullText | null>(null);
  const inflightRef = useRef<Promise<ActionFullText> | null>(null);

  const fetchOnce = useCallback(async (): Promise<ActionFullText> => {
    if (!fetchFullText) throw new Error("full text not available here");
    if (cacheRef.current) return cacheRef.current;
    if (inflightRef.current) return inflightRef.current;
    const p = fetchFullText(String(actionId))
      .then((v) => {
        cacheRef.current = v;
        return v;
      })
      .finally(() => {
        inflightRef.current = null;
      });
    inflightRef.current = p;
    return p;
  }, [actionId, fetchFullText]);

  return { fetchOnce, available: !!fetchFullText };
}

// McpBadge highlights an MCP tool call in the timeline (server / tool). It
// takes the already-resolved identity (see mcpIdentity) so it lights up for
// every adapter — the mcp__ names, the colon server:tool forms, and rows
// carrying only the action_type="mcp_call" signal.
function McpBadge({ id, copy }: { id: { server: string; tool: string }; copy: string }) {
  return (
    <CopyOnClick value={copy} className="shrink-0" title="MCP tool call">
      <span className="inline-flex items-center gap-1 rounded-pill border border-accent/40 bg-accent/10 px-2 py-0.5 font-mono text-[10px] font-medium leading-none text-accent">
        <span className="uppercase tracking-[0.06em] opacity-80">MCP</span>
        <span>
          {id.server}
          {id.tool ? ` / ${id.tool}` : ""}
        </span>
      </span>
    </CopyOnClick>
  );
}

type EditHunk = { old: string; neu: string };

// parseEditInput turns an edit_file/write_file raw_tool_input into a renderable
// change: Edit → old→new hunks (incl. MultiEdit's edits[]); Write → the new
// content. Falls back to the raw text/JSON when the shape is unfamiliar so a
// change is never silently hidden.
function parseEditInput(
  actionType: string,
  raw: string,
): { file?: string; hunks: EditHunk[]; content?: string; fallback?: string } {
  let j: Record<string, unknown>;
  try {
    j = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return { hunks: [], fallback: raw };
  }
  const file = typeof j.file_path === "string" ? j.file_path : undefined;
  if (actionType === "write_file") {
    const content =
      typeof j.content === "string"
        ? j.content
        : typeof j.new_string === "string"
          ? j.new_string
          : undefined;
    return { file, hunks: [], content };
  }
  const hunks: EditHunk[] = [];
  if (Array.isArray(j.edits)) {
    for (const e of j.edits as Array<Record<string, unknown>>) {
      if (e && typeof e.old_string === "string" && typeof e.new_string === "string") {
        hunks.push({ old: e.old_string, neu: e.new_string });
      }
    }
  } else if (typeof j.old_string === "string" && typeof j.new_string === "string") {
    hunks.push({ old: j.old_string, neu: j.new_string });
  }
  if (hunks.length === 0) {
    return { file, hunks: [], fallback: JSON.stringify(j, null, 2) };
  }
  return { file, hunks };
}

// DiffBlock renders one old→new hunk as a minimal line diff: common leading /
// trailing lines shown dim as context, the differing middle as removed (−) /
// added (+). Claude's Edit already passes a minimal changed region, so context
// stays small.
function DiffBlock({ oldText, newText }: { oldText: string; newText: string }) {
  const o = oldText.split("\n");
  const n = newText.split("\n");
  let pre = 0;
  while (pre < o.length && pre < n.length && o[pre] === n[pre]) pre++;
  let suf = 0;
  while (
    suf < o.length - pre &&
    suf < n.length - pre &&
    o[o.length - 1 - suf] === n[n.length - 1 - suf]
  ) {
    suf++;
  }
  const ctxPre = o.slice(0, pre);
  const removed = o.slice(pre, o.length - suf);
  const added = n.slice(pre, n.length - suf);
  const ctxSuf = suf > 0 ? o.slice(o.length - suf) : [];
  const line = (t: string, kind: "ctx" | "del" | "add", key: string) => (
    <div
      key={key}
      className={
        kind === "del"
          ? "bg-danger/10 text-danger"
          : kind === "add"
            ? "bg-ok/10 text-ok"
            : "text-fg-3"
      }
    >
      <span className="select-none opacity-60">
        {kind === "del" ? "- " : kind === "add" ? "+ " : "  "}
      </span>
      {t || " "}
    </div>
  );
  return (
    <pre className="max-h-[360px] overflow-auto px-2 py-1 font-mono text-[10.5px] leading-snug">
      {ctxPre.map((t, i) => line(t, "ctx", "p" + i))}
      {removed.map((t, i) => line(t, "del", "d" + i))}
      {added.map((t, i) => line(t, "add", "a" + i))}
      {ctxSuf.map((t, i) => line(t, "ctx", "s" + i))}
    </pre>
  );
}

// EditChangeView renders the parsed edit/write change (file header + diff or
// full content). Lazily fed the raw_tool_input by ToolCallRowView on expand.
function EditChangeView({ actionType, rawInput }: { actionType: string; rawInput: string }) {
  const parsed = parseEditInput(actionType, rawInput);
  return (
    <div className="ml-6 mt-1 overflow-hidden rounded-1 border border-line-2 bg-bg-1">
      {parsed.file && (
        <div className="border-b border-line-2 px-2 py-1 font-mono text-[10px] text-fg-3">
          {parsed.file}
        </div>
      )}
      {parsed.content != null && (
        <pre className="max-h-[360px] overflow-auto whitespace-pre-wrap break-words px-2 py-1 font-mono text-[10.5px] leading-snug text-ok">
          {parsed.content || " "}
        </pre>
      )}
      {parsed.hunks.map((h, i) => (
        <div key={i} className={i > 0 ? "border-t border-line-2" : ""}>
          <DiffBlock oldText={h.old} newText={h.neu} />
        </div>
      ))}
      {parsed.fallback != null && (
        <pre className="max-h-[360px] overflow-auto whitespace-pre-wrap break-words px-2 py-1 font-mono text-[10.5px] text-fg-2">
          {parsed.fallback}
        </pre>
      )}
    </div>
  );
}

// UnavailableFullText — the honest "no fetcher" affordance. Rendered where a
// View / View-full / Change button would be when the row's body is elided but
// no fetchFullText was injected (the org's read-only, metadata-only mode).
function UnavailableFullText({ label = "full text not available here" }: { label?: string }) {
  return (
    <span
      className="shrink-0 rounded-1 border border-dashed border-line-2 px-1.5 py-0.5 font-mono text-[10px] text-fg-4"
      title="This surface does not expose the untruncated body; open it on the developer's device."
    >
      {label}
    </span>
  );
}

// BrowserChatBubble renders a browser-captured chat turn (browserchat
// *-web adapters) as an actual chat bubble: the user's prompt or the
// assistant's answer as wrapped, readable text — the on-screen content —
// rather than the dense tool-call row used for coding-agent tools. The
// assistant bubble also surfaces the per-turn API-call details
// (request_url / id_source / granularity / token estimates / latency)
// captured in actions.metadata. Falls back to the target preview when a
// turn carried no content (usage_only granularity), and offers the same
// lazy "View full" affordance for bodies that exceeded the inline cap.
function BrowserChatBubble({
  tc,
  fetchFullText,
}: {
  tc: ToolCallRow;
  fetchFullText?: FetchFullText;
}) {
  const isUser = tc.action_type === "user_prompt";
  const [viewOpen, setViewOpen] = useState(false);
  const { fetchOnce, available } = useActionFullText(tc.action_id, fetchFullText);
  // The captured on-screen text: full_text is the (inline-capped) prompt
  // for user rows and the response body for assistant rows. target is the
  // one-line preview the adapter stored; used as a fallback when no
  // content was captured (usage_only granularity).
  const body = tc.full_text || "";
  const preview = tc.target || "";
  const hasBody = body.trim() !== "";
  // "View full" is offered when the inline body was truncated OR a fuller
  // raw_tool_output exists server-side — AND a fetcher is available.
  const wantsView = tc.full_text_elided === true || tc.has_full_output === true;
  const showView = wantsView && available;
  // API-call detail chips — only on assistant rows, only where captured.
  const details: { label: string; value: string; title?: string }[] = [];
  if (!isUser) {
    if (tc.request_url)
      details.push({
        label: "url",
        value: tc.request_url,
        title: tc.request_url,
      });
    if (tc.id_source)
      details.push({ label: "id via", value: tc.id_source });
    if (tc.granularity)
      details.push({ label: "granularity", value: tc.granularity });
    if (tc.prompt_tokens_est)
      details.push({
        label: "prompt~",
        value: `${fmtInt(tc.prompt_tokens_est)} tok`,
      });
    if (tc.response_tokens_est)
      details.push({
        label: "response~",
        value: `${fmtInt(tc.response_tokens_est)} tok`,
      });
    if (tc.duration_ms && tc.duration_ms > 0)
      details.push({ label: "latency", value: fmtDuration(tc.duration_ms) });
  }
  return (
    <div
      className={clsx(
        "flex flex-col gap-1.5 rounded-2 px-3 py-2",
        isUser
          ? "border border-accent/30 bg-accent-soft/40"
          : "border border-success/25 bg-success-soft/30",
      )}
      onClick={(e) => e.stopPropagation()}
    >
      <div className="flex items-center gap-2">
        <Pill variant={isUser ? "accent" : "success"}>
          {isUser ? "user" : "assistant"}
        </Pill>
        {tc.raw_tool_name && (
          <span className="font-mono text-[10px] text-fg-3">
            {tc.raw_tool_name}
          </span>
        )}
        {showView ? (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setViewOpen(true);
            }}
            title="View full text"
            className="ml-auto shrink-0 rounded-1 border border-line-2 bg-bg-3 px-1.5 py-0.5 font-mono text-[10px] text-fg-3 transition-colors hover:border-accent hover:text-accent"
          >
            View full
          </button>
        ) : wantsView ? (
          <span className="ml-auto">
            <UnavailableFullText />
          </span>
        ) : null}
      </div>
      {hasBody ? (
        <CopyOnClick
          value={body}
          resolveValue={
            showView
              ? async () => {
                  const v = await fetchOnce();
                  return (isUser ? v.raw_tool_input : v.raw_tool_output) || body;
                }
              : undefined
          }
          className="block"
          title="Click to copy full text"
        >
          <div className="max-h-[420px] overflow-auto whitespace-pre-wrap break-words text-[12px] leading-relaxed text-fg-1">
            {body}
            {tc.full_text_elided ? (
              <span className="text-fg-3"> …(truncated - View full)</span>
            ) : null}
          </div>
        </CopyOnClick>
      ) : preview ? (
        <div className="whitespace-pre-wrap break-words text-[12px] leading-relaxed text-fg-2">
          {preview}
        </div>
      ) : (
        <div className="text-[11px] italic text-fg-3">
          No content captured for this turn (usage-only granularity).
        </div>
      )}
      {details.length > 0 && (
        <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-line-1 pt-1.5 text-[10px] text-fg-3">
          {details.map((d) => (
            <span
              key={d.label}
              className="inline-flex items-center gap-1"
              title={d.title}
            >
              <span className="uppercase tracking-[0.05em] text-fg-4">
                {d.label}
              </span>
              <span className="max-w-[280px] truncate font-mono text-fg-2">
                {d.value}
              </span>
            </span>
          ))}
        </div>
      )}
      {viewOpen && (
        <FullTextModal
          actionId={tc.action_id}
          fetcher={fetchOnce}
          actionType={tc.action_type}
          rawToolName={tc.raw_tool_name}
          onClose={() => setViewOpen(false)}
        />
      )}
    </div>
  );
}

// ToolCallRowView — one expanded tool-call row inside a message. The
// design's expand row puts the action pill + target + status + any
// excerpt / error inline; we render each text piece via CopyOnClick
// so the operator can grab any subset (the target path, an output
// snippet, the error message) without selecting through the row's
// click-to-collapse handler.
//
// On-demand full-text: when tc.full_text_elided or tc.has_full_output is set,
// the inline `full_text` / `excerpt` is a truncated preview. The copy buttons
// fetch the untruncated body via the injected fetchFullText on click; a
// separate "View" button opens a modal showing the full text. The fetch is
// lazy + cached per row. When no fetcher is injected, the View / Change
// affordances render an honest "not available here" state.
function ToolCallRowView({
  tc,
  browser = false,
  fetchFullText,
}: {
  tc: ToolCallRow;
  browser?: boolean;
  fetchFullText?: FetchFullText;
}) {
  // Browser-captured chat: render the user prompt / assistant answer as a
  // proper chat bubble (the on-screen text) rather than the dense tool-call
  // row. Gated on `browser` so coding-agent assistant_message rows keep the
  // existing rendering below untouched.
  if (
    browser &&
    (tc.action_type === "assistant_message" || tc.action_type === "user_prompt")
  ) {
    return <BrowserChatBubble tc={tc} fetchFullText={fetchFullText} />;
  }
  // `primary` is what gets rendered (truncated at 140 chars in the
  // narrow case). `primaryFull` is what gets copied — the backend
  // serves `full_text` from actions.raw_tool_input (preview capped at
  // 4 KiB inline; longer rows carry full_text_elided=true and require
  // a fetchFullText call for the untruncated body), while `target` is
  // capped at 200 chars at store time. Preferring full_text means the
  // copy button hands the operator the actual text they typed, not the
  // dashboard's display-truncated version.
  const primary = tc.target || tc.raw_tool_name || "";
  const primaryFull = tc.full_text || primary;
  const { fetchOnce, available } = useActionFullText(tc.action_id, fetchFullText);
  const hasLazyFullText = tc.full_text_elided === true && available;
  const hasLazyOutput = tc.has_full_output === true && available;
  // wantsFetch: the row HAS a fuller body but no fetcher is available.
  const wantsFetch =
    (tc.full_text_elided === true || tc.has_full_output === true) && !available;
  const [viewOpen, setViewOpen] = useState(false);

  // Resolver for the primary CopyOnClick. Returns the untruncated
  // raw_tool_input when full_text_elided; otherwise undefined so
  // CopyOnClick falls back to the inline `value`.
  const resolvePrimary = hasLazyFullText
    ? async () => {
        const v = await fetchOnce();
        return v.raw_tool_input || primaryFull;
      }
    : undefined;

  // Resolver for the excerpt CopyOnClick. Returns the untruncated
  // raw_tool_output when has_full_output; otherwise undefined so
  // CopyOnClick falls back to the inline excerpt.
  const resolveOutput = hasLazyOutput
    ? async () => {
        const v = await fetchOnce();
        return v.raw_tool_output || tc.excerpt || "";
      }
    : undefined;

  const showViewButton = hasLazyFullText || hasLazyOutput;

  // Edit/Write "View change" — a lazy inline diff. The messages payload
  // carries only the filename for these rows; the actual change lives in
  // raw_tool_input, fetched on demand (same cached fetch as the copy/View
  // buttons) so a long session doesn't preload every diff.
  const isEditWrite = tc.action_type === "edit_file" || tc.action_type === "write_file";
  const [changeOpen, setChangeOpen] = useState(false);
  const [changeInput, setChangeInput] = useState<string | null>(null);
  const [changeErr, setChangeErr] = useState<string | null>(null);
  const toggleChange = (e: { stopPropagation: () => void }) => {
    e.stopPropagation();
    const next = !changeOpen;
    setChangeOpen(next);
    if (next && changeInput == null && changeErr == null) {
      fetchOnce()
        .then((v) => setChangeInput(v.raw_tool_input || ""))
        .catch((err) => setChangeErr(err instanceof Error ? err.message : String(err)));
    }
  };
  // The Change button only makes sense with a fetcher (the diff comes from the
  // fetched raw_tool_input). Without one, an inline changePreview may still
  // render below from the already-present full_text.
  const showChangeButton = isEditWrite && available;

  // For write/edit rows the inline `excerpt` is the harness result string
  // ("File created successfully at …"), which says nothing about the change.
  // When the input was captured inline (full_text — the raw_tool_input,
  // already returned inline-capped), show a short preview of the new content
  // / first hunk instead, so the actual change is visible without expanding.
  const changePreview = (() => {
    if (!isEditWrite || !tc.full_text) return null;
    const p = parseEditInput(tc.action_type, tc.full_text);
    const body = p.content ?? p.hunks[0]?.neu ?? p.fallback ?? "";
    const lines = body.split("\n");
    const head = lines.slice(0, 3).join("\n").replace(/\s+$/, "");
    if (!head.trim()) return null;
    return { head, more: lines.length > 3 };
  })();

  return (
    <div
      className="flex flex-col gap-1 rounded-1 bg-bg-2 px-2.5 py-1.5"
      style={{
        borderLeft: `2px solid ${
          tc.success ? "var(--accent)" : "var(--danger)"
        }`,
      }}
      onClick={(e) => e.stopPropagation()}
    >
      <div className="flex items-center gap-2.5">
        <span
          className="inline-flex items-center gap-1 rounded-pill border border-line-2 bg-bg-3 px-2 py-0.5 font-mono text-[10.5px] font-medium leading-none"
          style={{ color: "var(--act-cmd)" }}
        >
          {actionMeta(tc.action_type).label}
        </span>
        {(() => {
          const mcp = mcpIdentity(tc);
          if (mcp) return <McpBadge id={mcp} copy={tc.raw_tool_name || tc.target || ""} />;
          return tc.raw_tool_name ? (
            <CopyOnClick
              value={tc.raw_tool_name}
              className="font-mono text-[10.5px] text-fg-3"
            >
              {tc.raw_tool_name}
            </CopyOnClick>
          ) : null;
        })()}
        {primary && (
          <CopyOnClick
            value={primaryFull}
            resolveValue={resolvePrimary}
            className="min-w-0 flex-1 font-mono text-[11px] text-fg-1"
            title={
              hasLazyFullText
                ? "Click to fetch and copy full text"
                : "Click to copy full text"
            }
          >
            {primary.length > 140 || primaryFull.length > primary.length ? (
              <Tooltip
                content={<span className="break-all font-mono">{primaryFull}</span>}
                maxWidth={420}
              >
                <span tabIndex={0} className="block cursor-help truncate focus:outline-none">
                  {truncate(primary, 140)}
                </span>
              </Tooltip>
            ) : (
              <span className="block truncate">{primary}</span>
            )}
          </CopyOnClick>
        )}
        {showViewButton && (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setViewOpen(true);
            }}
            title={
              hasLazyFullText && hasLazyOutput
                ? "View full input + output"
                : hasLazyFullText
                  ? "View full input"
                  : "View full output"
            }
            className="shrink-0 rounded-1 border border-line-2 bg-bg-3 px-1.5 py-0.5 font-mono text-[10px] text-fg-3 transition-colors hover:border-accent hover:text-accent"
          >
            View
          </button>
        )}
        {wantsFetch && !showViewButton && <UnavailableFullText />}
        {showChangeButton && (
          <button
            type="button"
            onClick={toggleChange}
            title={changeOpen ? "Hide change" : "View the file change"}
            className="shrink-0 rounded-1 border border-line-2 bg-bg-3 px-1.5 py-0.5 font-mono text-[10px] text-fg-3 transition-colors hover:border-accent hover:text-accent"
          >
            {changeOpen ? "▾ Change" : "▸ Change"}
          </button>
        )}
        {tc.duration_ms != null && tc.duration_ms > 0 && (
          <span className="shrink-0 font-mono text-[10px] tabular-nums text-fg-3">
            {fmtDuration(tc.duration_ms)}
          </span>
        )}
        {!tc.success && (
          <Pill variant="danger">
            {tc.error_message ? truncate(tc.error_message, 32) : "failed"}
          </Pill>
        )}
      </div>
      {changePreview ? (
        <div className="ml-6 block font-mono text-[10.5px] leading-snug text-fg-3">
          <span className="block whitespace-pre-wrap break-words opacity-90">
            {changePreview.head}
            {changePreview.more ? "\n…" : ""}
          </span>
        </div>
      ) : tc.excerpt ? (
        <CopyOnClick
          value={tc.full_text || tc.excerpt}
          resolveValue={resolveOutput}
          className="ml-6 block font-mono text-[10.5px] text-fg-3"
          title={
            hasLazyOutput
              ? "Click to fetch and copy full output"
              : "Click to copy full output"
          }
        >
          <span className="block whitespace-pre-wrap break-words">
            {tc.excerpt}
          </span>
        </CopyOnClick>
      ) : null}
      {tc.error_message && (
        <CopyOnClick
          value={tc.error_message}
          className="ml-6 block font-mono text-[10.5px] text-danger"
        >
          <span className="block whitespace-pre-wrap break-words">
            {tc.error_message}
          </span>
        </CopyOnClick>
      )}
      {changeOpen &&
        (changeErr != null ? (
          <div className="ml-6 mt-1 font-mono text-[10.5px] text-danger">
            failed to load change: {changeErr}
          </div>
        ) : changeInput == null ? (
          <div className="ml-6 mt-1 font-mono text-[10.5px] text-fg-3">loading change…</div>
        ) : changeInput === "" ? (
          <div className="ml-6 mt-1 font-mono text-[10.5px] text-fg-3">
            no change content captured for this action
          </div>
        ) : (
          <EditChangeView actionType={tc.action_type} rawInput={changeInput} />
        ))}
      {viewOpen && (
        <FullTextModal
          actionId={tc.action_id}
          fetcher={fetchOnce}
          actionType={tc.action_type}
          rawToolName={tc.raw_tool_name}
          onClose={() => setViewOpen(false)}
        />
      )}
    </div>
  );
}

// FullTextModal — centered overlay that loads the untruncated
// raw_tool_input + raw_tool_output for one action and renders both
// with copy buttons. Mounted above the SessionDetailPanel slide-over
// (z-[60]) so the operator can drill into a single row's full content
// without losing the messages timeline behind it. Closes on Escape or
// backdrop click; the fetch is the same one CopyOnClick uses behind
// the scenes so opening View immediately after copying is free.
function FullTextModal({
  actionId,
  fetcher,
  actionType,
  rawToolName,
  onClose,
}: {
  actionId: number;
  fetcher: () => Promise<ActionFullText>;
  actionType: string;
  rawToolName: string;
  onClose: () => void;
}) {
  const [data, setData] = useState<ActionFullText | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    fetcher()
      .then((v) => {
        if (!cancelled) setData(v);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [fetcher]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  const meta = actionMeta(actionType);
  const inputBody = data?.raw_tool_input ?? "";
  const outputBody = data?.raw_tool_output ?? "";

  return createPortal(
    <AnimatePresence>
      <motion.div
        key="ft-backdrop"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.15, ease: "easeOut" }}
        onClick={onClose}
        className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 p-6"
      >
        <motion.div
          key="ft-panel"
          initial={{ scale: 0.97, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.97, opacity: 0 }}
          transition={{ duration: 0.18, ease: "easeOut" }}
          onClick={(e) => e.stopPropagation()}
          className="flex max-h-[88vh] w-full max-w-[1000px] flex-col overflow-hidden rounded-2 border border-line-2 bg-bg-1 shadow-drawer"
        >
          <header className="flex items-center justify-between gap-3 border-b border-line-1 px-5 py-3">
            <div className="flex min-w-0 items-center gap-2">
              <span
                className="inline-flex items-center gap-1 rounded-pill border border-line-2 bg-bg-3 px-2 py-0.5 font-mono text-[10.5px] font-medium leading-none"
                style={{ color: "var(--act-cmd)" }}
              >
                {meta.label}
              </span>
              {rawToolName && (
                <span className="truncate font-mono text-[11px] text-fg-3">
                  {rawToolName}
                </span>
              )}
              <span className="shrink-0 font-mono text-[10px] text-fg-3">
                action #{actionId}
              </span>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="shrink-0 rounded-1 border border-line-2 bg-bg-3 px-2 py-0.5 font-mono text-[10.5px] text-fg-2 transition-colors hover:border-accent hover:text-accent"
            >
              Close
            </button>
          </header>
          <div className="flex-1 overflow-y-auto px-5 py-4">
            {!data && !error && (
              <div className="font-mono text-[11px] text-fg-3">Loading…</div>
            )}
            {error && (
              <div className="font-mono text-[11px] text-danger">
                Failed to load full text: {error}
              </div>
            )}
            {data && (
              <div className="flex flex-col gap-4">
                {inputBody && (
                  <FullTextSection label="raw_tool_input" body={inputBody} />
                )}
                {outputBody && (
                  <FullTextSection label="raw_tool_output" body={outputBody} />
                )}
                {!inputBody && !outputBody && (
                  <div className="font-mono text-[11px] text-fg-3">
                    No captured content for this action.
                  </div>
                )}
              </div>
            )}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>,
    document.body,
  );
}

function FullTextSection({ label, body }: { label: string; body: string }) {
  return (
    <section className="flex flex-col gap-1">
      <div className="flex items-center justify-between">
        <span className="font-mono text-[10px] uppercase tracking-wide text-fg-3">
          {label}{" "}
          <span className="text-fg-3/70">({body.length.toLocaleString()} chars)</span>
        </span>
        <CopyOnClick
          value={body}
          className="rounded-1 border border-line-2 bg-bg-3 px-2 py-0.5 font-mono text-[10.5px] text-fg-2"
        >
          Copy
        </CopyOnClick>
      </div>
      <pre className="max-h-[55vh] overflow-auto rounded-1 border border-line-1 bg-bg-2 p-3 font-mono text-[11px] leading-relaxed text-fg-1 whitespace-pre-wrap break-words">
        {body}
      </pre>
    </section>
  );
}

function ContentSnippet({ row }: { row: MessageRow }) {
  // Backend doesn't index user/assistant body text, so we surface
  // the most informative substitute: for a tool-call-bearing
  // assistant row, the first tool call's target. For a tool-result
  // row, the action_type + truncated target. Otherwise the role.
  const toolCalls = row.tool_calls ?? [];
  if (toolCalls.length) {
    // Highlight an MCP call in the COLLAPSED row too — the McpBadge otherwise
    // only shows once a message is expanded, so mcp__ calls (incl. the
    // observer codeintel tools: search_symbols / get_symbols / get_relations)
    // looked un-highlighted in the default timeline. Surface the first MCP
    // tool call's server/tool badge inline; fall back to the plain label.
    const mcpTc = toolCalls.find((t) => mcpIdentity(t));
    if (mcpTc) {
      const id = mcpIdentity(mcpTc)!;
      return (
        <span className="inline-flex min-w-0 items-center gap-1.5">
          <McpBadge id={id} copy={mcpTc.raw_tool_name || mcpTc.target || ""} />
          {mcpTc.target ? (
            <span className="truncate font-mono text-[11px] text-fg-3">
              {truncate(mcpTc.target, 60)}
            </span>
          ) : null}
        </span>
      );
    }
    const tc = toolCalls[0];
    const label = (
      <>
        {actionMeta(tc.action_type).label}
        {tc.target ? ` · ${truncate(tc.target, 60)}` : ""}
      </>
    );
    if (!tc.target) return <span>{label}</span>;
    return (
      <Tooltip content={<span className="break-all font-mono">{tc.target}</span>} maxWidth={420}>
        <span tabIndex={0} className="cursor-help focus:outline-none">
          {label}
        </span>
      </Tooltip>
    );
  }
  return <span className="text-fg-4">-</span>;
}

function RolePill({ role }: { role: string }) {
  // Design's role color mapping (page-sessions.jsx:222-224):
  //   user      → accent (purple)
  //   assistant → success (green)
  //   tool      → warn (yellow)
  switch (role) {
    case "user":
      return <Pill variant="accent">user</Pill>;
    case "assistant":
      return <Pill variant="success">assistant</Pill>;
    case "tool":
      return <Pill variant="warn">tool</Pill>;
    case "system":
      return <Pill>system</Pill>;
    default:
      return <Pill>{role}</Pill>;
  }
}

function Caret({ open, disabled }: { open: boolean; disabled?: boolean }) {
  return (
    <svg
      width={9}
      height={9}
      viewBox="0 0 12 12"
      fill="none"
      className={clsx(
        "transition-transform",
        open ? "rotate-180" : "rotate-0",
        disabled && "opacity-30",
      )}
      aria-hidden
    >
      <path
        d="m3 4.5 3 3 3-3"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
