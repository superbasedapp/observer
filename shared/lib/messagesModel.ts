// Messages-table data model: the sort vocabulary, the column table, the
// persisted-sort reader and the watch-follow rule. Extracted VERBATIM from
// SessionDetailPanel.tsx during the tab split; the shell still owns the sort
// STATE (it feeds the request params), this file owns the shape of it.

export const MESSAGES_LIMIT = 25;
export const RAW_EVENTS_LIMIT = 50;

// ----- Messages table sort ----------------------------------------
//
// Sorting is SERVER-SIDE (/api/session/<id>/messages?sort_by&sort_dir) so it
// addresses the whole timeline rather than the current page — the point of
// the feature is that "time descending" puts the newest message at row 1 of
// page 1 while a live session is running, instead of appending it to the
// last page.
export type MessageSortKey =
  | "seq"
  | "timestamp"
  | "message_id"
  | "account"
  | "role"
  | "model"
  | "effort_level"
  | "input"
  | "cache_read"
  | "cache_creation"
  | "output"
  | "elapsed_ms"
  | "tokens_per_sec"
  | "tool_call_count"
  | "attachments"
  | "ai_cost_usd"
  | "tool_cost_usd"
  | "cost_usd"
  | "content";
export type SortDir = "asc" | "desc";

// The default reproduces the endpoint's historical chronological order; the
// server treats it as the identity permutation.
export const DEFAULT_MSG_SORT: MessageSortKey = "seq";
export const DEFAULT_MSG_DIR: SortDir = "asc";

// messageRowKey derives a message row's STABLE identity/expansion key: its
// message_id, or a `seq-<n>` fallback for the (rare) row with no message_id
// (seq is the server's whole-timeline ordinal, unique per row and carried
// through every reorder). This is the one rule the built-in tool-call expander
// keys off; a caller controlling row expansion from the outside (the org's
// audited-content disclosure sharing the row's open state via MessagesTable's
// expandedKeys / onToggleRow) MUST key off the same helper rather than
// duplicating the `message_id || seq-<n>` string, so the two affordances agree
// on one key per row. Kept structural (message_id + seq) to avoid importing the
// full MessageRowLike here.
export function messageRowKey(row: { message_id?: string; seq: number }): string {
  return row.message_id || `seq-${row.seq}`;
}

// MessageColumn is one row of the header table. `width` is the column's
// nominal px contribution to the table's min-width — the table is
// `table-auto`, so this is a LAYOUT BUDGET (what the column needs before
// horizontal scrolling starts), not a hard size. It exists so the min-width
// follows the VISIBLE column set instead of being pinned at the full-table
// 1460px: a 7-column preset that still forced a 1460px scroll would be a
// preset in name only.
export type MessageColumn = {
  key: MessageSortKey;
  label: string;
  right?: boolean;
  className?: string;
  width: number;
  tooltip?: string;
  tooltipMaxWidth?: number;
};

// MESSAGE_COLUMNS is the single source of truth for the Messages table
// header: one row per column, in table order, carrying its sort key, label,
// alignment and optional tooltip. Adding a column is one row here plus one
// row in the server's messageSortKeys table — never a new conditional.
// Nineteen columns; the widths below sum to 1700 (the account column added
// 190 to the pre-presets 1460 literal; the Att column added 50).
export const MESSAGE_COLUMNS: MessageColumn[] = [
  { key: "seq", label: "#", className: "pl-3", width: 40 },
  { key: "timestamp", label: "Time", width: 80 },
  { key: "message_id", label: "Msg ID", width: 104 },
  { key: "role", label: "Role", width: 80 },
  { key: "account", label: "Account", width: 190, tooltip: "Login observed for this message. Account changes preserve earlier labels; this is not provider billing confirmation." },
  { key: "model", label: "Model", width: 160 },
  {
    key: "effort_level",
    label: "Effort",
    width: 68,
    tooltip:
      "Reasoning effort - codex collaboration_mode.settings.reasoning_effort, antigravity SKU-encoded low/medium/high, etc. Empty for adapters that don't expose an effort knob (Anthropic models, copilot, etc.); those rows sort to the bottom in both directions. Sorts by intensity (low → high), not alphabetically.",
    tooltipMaxWidth: 420,
  },
  { key: "input", label: "In", right: true, width: 62 },
  { key: "cache_read", label: "Cache R", right: true, width: 76 },
  { key: "cache_creation", label: "Cache W", right: true, width: 76 },
  { key: "output", label: "Out", right: true, width: 62 },
  { key: "elapsed_ms", label: "Elapsed", right: true, width: 74 },
  {
    key: "tokens_per_sec",
    label: "Tok/s",
    right: true,
    width: 64,
    tooltip:
      "Output tokens per second - this turn's output tokens ÷ its elapsed time. Only output (generated) tokens count. Blank for turns with no output or no timing; those rows sort to the bottom in both directions.",
    tooltipMaxWidth: 420,
  },
  { key: "tool_call_count", label: "Tools", right: true, width: 58 },
  {
    key: "attachments",
    label: "Att",
    right: true,
    width: 50,
    tooltip:
      "Files/images/audio the user attached to this turn (presence, count and kind only - never filenames or content). Empty for turns with no attachment and for adapters/surfaces that don't capture it.",
    tooltipMaxWidth: 360,
  },
  { key: "ai_cost_usd", label: "API $", right: true, width: 70 },
  { key: "tool_cost_usd", label: "Tool $", right: true, width: 70 },
  { key: "cost_usd", label: "Total $", right: true, width: 74 },
  { key: "content", label: "Content", className: "pl-3 pr-3", width: 242 },
];

// ----- Column presets ---------------------------------------------
//
// WHY. Seventeen always-on columns make the timeline 1460px wide — wider than
// the documented `lg` (1024px) boundary, so every operator scrolls
// horizontally regardless of what they came to find out. A preset is a
// VISIBILITY control over the columns that already exist: no new data, no new
// request params, no new computed values. The row payload is unchanged — the
// server still returns every field, and sorting still addresses the whole
// timeline server-side.
//
// EXPORTS ARE NOT PRESET-SCOPED. There is no CSV/JSON export of message rows
// today (the dashboard's three CSV builders live on Sessions / Cost / Cache
// and cover other tables; TopBar's export re-fetches the current page's API
// endpoint). If one is ever added here, build it from MESSAGE_COLUMNS — the
// FULL set — never from the resolved preset: an export that silently drops
// columns because a view filter happened to be active is a data-loss trap,
// and the preset is a reading aid, not a scope.
//
// COVERAGE IS STRUCTURAL, NOT A LIST. "All" carries `keys: null`, which
// resolves to MESSAGE_COLUMNS itself rather than to a hand-maintained copy of
// it. A column added to MESSAGE_COLUMNS is therefore reachable the moment it
// exists, even if whoever adds it never reads this block — the failure mode
// where a new column is silently unreachable cannot occur.
export type MessageColumnPreset = "default" | "cost" | "speed" | "all";

export const MESSAGE_PRESETS: {
  id: MessageColumnPreset;
  label: string;
  /** What question this preset answers. Shown in the control's tooltip. */
  hint: string;
  /** null = every column, resolved from MESSAGE_COLUMNS (the escape hatch). */
  keys: MessageSortKey[] | null;
}[] = [
  {
    id: "default",
    label: "Default",
    hint: "what happened - when, who, which model, did it call tools, what it cost, what it was about",
    keys: ["seq", "timestamp", "role", "account", "model", "tool_call_count", "attachments", "cost_usd", "content"],
  },
  {
    id: "cost",
    label: "Cost",
    // Tokens live here, not in a preset of their own: the operator who opens
    // Cost is asking "why was this expensive", and the token split IS the
    // answer. Splitting tokens out would put one question behind two clicks.
    hint: "why it cost that - the token split (in / cache read / cache write / out) beside the three dollar columns",
    keys: [
      "seq",
      "role",
      "model",
      "input",
      "cache_read",
      "cache_creation",
      "output",
      "ai_cost_usd",
      "tool_cost_usd",
      "cost_usd",
      "content",
    ],
  },
  {
    id: "speed",
    label: "Speed",
    hint: "how fast it ran - elapsed time and output tokens/sec, with the effort knob and output volume that drive them",
    keys: [
      "seq",
      "timestamp",
      "role",
      "model",
      "effort_level",
      "output",
      "elapsed_ms",
      "tokens_per_sec",
      "content",
    ],
  },
  {
    id: "all",
    label: "All",
    // Msg ID is the one column no themed preset shows — a 10-char truncated
    // hash used to correlate a row with proxy / api_turns records. That is the
    // honest reason this option exists rather than being a redundant fourth
    // button.
    hint: "every column, including Msg ID - the 1460px full table",
    keys: null,
  },
];

export const DEFAULT_MSG_PRESET: MessageColumnPreset = "default";

// visibleMessageColumns resolves a preset to the columns to render, in table
// order. The ACTIVE SORT COLUMN is always included, whatever the preset: a
// table ordered by a column the operator cannot see is a worse failure than a
// wide table, and it would also make that sort impossible to reverse or clear
// (the header IS the sort control).
export function visibleMessageColumns(
  preset: MessageColumnPreset,
  sortBy: MessageSortKey,
): MessageColumn[] {
  const p = MESSAGE_PRESETS.find((x) => x.id === preset);
  if (!p || p.keys == null) return MESSAGE_COLUMNS;
  const want = new Set<MessageSortKey>(p.keys);
  want.add(sortBy);
  return MESSAGE_COLUMNS.filter((c) => want.has(c.key));
}

// messageTableMinWidth is the layout budget for a column set — the point at
// which the table starts scrolling horizontally instead of compressing.
export function messageTableMinWidth(cols: MessageColumn[]): number {
  return cols.reduce((n, c) => n + c.width, 0);
}

// visibleExtraColumnIds decides which app-supplied extra columns (see
// ExtraMessageColumn in lib/types) show under a preset. This is the preset
// visibility logic for extra columns, kept here beside the built-in preset
// table so both derive from the same rule. An extra column shows when: the
// "all" preset is active; OR it declares no `presets` (default = every preset);
// OR its `presets` includes the active preset; OR it IS the active sort column
// (an active sort must never be hidden, matching visibleMessageColumns). Kept
// React-free by taking a structural subset (id / presets / sortKey), so it can
// live in this pure model file without importing React or the row types.
export function visibleExtraColumnIds<
  T extends {
    id: string;
    presets?: MessageColumnPreset[];
    sortKey?: MessageSortKey;
  },
>(
  preset: MessageColumnPreset,
  sortBy: MessageSortKey,
  extra: readonly T[],
): Set<string> {
  const out = new Set<string>();
  for (const c of extra) {
    const inPreset =
      preset === "all" || !c.presets || c.presets.includes(preset);
    const isActiveSort = c.sortKey != null && c.sortKey === sortBy;
    if (inPreset || isActiveSort) out.add(c.id);
  }
  return out;
}

// Messages-table sort persistence — user-reported bug: closing and
// reopening a session (or reloading the page) reset the sort to "#"
// ascending, discarding whatever order the operator picked. Chosen scope is
// GLOBAL (survives switching sessions), not per-session, per the report.
// Follows the sb_* localStorage naming convention (sb_theme, sb_dock_pos,
// sb_win, etc.) rather than the older "namespace:feature:v1" style seen in
// FiltersDrawer.
export const MSG_SORT_LS_KEY = "sb_msg_sort";
const MESSAGE_SORT_KEYS = new Set<MessageSortKey>(
  MESSAGE_COLUMNS.map((c) => c.key),
);

// loadStoredMsgSort reads + validates the persisted sort. A stored value
// that doesn't parse to a known column key + "asc"/"desc" (stale key from a
// future/older build, hand-edited storage, etc.) must not survive into an
// invalid sort_by/sort_dir query param — fall back to the default instead.
export function loadStoredMsgSort(): { by: MessageSortKey; dir: SortDir } {
  try {
    const raw = localStorage.getItem(MSG_SORT_LS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as { by?: unknown; dir?: unknown };
      if (
        MESSAGE_SORT_KEYS.has(parsed.by as MessageSortKey) &&
        (parsed.dir === "asc" || parsed.dir === "desc")
      ) {
        return { by: parsed.by as MessageSortKey, dir: parsed.dir };
      }
    }
  } catch {
    // localStorage unavailable (private mode) or corrupt JSON; fall through.
  }
  return { by: DEFAULT_MSG_SORT, dir: DEFAULT_MSG_DIR };
}

// Column-preset persistence. Deliberately the SAME mechanism and the same
// scope as the sort above — localStorage, global, `sb_*` key — because it is
// the same kind of state: a personal, durable preference about how this one
// table is read, which should follow the operator into the next session
// rather than be re-picked each time.
//
// NOT the URL. `?tab=` (SessionDetailPanel, following Settings.tsx's
// `?section=`) is for ADDRESSABLE state — which view a shared or bookmarked
// link opens on. A column preset is not something one operator sends another;
// putting it in the URL would also mean a link captured under "Cost" would
// silently re-shape the recipient's table. Two existing patterns, and this
// state matches the localStorage one — no third pattern is introduced.
export const MSG_PRESET_LS_KEY = "sb_msg_cols";
const MESSAGE_PRESET_IDS = new Set<string>(MESSAGE_PRESETS.map((p) => p.id));

// loadStoredMsgPreset reads + validates the persisted preset, falling back to
// the default for anything unrecognised (a preset id from a future build,
// hand-edited storage, unavailable localStorage) — same contract as
// loadStoredMsgSort.
export function loadStoredMsgPreset(): MessageColumnPreset {
  try {
    const raw = localStorage.getItem(MSG_PRESET_LS_KEY);
    if (raw && MESSAGE_PRESET_IDS.has(raw)) return raw as MessageColumnPreset;
  } catch {
    // localStorage unavailable (private mode); fall through.
  }
  return DEFAULT_MSG_PRESET;
}

// storeMsgPreset persists the operator's pick. Failures are swallowed: a
// preference that can't be saved must not break the table.
export function storeMsgPreset(p: MessageColumnPreset): void {
  try {
    localStorage.setItem(MSG_PRESET_LS_KEY, p);
  } catch {
    // quota / private mode — the in-memory pick still applies this session.
  }
}

// watchFollowEdge decides which edge of the table live watch-mode should
// track under the active sort. The chat-follow default assumes "newest is
// last" — true only for the chronological ascending orders. Under a
// chronological DESCENDING sort the newest row is at the TOP (page 1), which
// is the whole point of sorting time descending during a live session. Under
// any other sort the position of a new row is unpredictable, so we follow
// nothing rather than yank the operator's viewport around.
export function watchFollowEdge(
  sortBy: MessageSortKey,
  sortDir: SortDir,
): "bottom" | "top" | "none" {
  if (sortBy !== "seq" && sortBy !== "timestamp") return "none";
  return sortDir === "asc" ? "bottom" : "top";
}
