// sessionColumns: the Sessions table's column table and the pure rules that
// read it (docs/plans/sessions-table-redesign-2026-11-21.md).
//
// One table owns every column's picker label, width budget, default
// visibility and fit priority; the page builds its column defs from it, the
// Columns picker lists it, and the fit rule below decides what a given card
// width shows. Pure: no React, no DOM globals. Storage is injected and every
// read / write is wrapped, because localStorage can throw (private window,
// blocked site data) or come back empty.

/** Every column the Sessions table can show, in display order. */
export type SessionColumnId =
  | "favorite"
  | "session"
  | "tool"
  | "client"
  | "ran"
  | "project"
  | "tags"
  | "models"
  | "started_at"
  | "elapsed"
  | "actions"
  | "ai_code_lines"
  | "tokens"
  | "input"
  | "cache_r"
  | "cache_w"
  | "output"
  | "cost"
  | "quality"
  | "errors"
  | "redundancy";

export type SessionColumnSpec = {
  id: SessionColumnId;
  /** The name the Columns picker shows. */
  label: string;
  /** Width budget in px. For the flexible Session column, its minimum. */
  width: number;
  /** Shown when the viewer has not chosen. */
  defaultOn: boolean;
  /**
   * Fit priority for a default column: when the card is too narrow, default
   * columns are dropped from the HIGHEST number down. 0 = never dropped.
   */
  priority: number;
  /** Always shown and not listed in the picker (favorite, session). */
  locked?: boolean;
  /** Exists only when at least one session in view has a quality score. */
  scoring?: boolean;
  /** The one column that takes the leftover width. */
  flex?: boolean;
};

/**
 * SESSION_COLUMNS is the one column table, in display order. Widths are sized
 * to the HEADER (label + help dot + sort caret) or the typical value,
 * whichever is wider. Fit priorities: Total $ is kept longest, then Started,
 * Tool, Project, Tokens, Model(s), Elapsed, Actions, Quality, AI code, Tags.
 * With these numbers the default set fits a 1280px viewport with the nav
 * open (978px of card) and shows every default column at 1920px.
 */
export const SESSION_COLUMNS: readonly SessionColumnSpec[] = [
  { id: "favorite", label: "Favorite and rating", width: 52, defaultOn: true, priority: 0, locked: true },
  { id: "session", label: "Session", width: 180, defaultOn: true, priority: 0, locked: true, flex: true },
  { id: "tool", label: "Tool", width: 140, defaultOn: true, priority: 3 },
  { id: "client", label: "Client", width: 120, defaultOn: false, priority: 12 },
  { id: "ran", label: "Where it ran", width: 84, defaultOn: false, priority: 13 },
  { id: "project", label: "Project", width: 136, defaultOn: true, priority: 4 },
  { id: "tags", label: "Tags", width: 164, defaultOn: true, priority: 11 },
  { id: "models", label: "Model(s)", width: 140, defaultOn: true, priority: 6 },
  { id: "started_at", label: "Started", width: 104, defaultOn: true, priority: 2 },
  { id: "elapsed", label: "Elapsed", width: 80, defaultOn: true, priority: 7 },
  { id: "actions", label: "Actions", width: 80, defaultOn: true, priority: 8 },
  { id: "ai_code_lines", label: "AI code", width: 80, defaultOn: true, priority: 10 },
  { id: "tokens", label: "Tokens", width: 80, defaultOn: true, priority: 5 },
  { id: "input", label: "Input tokens", width: 76, defaultOn: false, priority: 14 },
  { id: "cache_r", label: "Cache reads", width: 84, defaultOn: false, priority: 15 },
  { id: "cache_w", label: "Cache writes", width: 86, defaultOn: false, priority: 16 },
  { id: "output", label: "Output tokens", width: 80, defaultOn: false, priority: 17 },
  { id: "cost", label: "Total $", width: 80, defaultOn: true, priority: 1 },
  { id: "quality", label: "Quality", width: 72, defaultOn: true, priority: 9, scoring: true },
  { id: "errors", label: "Errors", width: 72, defaultOn: false, priority: 18, scoring: true },
  { id: "redundancy", label: "Redundancy", width: 120, defaultOn: false, priority: 19, scoring: true },
];

const BY_ID = new Map<string, SessionColumnSpec>(SESSION_COLUMNS.map((c) => [c.id, c]));

/** sessionColumn returns the table row for an id, or undefined. */
export function sessionColumn(id: string): SessionColumnSpec | undefined {
  return BY_ID.get(id);
}

/** The viewer's explicit choices: id -> shown. Absent = the default. */
export type ColumnOverrides = Partial<Record<SessionColumnId, boolean>>;

/** The localStorage key the overrides live under (per browser, per viewer). */
export const COLUMN_STORAGE_KEY = "superbased.sessions.columns.v1";

/**
 * parseColumnOverrides accepts only a JSON object of known, unlocked column
 * ids mapped to booleans. Anything else (null, junk JSON, an array, unknown
 * ids, a locked column, a non-boolean value) is dropped, never guessed.
 */
export function parseColumnOverrides(raw: string | null | undefined): ColumnOverrides {
  if (!raw) return {};
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return {};
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) return {};
  const out: ColumnOverrides = {};
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    const spec = BY_ID.get(k);
    if (!spec || spec.locked || typeof val !== "boolean") continue;
    out[spec.id] = val;
  }
  return out;
}

/** The slice of Storage the helpers need (so tests pass a plain object). */
export type ColumnStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;

/** loadColumnOverrides reads the stored choices; any failure is "none". */
export function loadColumnOverrides(storage: ColumnStorage | null | undefined): ColumnOverrides {
  if (!storage) return {};
  try {
    return parseColumnOverrides(storage.getItem(COLUMN_STORAGE_KEY));
  } catch {
    return {};
  }
}

/**
 * saveColumnOverrides writes the choices (or removes the key when there are
 * none). Returns false when storage refused; the page keeps working with
 * the in-memory choice either way.
 */
export function saveColumnOverrides(
  storage: ColumnStorage | null | undefined,
  overrides: ColumnOverrides,
): boolean {
  if (!storage) return false;
  try {
    if (Object.keys(overrides).length === 0) storage.removeItem(COLUMN_STORAGE_KEY);
    else storage.setItem(COLUMN_STORAGE_KEY, JSON.stringify(overrides));
    return true;
  } catch {
    return false;
  }
}

export type ResolvedColumns = {
  /** The columns to render, in display order. */
  shown: SessionColumnId[];
  /** Default columns the fit rule dropped because the card is too narrow. */
  autoHidden: SessionColumnId[];
  /** Optional columns not shown because they are off (by default or by choice). */
  off: SessionColumnId[];
  /** Sum of the shown columns' width budgets (Session at its fit budget). */
  minWidth: number;
  /** True when the shown columns need more than the available width. */
  overflow: boolean;
  /**
   * The width the flexible Session column declares: whatever the card has
   * left after the other shown columns, at least its fit budget and at most
   * FLEX_MAX (anything beyond that is shared by every column). Null until the
   * card is measured, when Session simply takes the leftover space.
   */
  flexWidth: number | null;
};

/** Session's preferred width on a desktop card: room for a short title next to its status. */
export const FLEX_PREFERRED = 240;
/** Session never grows past this; the rest of a wide card goes to every column. */
export const FLEX_MAX = 360;

/**
 * flexBudget is the width Session counts as while the fit rule runs: a
 * quarter of the card, kept between the column's minimum (a phone) and
 * FLEX_PREFERRED (a desktop). Unmeasured cards use the preferred width.
 */
export function flexBudget(available: number | null): number {
  const min = BY_ID.get("session")?.width ?? 180;
  if (available == null || !Number.isFinite(available)) return FLEX_PREFERRED;
  return Math.max(min, Math.min(FLEX_PREFERRED, Math.round(available / 4)));
}

/**
 * resolveSessionColumns applies the viewer's choices, then the fit rule:
 * while the shown columns need more than `available` px, drop the default-on
 * (not explicitly chosen) column with the highest priority number. A locked
 * column or one the viewer turned on explicitly is never dropped, so a
 * viewer who picks more than fits gets a horizontal scroll, not a column that
 * silently refuses to appear; and when those alone cannot fit, nothing is
 * dropped at all (the table scrolls either way). `available` null (not
 * measured yet) drops nothing.
 */
export function resolveSessionColumns(opts: {
  overrides: ColumnOverrides;
  scoring: boolean;
  available: number | null;
}): ResolvedColumns {
  const { overrides, scoring, available } = opts;
  const measured = available != null && Number.isFinite(available);
  const flex = flexBudget(measured ? available : null);
  const widthOf = (c: SessionColumnSpec) => (c.flex ? flex : c.width);
  const candidates = SESSION_COLUMNS.filter((c) => scoring || !c.scoring);
  const chosen = candidates.filter((c) => c.locked || (overrides[c.id] ?? c.defaultOn));
  const off = candidates.filter((c) => !chosen.includes(c)).map((c) => c.id);
  const kept = new Set(chosen.map((c) => c.id));
  const autoHidden: SessionColumnId[] = [];
  const sum = () => chosen.filter((c) => kept.has(c.id)).reduce((a, c) => a + widthOf(c), 0);
  // What the viewer insisted on (locked + explicitly on). When even that is
  // wider than the card, the table scrolls whatever happens, so hiding
  // default columns would only lose them: drop nothing.
  const required = chosen
    .filter((c) => c.locked || overrides[c.id] === true)
    .reduce((a, c) => a + widthOf(c), 0);
  if (measured && required <= available) {
    let total = sum();
    while (total > available) {
      const droppable = chosen
        .filter((c) => kept.has(c.id) && !c.locked && overrides[c.id] !== true)
        .sort((a, b) => b.priority - a.priority);
      const next = droppable[0];
      if (!next) break;
      kept.delete(next.id);
      autoHidden.push(next.id);
      total -= next.width;
    }
  }
  const shown = chosen.filter((c) => kept.has(c.id)).map((c) => c.id);
  const minWidth = sum();
  const overflow = measured && minWidth > available;
  return {
    shown,
    autoHidden,
    off,
    minWidth,
    overflow,
    flexWidth: !measured
      ? null
      : overflow
        ? flex
        : Math.min(FLEX_MAX, flex + (available - minWidth)),
  };
}

/**
 * toggleColumn records the viewer's explicit choice: a shown column becomes
 * explicitly off, anything not shown (off, or dropped for room) becomes
 * explicitly on. Locked columns ignore the toggle.
 */
export function toggleColumn(
  overrides: ColumnOverrides,
  id: SessionColumnId,
  currentlyShown: boolean,
): ColumnOverrides {
  if (BY_ID.get(id)?.locked) return overrides;
  return { ...overrides, [id]: !currentlyShown };
}

/** hiddenCount is how many optional columns are not on screen. */
export function hiddenCount(r: ResolvedColumns): number {
  return r.autoHidden.length + r.off.length;
}

/**
 * inlineFacets says which facets the Tool cell carries as glyphs: the client
 * and where-it-ran, each only while its own column is not shown, so a
 * viewer who turns the column on does not see it twice.
 */
export function inlineFacets(shown: readonly SessionColumnId[]): { client: boolean; ran: boolean } {
  return { client: !shown.includes("client"), ran: !shown.includes("ran") };
}

// ---------------------------------------------------------------- sorting

export type SortOption = { id: string; desc: boolean; label: string };

/**
 * SORT_OPTIONS backs the toolbar's Sort menu: the server sort keys that are
 * handy without hunting for a header, including the ones whose column is
 * off by default (the four token buckets, which the Tokens column sums and
 * cannot sort by) and rating, which has no column at all.
 */
export const SORT_OPTIONS: readonly SortOption[] = [
  { id: "started_at", desc: true, label: "Started (newest first)" },
  { id: "cost", desc: true, label: "Cost (highest first)" },
  { id: "elapsed", desc: true, label: "Elapsed (longest first)" },
  { id: "actions", desc: true, label: "Actions (most first)" },
  { id: "ai_code_lines", desc: true, label: "AI code lines (most first)" },
  { id: "input", desc: true, label: "Input tokens (most first)" },
  { id: "output", desc: true, label: "Output tokens (most first)" },
  { id: "cache_r", desc: true, label: "Cache reads (most first)" },
  { id: "cache_w", desc: true, label: "Cache writes (most first)" },
  { id: "rating", desc: true, label: "Rating (best first)" },
  { id: "rating", desc: false, label: "Rating (worst first)" },
  { id: "favorite", desc: true, label: "Favorites first" },
];

/** matchSortOption is the menu row for the current sort, if any. */
export function matchSortOption(sortBy: string, desc: boolean): SortOption | undefined {
  return SORT_OPTIONS.find((o) => o.id === sortBy && o.desc === desc);
}

/**
 * sortButtonLabel names the active sort on the toolbar button: the menu row
 * when one matches, otherwise the column's name and direction (a header sort
 * on a column that may now be hidden), otherwise plain "Sort".
 */
export function sortButtonLabel(sortBy: string, desc: boolean): string {
  const opt = matchSortOption(sortBy, desc);
  if (opt) return `Sort: ${opt.label}`;
  const col = BY_ID.get(sortBy);
  if (col) return `Sort: ${col.label} (${sortDirectionWords(sortBy, desc)})`;
  return "Sort";
}

// Header sorts on text columns order by name and Started by time; every
// other sortable column is a number.
const TEXT_SORT_IDS = new Set(["session", "tool", "project"]);
const TIME_SORT_IDS = new Set(["started_at"]);

/** sortDirectionWords says which way a column sort runs, in its own terms. */
export function sortDirectionWords(sortBy: string, desc: boolean): string {
  if (TEXT_SORT_IDS.has(sortBy)) return desc ? "Z to A" : "A to Z";
  if (TIME_SORT_IDS.has(sortBy)) return desc ? "newest first" : "oldest first";
  return desc ? "high to low" : "low to high";
}

// ------------------------------------------------------------ cell helpers

/**
 * projectName is the folder name a project cell shows: the last segment of a
 * POSIX or Windows path, ignoring trailing separators. The full path stays in
 * the tooltip. An empty or separator-only path returns "".
 */
export function projectName(path: string | null | undefined): string {
  const p = (path ?? "").trim().replace(/[\\/]+$/, "");
  if (!p) return "";
  const i = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
  return i >= 0 ? p.slice(i + 1) : p;
}

/** The most tag pills a row shows before the rest collapse into "+n". */
export const MAX_ROW_TAGS = 2;

// Estimated pixel cost of the Tags cell's parts (10px semibold pill text is
// about 6px a character; a pill adds its padding and border). An estimate
// is enough: the pills can still shrink and ellipsize if it is a little off.
const TAG_PX = { perChar: 6, pill: 18, more: 18, note: 16, editor: 16, gap: 4, cellPad: 16 };

/**
 * rowTagCount is how many tag pills a row shows: up to MAX_ROW_TAGS while
 * they fit the cell beside the "+n" count, the note glyph and the editor
 * trigger, and never fewer than one when the row has tags. One readable pill
 * plus "+2" beats two pills cut to "ref…" and "fro…".
 */
export function rowTagCount(tags: readonly string[], hasNote: boolean, cellWidth: number): number {
  if (tags.length === 0) return 0;
  const content = cellWidth - TAG_PX.cellPad;
  const fixed = TAG_PX.editor + (hasNote ? TAG_PX.note + TAG_PX.gap : 0);
  for (let n = Math.min(MAX_ROW_TAGS, tags.length); n > 1; n--) {
    const pills = tags
      .slice(0, n)
      .reduce((a, t) => a + t.length * TAG_PX.perChar + TAG_PX.pill + TAG_PX.gap, 0);
    const more = tags.length > n ? TAG_PX.more + TAG_PX.gap : 0;
    if (pills + more + fixed <= content) return n;
  }
  return 1;
}

/** The token buckets a session row carries (a structural subset of SessionRow). */
export type TokenBuckets = {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_creation_tokens: number;
};

/**
 * sessionTokenTotal is what the Tokens column shows: the four billable
 * buckets added up, the same sum the server's total_tokens carries.
 */
export function sessionTokenTotal(r: TokenBuckets): number {
  const n = (v: number) => (Number.isFinite(v) && v > 0 ? v : 0);
  return n(r.input_tokens) + n(r.output_tokens) + n(r.cache_read_tokens) + n(r.cache_creation_tokens);
}

/** The separator a subagent session id carries (`<parent>:agent:<child>`). */
const SUBAGENT_SEP = ":agent:";

/** parentSessionId is the parent of a subagent session id, or null. */
export function parentSessionId(id: string): string | null {
  const i = id.indexOf(SUBAGENT_SEP);
  return i > 0 ? id.slice(0, i) : null;
}

/** shortSessionId is the 12-character display form of an id (the child part for a subagent). */
export function shortSessionId(id: string): string {
  const child = id.split(SUBAGENT_SEP).at(-1) ?? id;
  return child.length > 12 ? `${child.slice(0, 12)}…` : child;
}

/** The enrichment request's tone, as lib/cloud's chip variant. */
export type EnrichVariant = "neutral" | "info" | "warn" | "danger" | "success" | "accent";

/**
 * ENRICH_TONE_CLASS colours the Session cell's enrichment button by request
 * state. A ready result reads as accent (there is AI content to open), not
 * success; nothing-yet stays muted so 50 idle rows are quiet.
 */
export const ENRICH_TONE_CLASS: Record<EnrichVariant, string> = {
  neutral: "text-fg-4 hover:text-fg-1",
  info: "text-info hover:text-info",
  warn: "text-warn hover:text-warn",
  danger: "text-danger hover:text-danger",
  success: "text-accent hover:text-accent-strong",
  accent: "text-accent hover:text-accent-strong",
};
