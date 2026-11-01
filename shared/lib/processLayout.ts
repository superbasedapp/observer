// processLayout.ts - the pure model behind the session-detail "Call stack"
// view (ProcessFlame + ProcessSpawnStack) and the selection that Tree, Table
// and Call stack share.
//
// What "call stack" means here: the PROCESS spawn chain the operating system
// recorded (which process started which), not a code-level call stack. Depth is
// the spawn chain, width is a process lifetime. Everything is derived from the
// process tree the node (/api/session/<id>/processes) and the org
// (session_process_rows built into a tree from parent_run_key) already serve;
// nothing here needs new capture.
//
// Pure: no React, no DOM, no fetch. Importable under `node --test` (the tests
// live in web/src/lib/processLayout.test.ts).

import type { ProcessNodeLike } from "./types";

/** How a process's bar ends. */
export type ProcessEndKind =
  // exited: the exit was observed; end = start + duration.
  | "exited"
  // running: still alive as of the last capture; the bar runs to "now".
  | "running"
  // unseen: never marked exited, and the capture has not seen it for longer
  // than the staleness window, so its exit was missed (the daemon stopped, or
  // a poll gap). The bar ends at the last time it was seen, drawn faded.
  | "unseen";

/** One process placed on the time axis. Times are epoch milliseconds. */
export type ProcessStackItem = {
  key: string;
  parentKey: string | null;
  depth: number;
  node: ProcessNodeLike;
  start: number;
  end: number;
  endKind: ProcessEndKind;
  /** false when the row had no parseable started_at (placed at its parent's start). */
  timeKnown: boolean;
  /** Known only from the AI tool's own exec record (no OS process was captured). */
  derived: boolean;
  failed: boolean;
};

/** The indexed forest: items in pre-order, lookups, children sorted by start. */
export type ProcessStackIndex = {
  items: ProcessStackItem[];
  byKey: Map<string, ProcessStackItem>;
  children: Map<string | null, ProcessStackItem[]>;
  minStart: number;
  maxEnd: number;
};

/** A process with no capture for this long is treated as "exit not seen". */
export const PROCESS_STALE_MS = 5 * 60_000;

/**
 * isDerivedProcess marks a row synthesized from the AI tool's exec record (a
 * run_command action) rather than observed at the OS level: no pid, no
 * resource metrics, no subtree. Keyed on attribution_source + the pid 0
 * sentinel, the same rule the Tree and Table views use.
 */
export function isDerivedProcess(n: ProcessNodeLike): boolean {
  return n.attribution_source === "action_correlation" && n.pid === 0;
}

/**
 * isFailedProcess: a non-zero exit code or a terminating signal. A derived row
 * only knows success or failure, carried as exit_code 0 or non-zero. A
 * running process has not failed.
 */
export function isFailedProcess(n: ProcessNodeLike): boolean {
  if (isDerivedProcess(n)) return n.exit_code !== 0;
  if (!n.exited) return false;
  return (n.exit_signal ?? 0) > 0 || n.exit_code !== 0;
}

function parseTime(s: string | undefined): number | null {
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

/**
 * indexProcesses walks the forest into placed items. A row with no start time
 * inherits its parent's start (timeKnown=false); a root with none takes the
 * earliest known start. nowMs is the right edge for running processes.
 */
export function indexProcesses(
  roots: ProcessNodeLike[],
  nowMs: number,
  staleMs: number = PROCESS_STALE_MS,
): ProcessStackIndex {
  const items: ProcessStackItem[] = [];
  const byKey = new Map<string, ProcessStackItem>();
  const children = new Map<string | null, ProcessStackItem[]>();

  // First pass: the earliest known start, the fallback for a root without one.
  let earliest = Number.POSITIVE_INFINITY;
  const scan = (ns: ProcessNodeLike[]) => {
    for (const n of ns) {
      const t = parseTime(n.started_at);
      if (t != null && t < earliest) earliest = t;
      scan(n.children);
    }
  };
  scan(roots);
  if (!Number.isFinite(earliest)) earliest = nowMs;

  const visit = (n: ProcessNodeLike, parent: ProcessStackItem | null, depth: number) => {
    if (byKey.has(n.process_key)) return; // defensive: a duplicate key is placed once
    const parsed = parseTime(n.started_at);
    const start = parsed ?? (parent ? parent.start : earliest);
    let end: number;
    let endKind: ProcessEndKind;
    const derived = isDerivedProcess(n);
    if (n.exited || derived) {
      end = start + Math.max(0, n.duration_ms || 0);
      endKind = "exited";
    } else {
      const seen = parseTime(n.last_seen_at);
      if (seen != null && nowMs - seen > staleMs) {
        end = Math.max(start, seen);
        endKind = "unseen";
      } else {
        end = Math.max(start, nowMs);
        endKind = "running";
      }
    }
    const item: ProcessStackItem = {
      key: n.process_key,
      parentKey: parent ? parent.key : null,
      depth,
      node: n,
      start,
      end,
      endKind,
      timeKnown: parsed != null,
      derived,
      failed: isFailedProcess(n),
    };
    items.push(item);
    byKey.set(item.key, item);
    const sib = children.get(item.parentKey) ?? [];
    sib.push(item);
    children.set(item.parentKey, sib);
    for (const c of n.children) visit(c, item, depth + 1);
  };
  for (const r of roots) visit(r, null, 0);

  for (const list of children.values()) list.sort(byStart);
  let minStart = Number.POSITIVE_INFINITY;
  let maxEnd = Number.NEGATIVE_INFINITY;
  for (const it of items) {
    if (it.start < minStart) minStart = it.start;
    if (it.end > maxEnd) maxEnd = it.end;
  }
  if (!items.length) {
    minStart = nowMs;
    maxEnd = nowMs;
  }
  return { items, byKey, children, minStart, maxEnd };
}

function byStart(a: ProcessStackItem, b: ProcessStackItem): number {
  return a.start - b.start || a.node.pid - b.node.pid || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
}

/** chainOf: the selected process then its ancestors up to the root (innermost first). */
export function chainOf(index: ProcessStackIndex, key: string | null | undefined): ProcessStackItem[] {
  const out: ProcessStackItem[] = [];
  let cur = key ? index.byKey.get(key) : undefined;
  const guard = new Set<string>();
  while (cur && !guard.has(cur.key)) {
    guard.add(cur.key);
    out.push(cur);
    cur = cur.parentKey ? index.byKey.get(cur.parentKey) : undefined;
  }
  return out;
}

/** isDescendantOf reports whether `key` sits strictly below `ancestor`. */
export function isDescendantOf(index: ProcessStackIndex, key: string, ancestor: string): boolean {
  return chainOf(index, key).some((it, i) => i > 0 && it.key === ancestor);
}

/** countDescendants: every process below `key`. */
export function countDescendants(index: ProcessStackIndex, key: string): number {
  let n = 0;
  const stack = [...(index.children.get(key) ?? [])];
  while (stack.length) {
    const it = stack.pop()!;
    n++;
    stack.push(...(index.children.get(it.key) ?? []));
  }
  return n;
}

// ---------------------------------------------------------------------------
// Keyboard navigation. One table of moves, shared by the chart and the spawn
// stack: up = the parent, down = the first child, left/right = the previous /
// next sibling by start time.
// ---------------------------------------------------------------------------

export type StackMove = "parent" | "firstChild" | "prevSibling" | "nextSibling";

/** STACK_KEYS maps a keyboard key to a move. Unlisted keys are not handled. */
export const STACK_KEYS: Readonly<Record<string, StackMove>> = {
  ArrowUp: "parent",
  ArrowDown: "firstChild",
  ArrowLeft: "prevSibling",
  ArrowRight: "nextSibling",
};

/**
 * moveSelection returns the key a move lands on, or the current key when the
 * move has nowhere to go. With no selection any move lands on the first root.
 * `visible` (optional) restricts the landing set (e.g. "only failed chains").
 */
export function moveSelection(
  index: ProcessStackIndex,
  key: string | null,
  move: StackMove,
  visible?: ReadonlySet<string>,
): string | null {
  const ok = (it: ProcessStackItem | undefined) => !!it && (!visible || visible.has(it.key));
  if (!key || !index.byKey.has(key)) {
    const first = (index.children.get(null) ?? []).find(ok);
    return first ? first.key : key;
  }
  const cur = index.byKey.get(key)!;
  if (move === "parent") {
    const p = cur.parentKey ? index.byKey.get(cur.parentKey) : undefined;
    return ok(p) ? p!.key : key;
  }
  if (move === "firstChild") {
    const c = (index.children.get(cur.key) ?? []).find(ok);
    return c ? c.key : key;
  }
  const sibs = (index.children.get(cur.parentKey) ?? []).filter(ok);
  const i = sibs.findIndex((s) => s.key === key);
  const j = move === "prevSibling" ? i - 1 : i + 1;
  return j >= 0 && j < sibs.length ? sibs[j].key : key;
}

/** stepInList moves through a flat ordered list (Tree and Table rows). */
export function stepInList(keys: readonly string[], key: string | null, delta: number): string | null {
  if (!keys.length) return key;
  const i = key ? keys.indexOf(key) : -1;
  if (i < 0) return delta >= 0 ? keys[0] : keys[keys.length - 1];
  const j = Math.min(keys.length - 1, Math.max(0, i + delta));
  return keys[j];
}

// ---------------------------------------------------------------------------
// Filters and folding.
// ---------------------------------------------------------------------------

/**
 * failedChainKeys: every failed process plus its whole chain up to the root
 * and everything below it, so the reader still sees where a failure came from
 * and what it took down with it.
 */
export function failedChainKeys(index: ProcessStackIndex): Set<string> {
  const keep = new Set<string>();
  for (const it of index.items) {
    if (!it.failed) continue;
    for (const a of chainOf(index, it.key)) keep.add(a.key);
    const stack = [it.key];
    while (stack.length) {
      const k = stack.pop()!;
      keep.add(k);
      for (const c of index.children.get(k) ?? []) stack.push(c.key);
    }
  }
  return keep;
}

/** A bar on the chart: one process, or a folded group of identical siblings. */
export type StackUnit =
  | { kind: "process"; key: string; item: ProcessStackItem }
  | {
      kind: "group";
      key: string;
      parentKey: string | null;
      depth: number;
      start: number;
      end: number;
      exe: string;
      members: ProcessStackItem[];
      failedCount: number;
      /** processes hidden under the members, not counted in members */
      hiddenBelow: number;
    };

/** Above this many processes the chart folds groups of identical siblings. */
export const FOLD_TOTAL_THRESHOLD = 150;
/** A sibling group folds only when it has more than this many members. */
export const FOLD_MIN_GROUP = 8;
/**
 * ...and only when at least this many of them ran at the same time: a fan-out
 * (test workers, a parallel build) folds, the same command run again and again
 * across the session does not, since those are the session's own steps.
 */
export const FOLD_MIN_CONCURRENT = 3;

/** peakConcurrency: the most items alive at one instant (ends are exclusive). */
export function peakConcurrency(items: readonly { start: number; end: number }[]): number {
  const ev: Array<[number, number]> = [];
  for (const it of items) {
    ev.push([it.start, 1]);
    ev.push([Math.max(it.end, it.start), -1]);
  }
  ev.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  let cur = 0;
  let peak = 0;
  for (const [, d] of ev) {
    cur += d;
    if (cur > peak) peak = cur;
  }
  return peak;
}

/**
 * siblingSignature groups siblings that are "the same thing run many times":
 * same exe and the same command line once numbers are blanked (worker ids,
 * ports, temp suffixes).
 */
export function siblingSignature(n: ProcessNodeLike): string {
  const argv = (n.argv_preview || "").replace(/\d+/g, "#");
  return `${n.exe}\u0000${argv}`;
}

/**
 * buildUnits turns the visible items into chart units. When the session is
 * large, a fan-out of identical siblings (more than FOLD_MIN_GROUP of them, at
 * least FOLD_MIN_CONCURRENT at once) folds into one bar (subtrees hidden),
 * unless the group holds the selected process or the reader expanded it
 * (expanded holds group keys).
 */
export function buildUnits(
  index: ProcessStackIndex,
  opts: {
    visible?: ReadonlySet<string>;
    selectedKey?: string | null;
    expanded?: ReadonlySet<string>;
    fold?: boolean;
  } = {},
): StackUnit[] {
  const fold = opts.fold ?? index.items.length > FOLD_TOTAL_THRESHOLD;
  const selChain = new Set(chainOf(index, opts.selectedKey).map((it) => it.key));
  const units: StackUnit[] = [];
  const walk = (parentKey: string | null) => {
    const kids = (index.children.get(parentKey) ?? []).filter((it) => !opts.visible || opts.visible.has(it.key));
    if (!kids.length) return;
    const groups = new Map<string, ProcessStackItem[]>();
    if (fold) {
      for (const k of kids) {
        const sig = siblingSignature(k.node);
        const g = groups.get(sig) ?? [];
        g.push(k);
        groups.set(sig, g);
      }
    }
    const folded = new Set<string>();
    for (const [sig, members] of groups) {
      if (members.length <= FOLD_MIN_GROUP) continue;
      if (peakConcurrency(members) < FOLD_MIN_CONCURRENT) continue;
      const gkey = `${parentKey ?? ""}#${sig}`;
      if (opts.expanded?.has(gkey) || members.some((m) => selChain.has(m.key))) continue;
      let start = Number.POSITIVE_INFINITY;
      let end = Number.NEGATIVE_INFINITY;
      let failedCount = 0;
      let hiddenBelow = 0;
      for (const m of members) {
        start = Math.min(start, m.start);
        end = Math.max(end, m.end);
        if (m.failed) failedCount++;
        hiddenBelow += countDescendants(index, m.key);
        folded.add(m.key);
      }
      units.push({
        kind: "group",
        key: gkey,
        parentKey,
        depth: members[0].depth,
        start,
        end,
        exe: members[0].node.exe,
        members,
        failedCount,
        hiddenBelow,
      });
    }
    for (const k of kids) {
      if (folded.has(k.key)) continue;
      units.push({ kind: "process", key: k.key, item: k });
      walk(k.key);
    }
  };
  walk(null);
  return units;
}

export function unitStart(u: StackUnit): number {
  return u.kind === "group" ? u.start : u.item.start;
}
export function unitEnd(u: StackUnit): number {
  return u.kind === "group" ? u.end : u.item.end;
}
export function unitDepth(u: StackUnit): number {
  return u.kind === "group" ? u.depth : u.item.depth;
}

// ---------------------------------------------------------------------------
// Lanes: each depth is a band; siblings that overlap in time stack into extra
// lanes inside their band so nothing is drawn on top of anything else.
// ---------------------------------------------------------------------------

export type LaneLayout = {
  /** unit key -> row index from the top (0-based, across all bands) */
  row: Map<string, number>;
  /** one entry per depth: first row and number of lanes */
  bands: { depth: number; firstRow: number; lanes: number }[];
  rows: number;
};

/**
 * packLanes assigns each unit to the first lane in its depth band whose last
 * bar ended at least minGap before it starts (greedy interval packing, in
 * start order).
 */
export function packLanes(units: readonly StackUnit[], minGap = 0): LaneLayout {
  const byDepth = new Map<number, StackUnit[]>();
  for (const u of units) {
    const d = unitDepth(u);
    const list = byDepth.get(d) ?? [];
    list.push(u);
    byDepth.set(d, list);
  }
  const depths = [...byDepth.keys()].sort((a, b) => a - b);
  const row = new Map<string, number>();
  const bands: LaneLayout["bands"] = [];
  let firstRow = 0;
  for (const d of depths) {
    const list = byDepth.get(d)!.slice().sort((a, b) => unitStart(a) - unitStart(b) || (a.key < b.key ? -1 : 1));
    const laneEnds: number[] = [];
    for (const u of list) {
      let lane = laneEnds.findIndex((e) => e + minGap <= unitStart(u));
      if (lane < 0) {
        lane = laneEnds.length;
        laneEnds.push(0);
      }
      laneEnds[lane] = Math.max(unitEnd(u), unitStart(u));
      row.set(u.key, firstRow + lane);
    }
    const lanes = Math.max(1, laneEnds.length);
    bands.push({ depth: d, firstRow, lanes });
    firstRow += lanes;
  }
  return { row, bands, rows: firstRow };
}

// ---------------------------------------------------------------------------
// Time scale. "Skip quiet" squeezes stretches where only long-running
// processes (the agent itself, MCP servers, dev servers) were alive, so a
// 0.2 s command and a 40 s test run are both readable in an hour-long session.
// Inside active stretches time stays linear, so a bar's width stays true.
// ---------------------------------------------------------------------------

export type TimeScale = {
  /** position of a time as a fraction 0..1 of the plot width */
  x: (t: number) => number;
  /** squeezed stretches (real times) */
  gaps: { a: number; b: number }[];
  /** real time at which each active stretch begins (axis tick candidates) */
  runStarts: number[];
  collapsed: boolean;
};

/** A process alive longer than this fraction of the session is "long-running". */
export const LONG_RUNNING_FRACTION = 0.25;

/** quietThresholdMs: the shortest quiet stretch worth squeezing for a domain. */
export function quietThresholdMs(spanMs: number): number {
  return spanMs > 60 * 60_000 ? 90_000 : 12_000;
}

/**
 * buildTimeScale maps real time to plot position over `domain`. With
 * collapse=false it is linear. With collapse=true every stretch longer than
 * the quiet threshold in which no short-lived ("foreground") process was alive
 * is drawn at a fixed narrow width.
 */
export function buildTimeScale(
  items: readonly { start: number; end: number }[],
  domain: readonly [number, number],
  opts: { collapse: boolean; sessionSpanMs?: number; quietMs?: number } = { collapse: false },
): TimeScale {
  const [d0, d1] = domain;
  const span = Math.max(1, d1 - d0);
  const clamp = (t: number) => Math.min(d1, Math.max(d0, t));
  if (!opts.collapse) {
    return { x: (t) => (clamp(t) - d0) / span, gaps: [], runStarts: [], collapsed: false };
  }
  const sessionSpan = Math.max(1, opts.sessionSpanMs ?? span);
  const quiet = opts.quietMs ?? quietThresholdMs(sessionSpan);
  const squeezed = quiet * 0.45;

  // Breakpoints: every start/end inside the domain, plus the domain edges.
  const pts = new Set<number>([d0, d1]);
  const delta = new Map<number, number>(); // foreground alive-count change at a time
  let aliveAtD0 = 0;
  for (const it of items) {
    if (it.start > d0 && it.start < d1) pts.add(it.start);
    if (it.end > d0 && it.end < d1) pts.add(it.end);
    if (it.end - it.start >= sessionSpan * LONG_RUNNING_FRACTION) continue;
    if (it.end <= d0 || it.start >= d1 || it.end <= it.start) continue;
    if (it.start <= d0) aliveAtD0++;
    else delta.set(it.start, (delta.get(it.start) ?? 0) + 1);
    if (it.end < d1) delta.set(it.end, (delta.get(it.end) ?? 0) - 1);
  }
  const arr = [...pts].sort((a, b) => a - b);
  const segs: { a: number; b: number; d0: number; dl: number }[] = [];
  const gaps: TimeScale["gaps"] = [];
  const runStarts: number[] = [];
  let acc = 0;
  let alive = aliveAtD0;
  let prevGap = true;
  for (let i = 0; i < arr.length - 1; i++) {
    const a = arr[i];
    const b = arr[i + 1];
    if (i > 0) alive += delta.get(a) ?? 0;
    const len = b - a;
    const gap = len > quiet && alive <= 0;
    const dl = gap ? squeezed : len;
    segs.push({ a, b, d0: acc, dl });
    acc += dl;
    if (gap) gaps.push({ a, b });
    else if (prevGap) runStarts.push(a);
    prevGap = gap;
  }
  const total = Math.max(1, acc);
  const x = (tIn: number) => {
    const t = clamp(tIn);
    let lo = 0;
    let hi = segs.length - 1;
    while (lo < hi) {
      const m = (lo + hi) >> 1;
      if (segs[m].b < t) lo = m + 1;
      else hi = m;
    }
    const s = segs[lo];
    if (!s) return 0;
    const f = s.b > s.a ? (t - s.a) / (s.b - s.a) : 0;
    return (s.d0 + f * s.dl) / total;
  };
  return { x, gaps, runStarts, collapsed: true };
}

/** NICE_STEPS_MS: axis tick steps for a linear scale, smallest first. */
const NICE_STEPS_MS = [
  100, 250, 500, 1_000, 2_000, 5_000, 10_000, 15_000, 30_000, 60_000, 120_000, 300_000, 600_000,
  900_000, 1_800_000, 3_600_000, 7_200_000, 21_600_000, 43_200_000, 86_400_000,
];

/** linearTicks: tick times for a linear domain, about `approx` of them. */
export function linearTicks(domain: readonly [number, number], approx: number): number[] {
  const span = Math.max(1, domain[1] - domain[0]);
  const want = span / Math.max(1, approx);
  const step = NICE_STEPS_MS.find((s) => s >= want) ?? NICE_STEPS_MS[NICE_STEPS_MS.length - 1];
  const out: number[] = [];
  for (let t = domain[0]; t <= domain[1] + 1e-6; t += step) out.push(t);
  return out;
}

/** fmtOffset renders a time relative to the session start: "+0:42", "+12:05", "+1h05m". */
export function fmtOffset(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `+${h}h${String(m).padStart(2, "0")}m`;
  return `+${m}:${String(s).padStart(2, "0")}`;
}

// ---------------------------------------------------------------------------
// Turn markers and the overview strip.
// ---------------------------------------------------------------------------

export type TurnMarker = { turn: number; at: number; messageId?: string; processes: number };

/**
 * turnMarkers: one marker per turn that started a process, placed at the first
 * process that turn started (honest: it is not the turn's own start time) and
 * carrying a message id when any of its processes was linked to one.
 */
export function turnMarkers(index: ProcessStackIndex): TurnMarker[] {
  const by = new Map<number, TurnMarker>();
  for (const it of index.items) {
    const t = it.node.turn_index;
    if (t == null) continue;
    const m = by.get(t) ?? { turn: t, at: it.start, processes: 0 };
    m.at = Math.min(m.at, it.start);
    m.processes++;
    if (!m.messageId && it.node.message_id) m.messageId = it.node.message_id;
    by.set(t, m);
  }
  return [...by.values()].sort((a, b) => a.at - b.at || a.turn - b.turn);
}

/** overviewBuckets counts process starts (and failures) per time bucket. */
export function overviewBuckets(
  index: ProcessStackIndex,
  n: number,
): { counts: number[]; failures: number[]; bucketMs: number } {
  const counts = new Array<number>(n).fill(0);
  const failures = new Array<number>(n).fill(0);
  const span = Math.max(1, index.maxEnd - index.minStart);
  const bucketMs = span / n;
  for (const it of index.items) {
    const b = Math.min(n - 1, Math.max(0, Math.floor((it.start - index.minStart) / bucketMs)));
    counts[b]++;
    if (it.failed) failures[b]++;
  }
  return { counts, failures, bucketMs };
}

/**
 * defaultWindow picks the chart window for a large session: the top-level
 * command (the selection's ancestor just below the root) padded, else the most
 * recent stretch of `width`. Always inside the session.
 */
export function defaultWindow(
  index: ProcessStackIndex,
  selectedKey: string | null,
  width: number,
): [number, number] {
  const lo = index.minStart;
  const hi = index.maxEnd;
  const w = Math.min(width, hi - lo);
  const chain = chainOf(index, selectedKey);
  if (chain.length) {
    const top = chain.length >= 2 ? chain[chain.length - 2] : chain[0];
    const center = top.start + Math.min(top.end - top.start, w) / 2;
    const a = Math.min(Math.max(lo, center - w / 2), hi - w);
    return [a, a + w];
  }
  return [hi - w, hi];
}

/**
 * zoomWindow: the selection's top-level command (its ancestor just below the
 * root), padded by 8% each side, clamped to the session.
 */
export function zoomWindow(index: ProcessStackIndex, selectedKey: string | null): [number, number] | null {
  const chain = chainOf(index, selectedKey);
  if (!chain.length) return null;
  const top = chain.length >= 2 ? chain[chain.length - 2] : chain[0];
  const a = top.start;
  const b = Math.max(top.end, a + 1);
  const pad = (b - a) * 0.08 + 250;
  return [Math.max(index.minStart, a - pad), Math.min(index.maxEnd, b + pad)];
}

// ---------------------------------------------------------------------------
// Capture honesty: what the partial-capture note reports.
// ---------------------------------------------------------------------------

export type CaptureGaps = { exitNotSeen: number; toolLogOnly: number; parentNotCaptured: number };

/**
 * DIRECT_ATTRIBUTION: the attribution sources that tie a process to the session
 * on its own evidence (the AI tool's root pid via the pid bridge, an adapter's
 * pid, the session env token). Such a process is where the session's own
 * process tree starts: the agent.
 */
const DIRECT_ATTRIBUTION: ReadonlySet<string> = new Set(["bridge", "adapter_pid", "env_token"]);

/** isAgentProcess: attributed on its own evidence, i.e. the agent's own process. */
export function isAgentProcess(n: ProcessNodeLike): boolean {
  return DIRECT_ATTRIBUTION.has(n.attribution_source);
}

/**
 * parentNotCaptured: a root that was attributed by INHERITANCE from an
 * ancestor, yet that ancestor is not in the session's rows - so its parent
 * existed and was never captured. A directly attributed root (the agent), a
 * boundary process and a tool-log row are legitimate roots.
 */
export function parentNotCaptured(_index: ProcessStackIndex, item: ProcessStackItem): boolean {
  return (
    item.parentKey === null &&
    !item.derived &&
    !item.node.is_boundary &&
    item.node.attribution_source === "inherited" &&
    item.node.ppid > 0
  );
}

/** captureGaps counts the reasons a chart is incomplete. */
export function captureGaps(index: ProcessStackIndex): CaptureGaps {
  let exitNotSeen = 0;
  let toolLogOnly = 0;
  let orphans = 0;
  for (const it of index.items) {
    if (it.endKind === "unseen") exitNotSeen++;
    if (it.derived) toolLogOnly++;
    if (parentNotCaptured(index, it)) orphans++;
  }
  return { exitNotSeen, toolLogOnly, parentNotCaptured: orphans };
}

/** stackText renders a chain as plain text for "Copy", innermost first. */
export function stackText(chain: readonly ProcessStackItem[], sessionLabel?: string): string {
  const lines = chain.map((it, i) => {
    const n = it.node;
    const who = it.derived ? `${n.exe} (from tool log)` : `${n.exe} pid ${n.pid}`;
    const state =
      it.endKind === "running"
        ? "running"
        : it.endKind === "unseen"
          ? "exit not seen"
          : it.derived
            ? it.failed
              ? "failed"
              : "ok"
            : (n.exit_signal ?? 0) > 0
              ? `signal ${n.exit_signal}`
              : `exit ${n.exit_code}`;
    const argv = n.argv_preview ? `  ${n.argv_preview}` : "";
    return `#${i} ${who} ${state}${argv}`;
  });
  if (sessionLabel) lines.push(`#${chain.length} ${sessionLabel}`);
  return lines.join("\n");
}
