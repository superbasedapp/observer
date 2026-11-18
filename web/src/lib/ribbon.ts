import { fmtCompact, fmtCostAs, type CostDisplayMode } from "../../../shared/lib/format.ts";
import type { DotTable } from "./liveSignals.ts";

// ribbon.ts: the live ribbon's pure model (local dashboard first run §8.2 to
// §8.5). The ribbon lives in the shell on every page: a chip in the top bar
// ("No agent running · Start one" when idle, "N live" when the strip is
// folded away) and a slim strip under the top bar while an agent session is
// live. Every decision here is a table walked top-down (CLAUDE.md #5), so
// ribbon.test.ts pins one case per row. Pure: no fetch, no React, no storage
// of its own (storage is injected), so the node tests run it as is.
//
// Honesty rules (binding, §8.4): numbers come only from the server and the
// counters tween between two real readings; a pulse only when a session's
// last activity really advanced; cost reads "est." when any part is an
// estimate, "cost not recorded" when the tool keeps no tokens, "price
// unknown" (never $0) when a model has no price; and the ribbon never shows
// an action, a file name or a path, only the project's name.

// ---------------------------------------------------------------- wire

/** The ribbon read: GET /api/live?view=ribbon. */
export const RIBBON_PATH = "/api/live";
export const RIBBON_PARAMS = { view: "ribbon" } as const;
/** The detail poll while something is live (the tooltip says so). */
export const RIBBON_POLL_MS = 5000;
/** A session with no activity for this long reads "quiet". */
export const QUIET_AFTER_MS = 2 * 60_000;
/** A session with activity this recent pings. */
export const ACTIVE_WITHIN_MS = 30_000;
/** The first-prompt receipt closes by itself after this long. */
export const RECEIPT_AUTOCLOSE_MS = 12_000;
/** The dismissal key the receipt is closed with (the daemon accepts it). */
export const RECEIPT_NOTICE = "first_prompt_receipt";
/** The per-browser "strip minimised" preference. */
export const RIBBON_MINIMISED_KEY = "sb_live_ribbon_minimised";

/** One live session as GET /api/live?view=ribbon returns it. */
export type RibbonSession = {
  session_id: string;
  tool: string;
  /** The project's name, never its path. */
  project?: string;
  model?: string;
  model_count: number;
  /** Lifetime tokens, all four buckets. */
  tokens: number;
  cost_usd: number;
  cost_estimated: boolean;
  /** False when the tool keeps no tokens on this machine. */
  cost_recorded: boolean;
  price_unknown: boolean;
  turns: number;
  actions_total: number;
  started_at: string;
  last_activity: string;
};

/** The one-time "Your first captured prompt" summary. */
export type RibbonReceipt = {
  session_id: string;
  tool: string;
  project?: string;
  model?: string;
  tokens: number;
  cost_usd: number;
  cost_estimated: boolean;
  cost_recorded: boolean;
  price_unknown: boolean;
  turns: number;
  files_read: number;
  edits: number;
  commands: number;
  fired_at?: string;
};

export type RibbonResponse = {
  generated_at: string;
  window_minutes: number;
  /** "ribbon" on a daemon that knows this read; absent on an older one. */
  view?: string;
  enabled: boolean;
  active_count: number;
  sessions: RibbonSession[];
  receipt?: RibbonReceipt | null;
};

/** The words the ribbon uses, in one place. */
export const RIBBON_TEXT = {
  idle: "No agent running",
  start: "Start one",
  live: (n: number) => `${n} live`,
  openLive: "Open Live",
  more: (n: number) => `+${n}`,
  moreOnLive: (n: number) => `${n} more on the Live page`,
  minimise: "Fold the live ribbon into the top bar",
  expand: "Show the live ribbon",
  notRecorded: "cost not recorded",
  noTokensYet: "no tokens yet",
  priceUnknown: "price unknown",
  est: "est.",
  lag: "Lifetime so far. Updates every 5 s while this tab is visible.",
  receiptTitle: "Your first captured prompt",
  openSession: "Open the session",
  nextCost: "Next: see Cost",
} as const;

// ---------------------------------------------------------------- gate

/** What decides whether the ribbon reads its detail. */
export type GateInput = {
  /** The org hid the Live page on this machine (or the posture is unknown). */
  liveHidden: boolean;
  /** [dashboard].live_ribbon, or null before the first read answered. */
  enabled: boolean | null;
  /** The nav's live count (/api/status, memoized ~15 s), null when unknown. */
  statusLive: number | null;
  /** A dashboard terminal is running in this tab's dock. */
  dockRunning: boolean;
  /** Sessions the last detail read reported live. */
  detailLive: number;
};

type GateRule = { name: string; when: (i: GateInput) => boolean; poll: boolean };

/**
 * GATE_RULES: the two-tier polling rule (§8.5). The free gate is the nav's
 * own count; the 5 s detail read runs only while something may be live.
 */
export const GATE_RULES: readonly GateRule[] = [
  { name: "the org hid Live: no ribbon, no read", when: (i) => i.liveHidden, poll: false },
  { name: "switched off in Settings", when: (i) => i.enabled === false, poll: false },
  { name: "a dashboard terminal is running: skip the lagging count", when: (i) => i.dockRunning, poll: true },
  { name: "the nav count says something is live", when: (i) => (i.statusLive ?? 0) > 0, poll: true },
  { name: "the last detail read still had live sessions", when: (i) => i.detailLive > 0, poll: true },
  { name: "quiet machine: no detail traffic", when: () => true, poll: false },
];

/** shouldPollDetail walks GATE_RULES. */
export function shouldPollDetail(i: GateInput): boolean {
  return (GATE_RULES.find((r) => r.when(i)) ?? GATE_RULES[GATE_RULES.length - 1]).poll;
}

// ---------------------------------------------------------------- chip

export type ChipInput = {
  /** Live hidden by the org, or the ribbon switched off. */
  off: boolean;
  /** The ?connecting=1 hand-off is waiting. */
  handoffWaiting: boolean;
  /** How many sessions are live. */
  live: number;
  /** The strip is on screen (it carries the live state itself). */
  stripOpen: boolean;
  /** This viewer may launch a terminal (owner-local, or a remote with the capability). */
  canLaunch: boolean;
};

export type ChipView =
  | { kind: "hidden" }
  | { kind: "idle"; text: string; action: string | null }
  | { kind: "live"; text: string };

type ChipRule = { name: string; when: (i: ChipInput) => boolean; view: (i: ChipInput) => ChipView };

/** CHIP_RULES: what the top-bar chip shows (§8.2, §8.3). */
export const CHIP_RULES: readonly ChipRule[] = [
  { name: "off or hidden by the org", when: (i) => i.off, view: () => ({ kind: "hidden" }) },
  {
    name: "hand-off waiting and nothing live: no decisions on screen",
    when: (i) => i.handoffWaiting && i.live === 0,
    view: () => ({ kind: "hidden" }),
  },
  {
    name: "nothing live",
    when: (i) => i.live === 0,
    view: (i) => ({ kind: "idle", text: RIBBON_TEXT.idle, action: i.canLaunch ? RIBBON_TEXT.start : null }),
  },
  { name: "the strip is open: it carries the live state", when: (i) => i.stripOpen, view: () => ({ kind: "hidden" }) },
  { name: "live with the strip folded away", when: () => true, view: (i) => ({ kind: "live", text: RIBBON_TEXT.live(i.live) }) },
];

/** chipView walks CHIP_RULES. */
export function chipView(i: ChipInput): ChipView {
  const rule = CHIP_RULES.find((r) => r.when(i)) ?? CHIP_RULES[CHIP_RULES.length - 1];
  return rule.view(i);
}

// ---------------------------------------------------------------- strip

export type StripInput = {
  off: boolean;
  live: number;
  minimised: boolean;
  /** Wide enough for the strip (>= sm); a phone keeps the chip. */
  wide: boolean;
};

type StripRule = { name: string; when: (i: StripInput) => boolean; open: boolean };

/** STRIP_RULES: whether the 32 px strip is on screen. Never empty. */
export const STRIP_RULES: readonly StripRule[] = [
  { name: "off or hidden by the org", when: (i) => i.off, open: false },
  { name: "nothing live: the chip says so", when: (i) => i.live === 0, open: false },
  { name: "minimised in this browser", when: (i) => i.minimised, open: false },
  { name: "phone width: the chip only", when: (i) => !i.wide, open: false },
  { name: "something live", when: () => true, open: true },
];

/** stripOpen walks STRIP_RULES. */
export function stripOpen(i: StripInput): boolean {
  return (STRIP_RULES.find((r) => r.when(i)) ?? STRIP_RULES[STRIP_RULES.length - 1]).open;
}

export type StripLayout = {
  mode: "single" | "segments" | "collapsed";
  /** The sessions drawn as segments, newest activity first. */
  shown: RibbonSession[];
  /** How many live sessions are not drawn ("+N"). */
  more: number;
};

type LayoutRule = { name: string; when: (n: number, max: number) => boolean; layout: (s: RibbonSession[], total: number, max: number) => StripLayout };

/**
 * LAYOUT_RULES: several live sessions collapse by count and by width (§8.2).
 * maxSegments is how many compact segments fit: 3 on a wide screen, 1 on a
 * narrow one.
 */
export const LAYOUT_RULES: readonly LayoutRule[] = [
  { name: "one session: the full segment", when: (n) => n <= 1, layout: (s) => ({ mode: "single", shown: s.slice(0, 1), more: 0 }) },
  {
    name: "a few that fit: compact segments",
    when: (n, max) => n <= max,
    layout: (s) => ({ mode: "segments", shown: s, more: 0 }),
  },
  {
    name: "more than fit: N live, the newest, +N",
    when: () => true,
    layout: (s, total, max) => {
      const shown = s.slice(0, Math.min(2, max));
      return { mode: "collapsed", shown, more: Math.max(0, total - shown.length) };
    },
  },
];

/** stripLayout walks LAYOUT_RULES. `total` is active_count (may exceed sessions). */
export function stripLayout(sessions: RibbonSession[], total: number, maxSegments: number): StripLayout {
  const n = Math.max(total, sessions.length);
  const rule = LAYOUT_RULES.find((r) => r.when(n, maxSegments)) ?? LAYOUT_RULES[LAYOUT_RULES.length - 1];
  return rule.layout(sessions, n, maxSegments);
}

// ---------------------------------------------------------------- cells

/** The cost part of a session or receipt. */
type CostFacts = Pick<RibbonSession, "cost_usd" | "cost_estimated" | "cost_recorded" | "price_unknown" | "turns">;

export type CostCell = { kind: "hidden" } | { kind: "text"; text: string; muted: boolean };

type CostRule = { name: string; when: (c: CostFacts, mode: CostDisplayMode) => boolean; cell: (c: CostFacts) => CostCell };

// A real cost under a cent reads "<$0.01", never a rounded "$0.00".
const money = (usd: number) => (usd > 0 && usd < 0.01 ? "<$0.01" : fmtCostAs("usd", usd));

/** COST_RULES: how a cost reads (§8.4 rule 3). Never $0 for an unpriced model. */
export const COST_RULES: readonly CostRule[] = [
  { name: "the tool keeps no tokens here", when: (c) => !c.cost_recorded, cell: () => ({ kind: "text", text: RIBBON_TEXT.notRecorded, muted: true }) },
  { name: "no turn captured yet", when: (c) => c.turns === 0, cell: () => ({ kind: "text", text: RIBBON_TEXT.noTokensYet, muted: true }) },
  { name: "the org shows token usage, not dollars", when: (_c, mode) => mode === "tokens", cell: () => ({ kind: "hidden" }) },
  {
    name: "nothing priced at all",
    when: (c) => c.price_unknown && c.cost_usd === 0,
    cell: () => ({ kind: "text", text: RIBBON_TEXT.priceUnknown, muted: true }),
  },
  {
    name: "any part estimated or unpriced",
    when: (c) => c.cost_estimated || c.price_unknown,
    cell: (c) => ({ kind: "text", text: `${money(c.cost_usd)} ${RIBBON_TEXT.est}`, muted: false }),
  },
  { name: "every turn proxy-recorded", when: () => true, cell: (c) => ({ kind: "text", text: money(c.cost_usd), muted: false }) },
];

/** costCell walks COST_RULES. */
export function costCell(c: CostFacts, mode: CostDisplayMode = "usd"): CostCell {
  const rule = COST_RULES.find((r) => r.when(c, mode)) ?? COST_RULES[COST_RULES.length - 1];
  return rule.cell(c);
}

/** The cost total for 2+ sessions ("3 live · $1.42 est."), or hidden when no
 *  session carries a priced cost. */
export function totalCostCell(sessions: RibbonSession[], mode: CostDisplayMode = "usd"): CostCell {
  const priced = sessions.filter((s) => s.cost_recorded && s.turns > 0);
  if (priced.length === 0 || mode === "tokens") return { kind: "hidden" };
  const facts: CostFacts = {
    cost_usd: priced.reduce((a, s) => a + s.cost_usd, 0),
    cost_estimated: priced.some((s) => s.cost_estimated),
    price_unknown: priced.some((s) => s.price_unknown),
    cost_recorded: true,
    turns: priced.reduce((a, s) => a + s.turns, 0),
  };
  return costCell(facts, mode);
}

/** "18.2k tok", or null when the session has no tokens to show. */
export function tokensText(s: Pick<RibbonSession, "tokens" | "turns" | "cost_recorded">): string | null {
  if (!s.cost_recorded || s.turns === 0) return null;
  return `${fmtCompact(s.tokens)} tok`;
}

/** The model label: the newest turn's model, "+N" for the others. */
export function modelText(s: Pick<RibbonSession, "model" | "model_count">): string | null {
  if (!s.model) return null;
  return s.model_count > 1 ? `${s.model} +${s.model_count - 1}` : s.model;
}

/** "14 actions" for a tool that keeps no tokens, else null. */
export function actionsText(s: Pick<RibbonSession, "cost_recorded" | "actions_total">): string | null {
  if (s.cost_recorded) return null;
  return `${s.actions_total} ${s.actions_total === 1 ? "action" : "actions"}`;
}

/** Whole minutes as "<1 m", "12 m" or "1 h 5 m". */
export function fmtMinutes(ms: number): string {
  const m = Math.floor(Math.max(0, ms) / 60_000);
  if (m < 1) return "<1 m";
  if (m < 60) return `${m} m`;
  const h = Math.floor(m / 60);
  const rest = m % 60;
  return rest === 0 ? `${h} h` : `${h} h ${rest} m`;
}

function ageMs(iso: string, nowMs: number): number | null {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? Math.max(0, nowMs - t) : null;
}

export type Freshness = "active" | "recent" | "quiet";

/** freshness: pings under 30 s, quiet after 2 min of no activity. */
export function freshness(s: Pick<RibbonSession, "last_activity">, nowMs: number): Freshness {
  const age = ageMs(s.last_activity, nowMs);
  if (age == null) return "quiet";
  if (age < ACTIVE_WITHIN_MS) return "active";
  if (age < QUIET_AFTER_MS) return "recent";
  return "quiet";
}

/** RIBBON_DOT: the per-session dot by freshness (§8.4). */
export const RIBBON_DOT: DotTable = {
  active: { tone: "success" },
  recent: { tone: "success", still: true },
  quiet: { tone: "idle", still: true },
};

/** "running 12 m" from the start, or "quiet 4 m" since the last activity. */
export function timeText(s: Pick<RibbonSession, "started_at" | "last_activity">, nowMs: number): string {
  if (freshness(s, nowMs) === "quiet") {
    return `quiet ${fmtMinutes(ageMs(s.last_activity, nowMs) ?? 0)}`;
  }
  const run = ageMs(s.started_at, nowMs);
  return run == null ? "running" : `running ${fmtMinutes(run)}`;
}

// ---------------------------------------------------------------- pulse

/**
 * advancedSessions returns the ids whose last activity moved forward since
 * the previous reading. The first reading (prev null) pulses nothing, and a
 * session seen for the first time does not pulse (it arrives instead).
 */
export function advancedSessions(
  prev: Readonly<Record<string, string>> | null,
  next: readonly Pick<RibbonSession, "session_id" | "last_activity">[],
): Set<string> {
  const out = new Set<string>();
  if (prev == null) return out;
  for (const s of next) {
    const before = prev[s.session_id];
    if (before == null) continue;
    const a = Date.parse(before);
    const b = Date.parse(s.last_activity);
    if (Number.isFinite(a) && Number.isFinite(b) && b > a) out.add(s.session_id);
  }
  return out;
}

/** lastActivityMap is the reading advancedSessions compares against. */
export function lastActivityMap(sessions: readonly Pick<RibbonSession, "session_id" | "last_activity">[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const s of sessions) out[s.session_id] = s.last_activity;
  return out;
}

// ---------------------------------------------------------------- receipt

export type ReceiptInput = {
  receipt: RibbonReceipt | null | undefined;
  /** The ribbon itself is shown (on, and Live not hidden). */
  ribbonOn: boolean;
  /** A remote viewer cannot close it on the daemon, so never sees it. */
  isRemote: boolean;
  /** Closed already (this tab or the daemon's dismissal list). */
  dismissed: boolean;
  /** Demo data is being served. The daemon never sends it then; belt and braces. */
  demo: boolean;
};

type ReceiptRule = { name: string; when: (i: ReceiptInput) => boolean; show: boolean };

/** RECEIPT_RULES: whether the one-time receipt card shows. */
export const RECEIPT_RULES: readonly ReceiptRule[] = [
  { name: "nothing fired", when: (i) => !i.receipt, show: false },
  { name: "the ribbon is off or hidden", when: (i) => !i.ribbonOn, show: false },
  { name: "demo data", when: (i) => i.demo, show: false },
  { name: "a remote viewer", when: (i) => i.isRemote, show: false },
  { name: "already closed", when: (i) => i.dismissed, show: false },
  { name: "fired and not closed", when: () => true, show: true },
];

/** receiptVisible walks RECEIPT_RULES. */
export function receiptVisible(i: ReceiptInput): boolean {
  return (RECEIPT_RULES.find((r) => r.when(i)) ?? RECEIPT_RULES[RECEIPT_RULES.length - 1]).show;
}

/** The receipt's two lines: the numbers, and what the agent did. */
export function receiptLines(r: RibbonReceipt, mode: CostDisplayMode = "usd"): { stats: string; work: string | null } {
  const parts: string[] = [];
  const model = modelText({ model: r.model, model_count: 1 });
  if (model) parts.push(model);
  const tok = tokensText(r);
  if (tok) parts.push(tok.replace(/ tok$/, " tokens"));
  const cost = costCell(r, mode);
  if (cost.kind === "text") parts.push(cost.text);
  const work: string[] = [];
  const count = (n: number, one: string, many: string) => {
    if (n > 0) work.push(`${n} ${n === 1 ? one : many}`);
  };
  count(r.files_read, "file read", "files read");
  count(r.edits, "edit", "edits");
  count(r.commands, "command", "commands");
  return { stats: parts.join(" · "), work: work.length ? work.join(" · ") : null };
}

/** Whether FirstCaptureToast may still celebrate: only where the receipt
 *  cannot (one celebration, not two). */
export type ToastInput = {
  /** The ribbon read answered at all. */
  answered: boolean;
  /** It answered with the ribbon shape (a daemon that has the receipt). */
  supported: boolean;
  /** The ribbon is on and Live is not hidden. */
  ribbonOn: boolean;
};

type ToastRule = { name: string; when: (i: ToastInput) => boolean; toast: boolean };

/** TOAST_RULES: who owns the first-capture celebration. */
export const TOAST_RULES: readonly ToastRule[] = [
  { name: "not known yet: wait", when: (i) => !i.answered, toast: false },
  { name: "an older daemon without the receipt", when: (i) => !i.supported, toast: true },
  { name: "the ribbon is off or hidden: the toast stays", when: (i) => !i.ribbonOn, toast: true },
  { name: "the receipt owns the first capture", when: () => true, toast: false },
];

/** firstCaptureToastAllowed walks TOAST_RULES. */
export function firstCaptureToastAllowed(i: ToastInput): boolean {
  return (TOAST_RULES.find((r) => r.when(i)) ?? TOAST_RULES[TOAST_RULES.length - 1]).toast;
}

// ---------------------------------------------------------------- actions

/** The dock session a ribbon session runs in, by its own id or the
 *  terminal link's correlated id; null for a session started elsewhere. */
export function dockTokenFor(
  sessionId: string,
  dock: readonly { token: string; sessionId: string }[],
  links: Readonly<Record<string, string>>,
): string | null {
  for (const d of dock) {
    if (d.sessionId && d.sessionId === sessionId) return d.token;
  }
  for (const d of dock) {
    if (links[d.token] && links[d.token] === sessionId) return d.token;
  }
  return null;
}

/** The tool "Start one" preselects: the most used one on this machine, or
 *  null for the dialog's own default. */
export function startToolFor(perTool: readonly { tool: string; action_count: number }[] | null | undefined): string | null {
  let best: { tool: string; action_count: number } | null = null;
  for (const t of perTool ?? []) {
    if (!t.tool) continue;
    if (best == null || t.action_count > best.action_count) best = t;
  }
  return best?.tool ?? null;
}

// ---------------------------------------------------------------- storage

/** The minimal Storage the minimise preference needs (injected). */
export type KeyValueStore = Pick<Storage, "getItem" | "setItem" | "removeItem">;

/** readMinimised: the strip is folded away in this browser. Fails to "not". */
export function readMinimised(store: KeyValueStore | null | undefined): boolean {
  try {
    return store?.getItem(RIBBON_MINIMISED_KEY) === "1";
  } catch {
    return false;
  }
}

/** writeMinimised keeps the preference; a storage failure is ignored. */
export function writeMinimised(store: KeyValueStore | null | undefined, minimised: boolean): void {
  try {
    if (minimised) store?.setItem(RIBBON_MINIMISED_KEY, "1");
    else store?.removeItem(RIBBON_MINIMISED_KEY);
  } catch {
    // A private window or blocked storage: the strip simply opens next time.
  }
}
