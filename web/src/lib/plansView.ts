// plansView: the pure view rules of the Plans & limits page. What a card
// leads with (what is LEFT, D-681), how the provider picker groups, filters
// and sorts the catalogue, which providers the "Track more" section
// suggests, which providers the experimental list shows, and which existing
// mark each provider wears. No React and no fetch, so the node test runner
// covers every rule (plansView.test.ts).

import { dollarsShown, fmtCompact, fmtRelative } from "../../../shared/lib/format.ts";
import {
  COVERAGE_LABELS,
  GAP_LABELS,
  GROUP_LABELS,
  SHOWS_LABELS,
  SOURCE_HOWTO,
  SOURCE_LABELS,
  fmtAmount,
  isMoney,
  periodPhrase,
  providerLabel,
  windowLabel,
  type CatalogProvider,
  type PlanAccount,
  type PlanBalance,
  type PlanCard,
  type PlanHeadline,
  type PlanSpend,
  type PlanUsageView,
  type StatusVocab,
  type Tone,
} from "./plans.ts";

// ---------- the headline ----------

/** HeadlineView is what a card's lead block renders. */
export type HeadlineView = {
  /** The big number, already worded: "$18.42 left", "36% left". */
  value: string;
  /** A short phrase beside it: "this week", "on this key". */
  context?: string;
  /** Quieter facts under it: "of $40.00, $21.58 used", "resets in 2 days". */
  details: string[];
  /** One honest note, e.g. that the vendor reports usage only. */
  note?: string;
  /** The share left, 0..1, when known (draws the meter). */
  leftFrac?: number;
  /** Colour of the big number: neutral unless little is left. */
  tone: Tone;
  /** The same balance in each other currency held: "CN¥52.30 left". Never converted. */
  also?: string[];
};

/** WINDOW_PHRASES words a window key after "36% left". */
const WINDOW_PHRASES: Record<string, string> = {
  "5h": "in this 5-hour window",
  daily: "today",
  weekly: "this week",
  monthly: "this month",
  cycle: "this cycle",
  key_cap: "on this key",
  spend_limit: "of the spend limit",
  extra_usage: "of extra usage",
  free_daily_requests: "of today's free requests",
  premium: "of premium requests",
  ai_credit: "of AI credits",
  bonus: "of bonus credits",
};

/** windowPhrase: "this week" for a known key, else the window's own label. */
export function windowPhrase(key: string): string {
  return WINDOW_PHRASES[key] ?? windowLabel(key);
}

/** USED_ONLY_NOTE is the one line under a usage-only headline. */
export const USED_ONLY_NOTE = "This vendor reports usage, not what is left.";

/** HIDDEN_MONEY_NOTE explains a money headline in the token cost display. */
export const HIDDEN_MONEY_NOTE = "Dollar amounts are hidden on this dashboard.";

function basisParts(basis: string | undefined): [string, string] {
  if (!basis) return ["", ""];
  const at = basis.indexOf(":");
  return at < 0 ? [basis, ""] : [basis.slice(0, at), basis.slice(at + 1)];
}

function leftTone(frac: number | undefined): Tone {
  if (frac == null) return "neutral";
  if (frac <= 0.1) return "danger";
  if (frac <= 0.3) return "warn";
  return "neutral";
}

function about(confidence: string | undefined, s: string): string {
  return confidence === "estimated" ? `About ${s}` : s;
}

function resetDetail(resetsAt: string | undefined, now: number): string | null {
  return resetsAt ? `resets ${fmtRelative(resetsAt, now)}` : null;
}

/**
 * headlineView words a card's headline. Remaining first: "$18.42 left" with
 * "of $40.00, $21.58 used" second; "36% left this week" with the reset; a
 * vendor that reports only usage says so instead of passing usage off as a
 * balance. A missing headline reads as no reading yet, never as zero.
 */
export function headlineView(h: PlanHeadline | undefined, now: number = Date.now()): HeadlineView {
  if (!h || h.kind === "none" || h.value == null || !Number.isFinite(h.value)) {
    return { value: "No reading yet", details: [], tone: "neutral" };
  }
  const [basisKind, basisKey] = basisParts(h.basis);
  const unit = h.unit ?? "";
  const reset = resetDetail(h.resets_at, now);

  if (h.kind === "percent_left") {
    const frac = Math.max(0, Math.min(1, h.value));
    return {
      value: about(h.confidence, `${Math.round(frac * 100)}% left`),
      context: basisKind === "window" ? windowPhrase(basisKey) : undefined,
      details: reset ? [reset] : [],
      leftFrac: frac,
      tone: leftTone(frac),
    };
  }

  if (h.kind === "used_only") {
    const amount = isMoney(unit) && !dollarsShown() ? null : fmtAmount(unit, h.value);
    const context = basisKind === "spend" ? periodPhrase(basisKey) : basisKind === "window" ? windowPhrase(basisKey) : "";
    const value = amount == null ? "Usage hidden" : `${basisKind === "spend" ? "Spent" : "Used"} ${h.confidence === "estimated" ? "about " : ""}${amount}`;
    return {
      value,
      context: context || undefined,
      details: reset ? [reset] : [],
      note: amount == null ? HIDDEN_MONEY_NOTE : USED_ONLY_NOTE,
      tone: "neutral",
    };
  }

  // kind "left": an amount left, in money, credits, requests ...
  const of = h.of != null && Number.isFinite(h.of) && h.of > 0 ? h.of : undefined;
  const frac = of != null ? Math.max(0, Math.min(1, h.value / of)) : undefined;
  const context = basisKind === "window" ? windowPhrase(basisKey) : undefined;
  if (isMoney(unit) && !dollarsShown()) {
    if (frac == null) {
      return { value: "Balance hidden", details: reset ? [reset] : [], note: HIDDEN_MONEY_NOTE, tone: "neutral" };
    }
    return {
      value: about(h.confidence, `${Math.round(frac * 100)}% left`),
      context,
      details: reset ? [reset] : [],
      leftFrac: frac,
      tone: leftTone(frac),
    };
  }
  const second: string[] = [];
  if (of != null) second.push(`of ${fmtAmount(unit, of)}`);
  if (h.used != null && Number.isFinite(h.used)) second.push(`${fmtAmount(unit, Math.max(h.used, 0))} used`);
  const details = [second.join(", "), reset].filter((s): s is string => !!s);
  const also = (h.also ?? [])
    .filter((a) => Number.isFinite(a.value) && !(isMoney(a.unit) && !dollarsShown()))
    .map((a) => about(h.confidence, `${fmtAmount(a.unit, a.value)} left`));
  return {
    value: about(h.confidence, `${fmtAmount(unit, h.value)} left`),
    context,
    details,
    leftFrac: frac,
    tone: leftTone(frac),
    also: also.length > 0 ? also : undefined,
  };
}

/**
 * otherBalances: the balances a card lists under its headline, without the
 * one the headline already shows (same kind and unit). Another currency of
 * the same kind stays, so a multi-currency balance shows every currency.
 */
export function otherBalances(c: Pick<PlanCard, "balances" | "headline">): PlanBalance[] {
  const h = c.headline;
  const [basisKind, basisKey] = basisParts(h?.basis);
  if (!h || h.kind !== "left" || basisKind !== "balance") return c.balances;
  const shown = new Set([h.unit ?? "", ...(h.also ?? []).map((a) => a.unit)]);
  return c.balances.filter((b) => !(b.kind === basisKey && shown.has(b.unit)));
}

/** UNIT_GROUP_LABELS names a currency or unit heading over a card's balance rows. */
export const UNIT_GROUP_LABELS: Record<string, string> = {
  usd_micros: "US dollars",
  cny_micros: "Chinese yuan",
  eur_micros: "Euros",
  jpy_micros: "Japanese yen",
  credits: "Credits",
  ai_credits: "AI credits",
  points: "Points",
  requests: "Requests",
  tokens: "Tokens",
  characters: "Characters",
  kwh: "Energy",
  hours: "Hours",
  percent: "Percent",
};

/** BalanceGroup is the balance rows of one currency or unit. */
export type BalanceGroup = { unit: string; label: string; rows: PlanBalance[] };

/**
 * balanceGroups: a card's balance rows, one group per currency or unit, so
 * yuan and dollars never sit in one list. The headline's currency comes
 * first, then the other currencies it names, then the rest in reply order.
 * Inside a group the rows reconcile with that currency's own total (the
 * vendor's breakdown, for example granted plus topped up). A heading is
 * given only when there is more than one group.
 */
export function balanceGroups(c: Pick<PlanCard, "balances" | "headline">): BalanceGroup[] {
  const rows = otherBalances(c);
  const order: string[] = [];
  const h = c.headline;
  if (h?.kind === "left" && h.unit) order.push(h.unit);
  for (const a of h?.also ?? []) if (!order.includes(a.unit)) order.push(a.unit);
  for (const b of rows) if (!order.includes(b.unit)) order.push(b.unit);
  const groups = order
    .map((unit) => ({ unit, label: "", rows: rows.filter((b) => b.unit === unit) }))
    .filter((g) => g.rows.length > 0);
  if (groups.length > 1) for (const g of groups) g.label = UNIT_GROUP_LABELS[g.unit] ?? "";
  return groups;
}

/**
 * otherSpend: the spend rows a card lists, without the one a usage-only
 * headline already leads with (same period and unit).
 */
export function otherSpend(c: Pick<PlanCard, "spend" | "headline">): PlanSpend[] {
  const h = c.headline;
  const [basisKind, basisKey] = basisParts(h?.basis);
  if (!h || h.kind !== "used_only" || basisKind !== "spend") return c.spend;
  return c.spend.filter((s) => !(s.period === basisKey && s.unit === h.unit));
}

// ---------- the provider picker ----------

/** PickerItem is one row of the provider picker. */
export type PickerItem = {
  id: string;
  label: string;
  group: string;
  /** "5-hour, Weekly, Per model": what the vendor reports. */
  shows: string;
  /** How Observer reads it, or null when the catalogue does not say. */
  coverage: StatusVocab | null;
  /** Why there is no live reading (type-it-in providers). */
  gap: string;
  experimental: boolean;
};

/** PickerGroup is one heading of the picker with its rows. */
export type PickerGroup = { group: string; label: string; items: PickerItem[] };

/** GROUP_ORDER: the order of the picker's headings. */
export const GROUP_ORDER = ["plans", "balance", "usage"];

/** showsText: up to `max` things a vendor reports, in plain words. */
export function showsText(shows: string[] | undefined, max = 4): string {
  const words = (shows ?? []).map((s) => SHOWS_LABELS[s]).filter(Boolean);
  const head = words.slice(0, max).join(", ");
  return words.length > max ? `${head} and more` : head;
}

/** pickerItem turns one catalogue row into a picker row. */
export function pickerItem(p: CatalogProvider): PickerItem {
  return {
    id: p.id,
    label: providerLabel(p.id),
    group: p.group,
    shows: showsText(p.shows),
    coverage: p.coverage ? (COVERAGE_LABELS[p.coverage] ?? null) : null,
    gap: p.gap ? (GAP_LABELS[p.gap] ?? "") : "",
    experimental: p.has_experimental,
  };
}

function norm(s: string): string {
  return s.toLowerCase().replace(/[_\-.&]+/g, " ").replace(/\s+/g, " ").trim();
}

function haystack(p: CatalogProvider): string {
  return norm(
    [
      providerLabel(p.id),
      p.id,
      GROUP_LABELS[p.group] ?? "",
      ...(p.shows ?? []).map((s) => SHOWS_LABELS[s] ?? ""),
      ...(p.tools ?? []),
    ].join(" "),
  );
}

/**
 * matchRank: how well a provider matches the query. 0 the name starts with
 * it, 1 a word of the name does, 2 everything else that contains every
 * query word, -1 no match. An empty query matches everything at rank 0.
 */
export function matchRank(p: CatalogProvider, query: string): number {
  const q = norm(query);
  if (!q) return 0;
  const name = norm(providerLabel(p.id));
  if (name.startsWith(q)) return 0;
  if (name.split(" ").some((w) => w.startsWith(q))) return 1;
  const hay = haystack(p);
  return q.split(" ").every((w) => hay.includes(w)) ? 2 : -1;
}

function byLabel(a: CatalogProvider, b: CatalogProvider): number {
  // The catch-all "other" row always sits last in its group.
  if (a.id === "other" || b.id === "other") return a.id === "other" ? (b.id === "other" ? 0 : 1) : -1;
  return providerLabel(a.id).localeCompare(providerLabel(b.id), "en", { sensitivity: "base" });
}

/**
 * pickerGroups: the catalogue grouped by kind (Coding plans, API balances,
 * Usage-based, in that order; an unknown group after them), filtered by the
 * query and sorted by match quality, then name. Empty groups are dropped.
 */
export function pickerGroups(catalog: CatalogProvider[], query = ""): PickerGroup[] {
  const groups = Array.from(new Set([...GROUP_ORDER, ...catalog.map((p) => p.group)]));
  const out: PickerGroup[] = [];
  for (const g of groups) {
    const rows = catalog
      .filter((p) => p.group === g)
      .map((p) => ({ p, rank: matchRank(p, query) }))
      .filter((r) => r.rank >= 0)
      .sort((a, b) => a.rank - b.rank || byLabel(a.p, b.p));
    if (rows.length === 0) continue;
    out.push({ group: g, label: GROUP_LABELS[g] ?? "Other", items: rows.map((r) => pickerItem(r.p)) });
  }
  return out;
}

/** pickerCount: how many rows a picker result holds. */
export function pickerCount(groups: PickerGroup[]): number {
  return groups.reduce((n, g) => n + g.items.length, 0);
}

/** vendorCount: catalogue rows a person can pick, without the catch-all. */
export function vendorCount(catalog: CatalogProvider[]): number {
  return catalog.filter((p) => p.id !== "other").length;
}

// ---------- step 2: how to read it ----------

/** MethodView is one choice card in step 2 of the add flow. */
export type MethodView = {
  id: string;
  label: string;
  howto: string;
  /** What you hand over, in plain words. */
  handOver: string;
  experimental: boolean;
};

/** AUTH_HAND_OVER: what a person hands over for each auth method. */
export const AUTH_HAND_OVER: Record<string, string> = {
  none: "Nothing, it reads what is already here",
  pasted_key: "An API key",
  undocumented: "An API key, for an endpoint the vendor has not documented",
  vendor_local: "Nothing, it uses the vendor's app on this machine",
  pasted_session: "A browser session you copy from the vendor's site",
  manual: "The numbers, typed in by you",
};

/** methodView words one way to read a provider. */
export function methodView(s: { id: string; auth?: string; experimental: boolean }): MethodView {
  const auth = s.auth ?? (s.id === "manual" ? "manual" : "");
  return {
    id: s.id,
    label: SOURCE_LABELS[s.id] ?? "Other",
    howto: SOURCE_HOWTO[s.id] ?? "",
    handOver: AUTH_HAND_OVER[auth] ?? "",
    experimental: s.experimental,
  };
}

/** passiveNames: the automatic sources of a provider, named for one line. */
export function passiveNames(p: CatalogProvider | undefined): string[] {
  return (p?.sources ?? []).filter((s) => s.passive).map((s) => SOURCE_LABELS[s.id]).filter(Boolean);
}

// ---------- Track more ----------

/** Suggestion is one "Track more" tile. */
export type Suggestion = PickerItem & {
  /** The tool id the person uses that draws from this plan, if any. */
  usedTool?: string;
};

const COVERAGE_RANK: Record<string, number> = { official: 0, experimental: 1, session: 2, manual_only: 3 };

/**
 * suggestions: the providers the "Track more" section offers. Not yet
 * tracked, never the catch-all. Providers behind a tool the person uses come
 * first (in the order of `usedTools`, most used first), then providers with
 * an official reading. A type-it-in-only provider is suggested only when the
 * person uses its tool.
 */
export function suggestions(
  catalog: CatalogProvider[],
  tracked: Set<string>,
  usedTools: string[],
  max = 6,
): Suggestion[] {
  const toolRank = new Map(usedTools.map((t, i) => [t, i]));
  const rows = catalog
    .filter((p) => p.id !== "other" && !tracked.has(p.id))
    .map((p, order) => {
      let best = Infinity;
      let usedTool: string | undefined;
      for (const t of p.tools ?? []) {
        const r = toolRank.get(t);
        if (r != null && r < best) {
          best = r;
          usedTool = t;
        }
      }
      return { p, order, best, usedTool, cov: COVERAGE_RANK[p.coverage ?? ""] ?? 4 };
    })
    .filter((r) => r.usedTool != null || r.cov <= 1);
  // Catalogue order breaks ties: it lists the widely used plans first, so a
  // fresh install is offered Claude or Copilot, not whatever sorts first.
  rows.sort((a, b) => a.best - b.best || a.cov - b.cov || a.order - b.order);
  return rows.slice(0, max).map((r) => ({ ...pickerItem(r.p), usedTool: r.usedTool }));
}

// ---------- experimental sources ----------

/** ExperimentalRow is one row of the experimental sources list. */
export type ExperimentalRow = {
  id: string;
  label: string;
  on: boolean;
  /** The experimental methods, named. */
  methods: string[];
  shows: string;
  /** Saved accounts that use an experimental method. */
  accounts: number;
};

/**
 * experimentalRows: providers whose experimental sources are switched on or
 * that have an account on an experimental method. Switching one on happens
 * in the add flow, so a provider nobody chose is not listed here.
 */
export function experimentalRows(
  catalog: CatalogProvider[],
  optIns: Set<string>,
  accounts: PlanAccount[],
): ExperimentalRow[] {
  const out: ExperimentalRow[] = [];
  for (const p of catalog) {
    if (!p.has_experimental) continue;
    const expIds = new Set(p.sources.filter((s) => s.experimental).map((s) => s.id));
    const n = accounts.filter((a) => a.provider === p.id && expIds.has(a.source)).length;
    if (!optIns.has(p.id) && n === 0) continue;
    out.push({
      id: p.id,
      label: providerLabel(p.id),
      on: optIns.has(p.id),
      methods: [...expIds].map((id) => SOURCE_LABELS[id]).filter(Boolean),
      shows: showsText(p.shows),
      accounts: n,
    });
  }
  return out.sort((a, b) => a.label.localeCompare(b.label, "en", { sensitivity: "base" }));
}

// ---------- marks ----------

/**
 * MarkRef names an EXISTING mark in a shared table: a tool logo
 * (shared/lib/toolLogos.tsx TOOL_LOGOS), a serving-host mark (HOST_MARKS) or
 * a model-family mark (MODEL_FAMILY_MARKS), or a monogram of the name.
 */
export type MarkRef =
  | { kind: "tool"; id: string }
  | { kind: "host"; id: string }
  | { kind: "family"; id: string }
  | { kind: "monogram"; letter: string };

/**
 * PROVIDER_MARKS: provider id -> the existing mark it wears. Only a mark that
 * IS the vendor's own goes here; everything else is an honest monogram.
 * plansView.test.ts checks every reference against the shared tables.
 */
export const PROVIDER_MARKS: Record<string, Exclude<MarkRef, { kind: "monogram" }>> = {
  claude: { kind: "family", id: "claude" },
  chatgpt: { kind: "family", id: "openai" },
  github_copilot: { kind: "tool", id: "copilot" },
  cursor: { kind: "tool", id: "cursor" },
  windsurf: { kind: "family", id: "windsurf" },
  kiro: { kind: "tool", id: "kiro-cli" },
  kimi_code: { kind: "tool", id: "kimi-code" },
  openrouter: { kind: "host", id: "openrouter" },
  deepseek: { kind: "family", id: "deepseek" },
  moonshot: { kind: "family", id: "kimi" },
  xai: { kind: "family", id: "grok" },
  clinepass: { kind: "tool", id: "cline" },
  opencode_go: { kind: "tool", id: "opencode" },
  factory: { kind: "tool", id: "droid" },
  fireworks: { kind: "host", id: "fireworks" },
  zai: { kind: "family", id: "glm" },
  minimax: { kind: "family", id: "minimax" },
  kilo: { kind: "tool", id: "kilo-code" },
  codebuff: { kind: "tool", id: "freebuff" },
  command_code: { kind: "tool", id: "command-code" },
  hugging_face: { kind: "host", id: "huggingface" },
  opencode: { kind: "tool", id: "opencode" },
  alibaba_coding_plan: { kind: "family", id: "qwen" },
  alibaba_token_plan: { kind: "family", id: "qwen" },
  qwen_cloud: { kind: "family", id: "qwen" },
  devin: { kind: "tool", id: "devin" },
  ollama: { kind: "host", id: "ollama" },
  zed: { kind: "tool", id: "zed" },
  perplexity: { kind: "family", id: "sonar" },
  sakana: { kind: "family", id: "sakana" },
  mistral: { kind: "family", id: "mistral" },
  qoder: { kind: "tool", id: "qoder" },
  stepfun: { kind: "family", id: "stepfun" },
  groq: { kind: "host", id: "groq" },
  claude_platform: { kind: "host", id: "anthropic" },
  openai_api: { kind: "host", id: "openai" },
  anthropic_api: { kind: "host", id: "anthropic" },
  azure_openai: { kind: "host", id: "azure" },
  gemini: { kind: "family", id: "gemini" },
  antigravity: { kind: "tool", id: "antigravity" },
  vertex_ai: { kind: "host", id: "vertexai" },
  jetbrains_ai: { kind: "tool", id: "junie" },
  doubao: { kind: "family", id: "doubao" },
  aws_bedrock: { kind: "host", id: "bedrock" },
  grok: { kind: "tool", id: "grok" },
  nous_portal: { kind: "tool", id: "hermes" },
  muse_code: { kind: "tool", id: "muse" },
  pi: { kind: "tool", id: "pi" },
  // 2026-10-21 capture wave (AP-134): each vendor's own tool logo.
  autohand: { kind: "tool", id: "autohand" },
  kimchi: { kind: "tool", id: "kimchi" },
  stakpak: { kind: "tool", id: "stakpak" },
  cortex_code: { kind: "tool", id: "cortex-code" },
};

/** monogramLetter: the first letter or digit of a name, upper case. */
export function monogramLetter(label: string): string {
  const m = /[\p{L}\p{N}]/u.exec(label);
  return m ? m[0].toUpperCase() : "?";
}

/** providerMark: the mark a provider wears, or its monogram. */
export function providerMark(id: string): MarkRef {
  return PROVIDER_MARKS[id] ?? { kind: "monogram", letter: monogramLetter(providerLabel(id)) };
}

// ---------- daily usage reconciliation ----------

/** UsageLabels words one provider's "usage by day" block. */
export type UsageLabels = { title: string; vendor: string; gap: string };

/**
 * USAGE_LABELS: the wording per provider whose source reports daily usage
 * (SourceDef.DailyUsage). The gap is "not captured here", never "cloud
 * usage": the vendor's daily total cannot say where the rest ran.
 */
export const USAGE_LABELS: Record<string, UsageLabels> = {
  chatgpt: {
    title: "Codex usage by day",
    vendor: "OpenAI",
    gap: "Codex cloud chats, other devices or sessions Observer did not run on",
  },
};

const USAGE_DEFAULT: UsageLabels = {
  title: "Usage by day",
  vendor: "Vendor",
  gap: "other surfaces, other devices or sessions Observer did not run on",
};

export function usageLabels(provider: string): UsageLabels {
  return USAGE_LABELS[provider] ?? USAGE_DEFAULT;
}

/** UsageRow is one day of the block, numbers already worded. */
export type UsageRow = {
  day: string;
  /** The UTC day as "Oct 30", never shifted into the viewer's zone. */
  label: string;
  vendor: string;
  captured: string;
  uncaptured: string;
  share: string;
  capturedN: number;
  uncapturedN: number;
  totalN: number;
};

/** UsageBlockView is what the card's "usage by day" block renders. */
export type UsageBlockView = {
  title: string;
  window: string;
  totals: { label: string; value: string }[];
  rows: UsageRow[];
  /** The widest bar in the list (vendor or captured, whichever is larger). */
  max: number;
  empty?: string;
  notes: string[];
};

const usageDayFmt = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", timeZone: "UTC" });

/** usageDayLabel words a UTC "YYYY-MM-DD" day as "Oct 30" in UTC. */
export function usageDayLabel(day: string): string {
  const t = Date.parse(`${day}T00:00:00Z`);
  return Number.isNaN(t) ? day : usageDayFmt.format(t);
}

function tokens(n: number): string {
  return fmtCompact(n);
}

function share(r: number | undefined): string {
  return r == null ? "" : `${Math.round(r * 100)}% captured`;
}

/**
 * usageBlock: the card block for an account's daily usage, or null when
 * there is nothing to show (the source has no daily usage, or no reading
 * has stored any yet). Tokens only, never a dollar figure.
 */
export function usageBlock(v: PlanUsageView | null | undefined): UsageBlockView | null {
  const r = v?.reconciliation;
  if (!v || !v.available || !r) return null;
  const l = usageLabels(v.provider);
  const tools = v.tools.length > 0 ? v.tools.join(", ") : "this tool";
  const rows: UsageRow[] = r.days.map((d) => ({
    day: d.day,
    label: usageDayLabel(d.day),
    vendor: d.vendor_reported ? tokens(d.vendor_tokens) : "none reported",
    captured: tokens(d.captured_tokens),
    uncaptured: tokens(d.uncaptured_tokens),
    share: share(d.ratio),
    capturedN: d.captured_tokens,
    uncapturedN: d.uncaptured_tokens,
    totalN: Math.max(d.vendor_tokens, d.captured_tokens),
  }));
  return {
    title: l.title,
    window: `Last ${v.days} ${v.days === 1 ? "day" : "days"}, UTC`,
    totals: [
      { label: `${l.vendor} total`, value: tokens(r.totals.vendor_tokens) },
      { label: "Captured here", value: tokens(r.totals.captured_tokens) },
      { label: "Not captured here", value: tokens(r.totals.uncaptured_tokens) },
    ],
    rows,
    max: rows.reduce((m, x) => Math.max(m, x.totalN), 0),
    empty: rows.length === 0 ? "No usage on any day in this window." : undefined,
    notes: [
      `Not captured here: ${l.gap}.`,
      `The ${l.vendor} total covers every surface and device on the login; captured here counts this machine's ${tools} sessions for any login.`,
      `Tokens only. Days are UTC; ${l.vendor} does not document its day boundary.`,
    ],
  };
}
