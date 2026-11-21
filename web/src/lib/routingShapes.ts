// routingShapes: the pure model behind the Settings > Routing shape cards
// (RoutingShapesCards.tsx): tier overrides, path classes, budget scopes,
// privacy rules, local upstreams and model fallbacks. No imports, so
// node:test pins it directly.
//
// Each card edits rows, checks them here with the same rules the daemon's
// save gate runs (internal/intelligence/dashboard/routing_shapes.go plus the
// loader's [routing] checks it calls), and saves ONE Set* field through the
// routing section save. The server stays the authority: it runs every check
// again and refuses with the file untouched. Key pools are not here and never
// will be: they hold API keys, which never go over HTTP.

/** The shipped tier vocabulary, best first (routingcore.AllTiers). */
export const ROUTING_TIERS = ["opus-class", "sonnet-class", "haiku-class", "free", "local", "unclassified"] as const;

/** Budget windows (rolling). */
export const BUDGET_WINDOWS = ["day", "week", "month"] as const;

/** What a budget scope does at 100%, "" being the default (advise only). */
export const BUDGET_EXHAUSTED = ["", "advise_only", "degrade_all", "hard_stop"] as const;

/** The budget scope kinds; every kind but "global" names a target. */
export const BUDGET_SCOPE_KINDS = ["global", "project", "tool", "tier"] as const;
export type BudgetScopeKind = (typeof BUDGET_SCOPE_KINDS)[number];

/** The burn bands a scope uses when it names none. */
export const DEFAULT_BUDGET_BANDS = [0.5, 0.8, 0.95];

/** Provider classes privacy rules compare with (lowercase; a router prefix
 *  such as openrouter counts too). "*" is deny-only. */
export const PROVIDER_CLASSES = ["anthropic", "openai", "google", "local", "openrouter"] as const;

// ---------------------------------------------------------------- wire

/** One [[routing.budget.scopes]] row as GET /api/config serves it. */
export type BudgetScopeWire = {
  Scope: string;
  LimitUSD: number;
  Window: string;
  Bands: number[] | null;
  Exhausted: string;
};

/** One [[routing.privacy.rules]] row. */
export type PrivacyRuleWire = {
  Project: string;
  PathClass: string;
  LocalOnly: boolean;
  DenyProviders: string[] | null;
  AllowProviders: string[] | null;
};

/** One [[routing.local_upstreams]] row. */
export type LocalUpstreamWire = { Name: string; BaseURL: string; Models: string[] | null };

/** The slice of GET /api/config's Routing section the cards read. */
export type RoutingShapesWire = {
  Tiers?: Record<string, string> | null;
  PathClasses?: Record<string, string[] | null> | null;
  Budget?: { Scopes?: BudgetScopeWire[] | null } | null;
  Privacy?: { Rules?: PrivacyRuleWire[] | null } | null;
  LocalUpstreams?: LocalUpstreamWire[] | null;
  Reliability?: { Fallbacks?: Record<string, string[] | null> | null } | null;
  Rules?: { Name?: string; When?: { PathClass?: string } | null }[] | null;
};

// ---------------------------------------------------------------- rows

export type TierRow = { model: string; tier: string };
export type PathClassRow = { name: string; patterns: string[] };
export type BudgetRow = {
  kind: BudgetScopeKind;
  target: string;
  /** Typed text: the dollar limit. */
  limit: string;
  window: string;
  /** Typed text: comma-separated burn fractions, empty for the defaults. */
  bands: string;
  exhausted: string;
};
export type PrivacyRow = { project: string; pathClass: string; localOnly: boolean; deny: string[]; allow: string[] };
export type UpstreamRow = { name: string; baseURL: string; models: string[] };
export type FallbackRow = { from: string; chain: string[] };

/** Blank rows the Add buttons append. */
export const BLANK = {
  tier: (): TierRow => ({ model: "", tier: "" }),
  pathClass: (): PathClassRow => ({ name: "", patterns: [] }),
  budget: (): BudgetRow => ({ kind: "global", target: "", limit: "", window: "month", bands: "", exhausted: "" }),
  privacy: (): PrivacyRow => ({ project: "", pathClass: "", localOnly: true, deny: [], allow: [] }),
  upstream: (): UpstreamRow => ({ name: "", baseURL: "", models: [] }),
  fallback: (): FallbackRow => ({ from: "", chain: [] }),
};

const t = (s: string | null | undefined) => (s ?? "").trim();
const list = (xs: readonly string[] | null | undefined) => (xs ?? []).map((x) => x.trim()).filter(Boolean);
const keysSorted = (m: Record<string, unknown> | null | undefined) => Object.keys(m ?? {}).sort();

// ---------------------------------------------------------------- from config

export function tierRows(rc: RoutingShapesWire | null | undefined): TierRow[] {
  const m = rc?.Tiers ?? {};
  return keysSorted(m).map((model) => ({ model, tier: m[model] ?? "" }));
}

export function pathClassRows(rc: RoutingShapesWire | null | undefined): PathClassRow[] {
  const m = rc?.PathClasses ?? {};
  return keysSorted(m).map((name) => ({ name, patterns: [...(m[name] ?? [])] }));
}

/** parseScope splits "project:alpha" into its kind and target. */
export function parseScope(scope: string): { kind: BudgetScopeKind; target: string } {
  const s = scope.trim();
  for (const kind of BUDGET_SCOPE_KINDS) {
    if (kind !== "global" && s.startsWith(kind + ":")) return { kind, target: s.slice(kind.length + 1) };
  }
  return { kind: "global", target: "" };
}

export function budgetRows(rc: RoutingShapesWire | null | undefined): BudgetRow[] {
  return (rc?.Budget?.Scopes ?? []).map((sc) => ({
    ...parseScope(sc.Scope ?? ""),
    limit: sc.LimitUSD ? String(sc.LimitUSD) : "",
    window: sc.Window ?? "",
    bands: (sc.Bands ?? []).join(", "),
    exhausted: sc.Exhausted ?? "",
  }));
}

export function privacyRows(rc: RoutingShapesWire | null | undefined): PrivacyRow[] {
  return (rc?.Privacy?.Rules ?? []).map((r) => ({
    project: r.Project ?? "",
    pathClass: r.PathClass ?? "",
    localOnly: Boolean(r.LocalOnly),
    deny: [...(r.DenyProviders ?? [])],
    allow: [...(r.AllowProviders ?? [])],
  }));
}

export function upstreamRows(rc: RoutingShapesWire | null | undefined): UpstreamRow[] {
  return (rc?.LocalUpstreams ?? []).map((u) => ({ name: u.Name ?? "", baseURL: u.BaseURL ?? "", models: [...(u.Models ?? [])] }));
}

export function fallbackRows(rc: RoutingShapesWire | null | undefined): FallbackRow[] {
  const m = rc?.Reliability?.Fallbacks ?? {};
  return keysSorted(m).map((from) => ({ from, chain: [...(m[from] ?? [])] }));
}

// ---------------------------------------------------------------- empty rows

// A row nobody filled in is dropped on save, not refused.
const emptyTier = (r: TierRow) => !t(r.model) && !t(r.tier);
const emptyPathClass = (r: PathClassRow) => !t(r.name) && list(r.patterns).length === 0;
const emptyBudget = (r: BudgetRow) => !t(r.target) && !t(r.limit) && !t(r.bands);
const emptyPrivacy = (r: PrivacyRow) =>
  !t(r.project) && !t(r.pathClass) && list(r.deny).length === 0 && list(r.allow).length === 0;
const emptyUpstream = (r: UpstreamRow) => !t(r.name) && !t(r.baseURL) && list(r.models).length === 0;
const emptyFallback = (r: FallbackRow) => !t(r.from) && list(r.chain).length === 0;

// ---------------------------------------------------------------- Set* bodies

/** The SetTiers value: trimmed, empty rows dropped, keys sorted. */
export function tiersValue(rows: readonly TierRow[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of [...rows].filter((r) => !emptyTier(r)).sort((a, b) => t(a.model).localeCompare(t(b.model)))) {
    out[t(r.model)] = t(r.tier);
  }
  return out;
}

export function pathClassesValue(rows: readonly PathClassRow[]): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const r of [...rows].filter((r) => !emptyPathClass(r)).sort((a, b) => t(a.name).localeCompare(t(b.name)))) {
    out[t(r.name)] = list(r.patterns);
  }
  return out;
}

/** parseBands reads "0.5, 0.8" as numbers; null when an entry is not one. */
export function parseBands(text: string): number[] | null {
  const parts = text.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
  const out: number[] = [];
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isFinite(n)) return null;
    out.push(n);
  }
  return out;
}

/** scopeOf renders a row's scope string ("global", "project:alpha"). */
export function scopeOf(r: Pick<BudgetRow, "kind" | "target">): string {
  return r.kind === "global" ? "global" : `${r.kind}:${t(r.target)}`;
}

export function budgetScopesValue(rows: readonly BudgetRow[]): BudgetScopeWire[] {
  return rows
    .filter((r) => !emptyBudget(r))
    .map((r) => ({
      Scope: scopeOf(r),
      LimitUSD: Number(t(r.limit)),
      Window: t(r.window),
      Bands: parseBands(r.bands) ?? [],
      Exhausted: t(r.exhausted),
    }));
}

export function privacyRulesValue(rows: readonly PrivacyRow[]): PrivacyRuleWire[] {
  return rows
    .filter((r) => !emptyPrivacy(r))
    .map((r) => ({
      Project: t(r.project),
      PathClass: t(r.pathClass),
      LocalOnly: r.localOnly,
      // Kept as typed even beside local only (which ignores them), so a
      // save never drops what the file held.
      DenyProviders: list(r.deny),
      AllowProviders: list(r.allow),
    }));
}

export function localUpstreamsValue(rows: readonly UpstreamRow[]): LocalUpstreamWire[] {
  return rows
    .filter((r) => !emptyUpstream(r))
    .map((r) => ({ Name: t(r.name), BaseURL: t(r.baseURL), Models: list(r.models) }));
}

export function fallbacksValue(rows: readonly FallbackRow[]): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const r of [...rows].filter((r) => !emptyFallback(r)).sort((a, b) => t(a.from).localeCompare(t(b.from)))) {
    out[t(r.from)] = list(r.chain);
  }
  return out;
}

/** The section body fields, one per card. */
export const SHAPE_BODY = {
  tiers: (rows: readonly TierRow[]) => ({ SetTiers: tiersValue(rows) }),
  pathClasses: (rows: readonly PathClassRow[]) => ({ SetPathClasses: pathClassesValue(rows) }),
  budgetScopes: (rows: readonly BudgetRow[]) => ({ SetBudgetScopes: budgetScopesValue(rows) }),
  privacyRules: (rows: readonly PrivacyRow[]) => ({ SetPrivacyRules: privacyRulesValue(rows) }),
  localUpstreams: (rows: readonly UpstreamRow[]) => ({ SetLocalUpstreams: localUpstreamsValue(rows) }),
  fallbacks: (rows: readonly FallbackRow[]) => ({ SetFallbacks: fallbacksValue(rows) }),
};

/** sameValue: two Set* values write the same thing. */
export function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

// ---------------------------------------------------------------- checks

const quote = (s: string) => `"${s}"`;
const isTier = (s: string) => (ROUTING_TIERS as readonly string[]).includes(s);
const tierList = ROUTING_TIERS.join(", ");

/** duplicates returns the values that occur more than once, in first order. */
function duplicates(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const dup = new Set<string>();
  for (const v of values) {
    if (seen.has(v)) dup.add(v);
    seen.add(v);
  }
  return [...dup];
}

/**
 * globValid mirrors the path-class matcher and Go's path.Match syntax: a
 * leading "**\/" and a trailing "/**" are the matcher's own forms; otherwise
 * every "[" class must close and hold at least one character, and a "\"
 * must escape something.
 */
export function globValid(pattern: string): boolean {
  const p = pattern.startsWith("**/") ? pattern.slice(3) : pattern;
  if (p.endsWith("/**")) return true;
  let i = 0;
  // esc consumes one class character (or escape) and reports whether the
  // class can still close after it.
  const esc = (): boolean => {
    if (i >= p.length || p[i] === "-" || p[i] === "]") return false;
    if (p[i] === "\\") {
      i++;
      if (i >= p.length) return false;
    }
    i++;
    return i < p.length;
  };
  while (i < p.length) {
    const c = p[i];
    if (c === "\\") {
      if (i + 1 >= p.length) return false;
      i += 2;
      continue;
    }
    if (c === "[") {
      i++;
      if (p[i] === "^") i++;
      let ranges = 0;
      for (;;) {
        if (i < p.length && p[i] === "]" && ranges > 0) {
          i++;
          break;
        }
        if (!esc()) return false;
        if (p[i] === "-") {
          i++;
          if (!esc()) return false;
        }
        ranges++;
      }
      continue;
    }
    i++;
  }
  return true;
}

/** baseURLProblem checks a local upstream address; "" when it is fine.
 *  No message repeats the address: a bad one may hold a password. */
export function baseURLProblem(raw: string): string {
  const s = raw.trim();
  if (!s) return "add the endpoint's address, for example http://localhost:11434/v1";
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return "the address is not a web address; use the form http://localhost:11434/v1";
  }
  if (u.username || u.password) return "the address must not carry a user name or password";
  if (!s.startsWith("http://") && !s.startsWith("https://")) return "the address must start with http:// or https://";
  if (!/^https?:\/\/[^/?#\s]/.test(s)) return "the address names no host; use the form http://localhost:11434/v1";
  if (s.includes("?") || s.includes("#")) return "the address must not have a ?query or #fragment";
  return "";
}

/** providerProblem checks one provider name of a privacy rule list. */
export function providerProblem(name: string, side: "deny" | "allow"): string {
  if (name === "*") return side === "deny" ? "" : `"*" only works in the block list (block every provider not allowed)`;
  if (name !== name.toLowerCase()) return `provider ${quote(name)} never matches: use ${quote(name.toLowerCase())}`;
  return "";
}

/** Where a path class is named outside the path-class card. */
export type PathClassUse = { name: string; by: string };

/** pathClassUses lists every privacy rule and custom rule naming a class. */
export function pathClassUses(rc: RoutingShapesWire | null | undefined): PathClassUse[] {
  const out: PathClassUse[] = [];
  (rc?.Privacy?.Rules ?? []).forEach((r, i) => {
    if (r.PathClass) out.push({ name: r.PathClass, by: `privacy rule ${i + 1}` });
  });
  for (const r of rc?.Rules ?? []) {
    const pc = r.When?.PathClass;
    if (pc) out.push({ name: pc, by: `custom rule ${quote(r.Name ?? "")}` });
  }
  return out;
}

/** upstreamModels: the model ids the saved local upstreams serve. */
function upstreamModels(ups: readonly LocalUpstreamWire[] | null | undefined): Set<string> {
  return new Set((ups ?? []).flatMap((u) => u.Models ?? []));
}

/** checkTiers. The local tier is for models a saved local upstream serves:
 *  privacy rules treat that tier as this machine, so a cloud model there
 *  would pass a local-only rule while still going to its provider. */
export function checkTiers(rows: readonly TierRow[], rc?: RoutingShapesWire | null): string[] {
  const out: string[] = [];
  const kept = rows.filter((r) => !emptyTier(r));
  const served = upstreamModels(rc?.LocalUpstreams);
  kept.forEach((r) => {
    if (!t(r.model)) out.push("Pick a model for every override (or remove the row).");
    else if (!isTier(t(r.tier))) out.push(`Pick a tier for ${t(r.model)} (one of ${tierList}).`);
    else if (t(r.tier) === "local" && !served.has(t(r.model))) {
      out.push(`${t(r.model)} can be in the local tier only when a local upstream serves it; add it under Local upstreams instead.`);
    }
  });
  for (const d of duplicates(kept.map((r) => t(r.model)).filter(Boolean))) out.push(`${d} is listed twice; keep one row.`);
  return out;
}

export function checkPathClasses(rows: readonly PathClassRow[], rc: RoutingShapesWire | null | undefined): string[] {
  const out: string[] = [];
  const kept = rows.filter((r) => !emptyPathClass(r));
  for (const r of kept) {
    const name = t(r.name);
    if (!name) {
      out.push("Name every path class (or remove the row).");
      continue;
    }
    const pats = list(r.patterns);
    if (pats.length === 0) out.push(`Add at least one path pattern to ${quote(name)} (or remove it).`);
    for (const p of pats) if (!globValid(p)) out.push(`${quote(name)}: ${quote(p)} is not a valid pattern; check its [ ] brackets.`);
  }
  const names = kept.map((r) => t(r.name)).filter(Boolean);
  for (const d of duplicates(names)) out.push(`${quote(d)} is listed twice; keep one class.`);
  const now = new Set(names);
  const saved = new Set(Object.keys(rc?.PathClasses ?? {}));
  for (const use of pathClassUses(rc)) {
    if (saved.has(use.name) && !now.has(use.name)) {
      out.push(`${quote(use.name)} is still used by ${use.by}; change or remove that rule first.`);
    }
  }
  return out;
}

export function checkBudgetScopes(rows: readonly BudgetRow[]): string[] {
  const out: string[] = [];
  const seen = new Map<string, number>();
  rows.forEach((r, i) => {
    if (emptyBudget(r)) return;
    const n = `Row ${i + 1}`;
    if (r.kind !== "global" && !t(r.target)) out.push(`${n}: pick the ${r.kind} this budget applies to.`);
    if (r.kind === "tier" && t(r.target) && !isTier(t(r.target))) out.push(`${n}: pick a tier (one of ${tierList}).`);
    const limit = Number(t(r.limit));
    if (!t(r.limit) || !Number.isFinite(limit) || limit <= 0) out.push(`${n}: enter a limit above 0 US dollars.`);
    if (!(BUDGET_WINDOWS as readonly string[]).includes(t(r.window))) out.push(`${n}: pick a window (day, week or month).`);
    if (!(BUDGET_EXHAUSTED as readonly string[]).includes(t(r.exhausted))) out.push(`${n}: pick what happens when the budget is used up.`);
    const bands = parseBands(r.bands);
    if (bands === null) out.push(`${n}: bands are numbers between 0 and 1, like 0.5, 0.8, 0.95.`);
    else if (bands.some((b) => b <= 0 || b >= 1)) out.push(`${n}: every band must be above 0 and below 1.`);
    else if (bands.some((b, j) => j > 0 && b <= bands[j - 1])) out.push(`${n}: list the bands from lowest to highest, each once.`);
    const key = `${scopeOf(r)}\u0000${t(r.window)}`;
    const first = seen.get(key);
    if (first !== undefined) out.push(`${n} repeats row ${first}; remove one.`);
    else seen.set(key, i + 1);
  });
  return out;
}

export function checkPrivacyRules(rows: readonly PrivacyRow[], rc: RoutingShapesWire | null | undefined): string[] {
  const out: string[] = [];
  const defined = new Set(Object.keys(rc?.PathClasses ?? {}));
  rows.forEach((r, i) => {
    if (emptyPrivacy(r)) return;
    const n = `Rule ${i + 1}`;
    if (!t(r.project) && !t(r.pathClass)) out.push(`${n}: pick a project or a path class it applies to.`);
    if (t(r.pathClass) && !defined.has(t(r.pathClass))) {
      out.push(`${n}: path class ${quote(t(r.pathClass))} is not saved yet; save it under Path classes first.`);
    }
    if (!r.localOnly && list(r.deny).length === 0 && list(r.allow).length === 0) {
      out.push(`${n}: keep it on local models, or name providers to block or allow.`);
    }
    for (const [side, names] of [["deny", r.deny], ["allow", r.allow]] as const) {
      for (const p of list(names)) {
        const msg = providerProblem(p, side);
        if (msg) out.push(`${n}: ${msg}.`);
      }
    }
  });
  return out;
}

/** checkLocalUpstreams. Removing the endpoint of a model a tier override
 *  pins to the local tier is refused (the other half of checkTiers). */
export function checkLocalUpstreams(rows: readonly UpstreamRow[], rc?: RoutingShapesWire | null): string[] {
  const out: string[] = [];
  const servedBy = new Map<string, string>();
  const names: string[] = [];
  const was = upstreamModels(rc?.LocalUpstreams);
  const now = new Set(rows.flatMap((r) => list(r.models)));
  for (const model of keysSorted(rc?.Tiers)) {
    if (rc?.Tiers?.[model] === "local" && was.has(model) && !now.has(model)) {
      out.push(`${quote(model)} is set to the local tier under Tier overrides; change that override first.`);
    }
  }
  rows.forEach((r, i) => {
    if (emptyUpstream(r)) return;
    const name = t(r.name) || `row ${i + 1}`;
    if (!t(r.name)) out.push(`Row ${i + 1}: name the endpoint (for example ollama).`);
    else names.push(t(r.name));
    const urlMsg = baseURLProblem(r.baseURL);
    if (urlMsg) out.push(`${name}: ${urlMsg}.`);
    const models = list(r.models);
    if (models.length === 0) out.push(`${name}: add at least one model it serves.`);
    for (const m of models) {
      const prev = servedBy.get(m);
      if (prev !== undefined) out.push(`${quote(m)} is served by both ${prev} and ${name}; keep it on one endpoint.`);
      else servedBy.set(m, name);
    }
  });
  for (const d of duplicates(names)) out.push(`${quote(d)} is listed twice; give each endpoint its own name.`);
  return out;
}

export function checkFallbacks(rows: readonly FallbackRow[]): string[] {
  const out: string[] = [];
  const kept = rows.filter((r) => !emptyFallback(r));
  for (const r of kept) {
    const from = t(r.from);
    if (!from) {
      out.push("Pick the model or tier every chain starts from (or remove the row).");
      continue;
    }
    const chain = list(r.chain);
    if (chain.length === 0) out.push(`Add at least one fallback model for ${from} (or remove the row).`);
    if (chain.includes(from)) out.push(`${from} falls back to itself; remove it from its own chain.`);
    for (const d of duplicates(chain)) out.push(`${from} lists ${d} twice.`);
  }
  for (const d of duplicates(kept.map((r) => t(r.from)).filter(Boolean))) out.push(`${d} has two chains; keep one row.`);
  return out;
}

// ---------------------------------------------------------------- pickers

/** projectNames: the project names routing matches (the folder name of each
 *  project root), deduplicated, from the project roots picker source. */
export function projectNames(roots: readonly { id: string; label?: string }[]): { id: string; label: string; sublabel?: string }[] {
  const seen = new Set<string>();
  const out: { id: string; label: string; sublabel?: string }[] = [];
  for (const r of roots) {
    const name = folderName(r.id);
    if (!name || seen.has(name)) continue;
    seen.add(name);
    out.push({ id: name, label: name, sublabel: r.id });
  }
  return out;
}

/** folderName is the last path segment of a root, either slash. */
export function folderName(root: string): string {
  const parts = root.replace(/[\\/]+$/, "").split(/[\\/]/);
  return parts[parts.length - 1] ?? "";
}

/** tierOptions: the tier vocabulary, each with how many known models it
 *  holds today (GET /api/routing/tiers), unknown tiers from that answer
 *  appended so nothing it names is hidden. */
export function tierOptions(byTier: Record<string, readonly string[] | null> | null | undefined): { id: string; label: string; sublabel?: string }[] {
  const names = [...ROUTING_TIERS, ...Object.keys(byTier ?? {}).filter((k) => !isTier(k)).sort()];
  return names.map((id) => {
    const n = byTier?.[id]?.length ?? 0;
    return { id, label: id, sublabel: byTier ? `${n} model${n === 1 ? "" : "s"} today` : undefined };
  });
}
