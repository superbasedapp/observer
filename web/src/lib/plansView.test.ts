// Pins lib/plansView.ts: the remaining-first headline for every headline kind
// and unit (one case per balance vendor shape), the provider picker's
// grouping, search and order, the "Track more" suggestions, the experimental
// list, and the provider mark table (every reference names an existing
// shared mark; every provider renders a mark or a monogram).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { setCostDisplayMode } from "../../../shared/lib/format.ts";
import { PROVIDER_LABELS, type CatalogProvider, type PlanAccount, type PlanCard, type PlanHeadline, type PlanUsageView } from "./plans.ts";
import {
  HIDDEN_MONEY_NOTE,
  PROVIDER_MARKS,
  USED_ONLY_NOTE,
  experimentalRows,
  headlineView,
  matchRank,
  methodView,
  monogramLetter,
  otherBalances,
  otherSpend,
  pickerCount,
  pickerGroups,
  providerMark,
  showsText,
  balanceGroups,
  suggestions,
  usageBlock,
  vendorCount,
  windowPhrase,
} from "./plansView.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const read = (rel: string) => readFileSync(path.join(root, rel), "utf8");

const NOW = Date.parse("2026-10-15T12:00:00Z");
const IN_2_DAYS = "2026-10-17T12:00:00Z";
const M = 1_000_000;

function withUSD<T>(fn: () => T): T {
  setCostDisplayMode("usd");
  try {
    return fn();
  } finally {
    setCostDisplayMode("usd");
  }
}

// ---------- headline ----------

type HeadCase = {
  name: string;
  h: PlanHeadline | undefined;
  value: RegExp;
  context?: string;
  details?: RegExp[];
  note?: string;
  tone?: string;
  leftFrac?: number;
};

const headCases: HeadCase[] = [
  {
    name: "OpenRouter: credits left of credits bought",
    h: { kind: "left", unit: "usd_micros", value: 18.42 * M, of: 40 * M, used: 21.58 * M, basis: "balance:prepaid", confidence: "exact" },
    value: /^\$18\.42 left$/,
    details: [/^of \$40\.00, \$21\.58 used$/],
    tone: "neutral",
    leftFrac: 0.4605,
  },
  {
    name: "DeepSeek: a yuan balance with no total",
    h: { kind: "left", unit: "cny_micros", value: 52.3 * M, basis: "balance:total", confidence: "exact" },
    value: /^CN¥52\.30 left$/,
    details: [],
  },
  {
    name: "Moonshot: available balance only",
    h: { kind: "left", unit: "usd_micros", value: 7.5 * M, basis: "balance:available" },
    value: /^\$7\.50 left$/,
    details: [],
  },
  {
    name: "xAI: an estimated balance says so",
    h: { kind: "left", unit: "usd_micros", value: 3 * M, used: 22 * M, basis: "balance:prepaid", confidence: "estimated" },
    value: /^About \$3\.00 left$/,
    details: [/^\$22\.00 used$/],
  },
  {
    name: "little left turns the number danger",
    h: { kind: "left", unit: "usd_micros", value: 2 * M, of: 40 * M, used: 38 * M, basis: "balance:prepaid" },
    value: /^\$2\.00 left$/,
    tone: "danger",
  },
  {
    name: "a request window left, with its reset",
    h: { kind: "left", unit: "requests", value: 120, of: 500, used: 380, basis: "window:monthly", resets_at: IN_2_DAYS },
    value: /^120 requests left$/,
    context: "this month",
    details: [/^of 500 requests, 380 requests used$/, /^resets in 2 days$/],
    tone: "warn",
  },
  {
    name: "Claude: percent of the weekly window left",
    h: { kind: "percent_left", unit: "percent", value: 0.36, basis: "window:weekly", resets_at: IN_2_DAYS },
    value: /^36% left$/,
    context: "this week",
    details: [/^resets in 2 days$/],
    leftFrac: 0.36,
  },
  {
    name: "percent left of a per-model window uses its label",
    h: { kind: "percent_left", unit: "percent", value: 0.8, basis: "window:model:opus" },
    value: /^80% left$/,
    context: "Weekly, Opus",
  },
  {
    name: "a used-only vendor says so",
    h: { kind: "used_only", unit: "usd_micros", value: 4.1 * M, basis: "spend:month" },
    value: /^Spent \$4\.10$/,
    context: "this month",
    note: USED_ONLY_NOTE,
  },
  {
    name: "used-only from a window",
    h: { kind: "used_only", unit: "credits", value: 340, basis: "window:cycle" },
    value: /^Used 340 credits$/,
    context: "this cycle",
    note: USED_ONLY_NOTE,
  },
  { name: "none", h: { kind: "none" }, value: /^No reading yet$/ },
  { name: "missing", h: undefined, value: /^No reading yet$/ },
  { name: "a value that is not a number is not a reading", h: { kind: "left", unit: "usd_micros", basis: "balance:prepaid" }, value: /^No reading yet$/ },
];

for (const c of headCases) {
  test(`headline: ${c.name}`, () => {
    const v = withUSD(() => headlineView(c.h, NOW));
    assert.match(v.value, c.value);
    if (c.context !== undefined) assert.equal(v.context, c.context);
    if (c.details) {
      assert.equal(v.details.length, c.details.length, JSON.stringify(v.details));
      c.details.forEach((re, i) => assert.match(v.details[i], re));
    }
    if (c.note !== undefined) assert.equal(v.note, c.note);
    if (c.tone !== undefined) assert.equal(v.tone, c.tone);
    if (c.leftFrac !== undefined) assert.ok(Math.abs((v.leftFrac ?? -1) - c.leftFrac) < 1e-9);
    assert.doesNotMatch(v.value, /NaN|undefined/);
  });
}

test("headline: money hides in the token cost display, never a dollar sign", () => {
  try {
    setCostDisplayMode("tokens");
    const left = headlineView({ kind: "left", unit: "usd_micros", value: 10 * M, of: 40 * M, basis: "balance:prepaid" }, NOW);
    assert.equal(left.value, "25% left");
    const noTotal = headlineView({ kind: "left", unit: "cny_micros", value: 10 * M, basis: "balance:total" }, NOW);
    assert.equal(noTotal.value, "Balance hidden");
    assert.equal(noTotal.note, HIDDEN_MONEY_NOTE);
    const used = headlineView({ kind: "used_only", unit: "usd_micros", value: 4 * M, basis: "spend:month" }, NOW);
    assert.equal(used.value, "Usage hidden");
    for (const v of [left, noTotal, used]) assert.doesNotMatch([v.value, ...v.details].join(" "), /\$|¥/);
  } finally {
    setCostDisplayMode("usd");
  }
});

test("window phrases: known keys read as words, others fall back to the label", () => {
  assert.equal(windowPhrase("5h"), "in this 5-hour window");
  assert.equal(windowPhrase("weekly"), "this week");
  assert.equal(windowPhrase("key_cap"), "on this key");
  assert.doesNotMatch(windowPhrase("some_new_key"), /_/);
});

test("other balances drop only the one the headline shows", () => {
  const card = {
    headline: { kind: "left", unit: "usd_micros", value: 1, basis: "balance:total" },
    balances: [
      { kind: "total", unit: "usd_micros", amount: 1 },
      { kind: "total", unit: "cny_micros", amount: 7 },
      { kind: "granted", unit: "usd_micros", amount: 2 },
    ],
  } as unknown as Pick<PlanCard, "balances" | "headline">;
  assert.deepEqual(
    otherBalances(card).map((b) => `${b.kind}/${b.unit}`),
    ["total/cny_micros", "granted/usd_micros"],
  );
  const pct = { ...card, headline: { kind: "percent_left", value: 0.5, basis: "window:5h" } } as typeof card;
  assert.equal(otherBalances(pct).length, 3);
});

// ---------- picker ----------

function prov(id: string, group: string, extra: Partial<CatalogProvider> = {}): CatalogProvider {
  return { id, group, has_experimental: false, sources: [], ...extra };
}

const catalog: CatalogProvider[] = [
  prov("claude", "plans", { coverage: "official", shows: ["5h", "weekly", "model", "spend"], tools: ["claude-code"] }),
  prov("cursor", "plans", { coverage: "experimental", has_experimental: true, shows: ["cycle", "spend"], tools: ["cursor"] }),
  prov("amp", "plans", { coverage: "official", shows: ["daily", "credits"] }),
  prov("other", "plans"),
  prov("openrouter", "balance", { coverage: "official", shows: ["balance", "key_cap", "spend"] }),
  prov("deepseek", "balance", { coverage: "official", shows: ["balance"] }),
  prov("opencode", "plans", { coverage: "manual_only", gap: "no_quota_api", tools: ["opencode"] }),
  prov("opencode_go", "plans", { coverage: "session", tools: ["opencode"] }),
  prov("fireworks", "usage", { coverage: "official", shows: ["spend"] }),
  prov("groq", "usage", { coverage: "manual_only", gap: "paid_probe" }),
];

test("picker: groups in kind order, names sorted, Other last", () => {
  const g = pickerGroups(catalog);
  assert.deepEqual(g.map((x) => x.label), ["Coding plans", "API balances", "Usage-based"]);
  assert.deepEqual(g[0].items.map((i) => i.id), ["amp", "claude", "cursor", "opencode", "opencode_go", "other"]);
  assert.deepEqual(g[1].items.map((i) => i.id), ["deepseek", "openrouter"]);
  assert.equal(pickerCount(g), catalog.length);
  assert.equal(vendorCount(catalog), catalog.length - 1);
});

test("picker: rows carry shows, coverage and the gap reason", () => {
  const rows = pickerGroups(catalog).flatMap((g) => g.items);
  const claude = rows.find((r) => r.id === "claude")!;
  assert.equal(claude.shows, "5-hour, Weekly, Per model, Spend");
  assert.equal(claude.coverage?.label, "Official");
  const opencode = rows.find((r) => r.id === "opencode")!;
  assert.equal(opencode.coverage?.label, "Type it in");
  assert.match(opencode.gap, /no way to read/);
  assert.equal(rows.find((r) => r.id === "opencode_go")!.coverage?.label, "Browser session");
  assert.equal(rows.find((r) => r.id === "cursor")!.experimental, true);
});

const searchCases: Array<[string, string[]]> = [
  ["open", ["opencode", "opencode_go", "openrouter"]],
  ["OPENR", ["openrouter"]],
  ["go", ["opencode_go"]],
  ["seek", ["deepseek"]],
  ["balance", ["deepseek", "openrouter"]],
  ["5-hour", ["claude"]],
  ["claude-code", ["claude"]],
  ["zzz", []],
  ["", catalog.map((p) => p.id)],
];

for (const [q, want] of searchCases) {
  test(`picker search ${JSON.stringify(q)}`, () => {
    const got = pickerGroups(catalog, q).flatMap((g) => g.items.map((i) => i.id));
    assert.deepEqual([...got].sort(), [...want].sort());
  });
}

test("picker search ranks a name prefix before a word match before a fact match", () => {
  const p = (id: string) => catalog.find((c) => c.id === id)!;
  assert.equal(matchRank(p("openrouter"), "open"), 0);
  assert.equal(matchRank(p("opencode_go"), "go"), 1);
  assert.equal(matchRank(p("deepseek"), "balance"), 2);
  assert.equal(matchRank(p("deepseek"), "weekly"), -1);
  const g = pickerGroups(
    [prov("aaa_cursor_fan", "plans", { tools: ["cursor"] }), prov("cursor", "plans")],
    "cursor",
  );
  assert.equal(g[0].items[0].id, "cursor");
});

test("showsText caps the list", () => {
  assert.equal(showsText(["5h", "daily", "weekly", "monthly", "cycle"]), "5-hour, Daily, Weekly, Monthly and more");
  assert.equal(showsText(undefined), "");
});

test("method view says what you hand over", () => {
  assert.equal(methodView({ id: "openrouter.api", auth: "pasted_key", experimental: false }).handOver, "An API key");
  assert.match(methodView({ id: "x.session", auth: "pasted_session", experimental: true }).handOver, /browser session/);
  assert.match(methodView({ id: "manual", experimental: false }).handOver, /typed in/);
});

// ---------- Track more ----------

test("suggestions: tools you use first, then official in catalogue order, never tracked or Other", () => {
  const s = suggestions(catalog, new Set(["claude"]), ["opencode", "cursor"]);
  assert.deepEqual(
    s.map((x) => x.id),
    ["opencode_go", "opencode", "cursor", "amp", "openrouter", "deepseek"],
  );
  assert.equal(s[0].usedTool, "opencode");
  assert.ok(!s.some((x) => x.id === "other" || x.id === "claude"));
  // A type-it-in-only provider without a used tool is never suggested.
  assert.ok(!suggestions(catalog, new Set(), []).some((x) => x.id === "groq"));
  assert.equal(suggestions(catalog, new Set(), [], 2).length, 2);
});

// ---------- experimental list ----------

test("experimental rows: only switched on or in use", () => {
  const cat: CatalogProvider[] = [
    prov("cursor", "plans", {
      has_experimental: true,
      shows: ["cycle"],
      sources: [{ id: "cursor.app", kind: "x", rung: "x", experimental: true, passive: false, secrets: [], params: [] }],
    }),
    prov("windsurf", "plans", {
      has_experimental: true,
      sources: [{ id: "windsurf.cache", kind: "x", rung: "x", experimental: true, passive: false, secrets: [], params: [] }],
    }),
    prov("kimi_code", "plans", {
      has_experimental: true,
      sources: [{ id: "kimi_code.api", kind: "x", rung: "x", experimental: true, passive: false, secrets: [], params: [] }],
    }),
  ];
  const acct = { id: "a1", provider: "windsurf", source: "windsurf.cache" } as PlanAccount;
  const rows = experimentalRows(cat, new Set(["cursor"]), [acct]);
  assert.deepEqual(rows.map((r) => [r.id, r.on, r.accounts]), [["cursor", true, 0], ["windsurf", false, 1]]);
  assert.deepEqual(rows[0].methods, ["Cursor sign-in"]);
  assert.equal(experimentalRows(cat, new Set(), []).length, 0);
});

// ---------- marks ----------

function keysBetween(rel: string, startMarker: string, endMarker: string | null): Set<string> {
  const src = read(rel);
  const start = src.indexOf(startMarker);
  const end = endMarker ? src.indexOf(endMarker, start) : src.length;
  return new Set([...src.slice(start, end).matchAll(/^\s+"([a-z0-9-]+)": [({]/gm)].map((m) => m[1]));
}

test("every provider mark names an existing shared mark", () => {
  const tools = keysBetween("shared/lib/toolLogos.tsx", "export const TOOL_LOGOS", "export const TOOL_PIPS");
  const hosts = keysBetween("shared/lib/brandMarks.tsx", "export const HOST_MARKS", "export const IDP_MARKS");
  const families = keysBetween("shared/lib/brandMarks.tsx", "export const MODEL_FAMILY_MARKS", "export const HOST_MARKS");
  assert.ok(tools.size > 40 && hosts.size > 10 && families.size > 20);
  const table = { tool: tools, host: hosts, family: families };
  for (const [provider, ref] of Object.entries(PROVIDER_MARKS)) {
    assert.ok(provider in PROVIDER_LABELS, `${provider} is not a provider`);
    assert.ok(table[ref.kind].has(ref.id), `${provider}: no ${ref.kind} mark ${ref.id}`);
  }
});

test("every catalogue provider renders a mark or a monogram", () => {
  const src = read("internal/planlimits/catalog.go");
  const ids = [...src.matchAll(/\{ID: "([a-z0-9_]+)"/g)].map((m) => m[1]);
  assert.ok(ids.length > 50, `catalogue parse found ${ids.length}`);
  for (const id of [...ids, ...Object.keys(PROVIDER_LABELS)]) {
    const m = providerMark(id);
    if (m.kind === "monogram") assert.match(m.letter, /^[A-Z0-9]$/, id);
    else assert.ok(m.id);
  }
  assert.equal(monogramLetter("ai&"), "A");
  assert.equal(monogramLetter("v0"), "V");
  assert.equal(monogramLetter("&&"), "?");
});

test("other spend drops only the period a usage-only headline shows", () => {
  const spend = [
    { period: "month", unit: "usd_micros", amount: 4 },
    { period: "day", unit: "usd_micros", amount: 1 },
  ];
  const used = { spend, headline: { kind: "used_only", unit: "usd_micros", value: 4, basis: "spend:month" } } as unknown as Pick<PlanCard, "spend" | "headline">;
  assert.deepEqual(otherSpend(used).map((s) => s.period), ["day"]);
  const left = { spend, headline: { kind: "left", unit: "usd_micros", value: 4, basis: "balance:prepaid" } } as unknown as Pick<PlanCard, "spend" | "headline">;
  assert.equal(otherSpend(left).length, 2);
});

// ---------- currencies never mix (DeepSeek audit) ----------

test("balance groups: one currency per group, headline currency first, rows reconcile", () => {
  const bal = (kind: string, unit: string, amount: number) => ({
    kind,
    unit,
    amount,
    source: "deepseek.api",
    source_kind: "official_api",
    rung: "official",
    confidence: "exact",
    observed_at: "",
  });
  const usdcny = {
    headline: {
      kind: "left" as const,
      unit: "usd_micros",
      value: 3_120_000,
      basis: "balance:total",
      also: [{ unit: "cny_micros", value: 52_300_000 }],
    },
    balances: [
      bal("granted", "cny_micros", 10_000_000),
      bal("topup", "cny_micros", 42_300_000),
      bal("total", "cny_micros", 52_300_000),
      bal("granted", "usd_micros", 120_000),
      bal("topup", "usd_micros", 3_000_000),
      bal("total", "usd_micros", 3_120_000),
    ],
  };
  const g = balanceGroups(usdcny);
  assert.deepEqual(
    g.map((x) => [x.unit, x.label]),
    [
      ["usd_micros", "US dollars"],
      ["cny_micros", "Chinese yuan"],
    ],
  );
  for (const grp of g) {
    assert.ok(grp.rows.every((b) => b.unit === grp.unit), "a group never mixes currencies");
    assert.ok(!grp.rows.some((b) => b.kind === "total"), "the totals are in the headline");
    const sum = grp.rows.reduce((n, b) => n + b.amount, 0);
    const total = grp.unit === "usd_micros" ? usdcny.headline.value : usdcny.headline.also[0].value;
    assert.equal(sum, total, `${grp.unit} rows add up to its total`);
  }
  const hv = headlineView(usdcny.headline);
  assert.equal(hv.also?.length, 1);
  assert.ok(hv.also![0].endsWith("52.30 left"), hv.also![0]);

  const cnyOnly = {
    headline: { kind: "left" as const, unit: "cny_micros", value: 52_300_000, basis: "balance:total" },
    balances: [
      bal("granted", "cny_micros", 10_000_000),
      bal("topup", "cny_micros", 42_300_000),
      bal("total", "cny_micros", 52_300_000),
    ],
  };
  const one = balanceGroups(cnyOnly);
  assert.equal(one.length, 1);
  assert.equal(one[0].label, "", "a single currency needs no heading");
  assert.equal(headlineView(cnyOnly.headline).also, undefined);
});

// ---------- daily usage reconciliation ----------

const usageFixture: PlanUsageView = {
  account_id: "a1",
  provider: "chatgpt",
  available: true,
  days: 30,
  fetched_at: "2026-11-01T09:00:00Z",
  tools: ["codex"],
  reconciliation: {
    from: "2026-10-03",
    to: "2026-11-01",
    days: [
      { day: "2026-10-30", vendor_reported: true, vendor_tokens: 136_533_390, captured_tokens: 0, uncaptured_tokens: 136_533_390, ratio: 0 },
      { day: "2026-10-09", vendor_reported: false, vendor_tokens: 0, captured_tokens: 5, uncaptured_tokens: 0 },
      { day: "2026-10-08", vendor_reported: true, vendor_tokens: 23_252_828, captured_tokens: 21_921_453, uncaptured_tokens: 1_331_375, ratio: 0.9427 },
    ],
    totals: { vendor_tokens: 159_786_218, captured_tokens: 21_921_458, uncaptured_tokens: 137_864_765, ratio: 0.137 },
  },
};

test("usageBlock: nothing before a reading or without the capability", () => {
  assert.equal(usageBlock(null), null);
  assert.equal(usageBlock({ ...usageFixture, reconciliation: undefined }), null);
  assert.equal(usageBlock({ ...usageFixture, available: false }), null);
});

test("usageBlock: Codex wording, tokens only, honest gap label", () => {
  const b = usageBlock(usageFixture)!;
  assert.equal(b.title, "Codex usage by day");
  assert.equal(b.window, "Last 30 days, UTC");
  assert.deepEqual(b.totals.map((t) => t.label), ["OpenAI total", "Captured here", "Not captured here"]);
  assert.equal(b.rows.length, 3);
  assert.equal(b.rows[0].vendor, "136.5M");
  assert.equal(b.rows[0].label, "Oct 30");
  assert.equal(b.rows[1].vendor, "none reported");
  assert.equal(b.rows[1].share, "");
  assert.equal(b.rows[2].share, "94% captured");
  assert.equal(b.max, 136_533_390);
  assert.match(b.notes[0], /^Not captured here: Codex cloud chats, other devices or sessions Observer did not run on\.$/);
  assert.match(b.notes.join(" "), /every surface and device on the login/);
  assert.match(b.notes.join(" "), /this machine's codex sessions for any login/);
  assert.match(b.notes.join(" "), /does not document its day boundary/);
  const all = JSON.stringify(b);
  assert.ok(!all.includes("$") && !/USD/.test(all), "tokens only, never dollars");
  assert.ok(!/cloud usage/i.test(all), "the gap is never called cloud usage");
  assert.ok(!all.includes("\u2014"), "no em-dashes in copy");
});

test("usageBlock: an empty window says so", () => {
  const b = usageBlock({
    ...usageFixture,
    days: 1,
    reconciliation: { ...usageFixture.reconciliation!, days: [], totals: { vendor_tokens: 0, captured_tokens: 0, uncaptured_tokens: 0 } },
  })!;
  assert.equal(b.window, "Last 1 day, UTC");
  assert.equal(b.empty, "No usage on any day in this window.");
});
