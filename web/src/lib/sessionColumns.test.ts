import assert from "node:assert/strict";
import test from "node:test";

import {
  COLUMN_STORAGE_KEY,
  ENRICH_TONE_CLASS,
  FLEX_MAX,
  FLEX_PREFERRED,
  MAX_ROW_TAGS,
  SESSION_COLUMNS,
  SORT_OPTIONS,
  flexBudget,
  hiddenCount,
  inlineFacets,
  loadColumnOverrides,
  matchSortOption,
  parentSessionId,
  parseColumnOverrides,
  projectName,
  resolveSessionColumns,
  rowTagCount,
  saveColumnOverrides,
  sessionColumn,
  sessionTokenTotal,
  shortSessionId,
  sortButtonLabel,
  sortDirectionWords,
  toggleColumn,
  type ColumnStorage,
  type SessionColumnId,
} from "./sessionColumns.ts";

// Card widths the design was sized for: viewport minus the 220px nav, the
// page padding and the card padding (docs/plans/sessions-table-redesign).
const CARD = { w1920: 1618, w1440: 1138, w1280: 978, w390: 324 };

const defaultsWithScoring = SESSION_COLUMNS.filter((c) => c.locked || c.defaultOn).map((c) => c.id);

test("the column table: unique ids, one flexible column, locked columns first", () => {
  const ids = SESSION_COLUMNS.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.deepEqual(SESSION_COLUMNS.filter((c) => c.flex).map((c) => c.id), ["session"]);
  assert.deepEqual(SESSION_COLUMNS.slice(0, 2).map((c) => c.id), ["favorite", "session"]);
  for (const c of SESSION_COLUMNS) {
    assert.ok(c.width > 0, c.id);
    assert.ok(c.label.length > 0 && c.label.length <= 40, c.id);
    if (c.locked) assert.equal(c.priority, 0, c.id);
    else assert.ok(c.priority > 0, c.id);
  }
  // Default columns carry distinct priorities, so the fit order is total.
  const prios = SESSION_COLUMNS.filter((c) => !c.locked && c.defaultOn).map((c) => c.priority);
  assert.equal(new Set(prios).size, prios.length);
  assert.equal(sessionColumn("tokens")?.label, "Tokens");
  assert.equal(sessionColumn("nope"), undefined);
});

// One row per viewport the design names: what the default set shows there.
const FIT_ROWS: { name: string; available: number; scoring: boolean; dropped: SessionColumnId[] }[] = [
  { name: "1920 shows every default column", available: CARD.w1920, scoring: true, dropped: [] },
  { name: "1440 drops tags, AI code, quality", available: CARD.w1440, scoring: true, dropped: ["tags", "ai_code_lines", "quality"] },
  { name: "1280 also drops actions and elapsed", available: CARD.w1280, scoring: true, dropped: ["tags", "ai_code_lines", "quality", "actions", "elapsed"] },
  {
    name: "390 keeps favorite, session and cost",
    available: CARD.w390,
    scoring: true,
    dropped: ["tags", "ai_code_lines", "quality", "actions", "elapsed", "models", "tokens", "project", "tool", "started_at"],
  },
  { name: "1440 without scores drops tags and AI code", available: CARD.w1440, scoring: false, dropped: ["tags", "ai_code_lines"] },
];

for (const row of FIT_ROWS) {
  test(`fit: ${row.name}`, () => {
    const r = resolveSessionColumns({ overrides: {}, scoring: row.scoring, available: row.available });
    assert.deepEqual(r.autoHidden, row.dropped);
    assert.equal(r.overflow, false, "default columns never scroll sideways");
    assert.ok(r.minWidth <= row.available);
    for (const id of row.dropped) assert.ok(!r.shown.includes(id));
    assert.ok(r.shown.includes("favorite") && r.shown.includes("session"));
  });
}

test("flex budget: a quarter of the card, between the minimum and the preferred width", () => {
  assert.equal(flexBudget(null), FLEX_PREFERRED);
  assert.equal(flexBudget(CARD.w1920), FLEX_PREFERRED);
  assert.equal(flexBudget(CARD.w1280), FLEX_PREFERRED);
  assert.equal(flexBudget(800), 200);
  assert.equal(flexBudget(CARD.w390), sessionColumn("session")?.width);
});

// Session's declared width per card: what is left after the other shown
// columns, never below its budget, never above FLEX_MAX.
const FLEX_ROWS: { name: string; available: number | null; want: number | null }[] = [
  { name: "unmeasured", available: null, want: null },
  { name: "1920 caps at the maximum", available: CARD.w1920, want: FLEX_MAX },
  { name: "1440 gets the leftover", available: CARD.w1440, want: 246 },
  { name: "1280 gets the leftover", available: CARD.w1280, want: 246 },
  { name: "390 gets the leftover", available: CARD.w390, want: 192 },
];
for (const row of FLEX_ROWS) {
  test(`flex width: ${row.name}`, () => {
    const r = resolveSessionColumns({ overrides: {}, scoring: true, available: row.available });
    assert.equal(r.flexWidth, row.want);
    if (row.want != null && row.available != null) {
      // Declared widths never exceed the card while the columns fit.
      assert.ok(r.minWidth - flexBudget(row.available) + row.want <= row.available);
    }
  });
}

test("flex width: an overflowing table gives Session its budget, not the leftover", () => {
  const r = resolveSessionColumns({
    overrides: { input: true, cache_r: true, cache_w: true, output: true },
    scoring: true,
    available: CARD.w390,
  });
  assert.equal(r.overflow, true);
  assert.equal(r.flexWidth, flexBudget(CARD.w390));
});

test("fit: the 390 phone keeps exactly favorite, session and Total $", () => {
  const r = resolveSessionColumns({ overrides: {}, scoring: true, available: CARD.w390 });
  assert.deepEqual(r.shown, ["favorite", "session", "cost"]);
});

test("fit: unmeasured width drops nothing; display order is the table order", () => {
  const r = resolveSessionColumns({ overrides: {}, scoring: true, available: null });
  assert.deepEqual(r.shown, defaultsWithScoring);
  assert.deepEqual(r.autoHidden, []);
  assert.equal(r.overflow, false);
});

test("fit: score columns exist only when something is scored", () => {
  const r = resolveSessionColumns({ overrides: { errors: true }, scoring: false, available: null });
  assert.ok(!r.shown.includes("quality"));
  assert.ok(!r.shown.includes("errors"));
  assert.ok(!r.off.includes("errors"));
});

test("fit: an explicit choice is never dropped; too many choices overflow instead", () => {
  const overrides = { input: true, cache_r: true, cache_w: true, output: true, tags: true } as const;
  const r = resolveSessionColumns({ overrides, scoring: true, available: CARD.w1280 });
  for (const id of ["input", "cache_r", "cache_w", "output", "tags"] as const) assert.ok(r.shown.includes(id), id);
  // Everything droppable went first, then the table overflows.
  assert.ok(!r.shown.includes("models"));
  assert.ok(r.autoHidden.length > 0);
});

test("fit: when the viewer's own choices cannot fit, no default column is hidden either", () => {
  const overrides = {
    tool: true, project: true, started_at: true, models: true, tokens: true,
    input: true, cache_r: true, cache_w: true, output: true, client: true, ran: true,
  } as const;
  const r = resolveSessionColumns({ overrides, scoring: true, available: CARD.w1280 });
  assert.equal(r.overflow, true);
  assert.deepEqual(r.autoHidden, []);
  assert.ok(r.shown.includes("cost"), "Total $ stays when the table scrolls anyway");
  assert.ok(r.shown.includes("tags"));
  // A card narrower than the locked columns alone also drops nothing.
  const tiny = resolveSessionColumns({ overrides: {}, scoring: false, available: 100 });
  assert.equal(tiny.overflow, true);
  assert.deepEqual(tiny.autoHidden, []);
});

test("fit: an explicit off stays off even with room", () => {
  const r = resolveSessionColumns({ overrides: { tool: false }, scoring: true, available: CARD.w1920 });
  assert.ok(!r.shown.includes("tool"));
  assert.ok(r.off.includes("tool"));
  assert.ok(!r.autoHidden.includes("tool"));
});

test("toggle: shown -> explicit off, hidden or dropped -> explicit on, locked ignored", () => {
  assert.deepEqual(toggleColumn({}, "tool", true), { tool: false });
  assert.deepEqual(toggleColumn({ tool: false }, "tool", false), { tool: true });
  assert.deepEqual(toggleColumn({}, "tags", false), { tags: true });
  const o = { input: true };
  assert.equal(toggleColumn(o, "session", true), o);
});

test("hiddenCount counts both dropped and switched-off columns", () => {
  const r = resolveSessionColumns({ overrides: {}, scoring: true, available: CARD.w1440 });
  assert.equal(hiddenCount(r), r.autoHidden.length + r.off.length);
  assert.ok(r.off.includes("input") && r.off.includes("client"));
});

test("inline facets: the Tool cell carries client and where-it-ran only while their columns are off", () => {
  assert.deepEqual(inlineFacets(["tool"]), { client: true, ran: true });
  assert.deepEqual(inlineFacets(["tool", "client"]), { client: false, ran: true });
  assert.deepEqual(inlineFacets(["tool", "client", "ran"]), { client: false, ran: false });
});

const PARSE_ROWS: { name: string; raw: string | null; want: object }[] = [
  { name: "null", raw: null, want: {} },
  { name: "empty", raw: "", want: {} },
  { name: "junk", raw: "{not json", want: {} },
  { name: "array", raw: "[1,2]", want: {} },
  { name: "scalar", raw: "true", want: {} },
  { name: "valid", raw: '{"tool":false,"input":true}', want: { tool: false, input: true } },
  { name: "unknown id dropped", raw: '{"tool":false,"nope":true}', want: { tool: false } },
  { name: "locked id dropped", raw: '{"session":false,"favorite":false}', want: {} },
  { name: "non-boolean dropped", raw: '{"tool":"yes","input":1}', want: {} },
];
for (const row of PARSE_ROWS) {
  test(`parseColumnOverrides: ${row.name}`, () => {
    assert.deepEqual(parseColumnOverrides(row.raw), row.want);
  });
}

function memStorage(): ColumnStorage & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => void data.set(k, v),
    removeItem: (k) => void data.delete(k),
  };
}

test("storage: save then load round-trips; empty choices remove the key", () => {
  const s = memStorage();
  assert.equal(saveColumnOverrides(s, { tags: false, input: true }), true);
  assert.deepEqual(loadColumnOverrides(s), { tags: false, input: true });
  assert.equal(saveColumnOverrides(s, {}), true);
  assert.equal(s.data.has(COLUMN_STORAGE_KEY), false);
  assert.deepEqual(loadColumnOverrides(s), {});
});

test("storage: a throwing or missing store is the defaults, never an error", () => {
  const throwing: ColumnStorage = {
    getItem: () => {
      throw new Error("blocked");
    },
    setItem: () => {
      throw new Error("quota");
    },
    removeItem: () => {
      throw new Error("blocked");
    },
  };
  assert.deepEqual(loadColumnOverrides(throwing), {});
  assert.equal(saveColumnOverrides(throwing, { tags: false }), false);
  assert.deepEqual(loadColumnOverrides(null), {});
  assert.equal(saveColumnOverrides(undefined, {}), false);
});

test("sort menu: every option is unique and matches its own sort", () => {
  const keys = SORT_OPTIONS.map((o) => `${o.id}|${o.desc}`);
  assert.equal(new Set(keys).size, keys.length);
  for (const o of SORT_OPTIONS) assert.equal(matchSortOption(o.id, o.desc), o);
  // The four buckets the Tokens column sums stay sortable from the menu.
  for (const id of ["input", "output", "cache_r", "cache_w"]) {
    assert.ok(SORT_OPTIONS.some((o) => o.id === id && o.desc), id);
  }
});

const SORT_LABEL_ROWS: { sortBy: string; desc: boolean; want: string }[] = [
  { sortBy: "started_at", desc: true, want: "Sort: Started (newest first)" },
  { sortBy: "started_at", desc: false, want: "Sort: Started (oldest first)" },
  { sortBy: "cost", desc: false, want: "Sort: Total $ (low to high)" },
  { sortBy: "errors", desc: true, want: "Sort: Errors (high to low)" },
  { sortBy: "project", desc: false, want: "Sort: Project (A to Z)" },
  { sortBy: "tool", desc: true, want: "Sort: Tool (Z to A)" },
  { sortBy: "rating", desc: false, want: "Sort: Rating (worst first)" },
  { sortBy: "mystery", desc: true, want: "Sort" },
];
for (const row of SORT_LABEL_ROWS) {
  test(`sortButtonLabel: ${row.sortBy} ${row.desc ? "desc" : "asc"}`, () => {
    assert.equal(sortButtonLabel(row.sortBy, row.desc), row.want);
  });
}

test("sortDirectionWords: text, time and number columns", () => {
  assert.equal(sortDirectionWords("session", false), "A to Z");
  assert.equal(sortDirectionWords("started_at", true), "newest first");
  assert.equal(sortDirectionWords("quality", true), "high to low");
});

const PROJECT_ROWS: [string | null | undefined, string][] = [
  ["/home/dev/src/superbased-observer", "superbased-observer"],
  ["/home/dev/src/superbased-observer/", "superbased-observer"],
  ["D:\\work\\clients\\acme-portal\\billing-service", "billing-service"],
  ["D:\\work\\mixed/sep\\leaf", "leaf"],
  ["relative", "relative"],
  ["/", ""],
  ["", ""],
  [null, ""],
  [undefined, ""],
];
for (const [path, want] of PROJECT_ROWS) {
  test(`projectName(${JSON.stringify(path)})`, () => {
    assert.equal(projectName(path), want);
  });
}

test("sessionTokenTotal adds the four buckets and ignores junk", () => {
  assert.equal(
    sessionTokenTotal({ input_tokens: 10, output_tokens: 20, cache_read_tokens: 300, cache_creation_tokens: 4 }),
    334,
  );
  assert.equal(
    sessionTokenTotal({ input_tokens: -1, output_tokens: Number.NaN, cache_read_tokens: 0, cache_creation_tokens: 5 }),
    5,
  );
});

test("subagent ids: parent and short display form", () => {
  assert.equal(parentSessionId("a4eb6fe3df0c:agent:7f3a2b1c9d8e0011"), "a4eb6fe3df0c");
  assert.equal(parentSessionId("a4eb6fe3df0c"), null);
  assert.equal(parentSessionId(":agent:x"), null);
  assert.equal(shortSessionId("a4eb6fe3df0c4e6f9a7b"), "a4eb6fe3df0c…");
  assert.equal(shortSessionId("a4eb6fe3df0c:agent:7f3a2b1c9d8e0011"), "7f3a2b1c9d8e…");
  assert.equal(shortSessionId("short"), "short");
});

test("enrichment tone: every request variant has a token-only class", () => {
  for (const v of ["neutral", "info", "warn", "danger", "success", "accent"] as const) {
    assert.match(ENRICH_TONE_CLASS[v], /^text-(fg-4|info|warn|danger|accent)\b/);
  }
});

// One row per Tags cell shape at the column's own budget.
const TAG_ROWS: { name: string; tags: string[]; note: boolean; want: number }[] = [
  { name: "no tags", tags: [], note: false, want: 0 },
  { name: "one tag", tags: ["bugfix"], note: true, want: 1 },
  { name: "two short tags fit", tags: ["feature", "backend"], note: false, want: 2 },
  { name: "two tags, a third and a note: one pill and +2", tags: ["refactor", "frontend", "perf"], note: true, want: 1 },
  { name: "one very long tag still shows", tags: ["a-very-long-custom-tag-name"], note: false, want: 1 },
  { name: "never more than the cap", tags: ["a", "b", "c", "d"], note: false, want: MAX_ROW_TAGS },
];
for (const row of TAG_ROWS) {
  test(`rowTagCount: ${row.name}`, () => {
    const width = sessionColumn("tags")?.width ?? 0;
    assert.equal(rowTagCount(row.tags, row.note, width), row.want);
  });
}
