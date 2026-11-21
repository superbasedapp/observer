import assert from "node:assert/strict";
import test from "node:test";

import {
  BLANK,
  SHAPE_BODY,
  baseURLProblem,
  budgetRows,
  checkBudgetScopes,
  checkFallbacks,
  checkLocalUpstreams,
  checkPathClasses,
  checkPrivacyRules,
  checkTiers,
  fallbackRows,
  folderName,
  globValid,
  parseBands,
  parseScope,
  pathClassRows,
  pathClassUses,
  privacyRows,
  projectNames,
  sameValue,
  tierOptions,
  tierRows,
  upstreamRows,
  type BudgetRow,
  type FallbackRow,
  type PathClassRow,
  type PrivacyRow,
  type RoutingShapesWire,
  type TierRow,
  type UpstreamRow,
} from "./routingShapes.ts";

// The Settings > Routing shape cards: rows from GET /api/config, the Set*
// bodies the save sends, and the client checks that mirror the daemon's gate
// (internal/intelligence/dashboard/routing_shapes.go + config.ValidateRouting).

const rc: RoutingShapesWire = {
  Tiers: { "gpt-5": "sonnet-class", "claude-opus-4-8": "opus-class" },
  PathClasses: { secrets: ["**/*.pem"], infra: ["infra/**"] },
  Budget: { Scopes: [{ Scope: "project:alpha", LimitUSD: 50, Window: "week", Bands: [0.6, 0.9], Exhausted: "degrade_all" }] },
  Privacy: { Rules: [{ Project: "", PathClass: "secrets", LocalOnly: true, DenyProviders: null, AllowProviders: null }] },
  LocalUpstreams: [{ Name: "ollama", BaseURL: "http://localhost:11434/v1", Models: ["qwen3:32b"] }],
  Reliability: { Fallbacks: { "claude-opus-4-8": ["claude-sonnet-4-6"] } },
  Rules: [{ Name: "infra-deny", When: { PathClass: "infra" } }],
};

test("rows read from the config and write back the same Set* values", () => {
  const cases: [string, unknown, unknown][] = [
    ["tiers", SHAPE_BODY.tiers(tierRows(rc)), { SetTiers: { "claude-opus-4-8": "opus-class", "gpt-5": "sonnet-class" } }],
    ["pathClasses", SHAPE_BODY.pathClasses(pathClassRows(rc)), { SetPathClasses: { infra: ["infra/**"], secrets: ["**/*.pem"] } }],
    [
      "budgetScopes",
      SHAPE_BODY.budgetScopes(budgetRows(rc)),
      { SetBudgetScopes: [{ Scope: "project:alpha", LimitUSD: 50, Window: "week", Bands: [0.6, 0.9], Exhausted: "degrade_all" }] },
    ],
    [
      "privacyRules",
      SHAPE_BODY.privacyRules(privacyRows(rc)),
      { SetPrivacyRules: [{ Project: "", PathClass: "secrets", LocalOnly: true, DenyProviders: [], AllowProviders: [] }] },
    ],
    [
      "localUpstreams",
      SHAPE_BODY.localUpstreams(upstreamRows(rc)),
      { SetLocalUpstreams: [{ Name: "ollama", BaseURL: "http://localhost:11434/v1", Models: ["qwen3:32b"] }] },
    ],
    ["fallbacks", SHAPE_BODY.fallbacks(fallbackRows(rc)), { SetFallbacks: { "claude-opus-4-8": ["claude-sonnet-4-6"] } }],
  ];
  for (const [name, got, want] of cases) assert.deepEqual(got, want, name);
});

test("an absent shape reads as no rows and saves as an empty (clearing) value", () => {
  const empty: RoutingShapesWire = { Tiers: null, PathClasses: null, Budget: null, Privacy: { Rules: null }, LocalUpstreams: null, Reliability: null };
  assert.deepEqual(SHAPE_BODY.tiers(tierRows(empty)), { SetTiers: {} });
  assert.deepEqual(SHAPE_BODY.pathClasses(pathClassRows(empty)), { SetPathClasses: {} });
  assert.deepEqual(SHAPE_BODY.budgetScopes(budgetRows(empty)), { SetBudgetScopes: [] });
  assert.deepEqual(SHAPE_BODY.privacyRules(privacyRows(empty)), { SetPrivacyRules: [] });
  assert.deepEqual(SHAPE_BODY.localUpstreams(upstreamRows(empty)), { SetLocalUpstreams: [] });
  assert.deepEqual(SHAPE_BODY.fallbacks(fallbackRows(empty)), { SetFallbacks: {} });
});

test("normalization trims, drops untouched rows and sorts map keys", () => {
  const tiers: TierRow[] = [{ model: " zeta ", tier: " haiku-class " }, BLANK.tier(), { model: "alpha", tier: "free" }];
  assert.deepEqual(Object.keys(SHAPE_BODY.tiers(tiers).SetTiers), ["alpha", "zeta"]);
  assert.equal(SHAPE_BODY.tiers(tiers).SetTiers.zeta, "haiku-class");

  const classes: PathClassRow[] = [{ name: " b ", patterns: [" x/** ", "", "  "] }, BLANK.pathClass()];
  assert.deepEqual(SHAPE_BODY.pathClasses(classes), { SetPathClasses: { b: ["x/**"] } });

  const budgets: BudgetRow[] = [BLANK.budget(), { ...BLANK.budget(), kind: "tool", target: " codex ", limit: " 12.5 ", bands: "0.5 , 0.9" }];
  assert.deepEqual(SHAPE_BODY.budgetScopes(budgets).SetBudgetScopes, [
    { Scope: "tool:codex", LimitUSD: 12.5, Window: "month", Bands: [0.5, 0.9], Exhausted: "" },
  ]);

  const privacy: PrivacyRow[] = [BLANK.privacy(), { ...BLANK.privacy(), project: " alpha ", localOnly: false, deny: [" openai ", ""] }];
  assert.deepEqual(SHAPE_BODY.privacyRules(privacy).SetPrivacyRules, [
    { Project: "alpha", PathClass: "", LocalOnly: false, DenyProviders: ["openai"], AllowProviders: [] },
  ]);

  const ups: UpstreamRow[] = [BLANK.upstream(), { name: " lm ", baseURL: " http://127.0.0.1:1234/v1 ", models: [" m1 ", ""] }];
  assert.deepEqual(SHAPE_BODY.localUpstreams(ups).SetLocalUpstreams, [{ Name: "lm", BaseURL: "http://127.0.0.1:1234/v1", Models: ["m1"] }]);

  const fb: FallbackRow[] = [{ from: "z", chain: ["a"] }, BLANK.fallback(), { from: " b ", chain: [" c "] }];
  assert.deepEqual(Object.keys(SHAPE_BODY.fallbacks(fb).SetFallbacks), ["b", "z"]);
});

test("sameValue: an unchanged editor is not dirty", () => {
  assert.ok(sameValue(SHAPE_BODY.tiers(tierRows(rc)), SHAPE_BODY.tiers([...tierRows(rc), BLANK.tier()])));
  assert.ok(!sameValue(SHAPE_BODY.tiers(tierRows(rc)), SHAPE_BODY.tiers(tierRows(rc).slice(1))));
});

// Each row: rows, then a substring every problem list must contain ("" = clean).
test("checkTiers", () => {
  const cases: [string, TierRow[], string][] = [
    ["clean", [{ model: "gpt-5", tier: "haiku-class" }], ""],
    ["blank row ignored", [BLANK.tier()], ""],
    ["no model", [{ model: "", tier: "free" }], "Pick a model"],
    ["no tier", [{ model: "gpt-5", tier: "" }], "Pick a tier for gpt-5"],
    ["unknown tier", [{ model: "gpt-5", tier: "super-class" }], "Pick a tier for gpt-5"],
    ["twice", [{ model: "gpt-5", tier: "free" }, { model: " gpt-5", tier: "haiku-class" }], "gpt-5 is listed twice"],
    ["served model in the local tier", [{ model: "qwen3:32b", tier: "local" }], ""],
    ["cloud model in the local tier", [{ model: "gpt-5", tier: "local" }], "gpt-5 can be in the local tier only when a local upstream serves it"],
  ];
  for (const [name, rows, want] of cases) expectProblems(name, checkTiers(rows, rc), want);
});

test("checkLocalUpstreams refuses to strand a local-tier pin", () => {
  const pinned: RoutingShapesWire = { ...rc, Tiers: { "qwen3:32b": "local" } };
  expectProblems("removed", checkLocalUpstreams([], pinned), `"qwen3:32b" is set to the local tier under Tier overrides`);
  expectProblems("moved", checkLocalUpstreams([{ name: "lm", baseURL: "http://127.0.0.1:1234/v1", models: ["qwen3:32b"] }], pinned), "");
});

test("checkPathClasses", () => {
  const cases: [string, PathClassRow[], string][] = [
    ["clean", pathClassRows(rc), ""],
    ["no name", [...pathClassRows(rc), { name: "", patterns: ["a/**"] }], "Name every path class"],
    ["no patterns", [...pathClassRows(rc), { name: "logs", patterns: [] }], `Add at least one path pattern to "logs"`],
    ["bad glob", [...pathClassRows(rc), { name: "logs", patterns: ["[oops"] }], `"[oops" is not a valid pattern`],
    ["twice", [...pathClassRows(rc), { name: "infra", patterns: ["x"] }], `"infra" is listed twice`],
    ["removed under a privacy rule", pathClassRows(rc).filter((r) => r.name !== "secrets"), `"secrets" is still used by privacy rule 1`],
    ["removed under a custom rule", pathClassRows(rc).filter((r) => r.name !== "infra"), `"infra" is still used by custom rule "infra-deny"`],
  ];
  for (const [name, rows, want] of cases) expectProblems(name, checkPathClasses(rows, rc), want);
});

test("checkBudgetScopes mirrors the loader's scope, limit, window, exhausted and band rules", () => {
  const ok: BudgetRow = { kind: "global", target: "", limit: "100", window: "month", bands: "", exhausted: "" };
  const cases: [string, BudgetRow[], string][] = [
    ["clean", [ok], ""],
    ["clean tier scope", [{ ...ok, kind: "tier", target: "opus-class" }], ""],
    ["blank row ignored", [BLANK.budget()], ""],
    ["no target", [{ ...ok, kind: "project" }], "Row 1: pick the project"],
    ["unknown tier", [{ ...ok, kind: "tier", target: "mega" }], "Row 1: pick a tier"],
    ["zero limit", [{ ...ok, limit: "0" }], "enter a limit above 0"],
    ["text limit", [{ ...ok, limit: "lots" }], "enter a limit above 0"],
    ["no window", [{ ...ok, window: "" }], "pick a window"],
    ["bad exhausted", [{ ...ok, exhausted: "explode" }], "pick what happens"],
    ["band not a number", [{ ...ok, bands: "0.5, x" }], "bands are numbers"],
    ["band out of range", [{ ...ok, bands: "0.5, 1" }], "above 0 and below 1"],
    ["bands descending", [{ ...ok, bands: "0.9, 0.5" }], "lowest to highest"],
    ["bands repeated", [{ ...ok, bands: "0.5, 0.5" }], "lowest to highest"],
    ["duplicate", [ok, { ...ok, limit: "5" }], "Row 2 repeats row 1"],
    ["same scope, other window is fine", [ok, { ...ok, window: "day" }], ""],
  ];
  for (const [name, rows, want] of cases) expectProblems(name, checkBudgetScopes(rows), want);
});

test("checkPrivacyRules mirrors the loader's selector and effect rules", () => {
  const ok: PrivacyRow = { project: "alpha", pathClass: "", localOnly: true, deny: [], allow: [] };
  const cases: [string, PrivacyRow[], string][] = [
    ["clean", [ok], ""],
    ["clean deny star + allow", [{ ...ok, localOnly: false, deny: ["*"], allow: ["local", "anthropic"] }], ""],
    ["blank row ignored", [BLANK.privacy()], ""],
    ["no selector", [{ ...ok, project: "", deny: ["openai"] }], "Rule 1: pick a project or a path class"],
    ["no effect", [{ ...ok, localOnly: false }], "keep it on local models, or name providers"],
    ["unsaved path class", [{ ...ok, pathClass: "drafts" }], `path class "drafts" is not saved yet`],
    ["uppercase provider", [{ ...ok, localOnly: false, deny: ["OpenAI"] }], `use "openai"`],
    ["star in allow", [{ ...ok, localOnly: false, allow: ["*"] }], "only works in the block list"],
  ];
  for (const [name, rows, want] of cases) expectProblems(name, checkPrivacyRules(rows, rc), want);
});

test("checkLocalUpstreams", () => {
  const ok: UpstreamRow = { name: "ollama", baseURL: "http://localhost:11434/v1", models: ["qwen3:32b"] };
  const cases: [string, UpstreamRow[], string][] = [
    ["clean loopback", [ok], ""],
    ["clean remote https", [{ name: "box", baseURL: "https://gpu.example.test/v1", models: ["m"] }], ""],
    ["blank row ignored", [BLANK.upstream()], ""],
    ["no name", [{ ...ok, name: "" }], "Row 1: name the endpoint"],
    ["no address", [{ ...ok, baseURL: "" }], "add the endpoint's address"],
    ["no models", [{ ...ok, models: [] }], "add at least one model"],
    ["two names", [ok, { ...ok, models: ["other"] }], `"ollama" is listed twice`],
    ["model twice", [ok, { ...ok, name: "lm" }], `"qwen3:32b" is served by both ollama and lm`],
  ];
  for (const [name, rows, want] of cases) expectProblems(name, checkLocalUpstreams(rows), want);
});

test("baseURLProblem never repeats the address", () => {
  const cases: [string, string][] = [
    ["http://localhost:11434/v1", ""],
    ["https://10.0.0.5:8000/v1", ""],
    ["ftp://localhost/v1", "must start with http:// or https://"],
    ["HTTP://localhost/v1", "must start with http:// or https://"],
    ["http://user:hunter2@localhost:11434/v1", "user name or password"],
    ["http://localhost:11434/v1?key=abc123", "?query or #fragment"],
    ["http://localhost:11434/v1#x", "?query or #fragment"],
    ["http:///v1", "names no host"],
    ["not a url", "not a web address"],
  ];
  for (const [raw, want] of cases) {
    const got = baseURLProblem(raw);
    if (!want) assert.equal(got, "", raw);
    else assert.ok(got.includes(want), `${raw}: ${got}`);
    assert.ok(!got.includes("hunter2") && !got.includes("abc123"), `${raw} echoed: ${got}`);
  }
});

test("checkFallbacks", () => {
  const cases: [string, FallbackRow[], string][] = [
    ["clean", [{ from: "claude-opus-4-8", chain: ["claude-sonnet-4-6", "claude-haiku-4-5"] }], ""],
    ["blank row ignored", [BLANK.fallback()], ""],
    ["no start", [{ from: "", chain: ["a"] }], "Pick the model or tier"],
    ["empty chain", [{ from: "a", chain: [] }], "Add at least one fallback model for a"],
    ["self", [{ from: "a", chain: ["a"] }], "a falls back to itself"],
    ["twice in chain", [{ from: "a", chain: ["b", "b"] }], "a lists b twice"],
    ["two chains", [{ from: "a", chain: ["b"] }, { from: "a", chain: ["c"] }], "a has two chains"],
  ];
  for (const [name, rows, want] of cases) expectProblems(name, checkFallbacks(rows), want);
});

test("globValid follows the matcher's forms and path.Match syntax", () => {
  const cases: [string, boolean][] = [
    ["**/*.pem", true],
    ["infra/**", true],
    ["**/vault/**", true],
    ["src/*.go", true],
    ["file?.txt", true],
    ["[abc]*.env", true],
    ["[a-z].txt", true],
    ["[^x]y", true],
    ["[unclosed", false],
    ["**/[", false],
    ["a[]b", false],
    ["trailing\\", false],
    ["[a-", false],
  ];
  for (const [pat, want] of cases) assert.equal(globValid(pat), want, pat);
});

test("scope, bands and picker helpers", () => {
  assert.deepEqual(parseScope("global"), { kind: "global", target: "" });
  assert.deepEqual(parseScope("project:alpha"), { kind: "project", target: "alpha" });
  assert.deepEqual(parseScope("tier:opus-class"), { kind: "tier", target: "opus-class" });
  assert.deepEqual(parseBands(""), []);
  assert.deepEqual(parseBands("0.5, 0.8 0.95"), [0.5, 0.8, 0.95]);
  assert.equal(parseBands("half"), null);
  assert.equal(folderName("/home/dev/alpha/"), "alpha");
  assert.equal(folderName("C:\\Users\\dev\\beta"), "beta");
  assert.deepEqual(
    projectNames([{ id: "/home/dev/alpha" }, { id: "/srv/alpha" }, { id: "/home/dev/beta" }]).map((p) => p.id),
    ["alpha", "beta"],
  );
  const opts = tierOptions({ "haiku-class": ["a", "b"], "custom-tier": ["c"] });
  assert.deepEqual(opts.map((o) => o.id), ["opus-class", "sonnet-class", "haiku-class", "free", "local", "unclassified", "custom-tier"]);
  assert.equal(opts.find((o) => o.id === "haiku-class")?.sublabel, "2 models today");
  assert.equal(tierOptions(null)[0].sublabel, undefined);
  assert.deepEqual(pathClassUses(rc), [
    { name: "secrets", by: "privacy rule 1" },
    { name: "infra", by: `custom rule "infra-deny"` },
  ]);
});

function expectProblems(name: string, got: string[], want: string): void {
  if (!want) {
    assert.deepEqual(got, [], `${name}: expected no problems`);
    return;
  }
  assert.ok(got.some((p) => p.includes(want)), `${name}: ${JSON.stringify(got)} has no ${JSON.stringify(want)}`);
}
