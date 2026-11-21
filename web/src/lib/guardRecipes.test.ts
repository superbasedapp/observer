import assert from "node:assert/strict";
import test from "node:test";

import {
  APPLY_TOAST,
  GUARD_OFF_CONFIRM_NOTE,
  appliedFor,
  appliedLine,
  applyBody,
  applyConfirmBody,
  applyConfirmTone,
  applyRefusal,
  promptGuardLine,
  changeCountLine,
  changeDecisionLabel,
  changeDirection,
  configMoves,
  copyName,
  decisionRank,
  groupChanges,
  levelStops,
  packChoices,
  previewQuery,
  recipeInput,
  recipeNameFromToml,
  recipeNameProblem,
  removeBody,
  renameRecipeToml,
  copyTitleToml,
  replayModeNote,
  replaySentence,
  isReplayProgress,
  replayProgressText,
  scopeBlockedReason,
  selectionFromApplied,
  selectionKey,
  selectionReady,
  simulateQuery,
  togglePack,
  topBlockingRules,
  type AppliedRecipe,
  type Recipe,
  type RecipeChange,
  type RecipePreview,
  type RecipeReplay,
  type RecipeSelection,
  type RecipesState,
} from "./guardRecipes.ts";

function recipe(over: Partial<Recipe>): Recipe {
  return {
    name: "x",
    kind: "pack",
    title: "",
    summary: "",
    version: 1,
    order: 0,
    mode: "",
    prompt_mode: "",
    extends: "",
    advice: [],
    inputs: [],
    source: "builtin",
    overrides: [],
    rule_ids: [],
    ...over,
  };
}

const CATALOG: Recipe[] = [
  recipe({ name: "strict", kind: "level", title: "Strict", order: 40 }),
  recipe({ name: "none", kind: "level", title: "None", order: 0 }),
  recipe({ name: "my-level", kind: "level", title: "Mine", order: 5, source: "user" }),
  recipe({ name: "balanced", kind: "level", title: "Balanced", order: 30 }),
  recipe({ name: "loose", kind: "level", title: "Loose", order: 10 }),
  recipe({ name: "lockdown", kind: "level", title: "Lockdown", order: 50 }),
  recipe({ name: "networking", title: "Networking" }),
  recipe({ name: "a-user-pack", title: "Mine too", source: "user" }),
  recipe({ name: "frontend", title: "Frontend & web" }),
];

const SEL: RecipeSelection = { level: "strict", packs: ["networking", "frontend"], scope: "global", projectRoot: "" };

test("level stops: built-ins by order, then the user's own levels", () => {
  assert.deepEqual(
    levelStops(CATALOG).map((r) => r.name),
    ["none", "loose", "balanced", "strict", "lockdown", "my-level"],
  );
  assert.deepEqual(levelStops(null), []);
});

test("pack chips: built-ins by name, then the user's own", () => {
  assert.deepEqual(
    packChoices(CATALOG).map((r) => r.name),
    ["frontend", "networking", "a-user-pack"],
  );
});

// One row per query: what the preview and the replay ask for.
const queryCases: { name: string; got: unknown; want: unknown }[] = [
  {
    name: "global level and packs, packs sorted and joined",
    got: previewQuery(SEL),
    want: { level: "strict", packs: "frontend,networking", scope: "global" },
  },
  {
    name: "packs only leaves the level out",
    got: previewQuery({ ...SEL, level: "" }),
    want: { level: undefined, packs: "frontend,networking", scope: "global" },
  },
  {
    name: "a project names its root",
    got: previewQuery({ level: "loose", packs: [], scope: "project", projectRoot: "/srv/app" }),
    want: { level: "loose", packs: undefined, scope: "project", project_root: "/srv/app" },
  },
  {
    name: "remove asks for the scope only",
    got: previewQuery({ ...SEL, scope: "project", projectRoot: "/srv/app" }, true),
    want: { remove: 1, scope: "project", project_root: "/srv/app" },
  },
  {
    name: "a global removal names no root",
    got: previewQuery({ ...SEL, projectRoot: "/srv/app" }, true),
    want: { remove: 1, scope: "global" },
  },
  {
    name: "the replay adds hours and recipe=1",
    got: simulateQuery(SEL, 720),
    want: { hours: 720, recipe: 1, level: "strict", packs: "frontend,networking", scope: "global" },
  },
  {
    name: "a removal replay",
    got: simulateQuery(SEL, 168, true),
    want: { hours: 168, recipe: 1, remove: 1, scope: "global" },
  },
];
for (const c of queryCases) {
  test(`query: ${c.name}`, () => assert.deepEqual(c.got, c.want));
}

test("write bodies carry the scope and only a project's root", () => {
  assert.deepEqual(applyBody(SEL), { level: "strict", packs: ["frontend", "networking"], scope: "global", project_root: "" });
  assert.deepEqual(applyBody({ ...SEL, scope: "project", projectRoot: "/p" }).project_root, "/p");
  assert.deepEqual(removeBody("global", "/p"), { scope: "global", project_root: "" });
  assert.deepEqual(removeBody("project", "/p"), { scope: "project", project_root: "/p" });
});

test("a selection is ready with a level or a pack, and a project needs its root", () => {
  assert.equal(selectionReady(SEL), true);
  assert.equal(selectionReady({ ...SEL, level: "", packs: [] }), false);
  assert.equal(selectionReady({ ...SEL, level: "", packs: ["frontend"] }), true);
  assert.equal(selectionReady({ ...SEL, scope: "project", projectRoot: "" }), false);
  assert.equal(selectionKey(SEL), selectionKey({ ...SEL, packs: ["frontend", "networking"] }));
  assert.notEqual(selectionKey(SEL), selectionKey(SEL, true));
  assert.deepEqual(togglePack(["networking"], "frontend"), ["frontend", "networking"]);
  assert.deepEqual(togglePack(["frontend", "networking"], "frontend"), ["networking"]);
});

const APPLIED: AppliedRecipe = {
  scope: "project",
  project_root: "/srv/app",
  path: "/home/u/.observer/guard-project-policies/abc.recipe.toml",
  readable: true,
  meta: { format: 1, scope: "project", level: { name: "strict", version: 2 }, packs: [{ name: "frontend", version: 1 }] },
};

test("the applied recipe is found per scope and seeds the picker", () => {
  const st = { global: null, projects: [APPLIED] } as unknown as RecipesState;
  assert.equal(appliedFor(st, "project", "/srv/app"), APPLIED);
  assert.equal(appliedFor(st, "project", "/elsewhere"), null);
  assert.equal(appliedFor(st, "global", ""), null);
  assert.equal(appliedFor(null, "global", ""), null);
  assert.deepEqual(selectionFromApplied(APPLIED, "project", "/srv/app"), { level: "strict", packs: ["frontend"], scope: "project", projectRoot: "/srv/app" });
  assert.deepEqual(selectionFromApplied(null, "global", ""), { level: "", packs: [], scope: "global", projectRoot: "" });
  assert.equal(appliedLine(APPLIED, CATALOG), "Strict v2 + Frontend & web v1");
  assert.equal(appliedLine(null, CATALOG), "");
});

// Decision ordering: one row per pair. An allow lets the action through as
// silently as an absent or off row (sweep finding UI-7b), so a new
// [[rule]] at allow is never "stricter".
const directionCases: [string, string, string][] = [
  ["flag", "ask", "tighter"],
  ["ask", "deny", "tighter"],
  ["off", "allow", "same"],
  ["absent", "allow", "same"],
  ["allow", "flag", "tighter"],
  ["absent", "flag", "tighter"],
  ["deny", "ask", "looser"],
  ["ask", "off", "looser"],
  ["flag", "allow", "looser"],
  ["allow", "absent", "same"],
  ["off", "absent", "same"],
  ["ask", "ask", "same"],
];
for (const [before, after, want] of directionCases) {
  test(`decision order: ${before} -> ${after} is ${want}`, () => assert.equal(changeDirection(before, after), want));
}

test("decision ranks and labels", () => {
  assert.ok(decisionRank("deny") > decisionRank("ask"));
  assert.ok(decisionRank("ask") > decisionRank("flag"));
  assert.ok(decisionRank("flag") > decisionRank("allow"));
  assert.equal(decisionRank("allow"), decisionRank("off"));
  assert.equal(decisionRank("allow"), decisionRank("absent"));
  assert.equal(decisionRank("something-new"), decisionRank("flag"));
  assert.equal(changeDecisionLabel("off"), "Off");
  assert.equal(changeDecisionLabel("absent"), "Not present");
  assert.equal(changeDecisionLabel("ask"), "Ask");
});

const CHANGES: RecipeChange[] = [
  { rule_id: "R-171", doc: "upload", category: "exfil", before: "ask", after: "deny" },
  { rule_id: "R-150", doc: "outside", category: "boundary", before: "flag", after: "ask" },
  { rule_id: "R-121", doc: "update", category: "destructive", before: "flag", after: "ask" },
  { rule_id: "R-120", doc: "drop", category: "destructive", before: "ask", after: "deny" },
  { rule_id: "U-1", doc: "mine", category: "", before: "absent", after: "deny" },
  { rule_id: "R-301", doc: "mcp", category: "mcp", before: "deny", after: "flag" },
];

test("changes group by category in catalog order, rules by id", () => {
  const groups = groupChanges(CHANGES);
  assert.deepEqual(
    groups.map((g) => [g.category, g.label, g.changes.map((c) => c.rule_id)]),
    [
      ["destructive", "Destructive commands", ["R-120", "R-121"]],
      ["boundary", "Project boundary", ["R-150"]],
      ["exfil", "Data exfiltration", ["R-171"]],
      ["mcp", "MCP servers", ["R-301"]],
      ["other", "Other", ["U-1"]],
    ],
  );
  assert.deepEqual(groupChanges(null), []);
});

test("the count line and the apply confirm", () => {
  assert.equal(changeCountLine([]), "No rule changes its decision");
  assert.equal(changeCountLine(CHANGES.slice(0, 1)), "1 rule changes");
  assert.equal(changeCountLine(CHANGES), "6 rules change");
  const p = {
    scope: "global",
    changes: CHANGES,
    mode_before: "observe",
    mode_after: "enforce",
  } as unknown as RecipePreview;
  const body = applyConfirmBody(p);
  assert.equal(body[0], "6 rules change (5 stricter, 1 looser).");
  assert.equal(body[1], "The guard mode moves from Observe to Enforce.");
  const proj = applyConfirmBody({ ...p, scope: "project" });
  assert.match(proj[1], /cannot change the machine-wide mode/);
});

test("a new allow rule is not counted as stricter", () => {
  const p = {
    scope: "global",
    changes: [{ rule_id: "U-2", doc: "mine", category: "", before: "absent", after: "allow" }],
    mode_before: "enforce",
    mode_after: "enforce",
    prompt_mode_before: "block",
    prompt_mode_after: "block",
  } as unknown as RecipePreview;
  assert.equal(applyConfirmBody(p)[0], "1 rule changes.");
});

// Sweep finding UI-6: level none moves the guard mode AND the prompt guard
// off; the confirm names both, drops the layering sentence (false once the
// mode is off) and takes the danger tone.
test("the apply confirm for level none names every mode move", () => {
  const none = {
    scope: "global",
    changes: [],
    mode_before: "enforce",
    mode_after: "off",
    prompt_mode_before: "ask-once",
    prompt_mode_after: "off",
  } as unknown as RecipePreview;
  const body = applyConfirmBody(none);
  assert.ok(body.includes("The guard mode moves from Enforce to Off."), body.join(" | "));
  assert.ok(body.includes("The prompt guard moves from Ask once to Off."), body.join(" | "));
  assert.ok(body.includes(GUARD_OFF_CONFIRM_NOTE), body.join(" | "));
  assert.ok(!body.some((s) => s.includes("Your own rules still win")), body.join(" | "));
  assert.equal(applyConfirmTone(none), "danger");
});

const toneCases: [string, string, string, string, string, "danger" | "primary"][] = [
  ["global", "observe", "enforce", "warn", "block", "primary"],
  ["global", "enforce", "enforce", "ask-once", "ask-once", "primary"],
  ["global", "enforce", "observe", "block", "block", "danger"],
  ["global", "enforce", "enforce", "block", "warn", "danger"],
  ["global", "", "off", "", "off", "danger"],
  ["global", "", "enforce", "", "block", "primary"],
  ["global", "observe", "observe", "ask-once", "redact", "primary"],
  ["global", "observe", "observe", "block", "redact", "danger"],
  ["project", "enforce", "observe", "block", "off", "primary"],
];
for (const [scope, mb, ma, pb, pa, want] of toneCases) {
  test(`apply confirm tone: ${scope} mode ${mb || "default"}->${ma}, prompt ${pb || "default"}->${pa} is ${want}`, () => {
    const p = { scope, changes: [], mode_before: mb, mode_after: ma, prompt_mode_before: pb, prompt_mode_after: pa } as unknown as RecipePreview;
    assert.equal(applyConfirmTone(p), want);
  });
}

test("the apply confirm keeps the layering sentence while the guard stays on", () => {
  const p = {
    scope: "global",
    changes: [],
    mode_before: "observe",
    mode_after: "enforce",
    prompt_mode_before: "warn",
    prompt_mode_after: "block",
  } as unknown as RecipePreview;
  const body = applyConfirmBody(p);
  assert.ok(body.includes("The prompt guard moves from Warn to Block."), body.join(" | "));
  assert.equal(body[body.length - 1], "Your own rules still win over the recipe, and your organization's rules win over both.");
});

// Sweep finding UI-5: hook processes read the policy per command, so the
// toast says the apply is in force for new agent commands now.
test("the apply toast says what is in force now", () => {
  assert.match(APPLY_TOAST, /In force for new agent commands now/);
  assert.match(APPLY_TOAST, /restart the daemon for the proxy and watcher paths/);
});

test("config moves name the level by title and the modes in words", () => {
  const p = {
    level_before: "",
    level_after: "strict",
    mode_before: "enforce",
    mode_after: "enforce",
    prompt_mode_before: "ask-once",
    prompt_mode_after: "block",
  } as unknown as RecipePreview;
  assert.deepEqual(configMoves(p, CATALOG), [
    { label: "Level", before: "No level", after: "Strict", changed: true },
    { label: "Guard mode", before: "Enforce", after: "Enforce", changed: false },
    { label: "Prompt guard", before: "Ask once", after: "Block", changed: true },
  ]);
});

const REPLAY: RecipeReplay = {
  scanned: 2412,
  before: { mode: "enforce", verdicts: 40, by_decision: { flag: 30, ask: 4, deny: 1 }, by_rule_blocking: { "R-150": 3, "R-101": 1, "R-171": 1 } },
  after: { mode: "enforce", verdicts: 60, by_decision: { flag: 20, ask: 12, deny: 3 }, by_rule_blocking: { "R-150": 9, "R-171": 3, "R-175": 3 } },
};

test("the replay sentence", () => {
  assert.equal(
    replaySentence(REPLAY, 168),
    "Over the last 7 days this would have asked 12 times and denied 3 (today's policy: 4 asks, 1 deny), across 2,412 actions.",
  );
  const quiet: RecipeReplay = {
    scanned: 1,
    before: { mode: "observe", verdicts: 0, by_decision: null, by_rule_blocking: null },
    after: { mode: "observe", verdicts: 0, by_decision: { ask: 1 }, by_rule_blocking: null },
  };
  assert.equal(
    replaySentence(quiet, 720),
    "Over the last 30 days this would have asked once and denied nothing (today's policy: 0 asks, 0 denies), across 1 action.",
  );
  assert.match(replayModeNote(quiet), /only records/);
  assert.equal(replayModeNote(REPLAY), "");
});

test("top blocking rules sort by the recipe's count, then today's", () => {
  assert.deepEqual(topBlockingRules(REPLAY), [
    { rule: "R-150", after: 9, before: 3 },
    { rule: "R-171", after: 3, before: 1 },
    { rule: "R-175", after: 3, before: 0 },
    { rule: "R-101", after: 0, before: 1 },
  ]);
  assert.equal(topBlockingRules(REPLAY, 2).length, 2);
});

test("inputs read in plain words and link guard keys to Settings > Guard", () => {
  assert.deepEqual(recipeInput("guard.network.allow_hosts"), {
    key: "guard.network.allow_hosts",
    label: "Allowed hosts",
    where: "Settings > Guard > Network",
    href: "/settings?section=guard",
  });
  assert.equal(recipeInput("guard.something_new").href, "/settings?section=guard");
  assert.equal(recipeInput("routing.mode").href, "");
});

test("user recipe names", () => {
  assert.equal(recipeNameProblem("", CATALOG), "Give the recipe a name.");
  assert.match(recipeNameProblem("Bad Name", CATALOG), /lowercase/);
  assert.match(recipeNameProblem("strict", CATALOG), /built-in/);
  assert.match(recipeNameProblem("a-user-pack", CATALOG), /replaces it/);
  assert.equal(recipeNameProblem("a-user-pack", CATALOG, "a-user-pack"), "");
  assert.equal(recipeNameProblem("fresh-one", CATALOG), "");
  assert.equal(copyName("strict", CATALOG), "my-strict");
  assert.equal(copyName("level", [...CATALOG, recipe({ name: "my-level-2" })]), "my-level-3");
});

test("a duplicate's file is renamed at its top-level name key only", () => {
  const src = 'name = "strict"\nkind = "level"\n\n[[override]]\nrule = "R-150"\nname = "inner"\n';
  assert.equal(renameRecipeToml(src, "my-strict"), 'name = "my-strict"\nkind = "level"\n\n[[override]]\nrule = "R-150"\nname = "inner"\n');
  assert.equal(renameRecipeToml('kind = "pack"\n', "p"), 'name = "p"\nkind = "pack"\n');
});

test("a duplicate's top-level title is marked as a copy, once", () => {
  const src = 'name = "strict"\ntitle = "Strict"\n\n[[rule]]\nid = "RC-X-01"\ntitle = "inner"\n';
  assert.equal(copyTitleToml(src), 'name = "strict"\ntitle = "Strict (copy)"\n\n[[rule]]\nid = "RC-X-01"\ntitle = "inner"\n');
  assert.equal(copyTitleToml(copyTitleToml(src)), copyTitleToml(src));
  assert.equal(copyTitleToml('name = "p"\n[[override]]\ntitle = "x"\n'), 'name = "p"\n[[override]]\ntitle = "x"\n');
});

test("absent optional fields read as empty", () => {
  const sparse = [
    { name: "b", kind: "level", title: "B", summary: "", version: 1, advice: [], inputs: [], source: "builtin", overrides: [], rule_ids: [] },
    recipe({ name: "a", kind: "level", order: 0 }),
  ] as Recipe[];
  assert.deepEqual(levelStops(sparse).map((r) => r.name), ["a", "b"]);
});

test("the named project wins over the projects list, and a scope says why it cannot take a recipe", () => {
  const fromList = { ...APPLIED, path: "list" };
  const named = { ...APPLIED, path: "named" };
  const st = { global: null, projects: [fromList], project: named } as unknown as RecipesState;
  assert.equal(appliedFor(st, "project", "/srv/app")?.path, "named");
  assert.equal(appliedFor({ ...st, project: null }, "project", "/srv/app")?.path, "list");
  const base = { trusted_layer: true, user_layer: true } as unknown as RecipesState;
  assert.equal(scopeBlockedReason(base, "global"), "");
  assert.equal(scopeBlockedReason(base, "project"), "");
  assert.match(scopeBlockedReason({ ...base, user_layer: false }, "global"), /own policy file/);
  assert.equal(scopeBlockedReason({ ...base, user_layer: false }, "project"), "");
  assert.match(scopeBlockedReason({ ...base, trusted_layer: false }, "project"), /trusted per-project rules folder/);
  assert.equal(scopeBlockedReason({ trusted_layer: true } as unknown as RecipesState, "global"), "", "an older daemon without user_layer");
});

test("a refused apply's problems are read from its JSON body only", () => {
  assert.deepEqual(applyRefusal('{"applied":false,"problems":["R-160 cannot be loosened"]}'), ["R-160 cannot be loosened"]);
  assert.equal(applyRefusal("pick a level or at least one pack"), null);
  assert.equal(applyRefusal('{"applied":true}'), null);
});

test("an imported file names itself from its top-level name key", () => {
  assert.equal(recipeNameFromToml('# a pack\nname = "team-db"\nkind = "pack"\n'), "team-db");
  assert.equal(recipeNameFromToml('kind = "pack"\n[[override]]\nname = "inner"\n'), "");
  assert.equal(recipeNameFromToml(""), "");
});

test("applyRefusal also reads a refused remove", () => {
  assert.deepEqual(applyRefusal('{"removed":false,"problems":["the change would drop a policy layer"]}'), ["the change would drop a policy layer"]);
});

test("promptGuardLine says what the prompt guard does beside the guard mode", () => {
  assert.equal(promptGuardLine("observe", { enabled: true, mode: "ask-once", enforce_independent: true }), "prompt guard: asks once (acts in observe)");
  assert.equal(promptGuardLine("enforce", { enabled: true, mode: "ask-once", enforce_independent: true }), "prompt guard: asks once");
  assert.equal(promptGuardLine("observe", { enabled: true, mode: "ask-once", enforce_independent: false }), "prompt guard follows the guard mode");
  assert.equal(
    promptGuardLine("observe", { enabled: true, mode: "ask-once", enforce_independent: false, set_by_org: true }),
    "prompt guard follows your organization's guard mode",
  );
  assert.equal(promptGuardLine("observe", { enabled: true, mode: "off", enforce_independent: true }), "prompt guard: off");
  assert.equal(promptGuardLine("observe", undefined), "");
});

// Demo bug #14: the line a running replay shows, one row per state.
test("replayProgressText describes each state of a running replay", () => {
  const base = { running: true as const, queued: false, actions: 0, evaluated: 0, total: 0, elapsed_ms: 0 };
  const rows: Array<[Partial<typeof base>, string]> = [
    [{ queued: true, elapsed_ms: 3000 }, "Waiting for another replay on this machine to finish (3 s)..."],
    [{ elapsed_ms: 1000 }, "Loading the captured actions (1 s)..."],
    [{ actions: 38806, total: 116418, evaluated: 0, elapsed_ms: 2000 }, "Replaying 38,806 actions: 0% done (2 s)."],
    [{ actions: 38806, total: 116418, evaluated: 58209, elapsed_ms: 4000 }, "Replaying 38,806 actions: 50% done (4 s), about 4 s left."],
    [{ actions: 10, total: 30, evaluated: 30, elapsed_ms: 1500 }, "Replaying 10 actions: 100% done (2 s)."],
  ];
  for (const [over, want] of rows) assert.equal(replayProgressText({ ...base, ...over }), want);
  assert.equal(isReplayProgress({ ...base }), true);
  assert.equal(isReplayProgress({ window_hours: 168 }), false);
  assert.equal(isReplayProgress(null), false);
});
