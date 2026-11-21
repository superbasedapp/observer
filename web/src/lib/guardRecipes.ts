// guardRecipes - the pure half of the Security page's Recipes card (plan
// docs/plans/profile-guard-recipes-repo-grouping-plan-2026-11-07.md section
// 3d). A recipe is a guard quick-setup preset on two axes: a LEVEL (one per
// scope: none, loose, balanced, strict, lockdown, or a user level) and PACKS
// (any number, by kind of work). A scope is this whole machine or one
// project. This module holds the wire shapes of the /api/guard/recipes
// routes, the query and body builders, and the sentences the card shows.
// No fetch, no React: pinned by guardRecipes.test.ts.

import { guardCategoryLabel, guardDecisionLabel, guardRuleName } from "../../../shared/lib/guardRuleNames.ts";

// ---------- wire shapes ----------

/** RecipeKind is a recipe's axis. */
export type RecipeKind = "level" | "pack";

/** RecipeScope is where a recipe applies: the whole machine or one project. */
export type RecipeScope = "global" | "project";

/** RecipeOverride is one [[override]] row a recipe carries. */
export type RecipeOverride = { rule: string; decision: string; enforce: boolean | null; note: string };

/** Recipe is one catalog entry of GET /api/guard/recipes. `order`, `mode`,
 *  `prompt_mode` and `extends` may be absent (read as empty). */
export type Recipe = {
  name: string;
  kind: RecipeKind;
  title: string;
  summary: string;
  version: number;
  order?: number;
  mode?: string;
  prompt_mode?: string;
  extends?: string;
  advice: string[] | null;
  inputs: string[] | null;
  source: "builtin" | "user";
  overrides: RecipeOverride[] | null;
  rule_ids: string[] | null;
};

/** RecipeRef names one applied recipe and its version. */
export type RecipeRef = { name: string; version: number };

/** RecipeMeta is the applied recipe file's header. */
export type RecipeMeta = {
  format: number;
  scope: RecipeScope;
  project_root?: string;
  level?: RecipeRef | null;
  packs?: RecipeRef[] | null;
  mode?: string;
  prompt_mode?: string;
  applied_at?: string;
  applied_via?: string;
  previous?: { level: string; mode: string; prompt_mode: string } | null;
};

/** AppliedRecipe is the recipe applied at one scope. */
export type AppliedRecipe = {
  scope: RecipeScope;
  project_root?: string;
  path: string;
  readable: boolean;
  meta: RecipeMeta;
  /** "strict v1 -> v2": the catalog holds a newer version. */
  updates?: string[] | null;
  /** Applied recipes the catalog no longer holds. */
  missing?: string[] | null;
  /** Project recipes only: why what is applied is not what is in force ("" when it is). */
  drift?: string;
};

/** RecipesState is GET /api/guard/recipes. */
export type RecipesState = {
  catalog: Recipe[] | null;
  issues: string[] | null;
  level: string;
  mode: string;
  prompt_mode: string;
  global: AppliedRecipe | null;
  projects: AppliedRecipe[] | null;
  /** Non-empty when [guard] level disagrees with the applied global recipe. */
  level_drift: string;
  trusted_layer: boolean;
  /** [guard] enabled; absent on an older daemon (read as on). */
  enabled?: boolean;
  /** A user policy path is configured; false means a machine-wide recipe
   *  cannot be applied. Absent on an older daemon (read as configured). */
  user_layer?: boolean;
  /** The project ?project_root= names, when the daemon knows it. */
  project?: AppliedRecipe | null;
  recipe_dir: string;
  confirm_token: string;
};

/** ChangeDecision is a rule's decision before or after: a guard decision,
 *  "off" (disabled) or "absent" (the rule does not exist on that side). */
export type ChangeDecision = "off" | "absent" | "allow" | "flag" | "ask" | "deny";

/** RecipeChange is one rule whose effective decision a recipe changes. */
export type RecipeChange = { rule_id: string; doc: string; category: string; before: string; after: string };

/** RecipePreview is GET /api/guard/recipes/preview. */
export type RecipePreview = {
  scope: RecipeScope;
  project_root?: string;
  path: string;
  remove: boolean;
  level?: string;
  packs?: string[] | null;
  /** The compiled recipe file. */
  text?: string;
  level_before: string;
  level_after: string;
  mode_before: string;
  mode_after: string;
  prompt_mode_before: string;
  prompt_mode_after: string;
  mode_note?: string;
  changes: RecipeChange[] | null;
  /** Non-empty: the apply is refused. */
  problems?: string[] | null;
  /** Warnings (an organization floor keeping a rule, a module not loaded). */
  issues?: string[] | null;
  advice?: string[] | null;
  inputs?: string[] | null;
  replaces?: AppliedRecipe | null;
};

/** ReplaySummary is one side of a recipe replay. */
export type ReplaySummary = {
  mode: string;
  verdicts: number;
  by_decision: { flag?: number; ask?: number; deny?: number } | null;
  by_rule_blocking: Record<string, number> | null;
};

/** RecipeReplay is the recipe_replay block GET /api/guard/simulate adds with recipe=1. */
export type RecipeReplay = { scanned: number; before: ReplaySummary; after: ReplaySummary };

/** RecipeSelection is what the card has picked: one level ("" = none) and packs. */
export type RecipeSelection = { level: string; packs: string[]; scope: RecipeScope; projectRoot: string };

/** Query values, the subset of the api client's QueryParams this module builds. */
export type RecipeQuery = Record<string, string | number | undefined>;

// ---------- the catalog ----------

/** BUILTIN_LEVELS are the five built-in level stops, loosest first. */
export const BUILTIN_LEVELS = ["none", "loose", "balanced", "strict", "lockdown"] as const;

function byOrderThenName(a: Recipe, b: Recipe): number {
  return (a.order ?? 0) - (b.order ?? 0) || a.name.localeCompare(b.name);
}

/** levelStops returns the level slider's stops: the built-in levels by
 *  order, then the user's own levels by order. */
export function levelStops(catalog: Recipe[] | null | undefined): Recipe[] {
  const levels = (catalog ?? []).filter((r) => r.kind === "level");
  const builtin = levels.filter((r) => r.source !== "user").sort(byOrderThenName);
  const user = levels.filter((r) => r.source === "user").sort(byOrderThenName);
  return [...builtin, ...user];
}

/** packChoices returns the pack chips: built-in packs by name, then the user's own. */
export function packChoices(catalog: Recipe[] | null | undefined): Recipe[] {
  const packs = (catalog ?? []).filter((r) => r.kind === "pack");
  const byName = (a: Recipe, b: Recipe) => a.name.localeCompare(b.name);
  return [...packs.filter((r) => r.source !== "user").sort(byName), ...packs.filter((r) => r.source === "user").sort(byName)];
}

/** recipeTitle names a recipe by its title, falling back to its name. */
export function recipeTitle(catalog: Recipe[] | null | undefined, name: string): string {
  const r = (catalog ?? []).find((x) => x.name === name);
  return r?.title || name;
}

/** appliedFor returns the recipe applied at a scope, or null. */
export function appliedFor(state: RecipesState | null | undefined, scope: RecipeScope, projectRoot: string): AppliedRecipe | null {
  if (!state) return null;
  if (scope === "global") return state.global ?? null;
  if (!projectRoot) return null;
  if (state.project && state.project.project_root === projectRoot) return state.project;
  return (state.projects ?? []).find((p) => p.project_root === projectRoot) ?? null;
}

/** selectionFromApplied starts the picker at what a scope already has, so
 *  opening the card on an applied scope shows no change. */
export function selectionFromApplied(applied: AppliedRecipe | null, scope: RecipeScope, projectRoot: string): RecipeSelection {
  return {
    level: applied?.meta.level?.name ?? "",
    packs: (applied?.meta.packs ?? []).map((p) => p.name),
    scope,
    projectRoot,
  };
}

/** togglePack adds or removes a pack, keeping the list sorted and unique. */
export function togglePack(packs: string[], name: string): string[] {
  const set = new Set(packs);
  if (set.has(name)) set.delete(name);
  else set.add(name);
  return [...set].sort();
}

/** selectionReady reports whether a selection can be previewed: it names a
 *  level or a pack, and a project scope names its project. */
export function selectionReady(sel: RecipeSelection): boolean {
  if (sel.scope === "project" && !sel.projectRoot) return false;
  return sel.level !== "" || sel.packs.length > 0;
}

/** selectionKey is a stable key for one selection (or removal). */
export function selectionKey(sel: RecipeSelection, remove = false): string {
  return [remove ? "remove" : "apply", sel.scope, sel.scope === "project" ? sel.projectRoot : "", sel.level, [...sel.packs].sort().join(",")].join("|");
}

// ---------- requests ----------

function scopeParams(scope: RecipeScope, projectRoot: string): RecipeQuery {
  return scope === "project" ? { scope, project_root: projectRoot } : { scope };
}

/** previewQuery is GET /api/guard/recipes/preview's query for a selection,
 *  or for removing what its scope has when `remove` is set. */
export function previewQuery(sel: RecipeSelection, remove = false): RecipeQuery {
  if (remove) return { remove: 1, ...scopeParams(sel.scope, sel.projectRoot) };
  return {
    level: sel.level || undefined,
    packs: sel.packs.length > 0 ? [...sel.packs].sort().join(",") : undefined,
    ...scopeParams(sel.scope, sel.projectRoot),
  };
}

/** REPLAY_WINDOWS are the replay buttons: label and hours. */
export const REPLAY_WINDOWS = [
  { hours: 168, label: "Last 7 days" },
  { hours: 720, label: "Last 30 days" },
] as const;

/** simulateQuery is GET /api/guard/simulate's query for a recipe replay. */
export function simulateQuery(sel: RecipeSelection, hours: number, remove = false): RecipeQuery {
  return { hours, recipe: 1, ...previewQuery(sel, remove) };
}

/** ReplayProgress is the 202 body GET /api/guard/simulate?progress=1 answers
 *  while a replay runs (dashboard guard_simulate_job.go): the run's counts so
 *  the card can show how far it is instead of a bare disabled button. */
export type ReplayProgress = {
  running: true;
  /** Waiting for a different replay on this machine to finish first. */
  queued: boolean;
  /** Captured actions in the window (0 until loaded). */
  actions: number;
  /** Action checks done and to do: every action once per policy compared. */
  evaluated: number;
  total: number;
  elapsed_ms: number;
};

/** isReplayProgress tells a still-running poll answer from the result. */
export function isReplayProgress(x: unknown): x is ReplayProgress {
  return typeof x === "object" && x !== null && (x as { running?: unknown }).running === true;
}

/** REPLAY_POLL_MS is how often the card asks a running replay how far it is. */
export const REPLAY_POLL_MS = 1000;

/** replayProgressText is the line under the replay buttons while one runs. */
export function replayProgressText(p: ReplayProgress): string {
  const secs = Math.max(0, Math.round(p.elapsed_ms / 1000));
  if (p.queued) return `Waiting for another replay on this machine to finish (${secs} s)...`;
  if (p.actions <= 0 || p.total <= 0) return `Loading the captured actions (${secs} s)...`;
  const done = Math.min(p.evaluated, p.total);
  const pct = Math.floor((done / p.total) * 100);
  const n = p.actions.toLocaleString("en-US");
  let line = `Replaying ${n} actions: ${pct}% done (${secs} s)`;
  if (done > 0 && done < p.total) {
    const left = Math.ceil(((p.elapsed_ms / done) * (p.total - done)) / 1000);
    line += `, about ${left} s left`;
  }
  return line + ".";
}

/** applyBody is POST /api/guard/recipes/apply's body. */
export function applyBody(sel: RecipeSelection): { level: string; packs: string[]; scope: RecipeScope; project_root: string } {
  return {
    level: sel.level,
    packs: [...sel.packs].sort(),
    scope: sel.scope,
    project_root: sel.scope === "project" ? sel.projectRoot : "",
  };
}

/** removeBody is POST /api/guard/recipes/remove's body. */
export function removeBody(scope: RecipeScope, projectRoot: string): { scope: RecipeScope; project_root: string } {
  return { scope, project_root: scope === "project" ? projectRoot : "" };
}

// ---------- the preview ----------

/** DECISION_RANK orders the decisions a change can carry, loosest first: a
 *  rule that is off or absent judges nothing, and an allow lets the action
 *  through just as silently, so the three rank together. A new [[rule]] at
 *  allow (absent to allow) never makes anything stricter (sweep finding
 *  UI-7b): only flag, ask and deny stop or record an action. */
export const DECISION_RANK: Readonly<Record<ChangeDecision, number>> = {
  off: 0,
  absent: 0,
  allow: 0,
  flag: 2,
  ask: 3,
  deny: 4,
};

/** decisionRank ranks a decision; an unknown value ranks with "flag" so it
 *  never reads as tighter or looser than it is sure to be. */
export function decisionRank(d: string): number {
  return d in DECISION_RANK ? DECISION_RANK[d as ChangeDecision] : DECISION_RANK.flag;
}

/** ChangeDirection is whether a change makes the guard stricter or looser. */
export type ChangeDirection = "tighter" | "looser" | "same";

/** changeDirection compares a change's before and after decisions. */
export function changeDirection(before: string, after: string): ChangeDirection {
  const b = decisionRank(before);
  const a = decisionRank(after);
  return a > b ? "tighter" : a < b ? "looser" : "same";
}

/** changeDecisionLabel is the word for a change's decision. */
export function changeDecisionLabel(d: string): string {
  if (d === "off") return "Off";
  if (d === "absent") return "Not present";
  return guardDecisionLabel(d);
}

/** changeRuleLabel names a changed rule: its catalog name, else the doc the
 *  server sent, else the bare id. */
export function changeRuleLabel(c: RecipeChange): string {
  return guardRuleName(c.rule_id) ?? (c.doc || c.rule_id);
}

/** ChangeGroup is the changes of one rule category. */
export type ChangeGroup = { category: string; label: string; changes: RecipeChange[] };

// The category order the groups follow (the catalog's own order); anything
// else comes after, by name.
const CATEGORY_ORDER = ["destructive", "boundary", "exfil", "secrets", "pii", "injection", "posture", "mcp", "taint", "anomaly", "budget", "limit"];

function categoryIndex(c: string): number {
  const i = CATEGORY_ORDER.indexOf(c);
  return i < 0 ? CATEGORY_ORDER.length : i;
}

/** groupChanges groups a preview's changes by category, categories in the
 *  catalog's order and rules by id within each. A change with no category
 *  lands under "Other". */
export function groupChanges(changes: RecipeChange[] | null | undefined): ChangeGroup[] {
  const by = new Map<string, RecipeChange[]>();
  for (const c of changes ?? []) {
    const cat = c.category || "other";
    const list = by.get(cat) ?? [];
    list.push(c);
    by.set(cat, list);
  }
  return [...by.entries()]
    .sort(([a], [b]) => categoryIndex(a) - categoryIndex(b) || a.localeCompare(b))
    .map(([category, list]) => ({
      category,
      label: category === "other" ? "Other" : guardCategoryLabel(category),
      changes: [...list].sort((x, y) => x.rule_id.localeCompare(y.rule_id)),
    }));
}

/** changeCountLine is the preview's headline count. */
export function changeCountLine(changes: RecipeChange[] | null | undefined): string {
  const n = (changes ?? []).length;
  if (n === 0) return "No rule changes its decision";
  return n === 1 ? "1 rule changes" : `${n} rules change`;
}

/** changeTally counts the changes that tighten and loosen. */
export function changeTally(changes: RecipeChange[] | null | undefined): { tighter: number; looser: number } {
  let tighter = 0;
  let looser = 0;
  for (const c of changes ?? []) {
    const d = changeDirection(c.before, c.after);
    if (d === "tighter") tighter++;
    else if (d === "looser") looser++;
  }
  return { tighter, looser };
}

const MODE_LABEL: Readonly<Record<string, string>> = { off: "Off", observe: "Observe", enforce: "Enforce" };
const PROMPT_MODE_LABEL: Readonly<Record<string, string>> = {
  off: "Off",
  warn: "Warn",
  "ask-once": "Ask once",
  block: "Block",
  redact: "Redact",
};

/** modeLabel names a guard mode; "" reads as the default. */
export function modeLabel(m: string): string {
  return m ? MODE_LABEL[m] ?? m : "Default";
}

/** promptModeLabel names a prompt guard mode; "" reads as the default. */
export function promptModeLabel(m: string): string {
  return m ? PROMPT_MODE_LABEL[m] ?? m : "Default";
}

/** ConfigMove is one setting a preview moves (or keeps). */
export type ConfigMove = { label: string; before: string; after: string; changed: boolean };

/** configMoves lists the three settings an apply can move, in plain words:
 *  the level, the guard mode and the prompt guard mode. */
export function configMoves(p: RecipePreview, catalog: Recipe[] | null | undefined): ConfigMove[] {
  const level = (n: string) => (n ? recipeTitle(catalog, n) : "No level");
  return [
    { label: "Level", before: level(p.level_before), after: level(p.level_after), changed: p.level_before !== p.level_after },
    { label: "Guard mode", before: modeLabel(p.mode_before), after: modeLabel(p.mode_after), changed: p.mode_before !== p.mode_after },
    {
      label: "Prompt guard",
      before: promptModeLabel(p.prompt_mode_before),
      after: promptModeLabel(p.prompt_mode_after),
      changed: p.prompt_mode_before !== p.prompt_mode_after,
    },
  ];
}

/** modeMoveLine is the one sentence the apply confirm says about the mode. */
export function modeMoveLine(p: RecipePreview): string {
  if (p.mode_before === p.mode_after) return `The guard mode stays ${modeLabel(p.mode_after)}.`;
  return `The guard mode moves from ${modeLabel(p.mode_before)} to ${modeLabel(p.mode_after)}.`;
}

/** promptModeMoveLine is the apply confirm's sentence about the prompt
 *  guard, or "" when it does not move. */
export function promptModeMoveLine(p: RecipePreview): string {
  if (p.prompt_mode_before === p.prompt_mode_after) return "";
  return `The prompt guard moves from ${promptModeLabel(p.prompt_mode_before)} to ${promptModeLabel(p.prompt_mode_after)}.`;
}

// The strictness order of each mode, loosest first. "" is the default: the
// guard mode's is observe (D2); the prompt guard's default is not known
// here, so only a move to "off" from it counts as a lowering.
const MODE_RANK: Readonly<Record<string, number>> = { off: 0, "": 1, observe: 1, enforce: 2 };
const PROMPT_MODE_RANK: Readonly<Record<string, number>> = { off: 0, warn: 1, "ask-once": 2, redact: 3, block: 4 };

/** lowersMode reports whether a move from before to after loosens, by rank;
 *  a move to off from anything else always does, and a value the table does
 *  not know otherwise does not. */
function lowersMode(rank: Readonly<Record<string, number>>, before: string, after: string): boolean {
  if (before === after) return false;
  if (after === "off") return true;
  if (!(before in rank) || !(after in rank)) return false;
  return rank[after] < rank[before];
}

/** applyLowersModes reports whether a machine-wide apply moves the guard
 *  mode or the prompt guard down (sweep finding UI-6): the confirm then
 *  takes the danger tone. A project recipe moves no mode. */
export function applyLowersModes(p: RecipePreview): boolean {
  if (p.scope === "project") return false;
  return lowersMode(MODE_RANK, p.mode_before, p.mode_after) || lowersMode(PROMPT_MODE_RANK, p.prompt_mode_before, p.prompt_mode_after);
}

/** applyConfirmTone is the apply confirm's tone: danger when it lowers a
 *  mode, primary otherwise. */
export function applyConfirmTone(p: RecipePreview): "danger" | "primary" {
  return applyLowersModes(p) ? "danger" : "primary";
}

/** APPLY_TOAST is said after an apply that needs a restart: hook processes
 *  read the policy per command, so new agent commands follow at once, and
 *  only the daemon's own proxy and watcher paths wait for the restart
 *  (sweep finding UI-5; guard_recipes.go handleGuardRecipeApply). */
export const APPLY_TOAST = "Recipe applied. In force for new agent commands now; restart the daemon for the proxy and watcher paths.";

/** PROJECT_MODE_NOTE is said wherever a project recipe is previewed. */
export const PROJECT_MODE_NOTE =
  "A project recipe cannot change the machine-wide mode. It holds the level's mode for this project with explicit rules instead.";

/** NOT_A_FIREWALL_NOTE is said beside the network rules. */
export const NOT_A_FIREWALL_NOTE =
  "The rules judge what a command line names. They are not a firewall: a program can still reach a host the command does not name.";

/** GUARD_OFF_CONFIRM_NOTE replaces the layering sentence when an apply turns
 *  the guard off: with the mode off no rule is checked, the person's own
 *  included, so "your own rules still win" would be false. */
export const GUARD_OFF_CONFIRM_NOTE = "With the guard off, no rule is checked or recorded, your own rules included, until you turn it back on.";

/** applyConfirmBody is the paragraphs of the apply confirm: the rule count,
 *  every mode the apply moves (the guard mode and the prompt guard; sweep
 *  finding UI-6), and how the recipe layers, unless the guard goes off. */
export function applyConfirmBody(p: RecipePreview): string[] {
  const t = changeTally(p.changes);
  const parts: string[] = [];
  const count = changeCountLine(p.changes);
  const split = [t.tighter > 0 ? `${t.tighter} stricter` : "", t.looser > 0 ? `${t.looser} looser` : ""].filter(Boolean).join(", ");
  parts.push(split ? `${count} (${split}).` : `${count}.`);
  if (p.scope === "project") {
    parts.push(PROJECT_MODE_NOTE);
  } else {
    parts.push(modeMoveLine(p));
    const prompt = promptModeMoveLine(p);
    if (prompt) parts.push(prompt);
  }
  if (p.scope !== "project" && p.mode_after === "off") parts.push(GUARD_OFF_CONFIRM_NOTE);
  else parts.push("Your own rules still win over the recipe, and your organization's rules win over both.");
  return parts;
}

/** removeConfirmBody is the paragraphs of the remove confirm. */
export function removeConfirmBody(p: RecipePreview): string[] {
  const parts = [`${changeCountLine(p.changes)}.`];
  if (p.scope === "global") parts.push(`${modeMoveLine(p)} Removing restores the level and modes the first apply replaced.`);
  parts.push("Your own rules and your organization's rules are not touched.");
  return parts;
}

/** scopeBlockedReason says why a scope cannot take a recipe on this
 *  machine, or "" when it can. */
export function scopeBlockedReason(state: RecipesState | null | undefined, scope: RecipeScope): string {
  if (!state) return "";
  if (scope === "global" && state.user_layer === false) {
    return "A machine-wide recipe needs your own policy file, which is not set up here (Settings > Guard > Rules).";
  }
  if (scope === "project" && state.trusted_layer === false) {
    return "Project recipes need the trusted per-project rules folder, which is turned off in Settings > Guard.";
  }
  return "";
}

/** GUARD_OFF_NOTE is said when [guard] enabled is off. */
export const GUARD_OFF_NOTE = "The guard is turned off (Settings > Guard), so nothing a recipe sets is in force until you turn it on.";

/** applyRefusal reads the problems of a refused apply or remove (a 422 whose
 *  JSON body is {"applied":false,"problems":[...]} or {"removed":false,...}),
 *  or null for any other body. */
export function applyRefusal(body: string): string[] | null {
  try {
    const v = JSON.parse(body) as { applied?: boolean; removed?: boolean; problems?: unknown };
    if (v && (v.applied === false || v.removed === false) && Array.isArray(v.problems)) return v.problems.map(String);
  } catch {
    // A plain-text body: not a lint refusal.
  }
  return null;
}

// ---------- applied state ----------

const APPLIED_VIA: Readonly<Record<string, string>> = {
  dashboard: "the dashboard",
  cli: "the command line",
};

/** appliedLine describes what a scope has applied, or "" for nothing. */
export function appliedLine(a: AppliedRecipe | null, catalog: Recipe[] | null | undefined): string {
  if (!a) return "";
  const parts: string[] = [];
  const lvl = a.meta.level;
  if (lvl) parts.push(`${recipeTitle(catalog, lvl.name)} v${lvl.version}`);
  for (const p of a.meta.packs ?? []) parts.push(`${recipeTitle(catalog, p.name)} v${p.version}`);
  if (parts.length === 0) return "A recipe file with no level or pack";
  return parts.join(" + ");
}

/** appliedVia names the surface that applied a recipe. */
export function appliedVia(via: string | undefined): string {
  if (!via) return "";
  return APPLIED_VIA[via] ?? via;
}

// ---------- the replay ----------

function windowLabel(hours: number): string {
  if (hours % 24 === 0) {
    const d = hours / 24;
    return d === 1 ? "day" : `${d} days`;
  }
  return hours === 1 ? "hour" : `${hours} hours`;
}

function askedPart(n: number): string {
  if (n === 0) return "asked nothing";
  if (n === 1) return "asked once";
  return `asked ${n.toLocaleString("en-US")} times`;
}

function deniedPart(n: number): string {
  return n === 0 ? "denied nothing" : `denied ${n.toLocaleString("en-US")}`;
}

function plural(n: number, one: string, many: string): string {
  return `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;
}

/** replaySentence is the replay's headline: what the recipe would have
 *  asked and denied over the window, against today's policy. */
export function replaySentence(r: RecipeReplay, hours: number): string {
  const ask = r.after.by_decision?.ask ?? 0;
  const deny = r.after.by_decision?.deny ?? 0;
  const askNow = r.before.by_decision?.ask ?? 0;
  const denyNow = r.before.by_decision?.deny ?? 0;
  const would = `this would have ${askedPart(ask)} and ${deniedPart(deny)}`;
  const today = `today's policy: ${plural(askNow, "ask", "asks")}, ${plural(denyNow, "deny", "denies")}`;
  return `Over the last ${windowLabel(hours)} ${would} (${today}), across ${plural(r.scanned, "action", "actions")}.`;
}

/** replayModeNote says when the recipe's mode means nothing would block. */
export function replayModeNote(r: RecipeReplay): string {
  if (r.after.mode === "off") return "With this recipe the guard is off, so nothing is judged.";
  if (r.after.mode === "observe") return "With this recipe the guard only records: asks and denies are counted, not enforced.";
  return "";
}

/** BlockingRow is one rule's blocking count with the recipe and today. */
export type BlockingRow = { rule: string; after: number; before: number };

/** topBlockingRules returns the rules that would block most often with the
 *  recipe (then today), up to `n`. */
export function topBlockingRules(r: RecipeReplay, n = 5): BlockingRow[] {
  const after = r.after.by_rule_blocking ?? {};
  const before = r.before.by_rule_blocking ?? {};
  const ids = new Set([...Object.keys(after), ...Object.keys(before)]);
  return [...ids]
    .map((rule) => ({ rule, after: after[rule] ?? 0, before: before[rule] ?? 0 }))
    .filter((x) => x.after > 0 || x.before > 0)
    .sort((a, b) => b.after - a.after || b.before - a.before || a.rule.localeCompare(b.rule))
    .slice(0, n);
}

// ---------- inputs ----------

/** RecipeInput is a setting a recipe's rules read, in plain words. */
export type RecipeInput = { key: string; label: string; where: string; href: string };

const INPUT_LABELS: Readonly<Record<string, { label: string; group: string }>> = {
  "guard.database.prod_patterns": { label: "Production patterns", group: "Database" },
  "guard.network.allow_hosts": { label: "Allowed hosts", group: "Network" },
  "guard.network.deny_hosts": { label: "Denied hosts", group: "Network" },
};

/** recipeInput names one input key and where it is set; a guard key links
 *  to Settings > Guard. */
export function recipeInput(key: string): RecipeInput {
  const known = INPUT_LABELS[key];
  const guard = key.startsWith("guard.");
  return {
    key,
    label: known?.label ?? key,
    where: known ? `Settings > Guard > ${known.group}` : guard ? "Settings > Guard" : "",
    href: guard ? "/settings?section=guard" : "",
  };
}

// ---------- user recipes ----------

/** RECIPE_NAME_RX mirrors internal/guardrecipe.NameRx. */
export const RECIPE_NAME_RX = /^[a-z0-9][a-z0-9-]{0,63}$/;

/** recipeNameProblem returns why a user recipe name is refused, or "". */
export function recipeNameProblem(name: string, catalog: Recipe[] | null | undefined, editing = ""): string {
  const n = name.trim();
  if (!n) return "Give the recipe a name.";
  if (!RECIPE_NAME_RX.test(n)) return "Use lowercase letters, digits and dashes, starting with a letter or digit (at most 64).";
  const clash = (catalog ?? []).find((r) => r.name === n);
  if (clash && clash.source !== "user") return "A built-in recipe already has this name.";
  if (clash && n !== editing) return "One of your recipes already has this name; saving replaces it.";
  return "";
}

/** copyName suggests a name for a duplicate that no recipe holds yet. */
export function copyName(name: string, catalog: Recipe[] | null | undefined): string {
  const taken = new Set((catalog ?? []).map((r) => r.name));
  const base = `my-${name}`.slice(0, 60);
  if (!taken.has(base)) return base;
  for (let i = 2; i < 100; i++) {
    const n = `${base}-${i}`;
    if (!taken.has(n)) return n;
  }
  return base;
}

/** recipeNameFromToml reads a recipe file's top-level name, or "". */
export function recipeNameFromToml(toml: string): string {
  for (const raw of toml.split(/\r?\n/)) {
    const t = raw.trim();
    if (t.startsWith("[")) return "";
    const m = /^name\s*=\s*"([^"]*)"/.exec(t);
    if (m) return m[1];
  }
  return "";
}

/** renameRecipeToml rewrites a recipe file's top-level name key, so a
 *  duplicate does not collide with its source. A file with no name line
 *  gets one at the top. */
export function renameRecipeToml(toml: string, name: string): string {
  const line = `name = "${name}"`;
  const lines = toml.split(/\r?\n/);
  let inTable = false;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (t.startsWith("[")) {
      inTable = true;
      continue;
    }
    if (!inTable && /^name\s*=/.test(t)) {
      lines[i] = line;
      return lines.join("\n");
    }
  }
  return `${line}\n${toml}`;
}

/** copyTitleToml marks a duplicate's top-level title as a copy ("Strict"
 *  becomes "Strict (copy)"), so the copy and its source do not read the
 *  same on the level slider and in the pack chips. A title already ending
 *  in "(copy)", or a file with no title line, is left as it is. */
export function copyTitleToml(toml: string): string {
  const lines = toml.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (t.startsWith("[")) return toml;
    const m = /^title\s*=\s*"([^"]*)"\s*$/.exec(t);
    if (m) {
      if (/\(copy\)$/.test(m[1])) return toml;
      lines[i] = `title = "${m[1]} (copy)"`;
      return lines.join("\n");
    }
  }
  return toml;
}

/** RECIPE_TEMPLATE starts an imported recipe when nothing was pasted. */
export const RECIPE_TEMPLATE = `name = "my-pack"
kind = "pack"
title = "My pack"
summary = "One line saying what this pack tightens."
version = 1

[[override]]
rule = "R-171"
decision = "deny"
enforce = true
note = "uploading file contents off the machine"
`;

/** PromptGuardPosture is the prompt guard's state in GET /api/guard/summary. */
export type PromptGuardPosture = {
  enabled: boolean;
  mode: string;
  enforce_independent: boolean;
  /** The organization's guard mode decided the stance (its guard.mode pin). */
  set_by_org?: boolean;
};

const PROMPT_ACTS: Readonly<Record<string, string>> = {
  "ask-once": "asks once",
  warn: "warns",
  block: "blocks",
  redact: "redacts",
};

/** promptGuardLine says in plain words what the prompt guard does beside the
 *  guard mode: it acts on its own mode unless it is set to follow the guard
 *  mode, which the organization's guard mode decides when it pins one.
 *  "" when the daemon did not say. */
export function promptGuardLine(guardMode: string, p: PromptGuardPosture | null | undefined): string {
  if (!p) return "";
  if (!p.enabled || p.mode === "off") return "prompt guard: off";
  const acts = PROMPT_ACTS[p.mode] ?? "acts";
  if (!p.enforce_independent) {
    return p.set_by_org ? "prompt guard follows your organization's guard mode" : "prompt guard follows the guard mode";
  }
  return guardMode === "enforce" ? "prompt guard: " + acts : "prompt guard: " + acts + " (acts in " + guardMode + ")";
}
