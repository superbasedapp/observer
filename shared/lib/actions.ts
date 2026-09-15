// Action-type taxonomy for every application dashboard.
//
// The DATA here is GENERATED, not hand-maintained: `actiontax.gen.json`
// is emitted by `web/taxgen` from `internal/tooltax`, the one Go owner of
// the cross-adapter tool/MCP taxonomy (WP-T2 of
// docs/plans/tool-taxonomy-standardization-plan-2026-07-31.md). Before
// that, this file carried its own 34-row registry and its own MCP parser,
// and both had measurably drifted from the Go side.
//
// So: categories, the action-type → {category, label} registry and the
// MCP parse rules come from `actiontax.gen.json`, and the ActionCategory
// union comes from `actiontax.gen.ts` (which is why a category added in
// Go with no colour below is a compile error). Regenerate both with
// `make taxonomy-build`; CI's `taxonomy-build-drift` job fails until the
// regenerated files are committed.
//
// This file is also GATED as executed code, not just as types:
// `scripts/verify-taxonomy-ts.sh` (same CI job) compiles it and runs
// mcpIdentity over `actiontax.vectors.gen.json`, whose expectations are
// generated from `tooltax.MCPIdentity`. Changing the parser below
// without changing Go fails that gate.
//
// What stays here is PRESENTATION, which has no Go counterpart: the
// per-category colour, keyed off the --act-* CSS variables in
// styles/tokens.css (the brief assigns colour per category, not per
// type), the path/URL guards on the colon form, and the humanizing
// fallback for an action type the registry has never heard of.

import taxonomy from "./actiontax.gen.json";
import type { ActionCategory } from "./actiontax.gen";

// Re-exported so the category union keeps its historical import site
// (`ActionCategory` was declared here before WP-T2's follow-up moved it
// into the generated file).
export type { ActionCategory };

export type ActionMeta = {
  category: ActionCategory;
  label: string;
  colorVar: string;
};

// One --act-* var per canonical category. Both themes define all of
// them (styles/tokens.css). The key type is the GENERATED union
// (actiontax.gen.ts), so a category added to tooltax.Categories() and
// not given a colour here is a `npm run typecheck` COMPILE error — not a
// silent meta-gray chip. colorForCategory's fallback is only for a
// string that is not a category at all (a row from a newer daemon).
const CATEGORY_COLOR: Record<ActionCategory, string> = {
  file: "var(--act-file)",
  cmd: "var(--act-cmd)",
  search: "var(--act-search)",
  web: "var(--act-web)",
  agent: "var(--act-agent)",
  skill: "var(--act-skill)",
  mcp: "var(--act-mcp)",
  user: "var(--act-user)",
  meta: "var(--act-meta)",
  fail: "var(--act-fail)",
};

// One human label per canonical category. Presentational, so it has no
// Go counterpart — but it is keyed on the GENERATED union for the same
// reason CATEGORY_COLOR is: a category added to tooltax.Categories()
// without a label here is a `npm run typecheck` COMPILE error.
const CATEGORY_LABEL: Record<ActionCategory, string> = {
  file: "Files",
  cmd: "Commands",
  search: "Search",
  web: "Web",
  agent: "Agents",
  skill: "Skills",
  mcp: "MCP",
  user: "User",
  meta: "Meta",
  fail: "Failures",
};

// The canonical categories in display order (concrete work first, then
// coordination, then noise) — tooltax.Categories() verbatim.
export const ACTION_CATEGORIES = taxonomy.categories as ActionCategory[];

// The canonical SURFACES in display order — tooltax.Surfaces() verbatim
// (builtin / mcp / orchestration / meta): WHERE a tool lives, orthogonal
// to what it does. /api/tools/breakdown's by_surface histogram is keyed
// on these plus the "unresolved" bucket the API appends for rows whose
// native tool name it could not resolve.
export const ACTION_SURFACES: string[] = taxonomy.surfaces;

// Per-adapter capture depth: which canonical categories each tool's
// DECLARED native vocabulary covers. Generated from tooltax's per-tool
// rows — the browser never resolves native tool names itself (adapters do
// that at ingest), so only this derived summary ships, not the ~1,074-row
// (tool, native) table.
const TOOL_COVERAGE = taxonomy.toolCoverage as Record<
  string,
  { categories: string[] }
>;

// categoryMeta is actionMeta's counterpart one level up: the label +
// colour of a canonical CATEGORY, for surfaces that aggregate rather than
// list action types (the Tools page's action-mix panel).
export function categoryMeta(category: string): {
  category: ActionCategory;
  label: string;
  colorVar: string;
} {
  const known = (ACTION_CATEGORIES as string[]).includes(category);
  const c = (known ? category : FALLBACK_CATEGORY) as ActionCategory;
  return { category: c, label: CATEGORY_LABEL[c], colorVar: colorForCategory(c) };
}

// expressibleCategories returns the canonical categories a tool's DECLARED
// native vocabulary can express, or null when tooltax declares no
// vocabulary for that tool at all.
//
// The null is the honest zero and must be rendered as such: "we have not
// mapped this adapter" is a different statement from "this adapter
// expresses nothing", and the whole point of the coverage-depth row is
// that a shallow-capture adapter must not read as "doesn't use tools".
//
// Note the denominator is the tool's OWN vocabulary: tooltax's tool-less
// fallback rows and the global `mcp__*` glob apply to every adapter at
// resolve time and are deliberately NOT credited here, or every adapter
// would share an identical floor and the number would say nothing.
export function expressibleCategories(tool: string): ActionCategory[] | null {
  const row = TOOL_COVERAGE[tool];
  if (!row) return null;
  return row.categories as ActionCategory[];
}

// CoverageCaption is the rendered form of /api/tools/breakdown's coverage
// block: two SEPARATE statements, never one ratio.
export type CoverageCaption = {
  // seen states the observed fact on its own ("9 categories seen").
  seen: string;
  // span states the capture-depth fact on its own ("declared vocabulary
  // spans 8/10"), or the honest zero when the adapter is unmapped.
  span: string;
  // note explains an observation that falls outside the declared
  // vocabulary, or "" when there is none.
  note: string;
  // title is the long-form explanation for the tooltip.
  title: string;
};

// coverageCaption formats the capture-depth honesty row.
//
// It exists as a pure function, apart from the JSX, because the bug it
// fixes was a FORMATTING bug: observed categories and the declared
// vocabulary span were printed as a ratio ("N of M capturable categories
// seen"), and observed can legitimately exceed the span — tooltax's
// tool-less fallback rows and the global `mcp__*` glob resolve for every
// adapter without being credited to any adapter's declared vocabulary,
// and failure/meta events come from the harness rather than from a
// declared native tool. claude-code's declared span is 8 categories while
// a normal window observes 9, which rendered as the impossible
// "9 of 8 capturable categories seen".
//
// The fix keeps every observation (truncating a real observation to make
// a ratio work would be the dishonest option) and stops formatting the
// two facts as one: "9 categories seen · declared vocabulary spans 8/10",
// plus a note naming the excess.
export function coverageCaption(coverage: {
  observed_categories?: number;
  expressible_categories?: number;
  observed_beyond_declared?: number;
  canonical_categories?: number;
  vocabulary_declared?: boolean;
}): CoverageCaption {
  const observed = coverage.observed_categories ?? 0;
  const expressible = coverage.expressible_categories ?? 0;
  const beyond = coverage.observed_beyond_declared ?? 0;
  const canonical = coverage.canonical_categories || ACTION_CATEGORIES.length;
  const mapped = coverage.vocabulary_declared ?? false;
  const seen = `${observed} ${observed === 1 ? "category" : "categories"} seen`;
  if (!mapped) {
    return {
      seen,
      span: "capture depth not mapped",
      note: "",
      title:
        `${seen} in this window. This adapter has no declared native ` +
        `vocabulary in the taxonomy, so there is no capture-depth figure ` +
        `to compare against - an empty category is not evidence about the agent.`,
    };
  }
  const span = `declared vocabulary spans ${expressible}/${canonical}`;
  const note =
    beyond > 0 ? `${beyond} beyond declared vocabulary` : "";
  const title =
    `${seen} in this window. This adapter's declared native vocabulary ` +
    `covers ${expressible} of the ${canonical} canonical categories, so a ` +
    `category it never declares is a capture limit, not a verdict on the agent.` +
    (beyond > 0
      ? ` ${beyond} observed ${beyond === 1 ? "category is" : "categories are"} ` +
        `outside that declared vocabulary (e.g. MCP calls resolved by the ` +
        `shared mcp__ rule, or harness-emitted failure/meta events), which is ` +
        `why the two numbers are stated separately rather than as a ratio.`
      : "");
  return { seen, span, note, title };
}

const FALLBACK_CATEGORY = taxonomy.fallbackCategory as ActionCategory;

// tooltax's action-type registry. Keyed by canonical action_type; the
// values are exactly {category, label} — see actiontax.gen.json.
const ACTION_REGISTRY: Record<string, { category: string; label: string }> =
  taxonomy.actionTypes;

function colorForCategory(category: string): string {
  return CATEGORY_COLOR[category as ActionCategory] ?? CATEGORY_COLOR.meta;
}

const FALLBACK: ActionMeta = {
  category: FALLBACK_CATEGORY,
  label: "Unknown",
  colorVar: colorForCategory(FALLBACK_CATEGORY),
};

export function actionMeta(type: string | null | undefined): ActionMeta {
  if (!type) return FALLBACK;
  const reg = ACTION_REGISTRY[type];
  if (reg) {
    return {
      category: reg.category as ActionCategory,
      label: reg.label,
      colorVar: colorForCategory(reg.category),
    };
  }
  // Unregistered action_type — humanize the key and fall back to the
  // same category tooltax.CategoryForActionType falls back to.
  return {
    category: FALLBACK_CATEGORY,
    label: type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
    colorVar: colorForCategory(FALLBACK_CATEGORY),
  };
}

const MCP = taxonomy.mcp;

// parseMcpName implements tooltax.MCPIdentity — the canonical
// `mcp__<server>__<tool>` parse — off the generated rules, so the two
// languages cannot disagree — a claim the vector gate described at the
// top of this file actually EXECUTES against this function.
// Note `separatorMinIndex`: a separator at
// offset 0 of the post-prefix remainder is NOT a split point, so the
// degenerate `mcp____tool` yields {server: "__tool", tool: ""}. That is
// Go's behaviour; this file used to yield {server: "", tool: "tool"},
// the one divergence WP-T1 recorded and WP-T2 closes.
function parseMcpName(raw: string): { server: string; tool: string } | null {
  if (!raw.startsWith(MCP.prefix)) return null;
  const rest = raw.slice(MCP.prefix.length);
  const i = rest.indexOf(MCP.separator);
  if (i < MCP.separatorMinIndex) return { server: rest, tool: "" };
  return { server: rest.slice(0, i), tool: rest.slice(i + MCP.separator.length) };
}

// mcpIdentity returns the {server, tool} of an MCP tool call, or null when
// the row is not one. It's robust to the identity shapes adapters emit:
// the normalized action_type="mcp_call" signal, and/or a raw_tool_name of
// "mcp__<server>__<tool>" (Claude / gemini / cowork / openclaw / pi), a
// "<server>:<tool>" colon form in raw_tool_name (copilot-cli) or in
// `target` (cursor / codex / cline). This means even historical rows that
// predate the adapter normalization — where action_type is still
// "unknown" but raw_tool_name is "mcp__…" — are still recognised. Falls
// back to the bare name when it can't split cleanly (e.g. Hermes /
// cline-cli single-underscore names).
//
// The path/URL guards on the colon form are a UI-side extra with no Go
// counterpart: this function runs against `target`, which for many
// adapters is a file path, and a mis-split there would invent a server
// name in the Tools panel. They are pinned by the `ts-only-path-guard`
// vectors in actiontax.vectors.gen.json — the shapes they cover are a
// declared contract, stated Go-side, not whatever this code happens to
// do today.
export function mcpIdentity(row: {
  action_type?: string | null;
  raw_tool_name?: string | null;
  target?: string | null;
}): { server: string; tool: string } | null {
  const raw = row.raw_tool_name ?? "";
  const named = parseMcpName(raw);
  const isMcp = row.action_type === "mcp_call" || named !== null;
  if (!isMcp) return null;
  if (named) return named;
  const splitColon = (s?: string | null): { server: string; tool: string } | null => {
    if (!s) return null;
    const i = s.indexOf(MCP.targetSeparator);
    if (i <= 0) return null;
    const server = s.slice(0, i);
    const tool = s.slice(i + MCP.targetSeparator.length);
    // Guard against filesystem paths / URLs that also contain a colon.
    // A drive letter is a single alpha char before the colon, and the
    // rest of the path starts with EITHER separator; a POSIX path that
    // happens to contain a colon (`/tmp/socket:query`) starts with "/".
    const driveLetter = server.length === 1 && /^[a-z]$/i.test(server);
    if (
      !tool ||
      tool.includes("\\") || // C:\repo\file.txt
      tool.startsWith("//") || // https://example.com/x
      (driveLetter && tool.startsWith("/")) || // C:/repo/file.txt
      server.startsWith("/") || // /tmp/socket:query
      server.includes(" ") // prose with a colon, not an identity
    ) {
      return null;
    }
    return { server, tool };
  };
  return (
    splitColon(raw) ?? splitColon(row.target) ?? { server: raw || row.target || "mcp", tool: "" }
  );
}

// Known action-type keys for filter dropdowns. Sorted alphabetically.
export const KNOWN_ACTION_TYPES: string[] = Object.keys(ACTION_REGISTRY).sort();

export const KNOWN_EFFORT_LEVELS = [
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
  "max",
] as const;

export const KNOWN_PERMISSION_MODES = [
  "default",
  "plan",
  "acceptEdits",
  "auto",
  "dontAsk",
  "bypassPermissions",
] as const;
