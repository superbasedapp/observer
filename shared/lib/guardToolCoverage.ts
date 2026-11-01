import {
  GUARD_COVERAGE_OUTCOMES,
  GUARD_TOOL_COVERAGE,
  type GuardCoverageOutcome,
  type GuardCoverageSeam,
  type GuardLaneCoverage,
  type GuardToolCoverage,
} from "./guardToolCoverage.generated.ts";
import type { Tone } from "./tone.ts";

// guardToolCoverage - pure rendering helpers over the GENERATED per-tool rule
// coverage (guardToolCoverage.generated.ts, written by tools/guardcoveragegen
// from internal/controlcoverage.RuleCoverage). Nothing here names a tool: the
// data says, per tool and lane, what a developer experiences when a rule
// resolves to flag, ask or deny, and these helpers only pick the decision an
// org rule row pins and group the tools by outcome.

export type { GuardCoverageOutcome, GuardCoverageSeam, GuardLaneCoverage, GuardToolCoverage };
export { GUARD_TOOL_COVERAGE };

/** The lane a rule is judged on: the developer's own prompt, or a tool call. */
export type GuardCoverageLane = "prompt" | "toolCall";

/** The three rule decisions a lane answers. */
export type GuardRuleDecision = "flag" | "ask" | "deny";

/** The org rule row fields the effective decision depends on. */
export type GuardRuleRowLike = {
  decision: string;
  enforce: boolean;
  overridable?: boolean;
};

/**
 * effectiveRuleDecision is the decision an org rule row pins as a floor on a
 * developer's node (docs/guard.md "Admin coverage view"): with Block off the
 * rule only warns (flag); with Block on it is the row's decision, or the
 * rule's built-in enforce decision when the row keeps it ("" = no change);
 * a deny the developer may override is an ask. null when the row pins
 * nothing a lane acts on (allow, or no decision at all).
 */
export function effectiveRuleDecision(row: GuardRuleRowLike, builtinEnforce: string): GuardRuleDecision | null {
  const d = row.decision || builtinEnforce;
  if (d !== "flag" && d !== "ask" && d !== "deny") return null;
  if (!row.enforce) return "flag";
  if (d === "deny" && row.overridable === true) return "ask";
  return d;
}

/** OUTCOME_LABEL is each outcome's short admin-facing label. */
export const OUTCOME_LABEL: Readonly<Record<GuardCoverageOutcome, string>> = {
  blocks: "Blocks",
  redacts: "Masks the secret",
  asks: "Asks (native confirm)",
  asks_resend: "Asks by resend",
  warns: "Warns the developer",
  warns_model: "Warns the model only",
  records_only: "Records only, after the fact",
  not_covered: "Not covered",
};

/** OUTCOME_TONE is each outcome's Pill tone. */
export const OUTCOME_TONE: Readonly<Record<GuardCoverageOutcome, Tone>> = {
  blocks: "success",
  redacts: "success",
  asks: "accent",
  asks_resend: "accent",
  warns: "info",
  warns_model: "warn",
  records_only: "warn",
  not_covered: "neutral",
};

/** SEAM_NOTE qualifies a tool whose outcome depends on how it is run. */
export const SEAM_NOTE: Readonly<Partial<Record<GuardCoverageSeam, string>>> = {
  proxy: "via the Observer proxy",
};

/** One tool inside an outcome group. */
export type GuardCoverageEntry = {
  tool: string;
  name: string;
  seam: GuardCoverageSeam;
  caveats: string[];
};

/** One outcome with the tools that reach it. */
export type GuardCoverageGroup = {
  outcome: GuardCoverageOutcome;
  label: string;
  tone: Tone;
  tools: GuardCoverageEntry[];
};

/**
 * coverageByOutcome groups every tool by what `decision` does on `lane`,
 * strongest outcome first; tools inside a group are sorted by name and empty
 * groups are dropped.
 */
export function coverageByOutcome(
  lane: GuardCoverageLane,
  decision: GuardRuleDecision,
  data: readonly GuardToolCoverage[] = GUARD_TOOL_COVERAGE,
): GuardCoverageGroup[] {
  const groups = new Map<GuardCoverageOutcome, GuardCoverageEntry[]>();
  for (const t of data) {
    const l = t[lane];
    const outcome = l[decision];
    const list = groups.get(outcome) ?? [];
    list.push({ tool: t.tool, name: t.name, seam: l.seam, caveats: l.caveats });
    groups.set(outcome, list);
  }
  const out: GuardCoverageGroup[] = [];
  for (const outcome of GUARD_COVERAGE_OUTCOMES) {
    const tools = groups.get(outcome);
    if (!tools || tools.length === 0) continue;
    tools.sort((a, b) => a.name.localeCompare(b.name) || a.tool.localeCompare(b.tool));
    out.push({ outcome, label: OUTCOME_LABEL[outcome], tone: OUTCOME_TONE[outcome], tools });
  }
  return out;
}

/** coverageSummary is the one-line count, e.g. "Blocks 18 · Asks by resend 9 · Records only, after the fact 15". */
export function coverageSummary(groups: readonly GuardCoverageGroup[]): string {
  return groups.map((g) => `${g.label} ${g.tools.length}`).join(" · ");
}

/** DECISION_PHRASE names the decision the view is showing. */
export const DECISION_PHRASE: Readonly<Record<GuardRuleDecision, string>> = {
  flag: "a flag (Block off)",
  ask: "an ask",
  deny: "a deny",
};

/** LANE_PHRASE names the lane the view is showing. */
export const LANE_PHRASE: Readonly<Record<GuardCoverageLane, string>> = {
  prompt: "On a developer's prompt",
  toolCall: "On a tool call",
};

/**
 * laneOutcomeSummary is one tool's three outcomes on a lane as one line
 * ("deny: Blocks · ask: Asks by resend · flag: Warns the developer"), or null
 * for a tool the generated data does not list.
 */
export function laneOutcomeSummary(
  tool: string,
  lane: GuardCoverageLane,
  data: readonly GuardToolCoverage[] = GUARD_TOOL_COVERAGE,
): string | null {
  const t = data.find((x) => x.tool === tool);
  if (!t) return null;
  const l = t[lane];
  return (["deny", "ask", "flag"] as const).map((d) => `${d}: ${OUTCOME_LABEL[l[d]]}`).join(" · ");
}
