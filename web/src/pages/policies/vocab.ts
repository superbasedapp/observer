// The words for the closed values the Policies and Egress pages show
// (docs/app-design-system.md "Copy rules": every enum shown to a person goes
// through a vocabulary with a label; a raw wire value on screen is a bug).
// Pure tables plus one lookup; an unknown value keeps its spelling with
// underscores as spaces, never a blank and never a guess.

import { ADMISSION_DEGRADED } from "@shared/lib/obsVocab";

/** wordsFor looks a value up in a words table; unknown values keep their
 *  own spelling with underscores and dashes as spaces. */
export function wordsFor(table: Readonly<Record<string, string>>, value: string | null | undefined): string {
  const key = (value ?? "").trim();
  if (Object.prototype.hasOwnProperty.call(table, key)) return table[key];
  return key.replace(/[_-]+/g, " ") || "-";
}

// POLICY_MODE_LABEL: an admission or egress policy's mode, as a stat value.
export const POLICY_MODE_LABEL: Readonly<Record<string, string>> = {
  "": "Off",
  off: "Off",
  disabled: "Off",
  observe: "Observe only",
  advise: "Advise only",
  enforce: "Enforce",
};

// EGRESS_ACTION_LABEL: an egress rule's action, both the compiled spelling
// (status and decisions: route_upstream, route_model) and the editor's
// one-hot field names (route_to_upstream, route_to_model).
export const EGRESS_ACTION_LABEL: Readonly<Record<string, string>> = {
  "": "Log only",
  none: "Log only",
  no_route: "Log only",
  route_upstream: "Route to upstream",
  route_to_upstream: "Route to upstream",
  route_model: "Swap model",
  route_to_model: "Swap model",
  set_effort: "Set effort",
  deny: "Deny",
};

// ON_UNAVAILABLE_LABEL: what a routing rule does when its target is down.
export const ON_UNAVAILABLE_LABEL: Readonly<Record<string, string>> = {
  "": "Fall through",
  fail_open: "Fall through",
  deny: "Deny",
};

// TARGET_SHAPE_LABEL: an upstream target's API shape.
export const TARGET_SHAPE_LABEL: Readonly<Record<string, string>> = {
  openai: "OpenAI",
  anthropic: "Anthropic",
};

// EGRESS_REASON_LABEL: the closed egress reason-code vocabulary
// (types.ts EGRESS_REASON_CODES). "" lets the engine derive it.
export const EGRESS_REASON_LABEL: Readonly<Record<string, string>> = {
  "": "Derived from the action",
  egress_flagged_local: "Flagged, kept local",
  egress_budget_band: "Budget band",
  egress_cohort_upstream: "Cohort upstream",
  egress_overload_degrade: "Overload, degraded",
  egress_sensitive_local_only: "Sensitive, local only",
  egress_deny_unavailable: "Denied, target unavailable",
  egress_fail_open: "Fell through",
  egress_no_route: "No route",
  egress_switch_held: "Switch held (cooldown)",
  egress_effort_noop: "Effort unchanged",
};

// CRITERION_TYPE_LABEL: an admission criterion's type.
export const CRITERION_TYPE_LABEL: Readonly<Record<string, string>> = {
  valid_use_case: "Valid use case",
  denied_topics: "Denied topics",
  jailbreak: "Jailbreak",
  custom: "Custom (judged)",
};

// VERDICT_PATH_LABEL: a verdict's degraded code when it is NOT a failure,
// i.e. which deterministic layer decided (admission pipeline.go Degraded*).
// The genuine fail-open codes (judge failed, refused or missing) render
// through the shared ADMISSION_DEGRADED vocabulary instead.
export const VERDICT_PATH_LABEL: Readonly<Record<string, string>> = {
  prefiltered: "decided by the pre-filter",
  "secret-gate": "decided by the secret check",
  "budget-gate": "decided by the budget cap",
  "empty-text": "empty message",
  cache: "cached verdict",
  "switch-held-cooldown": "switch held (cooldown)",
};

/** isGenuineDegraded reports a fail-open code (the judge failed, refused or
 *  was missing), as the node's admission.IsDegraded classifies it. Every
 *  other non-empty code names the deterministic layer that decided. */
export function isGenuineDegraded(code: string | null | undefined): boolean {
  const c = (code ?? "").trim();
  return c !== "" && c !== "other" && Object.prototype.hasOwnProperty.call(ADMISSION_DEGRADED.entries, c);
}

// EGRESS_OUTCOME_LABEL: the proxy's realized routing outcome (tones and
// glyphs: vocabTones EGRESS_OUTCOME / VOCAB_ICONS.egressOutcome).
export const EGRESS_OUTCOME_LABEL: Readonly<Record<string, string>> = {
  applied: "applied",
  fail_closed: "failed closed",
  breaker_open: "breaker open",
  upstream_error: "upstream error",
  fallback_open: "fell back",
  splice_failed: "splice failed",
};
