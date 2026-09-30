// Shared types + write helpers for the Policies module tabs (Overview lives in
// Policies.tsx; Guardrails + Test in this folder). The DTO shapes mirror the
// backend wire shapes 1:1 (internal/obs/httpapi/admission.go + egress_editor.go
// and the [observability.judge]/[.admission.budget] config blocks), so the
// editor round-trips without lossy remapping.

import { getRemoteCSRF, isRemoteView } from "@/lib/remote";

export type Decision = "allow" | "flag" | "ask" | "deny";
export type Severity = "info" | "warn" | "high" | "critical";
export type AdmissionMode = "off" | "observe" | "enforce";
export type EgressMode = "off" | "advise" | "enforce";
export type CriterionType = "valid_use_case" | "denied_topics" | "jailbreak" | "custom";

// JUDGED_TYPES are the criterion types that call the LLM judge (and therefore
// need a `definition`). The rest are deterministic and run offline.
export const JUDGED_TYPES: CriterionType[] = ["valid_use_case", "custom"];
export function isJudged(t: CriterionType): boolean {
  return JUDGED_TYPES.includes(t);
}

export type AdmissionCriterion = {
  id: string;
  type: CriterionType;
  name: string;
  definition: string;
  topics: string[];
  decision: Decision;
  severity: Severity;
};

export type AdmissionPrefilter = {
  allow: string[];
  deny: string[];
  max_message_bytes: number;
};

export type AdmissionPolicy = {
  mode: AdmissionMode;
  strict: boolean;
  scope: "last_user" | "conversation";
  secret_remote_judge: "" | Decision;
  prefilter: AdmissionPrefilter;
  criteria: AdmissionCriterion[];
};

export type AdmissionPolicyGet = {
  enabled: boolean;
  mode: string;
  policy_hash?: string;
  policy: AdmissionPolicy;
};

// --- Egress (Routing tab + the Overview mode toggle) ---
export type EgressShape = "anthropic" | "openai";
export type EgressTarget = { id: string; url: string; shape: EgressShape };

export type EgressWhen = {
  verdict_at_least: string;
  criterion: string;
  severity_at_least: string;
  content_class: string;
  model_glob: string;
  provider: string;
  user: string;
  user_cohort: string;
  // A pointer on the wire: null = unset, 0 = a real "any burn" threshold.
  budget_band_at_least: number | null;
  min_prompt_tokens: number;
};
export type EgressAction = {
  route_to_upstream: string;
  route_to_model: string;
  set_effort: string;
  deny: boolean;
  no_route: boolean;
};
export type EgressRule = {
  name: string;
  when: EgressWhen;
  action: EgressAction;
  on_unavailable: string; // fail_open | deny
  reason: string;
  reason_code: string;
};
export type EgressPolicy = {
  mode: EgressMode;
  cooldown_seconds: number;
  targets: EgressTarget[];
  rules: EgressRule[];
  cohorts: Record<string, string>;
};
export type EgressPolicyGet = {
  enabled: boolean;
  mode: string;
  policy_hash?: string;
  policy: EgressPolicy;
};

// The closed reason-code vocabulary (egress_editor.go / the engine). "" = let
// the engine derive it from the action + fail-posture.
export const EGRESS_REASON_CODES: string[] = [
  "",
  "egress_flagged_local",
  "egress_budget_band",
  "egress_cohort_upstream",
  "egress_overload_degrade",
  "egress_sensitive_local_only",
  "egress_deny_unavailable",
  "egress_fail_open",
  "egress_no_route",
  "egress_switch_held",
  "egress_effort_noop",
];

// The action "kind" — exactly one primary is set on the wire; the UI edits a
// single kind + operand and materializes the one-hot EgressAction on submit.
export type EgressActionKind = "route_to_upstream" | "route_to_model" | "set_effort" | "deny" | "no_route";
export function egressActionKind(a: EgressAction): EgressActionKind {
  if (a.deny) return "deny";
  if (a.no_route) return "no_route";
  if (a.route_to_model) return "route_to_model";
  if (a.set_effort) return "set_effort";
  return "route_to_upstream";
}
export function emptyEgressWhen(): EgressWhen {
  return {
    verdict_at_least: "",
    criterion: "",
    severity_at_least: "",
    content_class: "",
    model_glob: "",
    provider: "",
    user: "",
    user_cohort: "",
    budget_band_at_least: null,
    min_prompt_tokens: 0,
  };
}

// --- POST /policy response (shared by admission + egress editors) ---
export type LintIssue = {
  criterion_id?: string;
  rule_name?: string;
  message: string;
  fatal: boolean;
};
export type PolicyApplyResponse = {
  applied: boolean;
  persisted: boolean;
  persist_error?: string;
  policy_hash?: string;
  error?: string;
  issues: LintIssue[];
};

// --- Admission verdict (POST /admission/test) ---
export type Verdict = {
  allowed: boolean;
  decision: Decision;
  severity: Severity;
  criterion?: string;
  reason?: string;
  mode: string;
  judge_used: boolean;
  degraded?: boolean;
  enforce_decision: Decision;
  latency_ms: number;
};

// --- Judge + budget (edited via PUT /api/config/section/observability) ---
export type JudgeConfig = {
  Model: string;
  BaseURL: string;
  APIKeyEnv: string;
  TimeoutMS: number;
  MaxTokens: number;
  NumCtx: number;
};
export type BudgetConfig = {
  Enabled: boolean;
  PerUser5hUSD: number;
  PerUserWeeklyUSD: number;
  PerUserMonthlyUSD: number;
  UserHeader: string;
};
export type ObservabilityConfig = {
  Enabled: boolean;
  Judge: JudgeConfig;
  Admission: { Budget: BudgetConfig; Judge: JudgeConfig };
};
export type ConfigResponse = { config: { Observability: ObservabilityConfig } };

// judgeHosting derives the same hosting bucket the backend derives from a
// judge base_url, so the editor can show a live badge as the operator types a
// URL (loopback → local/no-key; openrouter → aggregator; a known provider
// host → provider; anything else non-empty → private).
export function judgeHosting(baseURL: string): "local" | "aggregator" | "provider" | "private" | "none" {
  const u = baseURL.trim().toLowerCase();
  if (u === "") return "none";
  if (u.includes("127.0.0.1") || u.includes("localhost") || u.includes("::1") || u.includes("0.0.0.0")) return "local";
  if (u.includes("openrouter.ai")) return "aggregator";
  if (u.includes("api.openai.com") || u.includes("anthropic.com") || u.includes("googleapis.com") || u.includes("generativelanguage")) return "provider";
  return "private";
}

// postPolicy POSTs an admission/egress policy DTO and returns the parsed body
// on BOTH 200 and 422. The lint-reject path is a 422 whose body carries the
// `issues` array, so this must NOT throw on 422 — it reads the body itself
// instead of going through fetchJSON (which throws on any non-2xx and
// truncates the body to 200 chars). It mirrors fetchJSON's remote-CSRF header
// so a paired remote device can still author policy. A genuine 5xx / unparsable
// body throws.
export async function postPolicy(
  path: string,
  dto: unknown,
  persist: boolean,
): Promise<{ status: number; data: PolicyApplyResponse }> {
  const url = persist ? `${path}?persist=1` : path;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };
  if (isRemoteView()) {
    const csrf = getRemoteCSRF();
    if (csrf) headers["X-Remote-CSRF"] = csrf;
  }
  const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(dto) });
  const text = await res.text();
  if (!text) return { status: res.status, data: { applied: false, persisted: false, issues: [] } };
  let data: PolicyApplyResponse;
  try {
    data = JSON.parse(text) as PolicyApplyResponse;
  } catch {
    throw new Error(`policy POST ${res.status}: ${text.slice(0, 200)}`);
  }
  return { status: res.status, data };
}

// Guard / admission decision and severity tones live in ONE place,
// @shared/lib/guardCatalog (decisionTone / severityTone); the glyphs in
// @shared/lib/vocabIcons. Render them with @shared/lib/vocabPill.

// A stable-ish id for a freshly-added criterion. The engine only requires
// uniqueness within the policy; this is human-readable and collision-safe
// enough for hand-authoring (the operator can rename it).
export function newCriterionId(existing: AdmissionCriterion[]): string {
  let n = existing.length + 1;
  const ids = new Set(existing.map((c) => c.id));
  while (ids.has(`criterion-${n}`)) n += 1;
  return `criterion-${n}`;
}
