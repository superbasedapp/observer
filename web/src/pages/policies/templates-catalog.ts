// The Policies template catalog — a FRONTEND data file (handover §5): ready-made
// guardrail + routing bundles the operator can preview and apply with one click.
// It lives here (not a backend endpoint) so a bundle can compose multiple
// criteria/rules across both policies; applying just merges the contribution
// into the current live policy and POSTs it through the same editors' endpoints.

import {
  type AdmissionCriterion,
  type AdmissionPolicy,
  type BudgetConfig,
  type CriterionType,
  type Decision,
  type EgressPolicy,
  type EgressRule,
  type EgressTarget,
  emptyEgressWhen,
} from "./types";

export type TemplateContribution = {
  criteria?: AdmissionCriterion[];
  prefilterDeny?: string[];
  secretRemoteJudge?: Decision;
  egressTargets?: EgressTarget[];
  egressRules?: EgressRule[];
  budget?: BudgetConfig;
};

export type PolicyTemplate = TemplateContribution & {
  id: string;
  group: string;
  title: string;
  blurb: string;
};

// What a template touches, derived from its contribution — drives the summary
// pills and which write paths the apply runs.
export function templateTouches(t: TemplateContribution): ("guardrail" | "routing" | "budget")[] {
  const out: ("guardrail" | "routing" | "budget")[] = [];
  if (t.criteria?.length || t.prefilterDeny?.length || t.secretRemoteJudge) out.push("guardrail");
  if (t.egressTargets?.length || t.egressRules?.length) out.push("routing");
  if (t.budget) out.push("budget");
  return out;
}

// --- compact builders ---
function crit(o: { id: string; type: CriterionType; name?: string; definition?: string; topics?: string[]; decision?: Decision; severity?: AdmissionCriterion["severity"] }): AdmissionCriterion {
  return {
    id: o.id,
    type: o.type,
    name: o.name ?? o.id,
    definition: o.definition ?? "",
    topics: o.topics ?? [],
    decision: o.decision ?? "deny",
    severity: o.severity ?? "warn",
  };
}
function rule(o: { name: string; when?: Partial<EgressRule["when"]>; action: Partial<EgressRule["action"]>; on_unavailable?: string; reason_code?: string }): EgressRule {
  return {
    name: o.name,
    when: { ...emptyEgressWhen(), ...o.when },
    action: { route_to_upstream: "", route_to_model: "", set_effort: "", deny: false, no_route: false, ...o.action },
    on_unavailable: o.on_unavailable ?? "fail_open",
    reason: "",
    reason_code: o.reason_code ?? "",
  };
}

const ollamaLocal: EgressTarget = { id: "ollama-local", url: "http://127.0.0.1:11434", shape: "openai" };

export const TEMPLATE_CATALOG: PolicyTemplate[] = [
  // --- Scope ---
  {
    id: "employee-copilot-scope",
    group: "Scope",
    title: "Employee Copilot",
    blurb: "Ask the user to rephrase anything off-topic. Allows only questions about the company's own tools and knowledge.",
    criteria: [crit({ id: "on-scope", type: "valid_use_case", name: "on-scope", definition: "Allow only questions about using the company's internal tools, products, and knowledge base. Anything off-topic should be asked to rephrase.", decision: "ask", severity: "info" })],
  },
  {
    id: "customer-support-scope",
    group: "Scope",
    title: "Customer Support",
    blurb: "Keeps a support assistant on product-support topics; asks to rephrase off-topic requests.",
    criteria: [crit({ id: "support-scope", type: "valid_use_case", name: "support-scope", definition: "Allow only customer-support questions about the product: how-to, troubleshooting, account and billing help. Ask to rephrase anything else.", decision: "ask", severity: "info" })],
  },
  {
    id: "coding-assistant-scope",
    group: "Scope",
    title: "Coding-assistant only",
    blurb: "Denies non-coding requests outright - for an internal dev assistant.",
    criteria: [crit({ id: "coding-only", type: "valid_use_case", name: "coding-only", definition: "Allow only software-engineering requests: writing, explaining, reviewing, or debugging code and related tooling. Deny anything unrelated.", decision: "deny", severity: "warn" })],
  },

  // --- Safety ---
  {
    id: "block-jailbreaks",
    group: "Safety",
    title: "Block jailbreaks",
    blurb: "Deterministically detects and denies prompt-injection / jailbreak attempts.",
    criteria: [crit({ id: "jailbreak", type: "jailbreak", name: "jailbreak", decision: "deny", severity: "high" })],
  },
  {
    id: "denied-topics",
    group: "Safety",
    title: "Denied topics",
    blurb: "Flags requests about competitors and regulated-advice topics (legal / medical / financial).",
    criteria: [crit({ id: "denied-topics", type: "denied_topics", name: "denied-topics", topics: ["competitors", "legal advice", "medical advice", "financial advice"], decision: "flag", severity: "warn" })],
  },
  {
    id: "secrets-pii-guard",
    group: "Safety",
    title: "Secrets / PII guard",
    blurb: "Denies obvious credential patterns before the judge, and refuses to send a secret-bearing request to a remote judge.",
    prefilterDeny: ["(?i)\\b(api[_-]?key|secret|password|token)\\b\\s*[:=]", "-----BEGIN [A-Z ]*PRIVATE KEY-----"],
    secretRemoteJudge: "deny",
  },

  // --- Cost ---
  {
    id: "per-user-budget",
    group: "Cost",
    title: "Per-user budget caps",
    blurb: "Caps each end-user's spend ($5 / 5h, $25 / week, $80 / month). A breach denies (shadow in observe). Restart-only.",
    budget: { Enabled: true, PerUser5hUSD: 5, PerUserWeeklyUSD: 25, PerUserMonthlyUSD: 80, UserHeader: "" },
  },
  {
    id: "budget-band-cheaper",
    group: "Cost",
    title: "Budget-band → cheaper model",
    blurb: "Once a user has burned ≥80% of their band, swap them to a cheaper same-shape model.",
    egressRules: [rule({ name: "budget-band-cheaper", when: { budget_band_at_least: 0.8 }, action: { route_to_model: "claude-haiku-4-5" }, on_unavailable: "fail_open", reason_code: "egress_budget_band" })],
  },

  // --- Data locality ---
  {
    id: "flagged-to-local",
    group: "Data locality",
    title: "Flagged → on-prem",
    blurb: "Routes any flagged request to a local on-prem model; denies if that model is unavailable.",
    egressTargets: [ollamaLocal],
    egressRules: [rule({ name: "flagged-to-local", when: { verdict_at_least: "flag" }, action: { route_to_upstream: "ollama-local" }, on_unavailable: "deny", reason_code: "egress_flagged_local" })],
  },
  {
    id: "cohort-upstream",
    group: "Data locality",
    title: "Region cohort → upstream",
    blurb: "Routes a region cohort's traffic to a dedicated upstream. Edit the target URL to your regional endpoint.",
    egressTargets: [{ id: "regional-upstream", url: "https://REGION.example-upstream.local/v1", shape: "openai" }],
    egressRules: [rule({ name: "cohort-to-region", when: { user_cohort: "eu" }, action: { route_to_upstream: "regional-upstream" }, on_unavailable: "fail_open", reason_code: "egress_cohort_upstream" })],
  },

  // --- Bundles ---
  {
    id: "employee-copilot-bundle",
    group: "Bundles",
    title: "Employee Copilot (full bundle)",
    blurb: "The whole demo policy in one click: on-scope + jailbreak + denied-topics guardrails plus the flagged-to-local routing rule.",
    criteria: [
      crit({ id: "on-scope", type: "valid_use_case", name: "on-scope", definition: "Allow only questions about using the company's internal tools, products, and knowledge base. Anything off-topic should be asked to rephrase.", decision: "ask", severity: "info" }),
      crit({ id: "jailbreak", type: "jailbreak", name: "jailbreak", decision: "deny", severity: "high" }),
      crit({ id: "denied-topics", type: "denied_topics", name: "denied-topics", topics: ["competitors", "legal advice", "medical advice", "financial advice"], decision: "flag", severity: "warn" }),
    ],
    egressTargets: [ollamaLocal],
    egressRules: [rule({ name: "flagged-to-local", when: { verdict_at_least: "flag" }, action: { route_to_upstream: "ollama-local" }, on_unavailable: "deny", reason_code: "egress_flagged_local" })],
  },
];

export const TEMPLATE_GROUPS = ["Scope", "Safety", "Cost", "Data locality", "Bundles"];

// mergeAdmission folds a template's guardrail contribution into the current live
// admission policy: criteria upserted by id, prefilter deny-list unioned, secret
// remote-judge decision overridden when the template sets one. Null lists from
// the backend (nil slices) are coerced to [] so the merge is total.
export function mergeAdmission(cur: AdmissionPolicy, t: TemplateContribution): AdmissionPolicy {
  const byId = new Map((cur.criteria ?? []).map((c) => [c.id, c] as const));
  for (const c of t.criteria ?? []) byId.set(c.id, { ...c });
  const prevDeny = cur.prefilter?.deny ?? [];
  const deny = Array.from(new Set([...prevDeny, ...(t.prefilterDeny ?? [])]));
  return {
    ...cur,
    criteria: Array.from(byId.values()),
    prefilter: {
      allow: cur.prefilter?.allow ?? [],
      deny,
      max_message_bytes: cur.prefilter?.max_message_bytes ?? 0,
    },
    secret_remote_judge: t.secretRemoteJudge ?? cur.secret_remote_judge,
  };
}

// mergeEgress folds a template's routing contribution into the current live
// egress policy: targets added by id (existing kept), rules upserted by name.
export function mergeEgress(cur: EgressPolicy, t: TemplateContribution): EgressPolicy {
  const targets = new Map((cur.targets ?? []).map((x) => [x.id, x] as const));
  for (const x of t.egressTargets ?? []) if (!targets.has(x.id)) targets.set(x.id, { ...x });
  const rules = new Map((cur.rules ?? []).map((x) => [x.name, x] as const));
  for (const x of t.egressRules ?? []) rules.set(x.name, { ...x });
  return { ...cur, targets: Array.from(targets.values()), rules: Array.from(rules.values()) };
}
