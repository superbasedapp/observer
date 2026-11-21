// Plane A (hosted-app observability) vocabularies (promoted from
// web2/src/lib/vocabs/obs.ts for B5-0, 2026-11-19; web2 keeps a re-export
// shim): span kinds, trace/span
// status, eval verdicts, admission decisions and degraded codes, gateway
// capture levels.
//
// Before 2026-09-28 the span-kind colour lived twice (obs/chips KindChip and
// the inspector's KindPill, "keep in sync by hand") and the free-text eval
// label heuristic twice, with different word lists.
import { FlaskConical, Tags, TriangleAlert } from "lucide-react";
import type { VocabDef } from "./vocabDef.ts";

/** A gateway capture policy's level (web2 lib/api.ts GatewayCaptureLevel). */
export type GatewayCaptureLevel = "metadata_only" | "classified_safe" | "full_redacted";

// SPAN_KIND: an OTel GenAI span's kind. The tones double as the agent
// graph's node colours (AgentGraphSvg), so they are categorical here.
export const SPAN_KIND: VocabDef<"llm" | "tool" | "agent" | "retriever" | "chain" | "embedding" | "other"> = {
  vocab: "spanKind",
  entries: {
    llm: { tone: "accent" },
    tool: { tone: "info" },
    agent: { tone: "success" },
    retriever: { tone: "warn" },
    chain: { tone: "neutral" },
    embedding: { tone: "neutral" },
    other: { tone: "neutral" },
  },
};

// TRACE_STATUS: a trace's or span's status.
export const TRACE_STATUS: VocabDef<"ok" | "error"> = {
  vocab: "traceStatus",
  entries: {
    ok: { tone: "success" },
    error: { tone: "danger" },
  },
};

// EVAL_VERDICT: an eval result as pass / fail / neutral, plus the run
// markers shown beside it.
export const EVAL_VERDICT: VocabDef<"pass" | "fail" | "neutral" | "reviewed" | "regression" | "online" | "org-run"> = {
  vocab: "evalVerdict",
  entries: {
    pass: { tone: "success" },
    fail: { tone: "danger" },
    neutral: { tone: "neutral" },
    reviewed: { tone: "info" },
    regression: { tone: "danger" },
    online: { tone: "info" },
    "org-run": { tone: "accent" },
  },
};

// Eval labels are free text ("correct", "unsafe", "PASS", "no"), so a label
// is bucketed by whole words. FAIL is checked first: "incorrect" and
// "unsafe" contain a pass word. Short words (no, ok) only match a whole
// word, so "none" or "token" do not.
const EVAL_WORDS: { verdict: "fail" | "pass"; words: readonly string[] }[] = [
  { verdict: "fail", words: ["fail", "bad", "false", "no", "incorrect", "unsafe", "error", "danger", "denied", "blocked"] },
  { verdict: "pass", words: ["pass", "good", "true", "yes", "ok", "correct", "safe", "success", "healthy", "efficient"] },
];

/** evalLabelVerdict buckets a free-text eval label into pass / fail /
 *  neutral. Content-free (the label only, never the rationale); errs toward
 *  neutral when the label does not clearly read either way. */
export function evalLabelVerdict(label: string | null | undefined): "pass" | "fail" | "neutral" {
  const tokens = (label ?? "").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const hit = EVAL_WORDS.find((row) =>
    tokens.some((t) => row.words.some((w) => (w.length <= 2 ? t === w : t.startsWith(w)))),
  );
  return hit?.verdict ?? "neutral";
}

// ADMISSION_DECISION: an input-admission verdict. `ask` is info (the same
// tone as a guard ask); would_block is danger: it WOULD have blocked in
// enforce mode.
export const ADMISSION_DECISION: VocabDef<"allow" | "flag" | "ask" | "would_block" | "deny"> = {
  vocab: "admissionDecision",
  entries: {
    allow: { tone: "success" },
    flag: { tone: "warn" },
    ask: { tone: "info" },
    would_block: { tone: "danger", label: "would block" },
    deny: { tone: "danger" },
  },
};

// ADMISSION_DEGRADED: a verdict's degraded code. The GENUINE fail-open
// codes read unmistakably as "not enforced" (danger), so a fail-open ALLOW
// never passes for a clean one; any other code (a benign short-circuit or
// cache marker) is `other`, warn, labelled by its raw code. Mirrors the
// node's admission.IsDegraded classification.
export const ADMISSION_DEGRADED: VocabDef<"timeout-failopen" | "judge-error" | "no-judge" | "other"> = {
  vocab: "admissionMode",
  icons: { other: TriangleAlert },
  entries: {
    "timeout-failopen": { tone: "danger", label: "not enforced (judge failed)", glyph: "degraded" },
    "judge-error": { tone: "danger", label: "not enforced (judge refused the request)", glyph: "degraded" },
    "no-judge": { tone: "danger", label: "not enforced (no judge)", glyph: "degraded" },
    other: { tone: "warn" },
  },
};

// ADMISSION_MODE: an admission policy's mode (enforce blocks for real).
export const ADMISSION_MODE: VocabDef<"observe" | "enforce"> = {
  vocab: "admissionMode",
  entries: {
    observe: { tone: "neutral", label: "Observe only" },
    enforce: { tone: "danger", label: "Enforce" },
  },
};

// JUDGE_HOSTING_LABEL names where the admission LLM judge runs, as a node
// reports it (cmd/observer obs_wire.go: org_relay / off, or the hosting
// class judgeHostingLabel derives from the judge endpoint). The raw value
// was shown as a KPI tile's hero text (design review 2026-10-13).
export const JUDGE_HOSTING_LABEL: Readonly<Record<string, string>> = {
  org_relay: "Org relay",
  local: "Local model",
  aggregator: "Model aggregator",
  provider: "Model provider",
  private: "Private endpoint",
  off: "Off",
};

/** judgeHostingLabel names a judge hosting value; an unknown one keeps its
 *  spelling with underscores as spaces, never a blank. */
export function judgeHostingLabel(v: string | null | undefined): string {
  const key = (v ?? "").trim();
  if (!key) return "-";
  return JUDGE_HOSTING_LABEL[key] ?? key.replace(/_/g, " ");
}

// TELEMETRY_CAPTURE: a gateway capture policy's level.
export const TELEMETRY_CAPTURE: VocabDef<GatewayCaptureLevel> = {
  vocab: "telemetryCapture",
  entries: {
    metadata_only: { tone: "neutral" },
    classified_safe: { tone: "accent" },
    full_redacted: { tone: "warn" },
  },
};

// CACHE_CALL_VERDICT: the per-call prompt-cache verdict on the Cache
// analysis call timeline. The session's first call is never a miss by
// definition (neutral); a hit is success (a partial hit keeps the hit tone,
// the caller appends "partial"); a miss is warn, followed by its cause.
export const CACHE_CALL_VERDICT: VocabDef<"first_call" | "hit" | "miss"> = {
  vocab: "cacheCallVerdict",
  entries: {
    first_call: { tone: "neutral", label: "first call" },
    hit: { tone: "success" },
    miss: { tone: "warn" },
  },
};

// DATASET_SOURCE (moved from web2 lib/vocabs/jobs.ts, B5-0): where a dataset's items came from.
export const DATASET_SOURCE: VocabDef<"manual" | "tag_rule" | "experiment"> = {
  vocab: "projectEvidence",
  icons: { tag_rule: Tags, experiment: FlaskConical },
  entries: {
    manual: { tone: "neutral" },
    tag_rule: { tone: "info", label: "tag rule" },
    experiment: { tone: "accent" },
  },
};

// TRACE_SOURCE: how a trace or span reached this machine (the obs ingestion
// source, internal/obs/span Source*). The raw value was shown as an
// Analytics "By source" key (design review 2026-11-21).
export const TRACE_SOURCE: VocabDef<"sdk_otlp" | "otlp_trace" | "proxy_turn"> = {
  vocab: "traceSource",
  entries: {
    sdk_otlp: { tone: "accent", label: "SDK", case: "none" },
    otlp_trace: { tone: "info", label: "OpenTelemetry", case: "none" },
    proxy_turn: { tone: "neutral", label: "proxy" },
  },
};

// SCORE_SOURCE: where a score on a trace came from (contracts/scores.md).
export const SCORE_SOURCE: VocabDef<"sdk" | "feedback" | "otel" | "eval" | "user" | "review" | "llm" | "rule"> = {
  vocab: "scoreSource",
  entries: {
    sdk: { tone: "accent", label: "SDK", case: "none" },
    feedback: { tone: "info", label: "user feedback" },
    otel: { tone: "info", label: "OpenTelemetry", case: "none" },
    eval: { tone: "neutral", label: "eval run" },
    user: { tone: "neutral" },
    review: { tone: "neutral" },
    llm: { tone: "neutral", label: "LLM judge" },
    rule: { tone: "neutral", label: "online rule" },
  },
};

// SCORE_KIND: a score's value type.
export const SCORE_KIND: VocabDef<"boolean" | "numeric" | "categorical"> = {
  vocab: "scoreKind",
  entries: {
    boolean: { tone: "neutral", label: "yes / no" },
    numeric: { tone: "neutral", label: "number" },
    categorical: { tone: "neutral", label: "category" },
  },
};

// PROMPT_TYPE: a versioned prompt's template shape.
export const PROMPT_TYPE: VocabDef<"text" | "chat"> = {
  vocab: "promptType",
  entries: {
    text: { tone: "neutral" },
    chat: { tone: "neutral" },
  },
};
