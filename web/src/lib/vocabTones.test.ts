// Pins the vocabulary presentation tables (WS5 "one {tone, icon, label} per
// vocabulary"): every value a tone table colours also has a glyph in
// shared/lib/vocabIcons.ts under the vocabulary it is rendered with, so a
// value added to one table without the other fails here instead of drawing
// the CircleHelp fallback on a known value. Also pins vocabView's honesty
// rules (unknown = neutral + raw label + CircleHelp; in flight = the spinning
// LoaderCircle) and the deliberate tone decisions the unification made.
import { test } from "node:test";
import assert from "node:assert/strict";
import { CircleHelp, LoaderCircle } from "lucide-react";
import { VOCAB_ICONS, type Vocab } from "../../../shared/lib/vocabIcons.ts";
import { vocabTone, vocabView, type VocabTable } from "../../../shared/lib/vocabEntry.ts";
import {
  CACHE_CAUSE,
  CACHE_ENTRY_STATE,
  CACHE_EVENT_KIND,
  CACHE_EXPIRY,
  CACHE_TIER,
} from "../../../shared/lib/cacheVocab.ts";
import { JOB_STATUS, MESSAGE_ROLE, STOP_REASON, TASK_STATUS } from "../../../shared/lib/sessionVocab.ts";
import { SOURCE_TIER } from "../../../shared/lib/sourceVocab.ts";
import {
  AUDIT_CHAIN,
  CHECK_STATUS,
  COMMIT_CAPTURE,
  EGRESS_OUTCOME,
  POLICY_MODE,
  PROMPT_GUARD_OUTCOME,
  SUGGESTION_CATEGORY,
  SUGGESTION_SCOPE,
  SUGGESTION_SEVERITY,
  promptGuardOutcomeKey,
} from "./vocabTones.ts";

// One row per table: [name, the vocabulary its pills pass to vocabIcon, table].
const TABLES: [string, Vocab, VocabTable][] = [
  ["CACHE_EVENT_KIND", "cacheEventKind", CACHE_EVENT_KIND],
  ["CACHE_CAUSE", "cacheCause", CACHE_CAUSE],
  ["CACHE_TIER", "sourceTier", CACHE_TIER],
  ["CACHE_EXPIRY", "cacheExpiry", CACHE_EXPIRY],
  ["CACHE_ENTRY_STATE", "cacheEntryState", CACHE_ENTRY_STATE],
  ["SOURCE_TIER", "sourceTier", SOURCE_TIER],
  ["MESSAGE_ROLE", "messageRole", MESSAGE_ROLE],
  ["STOP_REASON", "stopReason", STOP_REASON],
  ["TASK_STATUS", "taskStatus", TASK_STATUS],
  ["JOB_STATUS", "jobStatus", JOB_STATUS],
  ["POLICY_MODE", "guardMode", POLICY_MODE],
  ["PROMPT_GUARD_OUTCOME", "promptGuardOutcome", PROMPT_GUARD_OUTCOME],
  ["EGRESS_OUTCOME", "egressOutcome", EGRESS_OUTCOME],
  ["CHECK_STATUS", "healthCheck", CHECK_STATUS],
  ["COMMIT_CAPTURE", "commitCapture", COMMIT_CAPTURE],
  ["AUDIT_CHAIN", "auditChain", AUDIT_CHAIN],
  ["SUGGESTION_SEVERITY", "suggestionSeverity", SUGGESTION_SEVERITY],
  ["SUGGESTION_CATEGORY", "suggestionCategory", SUGGESTION_CATEGORY],
  ["SUGGESTION_SCOPE", "suggestionScope", SUGGESTION_SCOPE],
];

for (const [name, vocab, table] of TABLES) {
  test(`${name}: every value has a ${vocab} glyph`, () => {
    const glyphs = VOCAB_ICONS[vocab] as Record<string, unknown>;
    const missing = Object.keys(table).filter((v) => !(v in glyphs));
    assert.deepEqual(missing, []);
  });
}

test("vocabView: a known value resolves tone, label and its glyph", () => {
  const v = vocabView("stopReason", STOP_REASON, "max_tokens");
  assert.equal(v.tone, "warn");
  assert.equal(v.label, "max_tokens");
  assert.equal(v.icon, VOCAB_ICONS.stopReason.max_tokens);
  assert.equal(v.spin, false);
});

test("vocabView: an unknown value is neutral, raw-labelled, CircleHelp", () => {
  for (const value of ["no-such-value", null, undefined]) {
    const v = vocabView("taskStatus", TASK_STATUS, value);
    assert.equal(v.tone, "neutral");
    assert.equal(v.label, value ?? "");
    assert.equal(v.icon, CircleHelp);
    assert.equal(v.spin, false);
  }
});

test("vocabView: an in-flight value spins the LoaderCircle", () => {
  for (const [vocab, table, value] of [
    ["taskStatus", TASK_STATUS, "in_progress"],
    ["jobStatus", JOB_STATUS, "running"],
    ["jobStatus", JOB_STATUS, "queued"],
  ] as [Vocab, VocabTable, string][]) {
    const v = vocabView(vocab, table, value);
    assert.equal(v.spin, true, `${vocab}.${value}`);
    assert.equal(v.icon, LoaderCircle, `${vocab}.${value}`);
  }
  assert.equal(vocabView("taskStatus", TASK_STATUS, "in_progress").label, "in progress");
});

test("vocabTone reads only the tone, neutral when unknown", () => {
  assert.equal(vocabTone(CACHE_EVENT_KIND, "hit"), "success");
  assert.equal(vocabTone(CACHE_EVENT_KIND, "nope"), "neutral");
  assert.equal(vocabTone(CACHE_EVENT_KIND, null), "neutral");
});

// The deliberate decisions the 2026-09-28 unification made, one row each.
const DECISIONS: [string, VocabTable, string, string][] = [
  ["cache hit is healthy", CACHE_EVENT_KIND, "hit", "success"],
  ["the engine's mispredict is worth a look", CACHE_EVENT_KIND, "mispredict", "warn"],
  ["a rewrite is worth a look", CACHE_EVENT_KIND, "expiry_rewrite", "warn"],
  ["a critical cache is at risk", CACHE_EXPIRY, "critical", "danger"],
  ["a cold cache is gone, informational", CACHE_EXPIRY, "cold", "neutral"],
  ["a warm cache is fine", CACHE_EXPIRY, "ok", "success"],
  ["proxy capture is the accurate tier", SOURCE_TIER, "proxy", "success"],
  ["the cache tier reuses the source tone", CACHE_TIER, "mixed", SOURCE_TIER.mixed.tone],
  ["enforce actively blocks", POLICY_MODE, "enforce", "warn"],
  ["observe only records", POLICY_MODE, "observe", "info"],
  ["a fail-open fallback let the request through", EGRESS_OUTCOME, "fallback_open", "warn"],
  ["a fail-closed stop is an error", EGRESS_OUTCOME, "fail_closed", "danger"],
];

for (const [why, table, value, tone] of DECISIONS) {
  test(`tone decision: ${why}`, () => {
    assert.equal(vocabTone(table, value), tone);
  });
}

test("promptGuardOutcomeKey folds every degraded:* outcome onto one row", () => {
  assert.equal(promptGuardOutcomeKey("degraded:no_hook"), "degraded");
  assert.equal(promptGuardOutcomeKey("blocked"), "blocked");
  assert.equal(vocabTone(PROMPT_GUARD_OUTCOME, promptGuardOutcomeKey("degraded:x")), "warn");
});

test("CACHE_CAUSE covers the internal/cachetrack Cause closed set", () => {
  // internal/cachetrack/attribute.go Cause values, verbatim.
  const causes = [
    "reanchor", "handoff_rehydration", "model_changed", "fast_toggle", "tools_changed",
    "system_changed", "tools_or_system_changed", "context_compacted", "ttl_expired",
    "lookback_window_missed", "block_diverged", "below_min_cacheable", "parallel_cold_start",
    "suffix_growth", "unknown", "implicit_hit", "prefix_churn", "prefix_shrink",
    "prompt_cache_key_overflow",
  ];
  assert.deepEqual(causes.filter((c) => !(c in CACHE_CAUSE)), []);
});

test("CACHE_EVENT_KIND covers the internal/cachetrack Kind closed set", () => {
  const kinds = [
    "hit", "write", "expiry_rewrite", "invalidation_rewrite", "model_switch_rewrite",
    "compaction_reset", "reanchor", "mispredict", "below_min", "implicit_hit", "implicit_miss",
    "implicit_write",
  ];
  assert.deepEqual(kinds.filter((k) => !(k in CACHE_EVENT_KIND)), []);
});
