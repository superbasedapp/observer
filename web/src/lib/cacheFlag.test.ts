// Pins the ONE flagged-cache presentation (shared/lib/cacheVocab.ts
// CACHE_FLAG + cacheEventTone / cacheCauseTone / cacheSummaryTone), decided
// 2026-09-28: a flagged cache mark is warn everywhere - the node Cache page,
// the Overview tile, the Cost annotation, the shared session-detail timeline
// and KPI strip, and the org drawer's CacheTimeline all read it from here.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CACHE_FLAG,
  CACHE_FLAGGED_TONE,
  CACHE_SUMMARY_TONE_RULES,
  cacheCauseTone,
  cacheEventTone,
  cacheSummaryTone,
  type CacheSummaryToneInput,
} from "../../../shared/lib/cacheVocab.ts";
import type { Tone } from "../../../shared/lib/tone.ts";

test("CACHE_FLAG: flagged is warn with the label 'flagged'", () => {
  assert.deepEqual(CACHE_FLAG.flagged, { tone: "warn", label: "flagged" });
  assert.equal(CACHE_FLAGGED_TONE, "warn");
});

const EVENT_CASES: { kind: string | null | undefined; flagged?: boolean; want: Tone; why: string }[] = [
  { kind: "hit", flagged: true, want: "warn", why: "a flag overrides a healthy kind" },
  { kind: "below_min", flagged: true, want: "warn", why: "a flag overrides a neutral kind" },
  { kind: "invalidation_rewrite", flagged: true, want: "warn", why: "flagged rewrite" },
  { kind: "hit", flagged: false, want: "success", why: "unflagged reads the kind table" },
  { kind: "write", want: "info", why: "flag absent reads the kind table" },
  { kind: "mispredict", flagged: false, want: "warn", why: "kind table warn" },
  { kind: "below_min", flagged: false, want: "neutral", why: "kind table neutral" },
  { kind: "no_such_kind", flagged: false, want: "neutral", why: "unknown kind is neutral" },
  { kind: null, want: "neutral", why: "missing kind is neutral" },
  { kind: "no_such_kind", flagged: true, want: "warn", why: "a flag wins even over an unknown kind" },
];

for (const c of EVENT_CASES) {
  test(`cacheEventTone(${String(c.kind)}, ${String(c.flagged)}) = ${c.want} (${c.why})`, () => {
    assert.equal(cacheEventTone(c.kind, c.flagged), c.want);
  });
}

const CAUSE_CASES: { cause: string | null | undefined; flagged?: boolean; want: Tone }[] = [
  { cause: "tools_changed", flagged: true, want: "warn" },
  { cause: "suffix_growth", flagged: true, want: "warn" },
  { cause: "suffix_growth", flagged: false, want: "info" },
  { cause: "reanchor", want: "neutral" },
  { cause: "ttl_expired", flagged: false, want: "warn" },
  { cause: "no_such_cause", want: "neutral" },
  { cause: undefined, want: "neutral" },
];

for (const c of CAUSE_CASES) {
  test(`cacheCauseTone(${String(c.cause)}, ${String(c.flagged)}) = ${c.want}`, () => {
    assert.equal(cacheCauseTone(c.cause, c.flagged), c.want);
  });
}

// One case per CACHE_SUMMARY_TONE_RULES row, in order, plus precedence.
const SUMMARY_CASES: { rule: string; s: CacheSummaryToneInput; want: Tone }[] = [
  { rule: "flagged_rewrites", s: { has_flagged_rewrites: true, rewrite_count: 3 }, want: "warn" },
  { rule: "rewrites", s: { has_flagged_rewrites: false, rewrite_count: 2 }, want: "warn" },
  { rule: "healthy", s: { has_flagged_rewrites: false, rewrite_count: 0 }, want: "info" },
];

test("CACHE_SUMMARY_TONE_RULES: the rule order is pinned", () => {
  assert.deepEqual(
    CACHE_SUMMARY_TONE_RULES.map((r) => r.name),
    SUMMARY_CASES.map((c) => c.rule),
  );
});

for (const c of SUMMARY_CASES) {
  test(`cacheSummaryTone row ${c.rule} = ${c.want}`, () => {
    const hit = CACHE_SUMMARY_TONE_RULES.find((r) => r.when(c.s));
    assert.equal(hit?.name, c.rule);
    assert.equal(cacheSummaryTone(c.s), c.want);
  });
}

test("cacheSummaryTone: an empty summary is healthy info", () => {
  assert.equal(cacheSummaryTone({}), "info");
});
