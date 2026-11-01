import type { Tone } from "./tone.ts";
import { vocabTone, type VocabTable } from "./vocabEntry.ts";
import { SOURCE_TIER } from "./sourceVocab.ts";

// cacheVocab - the ONE presentation table per prompt-cache vocabulary, shared
// by the node Cache page (web/src/pages/Cache.tsx), the cache-expiry card and
// cockpit (web/src/components/CacheExpiryCard.tsx, cockpit/CockpitContent.tsx)
// and the shared session-detail renderers (CacheTimelineList, CacheTierBadge)
// that the org drawer also mounts. Values are the closed sets in
// internal/cachetrack/attribute.go (Kind, Cause) and internal/cachewarm
// (severity); glyphs are VOCAB_ICONS.cacheEventKind / .cacheCause /
// .sourceTier / .cacheExpiry in ./vocabIcons.ts. Before 2026-09-28 the Cache
// page and the timeline disagreed (hit info vs success, mispredict neutral vs
// warn, mixed tier warn vs info); this file is the single answer.

// CACHE_EVENT_KIND - cache_events.kind. Healthy reads are success, healthy
// writes and the first-turn reanchor are info, below_min (the cache was never
// going to engage) is neutral, and every rewrite / reset / miss plus the
// engine's own mispredict is warn: something to look at, not a failure.
// A flagged event renders CACHE_FLAG's tone (warn) regardless of kind - read
// it through cacheEventTone below, never a per-site ternary.
export const CACHE_EVENT_KIND: VocabTable = {
  hit: { tone: "success" },
  implicit_hit: { tone: "success" },
  write: { tone: "info" },
  implicit_write: { tone: "info" },
  reanchor: { tone: "info" },
  below_min: { tone: "neutral" },
  mispredict: { tone: "warn" },
  invalidation_rewrite: { tone: "warn" },
  expiry_rewrite: { tone: "warn" },
  model_switch_rewrite: { tone: "warn" },
  compaction_reset: { tone: "warn" },
  implicit_miss: { tone: "warn" },
};

// CACHE_CAUSE - cache_events.cause. The unflagged baselines (suffix growth,
// an implicit hit) are info; causes that are expected by design (first turn,
// handoff rehydration, a prefix under the cacheable minimum) and the honest
// "unknown" are neutral; every real invalidation cause is warn. A flagged
// cause renders CACHE_FLAG's tone (warn) - read it through cacheCauseTone.
// Every row carries a plain label (T-803: the Overview tile printed the raw
// wire id "tools_or_system_changed", truncated), so no pill shows a
// snake_case key.
export const CACHE_CAUSE: VocabTable = {
  suffix_growth: { tone: "info", label: "Conversation grew" },
  implicit_hit: { tone: "info", label: "Prefix reused" },
  // Plain words (WINNODE2 16b); the engine's term "re-anchor" stays in the
  // help entry.
  reanchor: { tone: "neutral", label: "Cache restarted" },
  handoff_rehydration: { tone: "neutral", label: "Handoff reload" },
  below_min_cacheable: { tone: "neutral", label: "Too short to cache" },
  unknown: { tone: "neutral", label: "Unknown" },
  model_changed: { tone: "warn", label: "Model changed" },
  fast_toggle: { tone: "warn", label: "Fast mode toggled" },
  tools_changed: { tone: "warn", label: "Tools changed" },
  system_changed: { tone: "warn", label: "System prompt changed" },
  tools_or_system_changed: { tone: "warn", label: "Tools or prompt changed" },
  context_compacted: { tone: "warn", label: "Context compacted" },
  ttl_expired: { tone: "warn", label: "Cache expired" },
  lookback_window_missed: { tone: "warn", label: "Lookback missed" },
  block_diverged: { tone: "warn", label: "Prompt block changed" },
  parallel_cold_start: { tone: "warn", label: "Parallel cold start" },
  prefix_churn: { tone: "warn", label: "Prefix changed" },
  prefix_shrink: { tone: "warn", label: "Prefix shrank" },
  prompt_cache_key_overflow: { tone: "warn", label: "Cache key overflow" },
};

// CACHE_FLAG - the ONE presentation of the engine's `flagged` mark (a cause
// with a known limitation, e.g. tools_changed on an MCP server toggle, and a
// session summary's has_flagged_rewrites). Decided 2026-09-28: flagged is
// warn everywhere - the cause is real and worth a look, but it is not a
// failure. Before that the node rendered it neutral and the org drawer danger.
// Every flagged cache event, cause, rewrite count, row tint and "flagged"
// label reads this table (directly or via the helpers below).
export const CACHE_FLAG: VocabTable = {
  flagged: { tone: "warn", label: "flagged" },
};

/** CACHE_FLAGGED_TONE - the tone of any flagged cache mark (CACHE_FLAG). */
export const CACHE_FLAGGED_TONE: Tone = vocabTone(CACHE_FLAG, "flagged");

/**
 * cacheEventTone - the tone of one cache_events.kind: the flagged tone when
 * the event is flagged (a flag overrides every kind), otherwise the kind's
 * CACHE_EVENT_KIND tone (neutral for an unknown kind).
 */
export function cacheEventTone(kind: string | null | undefined, flagged?: boolean): Tone {
  return flagged === true ? CACHE_FLAGGED_TONE : vocabTone(CACHE_EVENT_KIND, kind);
}

/**
 * cacheCauseTone - the tone of one cache_events.cause: the flagged tone when
 * the cause is flagged, otherwise the cause's CACHE_CAUSE tone (neutral for an
 * unknown cause).
 */
export function cacheCauseTone(cause: string | null | undefined, flagged?: boolean): Tone {
  return flagged === true ? CACHE_FLAGGED_TONE : vocabTone(CACHE_CAUSE, cause);
}

/**
 * cacheCauseLabel - the plain label of one cache_events.cause. An unknown
 * cause reads as its words ("new_cause" -> "new cause"), never a raw
 * snake_case key.
 */
export function cacheCauseLabel(cause: string | null | undefined): string {
  if (!cause) return "";
  return CACHE_CAUSE[cause]?.label ?? cause.replace(/_+/g, " ");
}

/** The session cache-summary fields cacheSummaryTone reads. */
export type CacheSummaryToneInput = {
  has_flagged_rewrites?: boolean;
  rewrite_count?: number;
};

// CACHE_SUMMARY_TONE_RULES - a session cache summary's one-pill tone (the
// Cost page's per-model cache annotation, the KPI strip's Rewrites stat).
// Ordered, first match wins: flagged rewrites take the flagged tone, other
// rewrites the invalidation_rewrite kind tone, and a rewrite-free summary is
// info (healthy hit/write traffic).
export const CACHE_SUMMARY_TONE_RULES: readonly {
  name: string;
  when: (s: CacheSummaryToneInput) => boolean;
  tone: Tone;
}[] = [
  { name: "flagged_rewrites", when: (s) => s.has_flagged_rewrites === true, tone: CACHE_FLAGGED_TONE },
  { name: "rewrites", when: (s) => (s.rewrite_count ?? 0) > 0, tone: vocabTone(CACHE_EVENT_KIND, "invalidation_rewrite") },
  { name: "healthy", when: () => true, tone: "info" },
];

/** cacheSummaryTone walks CACHE_SUMMARY_TONE_RULES top-down. */
export function cacheSummaryTone(s: CacheSummaryToneInput): Tone {
  for (const r of CACHE_SUMMARY_TONE_RULES) if (r.when(s)) return r.tone;
  return "info";
}

// CACHE_TIER - which capture path graded a session's cache. The tones are
// the capture-source tones (./sourceVocab.ts SOURCE_TIER: proxy success,
// transcript info, mixed warn - the engine ran over the session twice and
// the grading can drift - none neutral); `label` is the session-detail badge
// wording, while the Cache page's compact table shows the raw tier id.
export const CACHE_TIER: VocabTable = {
  proxy: { ...SOURCE_TIER.proxy, label: "Tier 1 · proxy" },
  transcript: { ...SOURCE_TIER.transcript, label: "Tier 2 · transcript" },
  mixed: { ...SOURCE_TIER.mixed, label: "Mixed" },
  none: { ...SOURCE_TIER.none, label: "None" },
};

// CACHE_ENTRY_STATE - a cache_entries row's state (the Cache page's entry
// states bar): live info, unverified neutral, expired warn, invalidated
// danger. Glyphs: VOCAB_ICONS.cacheEntryState.
export const CACHE_ENTRY_STATE: VocabTable = {
  live: { tone: "info" },
  unverified: { tone: "neutral" },
  expired: { tone: "warn" },
  invalidated: { tone: "danger" },
};

// CACHE_EXPIRY - a live cache window's severity (internal/cachewarm
// Classify). Decided deliberately: ok (warm) is success, soon is warn,
// critical (about to go cold, money at risk) is danger, and cold is neutral:
// the cache is already gone, so it is information about the past, not an
// error to act on. Before 2026-09-28 critical rendered warn and cold danger.
export const CACHE_EXPIRY: VocabTable = {
  ok: { tone: "success", label: "warm" },
  soon: { tone: "warn" },
  critical: { tone: "danger" },
  cold: { tone: "neutral" },
};
