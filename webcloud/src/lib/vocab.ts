// vocab - the portal's closed-vocabulary presentation tables (design-kit
// WS5). One { tone, label } row per value, colocated here with the portal's
// other vocabulary maps (./labels.ts); the glyph is never chosen here, it is
// VOCAB_ICONS in shared/lib/vocabIcons.ts. An unknown value is honest:
// neutral, its raw id, the CircleHelp glyph.
//
// Consent purposes and field classes additionally carry a DISCLOSURE level
// (1 least - 4 most sensitive) so every surface lists them as an escalating
// ladder and draws the same 1-4 dot meter (components/Disclosure.tsx).
import type { LucideIcon } from "lucide-react";
import type { HeroStatVariant } from "@shared/primitives/HeroStat";
import type { Tone } from "@shared/lib/tone";
import { vocabView, type VocabEntry } from "@shared/lib/vocabEntry";
import { JOB_STATUS } from "@shared/lib/sessionVocab";
import { JOB_STATE_LABELS, labelFor } from "./labels";

// ---------------------------------------------------------------------------
// Disclosure levels
// ---------------------------------------------------------------------------

export type Disclosure = 1 | 2 | 3 | 4;

/** DISCLOSURE_LEVEL words each level for the meter's accessible name. */
export const DISCLOSURE_LEVEL: Readonly<Record<Disclosure, string>> = {
  1: "minimal",
  2: "low",
  3: "moderate",
  4: "high",
};

type DisclosureEntry = VocabEntry & { disclosure: Disclosure };

// CONSENT_PURPOSE: the seven purposes of internal/cloudcontract/consent.go,
// ranked by what each lets leave the account. Rationale per row:
//   1 account_device_operations    identity, devices, security events; no
//                                  session-derived upload at all.
//   2 structural_activity_insights structural counts and categories only.
//   2 community_cohort_benchmarking a DERIVED structural contribution, compared
//                                  privately against a minimum-size cohort.
//   3 bounded_context_enrichment   post-scrub excerpts of your own content.
//   3 public_community_profile     a structural contribution listed PUBLICLY
//                                  under a handle you choose.
//   4 extended_evidence_deep_review the richest content: evidence fields a
//                                  deep review needs, previewed per job.
//   4 research_model_improvement   content retained for a future research
//                                  corpus, beyond serving your own results.
// Ties keep the contract's canonical order.
export const CONSENT_PURPOSE: Readonly<Record<string, DisclosureEntry>> = {
  account_device_operations: { tone: "neutral", label: "Account and devices", disclosure: 1 },
  structural_activity_insights: { tone: "neutral", label: "Session structure", disclosure: 2 },
  community_cohort_benchmarking: { tone: "neutral", label: "Cohort benchmarking", disclosure: 2 },
  bounded_context_enrichment: { tone: "neutral", label: "Context excerpts", disclosure: 3 },
  public_community_profile: { tone: "neutral", label: "Public profile", disclosure: 3 },
  extended_evidence_deep_review: { tone: "neutral", label: "Deep-review evidence", disclosure: 4 },
  research_model_improvement: { tone: "neutral", label: "Research", disclosure: 4 },
};

// FIELD_CLASS: the six preview field classes a standing grant binds. The
// first user prompt excerpt is a strict SUBSET of content excerpts (one
// prompt, not the whole bounded excerpt set), so it ranks one step below it.
export const FIELD_CLASS: Readonly<Record<string, DisclosureEntry>> = {
  identity_linkage: { tone: "neutral", label: "Identity links", disclosure: 1 },
  structural_metrics: { tone: "neutral", label: "Structural metrics", disclosure: 1 },
  paths_project_identifiers: { tone: "neutral", label: "Path and project ids", disclosure: 2 },
  user_feedback: { tone: "neutral", label: "Your feedback", disclosure: 2 },
  first_user_prompt_excerpt: { tone: "neutral", label: "First prompt excerpt", disclosure: 3 },
  content_excerpts: { tone: "neutral", label: "Content excerpts", disclosure: 4 },
};

/**
 * byDisclosure orders vocabulary ids least to most sensitive. Ties keep the
 * table's own (contract) order; an id the table does not know sorts last, in
 * the order it arrived, rather than being guessed into the ladder.
 */
export function byDisclosure(table: Readonly<Record<string, DisclosureEntry>>, ids: readonly string[]): string[] {
  const rank = new Map(Object.keys(table).map((id, i) => [id, i]));
  const key = (id: string): [number, number] => {
    const e = table[id];
    return e ? [e.disclosure, rank.get(id) ?? 0] : [Number.POSITIVE_INFINITY, 0];
  };
  return ids
    .map((id, i) => ({ id, i }))
    .sort((a, b) => {
      const [da, ra] = key(a.id);
      const [db, rb] = key(b.id);
      return da - db || ra - rb || a.i - b.i;
    })
    .map((x) => x.id);
}

/** orderPurposes lists the server's purpose rows least to most sensitive (a
 *  consent screen then reads as an escalating disclosure ladder). */
export function orderPurposes<P extends { id: string }>(purposes: readonly P[]): P[] {
  const byId = new Map(purposes.map((p) => [p.id, p]));
  return byDisclosure(
    CONSENT_PURPOSE,
    purposes.map((p) => p.id),
  ).map((id) => byId.get(id) as P);
}

// ---------------------------------------------------------------------------
// Subscription status (Billing)
// ---------------------------------------------------------------------------

// SUBSCRIPTION_STATUS: a Paddle subscription's status. The ONE table the
// header pill, the subscription card and the hero all read (before
// 2026-09-28 past_due was a danger pill but a warn hero, paused a neutral
// pill but a warn hero). past_due is warn: access continues through the
// grace period, so it is a call to act, not a loss; paused is warn too;
// refunded / charged back revoke access (danger).
export const SUBSCRIPTION_STATUS: Readonly<Record<string, VocabEntry>> = {
  active: { tone: "success", label: "Active" },
  trialing: { tone: "info", label: "Trial" },
  canceled: { tone: "neutral", label: "Canceled" },
  past_due: { tone: "warn", label: "Past due" },
  paused: { tone: "warn", label: "Paused" },
  refunded: { tone: "danger", label: "Refunded" },
  charged_back: { tone: "danger", label: "Charged back" },
};

// HERO_VARIANT: the billing hero's colour for a status tone. The hero only
// has accent / warn / danger: every non-alarming tone reads as the calm
// accent hero; warn and danger carry through unchanged.
export const HERO_VARIANT: Readonly<Record<Tone, HeroStatVariant>> = {
  neutral: "accent",
  success: "accent",
  info: "accent",
  accent: "accent",
  warn: "warn",
  danger: "danger",
};

// ---------------------------------------------------------------------------
// Tones as colours, and the jobs-by-state donut
// ---------------------------------------------------------------------------

// TONE_COLOR lives with the Tone type in shared/lib/tone.ts (one owner).
import { TONE_COLOR } from "@shared/lib/tone";
export { TONE_COLOR };

/** A donut slice for one enrichment-job state, coloured by MEANING (the
 *  shared JOB_STATUS table: succeeded success, queued info, parked warn,
 *  failed danger) instead of by its rank in the chart. `spin` is the same
 *  table's in-flight flag (queued / running): the legend turns its glyph so
 *  work still in progress reads as live, never guessed from the label. */
export type JobStateSlice = { key: string; count: number; color: string; icon: LucideIcon; spin: boolean };

/** jobStateSlices turns a jobs-by-state count map into donut slices. Two wire
 *  spellings of one state (the server's `succeeded` and the node-side `done`)
 *  share one row in JOB_STATE_LABELS, so they fold into ONE slice here, at the
 *  boundary, instead of two slices with the same name. The first spelling seen
 *  keeps the slice's colour and glyph (both spellings share a JOB_STATUS tone). */
export function jobStateSlices(byState: Readonly<Record<string, number>>): JobStateSlice[] {
  const slices = new Map<string, JobStateSlice>();
  for (const [state, count] of Object.entries(byState)) {
    const key = labelFor(JOB_STATE_LABELS, state);
    const seen = slices.get(key);
    if (seen) {
      seen.count += count;
      continue;
    }
    const v = vocabView("jobStatus", JOB_STATUS, state);
    slices.set(key, { key, count, color: TONE_COLOR[v.tone], icon: v.icon, spin: v.spin });
  }
  return [...slices.values()];
}

/** jobsInFlight counts the jobs whose state JOB_STATUS marks in flight
 *  (spin), for the live indicator beside a jobs total. */
export function jobsInFlight(byState: Readonly<Record<string, number>>): number {
  return Object.entries(byState).reduce(
    (n, [state, count]) => n + (vocabView("jobStatus", JOB_STATUS, state).spin ? count : 0),
    0,
  );
}
