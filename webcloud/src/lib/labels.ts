// Human labels for the closed, machine-shaped vocabularies the portal reads
// off the API verbatim (feature ids, plan/pool names, job states, deletion
// and retention states). One small map per vocabulary, looked up through
// `labelFor`, which falls back to the raw token itself for anything not in
// the map — never invent a label for a token this build does not recognise
// (the same honesty rule `../consent.ts`'s `copyFor` already follows for
// consent purpose ids).

/** labelFor returns the human label for `token` from `map`, or the raw token
 * itself when the map has no entry — so a server-side addition never renders
 * as blank or "undefined". */
export function labelFor(map: Record<string, string>, token: string): string {
  return map[token] ?? token;
}

// FEATURE_LABELS covers store.FeatureSessionEnrichment
// (internal/cloudserver/store/reserve.go) — today the only feature this
// service meters.
export const FEATURE_LABELS: Record<string, string> = {
  session_enrichment: "Session enrichment",
};

// PLAN_LABELS covers the plan/budget-pool name vocabulary
// (internal/cloudserver/store/plans.go PlanFree/PlanPlusBeta). Usage's
// `budget_pool` field reuses the same names, so this map serves both.
export const PLAN_LABELS: Record<string, string> = {
  free: "Free",
  plus_beta: "Plus",
};

// JOB_STATE_LABELS covers the enrichment-job state vocabulary
// (internal/cloudserver/store/jobs.go, internal/cloudserver/store/results.go:
// "queued", "succeeded", "parked", "failed").
export const JOB_STATE_LABELS: Record<string, string> = {
  queued: "Queued",
  succeeded: "Succeeded",
  parked: "Parked",
  failed: "Failed",
};

// DELETION_STATE_LABELS covers DeletionResult.state
// (internal/cloudserver/store/deletion.go: "done").
export const DELETION_STATE_LABELS: Record<string, string> = {
  done: "Complete",
};

// RETENTION_STATE_LABELS covers GrantsResult.retention_state
// (internal/cloudserver/api/portalinsights.go: "retained_until_account_deletion").
export const RETENTION_STATE_LABELS: Record<string, string> = {
  retained_until_account_deletion: "Retained until account deletion",
};
