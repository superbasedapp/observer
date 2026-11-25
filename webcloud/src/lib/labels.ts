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

// PLAN_LABELS covers the plan names the portal reads off the API: the
// account plans and budget pools (internal/cloudserver/store/plans.go
// PlanFree/PlanPlusBeta; Usage's `budget_pool` reuses the same names) and the
// org plans a subscription row can name (internal/entitlements/catalog.go: a
// personal subscription re-keyed onto the personal org names personal_pro).
// The paid individual plan is "Personal Pro" under both of its internal
// names, plus_beta and personal_pro (operator ruling 2026-11-24: the only
// name a customer sees for it).
export const PLAN_LABELS: Record<string, string> = {
  free: "Free",
  plus_beta: "Personal Pro",
  personal_free: "Personal Free",
  personal_pro: "Personal Pro",
  team: "Team",
  business: "Business",
};

/** planDisplayName is the name a customer sees for a plan: the server's own
 * label when it sent one (GET /v1/usage `plan_label`, the catalog's), else
 * the plan token's PLAN_LABELS entry, else the token itself (labelFor's
 * honesty rule). "" when there is neither. */
export function planDisplayName(token: string | null | undefined, serverLabel?: string | null): string {
  if (serverLabel) return serverLabel;
  return token ? labelFor(PLAN_LABELS, token) : "";
}

// JOB_STATE_LABELS covers the enrichment-job state vocabulary
// (internal/cloudserver/store/jobs.go, internal/cloudserver/store/results.go:
// "queued", "succeeded", "parked", "failed"). `done` is the node-side
// spelling of the same terminal state (shared IntelResultCard / JOB_STATUS
// treat done and succeeded as one success state), so it reads the same here.
export const JOB_STATE_LABELS: Record<string, string> = {
  queued: "Queued",
  succeeded: "Succeeded",
  done: "Succeeded",
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
