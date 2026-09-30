// apiFailure: the ONE classification of a failed node API read into what a
// panel renders (the node twin of web2/src/lib/apiFailure.ts). Pure (no
// React, no imports), so the table below is unit-tested (apiFailure.test.ts)
// and useApi hands every panel the same reading of a failure.
//
// The distinction that matters: a denial (HTTP 403: a remote viewer reading a
// local-only endpoint, a feature the org policy turned off) is NOT an error.
// It renders as the shared PermissionDenied (ChartState's `denied` slot),
// never as a red "failed to load" card with a Retry that can never succeed.
// Every other status, and a failure with no response at all, stays an error
// exactly as before.
//
// It reads the status off the thrown value structurally (ApiError carries a
// numeric `status`) rather than importing ApiError, so this module stays
// importable by the node test runner without the app's path aliases.

/** What a panel needs to know about a failed read. */
export interface ApiFailure {
  /** HTTP status, or null for a failure that never got a response. */
  status: number | null;
  /** True for a denial (403): render the denied state, not ErrorState. */
  denied: boolean;
  /** The permission key the SERVER named in its 403 body, when it named one.
   *  Never inferred: null means "not stated". */
  permission: string | null;
}

// Permission keys are `<verb>:<noun>` (the same closed verb set the org
// dashboard recognises). A node 403 usually names none; when an org-governed
// gate does, the panel shows it.
const PERMISSION_KEY = /\b(read|write|admin|decide|scope):[a-z][a-z0-9_]*\b/;

/** permissionNamedIn returns the first permission key a sentence names, or
 *  null. Only ever applied to a 403's text: it reports what the server said. */
export function permissionNamedIn(text: string | null | undefined): string | null {
  if (!text) return null;
  const m = PERMISSION_KEY.exec(text);
  return m ? m[0] : null;
}

// STATUS_RULES: ordered status -> treatment table (walked top-down). A status
// without a row is an ordinary error (denied=false), as it always was.
const STATUS_RULES: { status: number; denied: boolean }[] = [{ status: 403, denied: true }];

/** statusOf reads an HTTP status off a thrown value, or null. */
export function statusOf(e: unknown): number | null {
  if (e && typeof e === "object" && "status" in e) {
    const s = (e as { status: unknown }).status;
    if (typeof s === "number" && Number.isFinite(s)) return s;
  }
  return null;
}

/** describeApiFailure classifies any thrown value from an API read. */
export function describeApiFailure(e: unknown): ApiFailure {
  const status = statusOf(e);
  const rule = status == null ? undefined : STATUS_RULES.find((r) => r.status === status);
  const denied = rule?.denied ?? false;
  const text = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  return { status, denied, permission: denied ? permissionNamedIn(text) : null };
}

/** isAccessDenied reports whether a thrown value is a denial. */
export function isAccessDenied(e: unknown): boolean {
  return describeApiFailure(e).denied;
}
