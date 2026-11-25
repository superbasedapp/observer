// apiFailureCore: the part of the failed-read classification both
// dashboards share (web/src/lib/apiFailure.ts and web2/src/lib/apiFailure.ts
// each keep their own status table and failure shape around it). Pure, no
// imports, so each app's apiFailure.test.ts runs it under plain node.

// Permission keys are `<verb>:<noun>` (internal/orgserver/rbac/permissions.go,
// e.g. read:people, write:pricing, admin:identity, decide:mcp_approvals,
// scope:org). The verb set is closed; a new verb is added here. A node 403
// usually names none; when an org-governed gate does, the panel shows it.
const PERMISSION_KEY = /\b(read|write|admin|decide|scope):[a-z][a-z0-9_]*\b/;

/** permissionNamedIn returns the first permission key a server sentence
 *  names, or null. Used only on a 403 body: it reports what the server said,
 *  it never guesses a key from the route. */
export function permissionNamedIn(text: string | null | undefined): string | null {
  if (!text) return null;
  const m = PERMISSION_KEY.exec(text);
  return m ? m[0] : null;
}
