// governanceRefusal.ts: reads the node dashboard's governance refusal body
// ({error, section, org_name, message}, internal/intelligence/dashboard
// governance.go writeGovernanceRefusal) out of a failed request, so a surface
// whose routes the organization hid can say WHY instead of showing a bare
// error (plans decision log P-031: with Terminals hidden on a managed node
// the New Terminal dialog got every route refused and did not say why; lane
// SEC-E). Pure: it reads only the error's status and body.

export type GovernanceRefusal = { code: "governance_hidden" | "governance_read_only"; section: string; orgName: string };

/** governanceRefusalOf returns the refusal when e is a governance 404/409. */
export function governanceRefusalOf(e: unknown): GovernanceRefusal | null {
  const err = e as { status?: unknown; body?: unknown } | null;
  if (!err || typeof err.body !== "string" || (err.status !== 404 && err.status !== 409)) return null;
  let parsed: { error?: unknown; section?: unknown; org_name?: unknown };
  try {
    parsed = JSON.parse(err.body) as typeof parsed;
  } catch {
    return null;
  }
  if (parsed.error !== "governance_hidden" && parsed.error !== "governance_read_only") return null;
  return {
    code: parsed.error,
    section: typeof parsed.section === "string" ? parsed.section : "",
    orgName: typeof parsed.org_name === "string" && parsed.org_name ? parsed.org_name : "your organization",
  };
}

/** terminalsRefusalSentence is the New Terminal dialog's plain answer for a
 *  route the organization refused, or null for any other error. */
export function terminalsRefusalSentence(e: unknown): string | null {
  const r = governanceRefusalOf(e);
  if (!r) return null;
  if (r.code === "governance_read_only") {
    return `${r.orgName} has made Terminals read-only on this managed machine, so new terminals cannot be started here.`;
  }
  return `${r.orgName} has hidden Terminals on this managed machine, so this dialog cannot list tools or start terminals. Ask your organization if you need them.`;
}
