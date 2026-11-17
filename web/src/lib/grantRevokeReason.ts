// grantRevokeReason.ts - how the node reads the reason an organization stored
// when it ended a grant (round-3 demo wording). The org server records an
// extension as a revoke of the old grant with the reason "superseded by G-<n>";
// a developer reads that as the grant being REPLACED, not taken away. This is
// the one place the node maps a stored revoke reason to words; every surface
// that shows one goes through it. Pure: no React, no fetch.

/** REPLACED_BY matches exactly the reason an extension leaves on the grant
 *  it replaced: "superseded by G-<n>" as stored today, or "replaced by G-<n>"
 *  from a server that words it so (the same table as Go's
 *  accessgrant.ReplacedBy). */
const REPLACED_BY = /^(?:superseded|replaced) by (G-\d+)$/;

/** replacedBy is the grant that replaced this one ("G-6"), or undefined when
 *  the reason is anything else. */
export function replacedBy(reason: string | undefined): string | undefined {
  const m = reason ? REPLACED_BY.exec(reason.trim()) : null;
  return m ? m[1] : undefined;
}

/** revokeReasonWords is a stored revoke reason as the developer reads it:
 *  "superseded by G-6" reads "replaced by G-6"; any other reason is shown as
 *  the admin wrote it. */
export function revokeReasonWords(reason: string): string {
  const by = replacedBy(reason);
  return by ? `replaced by ${by}` : reason;
}
