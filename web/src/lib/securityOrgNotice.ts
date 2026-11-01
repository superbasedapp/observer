// securityOrgNotice: the pure half of the affected-worker notice (security
// plan 7.12, lane SEC-E3). The body is GET /api/security/org-notice.

export type SecurityOrgNotice = {
  active: boolean;
  shared: string[];
  purpose: string;
  purpose_stated: boolean;
  /** What the organization's views can see under its current settings
   *  (ruling P-089): information, not a privacy promise. */
  org_sees?: string[] | null;
  /** The organization's optional purpose statement, "" unless it shows it. */
  not_for: string;
};

/** securityNoticeLine is the one-line summary: the organization's stated
 *  purpose (or that it has stated none yet), and its purpose statement only
 *  when it chose to show one. */
export function securityNoticeLine(n: SecurityOrgNotice): string {
  const purpose = n.purpose_stated
    ? `Stated purpose: ${n.purpose}.`
    : "Your organization has not stated a purpose for these views yet.";
  return n.not_for ? `${purpose} ${n.not_for}.` : purpose;
}
