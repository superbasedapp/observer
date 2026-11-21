// codeSecurityExplain - the pure half of the Findings tab's Explain button
// (component security.feedback; security pillar plan section 5.11 (b),
// lane sec-h). POST /api/security/findings/{id}/explain asks the configured
// judge for an advisory explanation of one finding; it changes nothing on
// the finding. The button shows only while security.feedback is SELECTED
// (GET /api/components/state's security_selected, the daemon's one opt-in
// rule): an unknown selection shows no button (fail closed).
//
// "Suggest a fix" is the same route with the body {"fix":true} (the
// dashboard form of `observer security explain --fix`, OS and CI plan
// section 14.8): the judge also gets the rule's fix hint and, for a
// dependency finding, the installed and smallest fixed versions (versions
// only, never advisory prose). Same caps, advisory label and judge routing;
// it changes nothing on the finding either.

/** The component that owns the explain flow. */
export const EXPLAIN_COMPONENT = "security.feedback";

/** POST /api/security/findings/{id}/explain's answer (dashapi.SecurityExplanation). */
export type SecurityExplanation = {
  available: boolean;
  text?: string;
  advisory: boolean;
  label?: string;
  reason?: string;
  model?: string;
  hosting?: string;
};

/** explainVisible reports whether the Explain button shows. */
export function explainVisible(selected: readonly string[] | null | undefined): boolean {
  return Boolean(selected && selected.includes(EXPLAIN_COMPONENT));
}

/** explainPath is the route for one finding id (the id is path-escaped). */
export function explainPath(id: string): string {
  return `/api/security/findings/${encodeURIComponent(id)}/explain`;
}

/**
 * explainView is what the tab shows for an answer: the text with its
 * advisory label, or the honest reason there is none. The text is shown as
 * plain text (never HTML), so a judge answer cannot inject markup.
 */
export function explainView(ex: SecurityExplanation): { body: string; note: string } {
  if (!ex.available || !ex.text) {
    return { body: ex.reason || "No explanation is available.", note: "" };
  }
  const who = [ex.model, ex.hosting].filter(Boolean).join(", ");
  const label = ex.label || "Advisory: it does not change this finding.";
  return { body: ex.text, note: who ? `${label} (${who})` : label };
}

/** The two asks the drawer offers. */
export type ExplainMode = "explain" | "fix";

/** explainBody is the POST body for a mode: {"fix":true} only for a fix suggestion. */
export function explainBody(mode: ExplainMode): { fix?: true } {
  return mode === "fix" ? { fix: true } : {};
}

/** explainAskingLabel is the busy button's words for a mode. */
export function explainAskingLabel(mode: ExplainMode): string {
  return mode === "fix" ? "Asking for a fix..." : "Asking the judge...";
}

/** explainHeading heads a shown answer: a fix suggestion says so. */
export function explainHeading(mode: ExplainMode): string {
  return mode === "fix" ? "Suggested fix" : "Explanation";
}
