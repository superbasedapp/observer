// The Policies apply rule and error wording, kept free of imports so the
// node test runner can load it (src/lib/policiesApplyRule.test.ts).

// ADMISSION_APPLY_PERSISTS is the U-27 rule (UI review 2026-11-21): applying
// an admission policy from the dashboard always saves it to config too. A
// live-only apply was silently lost on the next daemon restart, from any
// page. When the save fails, /admission/status reports live_unsaved, the
// page shows it and the restart confirm names it.
export const ADMISSION_APPLY_PERSISTS = true;

/** policyPostUrl is the POST target for a policy apply; persist adds the
 *  write-through flag the daemon reads (?persist=1). */
export function policyPostUrl(path: string, persist: boolean): string {
  return persist ? `${path}?persist=1` : path;
}

// ADMISSION_OFF_TEXT is what a policy action says when admission checks are
// off on this machine (UI review U-13: the page showed a raw "api 404
// /api/obs/admission/policy: admission not enabled" toast).
export const ADMISSION_OFF_TEXT = "Admission checks are off on this machine. Turn them on from the Overview tab of Policies.";

// POLICY_ERROR_TEXT words a failed policy request by HTTP status, first
// matching row wins. The page never shows an API error's own text (U-13).
export const POLICY_ERROR_TEXT: ReadonlyArray<{ match: (status: number) => boolean; text: string }> = [
  { match: (s) => s === 404, text: ADMISSION_OFF_TEXT },
  { match: (s) => s === 409, text: "Your organization's policy is in force on this machine, so a local change is not applied." },
  { match: (s) => s === 401 || s === 403, text: "This view cannot change policies. Open the dashboard on the machine itself." },
  { match: (s) => s >= 500, text: "The daemon could not apply the change. Try again; if it repeats, check Settings > Health." },
];

/** policyStatusText words a policy request that failed with this HTTP
 *  status. */
export function policyStatusText(status: number): string {
  const row = POLICY_ERROR_TEXT.find((r) => r.match(status));
  return row ? row.text : "The daemon refused the change. Reload the page and try again.";
}

/** NO_ANSWER_TEXT words a policy request that got no HTTP answer at all. */
export const NO_ANSWER_TEXT = "Could not reach the daemon. Check that it is running, then try again.";

// ADMISSION_STARTS_NEXT_TEXT is what the page says when admission is set up
// but only starts at the next daemon start (the daemon was started with it
// off, FR-M01).
export const ADMISSION_STARTS_NEXT_TEXT =
  "Admission checks are turned on and start the next time the daemon starts. Until then your app's requests are not checked.";

/** AdmissionCard is which card the Policies page shows over its tabs:
 *  "off" offers to turn checks on, "starts_next" says they are on and wait
 *  for the next daemon start (never the off card), "none" shows neither. */
export type AdmissionCard = "off" | "starts_next" | "none";

/** admissionCard resolves the status read to its card. The pending flag
 *  wins over "available is false": the daemon says admission is not running
 *  yet, not that it is off. */
export function admissionCard(s: { available?: boolean; pending_next_start?: boolean } | undefined): AdmissionCard {
  if (s?.pending_next_start === true) return "starts_next";
  return s?.available === false ? "off" : "none";
}
