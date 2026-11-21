// admissionMark: the admission decision a trace row carries (FX-C, B-1 /
// U-20). GET /api/obs/traces and /api/obs/trace/{id} return `admission` on a
// trace that has verdicts: its most restrictive one (internal/admissionmark).
// A denied trace's status is "ok" (nothing failed), so this chip is what says
// admission stopped it. Pure: the pill lives in
// components/apps/AdmissionMarkPill.tsx.

/** AdmissionMark mirrors internal/admissionmark.Mark. */
export interface AdmissionMark {
  decision: string;
  criterion_id?: string;
  mode?: string;
  count: number;
}

export type AdmissionChipValue = "allow" | "flag" | "ask" | "would_block" | "deny";

const BLOCKING = new Set(["ask", "deny"]);

/** admissionChip maps a mark to its ADMISSION_DECISION value and a tooltip.
 *  A blocking decision made in observe mode did not block, so it reads
 *  "would block". null when there is no mark. */
export function admissionChip(m: AdmissionMark | null | undefined): { value: AdmissionChipValue | string; title: string } | null {
  if (!m || !m.decision) return null;
  const observed = m.mode === "observe" && BLOCKING.has(m.decision);
  const value = observed ? "would_block" : m.decision;
  const parts = [observed ? `Admission would have answered ${m.decision} (observe mode, not enforced)` : `Admission answered ${m.decision}`];
  if (m.criterion_id) parts.push(`criterion ${m.criterion_id}`);
  if (m.count > 1) parts.push(`${m.count} verdicts on this trace`);
  return { value, title: parts.join(", ") + "." };
}
