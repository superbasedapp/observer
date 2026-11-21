// AdmissionMarkPill draws a trace's admission decision (FX-C, B-1 / U-20)
// as the ADMISSION_DECISION vocab chip, on the Traces list and in the trace
// inspector. Nothing renders for a trace without verdicts.

import { VocabDefPill } from "@shared/primitives/VocabDefPill";
import { ADMISSION_DECISION } from "@shared/lib/obsVocab";
import { admissionChip, type AdmissionMark } from "@/lib/admissionMark";

export function AdmissionMarkPill({ mark, withCriterion }: { mark?: AdmissionMark | null; withCriterion?: boolean }) {
  const chip = admissionChip(mark);
  if (!chip) return null;
  return (
    <span className="inline-flex items-center gap-1" data-testid="trace-admission">
      <VocabDefPill of={ADMISSION_DECISION} value={chip.value} title={chip.title} />
      {withCriterion && mark?.criterion_id && <span className="text-[12px] text-fg-3">{mark.criterion_id}</span>}
    </span>
  );
}
