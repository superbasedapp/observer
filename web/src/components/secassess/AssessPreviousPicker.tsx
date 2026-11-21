import { HelpInd } from "@/components/HelpInd";
import { Select } from "@/components/primitives";
import { fmtDateTime } from "@/lib/format";
import { ASSESS_NONE, assessPreviousLine, assessPreviousNote, assessPreviousOptionLabel, type AssessPrevious } from "@/lib/secAssess";

// AssessPreviousPicker is the comparison with an earlier threat model (docs/
// plans/security-assessments-depth-plan-2026-11-14.md W3.4): which earlier
// checked run of the project the new model is compared with once it has been
// checked. The choice is Observer's own comparison. Observer puts nothing from
// the earlier run in the task and the task asks the agent not to open other
// runs' folders; that is a request, not a barrier (an earlier run's files stay
// in the project's .observer/assessments folder), and the sentence under the
// picker says so (the server's, or assessPreviousNote's own when it sends
// none). The server picks a default (the newest); choosing here is a new plan
// read.

export function AssessPreviousPicker({
  previous,
  chosen,
  locked,
  onChange,
}: {
  previous: AssessPrevious;
  /** The developer's choice: a run id, ASSESS_NONE, or undefined when the server's pick stands. */
  chosen: string | undefined;
  locked: boolean;
  onChange: (run: string) => void;
}) {
  const value = chosen !== undefined && chosen !== "" ? chosen : previous.selected || ASSESS_NONE;
  return (
    <section aria-labelledby="assess-previous-h" className="space-y-1.5" data-testid="assess-previous">
      <h3 id="assess-previous-h" className="m-0 flex items-center text-[12px] font-medium text-fg-2">
        Compare with an earlier run
        <HelpInd id="card.code_security_assess_previous" />
      </h3>
      {previous.options.length > 0 && (
        <Select
          label="Earlier threat model of this project that was checked"
          value={value}
          disabled={locked}
          onChange={(e) => onChange(e.target.value)}
          data-testid="assess-previous-select"
        >
          <option value={ASSESS_NONE}>No comparison</option>
          {previous.options.map((o) => (
            <option key={o.id} value={o.id}>
              {assessPreviousOptionLabel(o, fmtDateTime)}
            </option>
          ))}
        </Select>
      )}
      <p className="m-0 break-words text-fg-2" data-testid="assess-previous-line">
        {assessPreviousLine(previous, fmtDateTime)}
      </p>
      <p className="m-0 break-words text-[11.5px] text-fg-3" data-testid="assess-previous-note">
        {assessPreviousNote(previous)}
      </p>
    </section>
  );
}
