import { useState } from "react";
import { Input } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { assessNoteDraftFor, type AssessNoteDraft, type AssessObjective } from "@/lib/secAssess";
import { OBJECTIVE_HELP, OBJECTIVE_MAX, clipObjective, objectiveCleanedNote, objectiveCounterLine } from "@/lib/secAssessRetest";

// AssessObjectiveField is the red team's objective on the plan (depth plan
// W7.3): one line in the developer's own words, at most the plan's bound in
// characters, optional. The agent works toward it; left empty the agent states
// an objective of its own, and the model view's Exercise tab says whose the
// objective is. The server cleans what is typed (no line breaks, no backticks)
// and the plan answers with the objective in force, which is shown when it is
// not what was typed.
//
// Like the scope note, what is typed is local until it applies, on Enter or
// when the field loses focus, so the plan (whose task text carries the
// objective) is not read again on every keystroke. The draft follows the
// objective the dialog holds (assessNoteDraftFor), so the field never shows
// one the choices do not hold. The text is counted in characters, not bytes.

export function AssessObjectiveField({
  objective,
  value,
  locked,
  onApply,
}: {
  objective: AssessObjective;
  /** The objective applied so far (what the plan was read with). */
  value: string;
  /** A run held for the organization keeps the objective it was filed with. */
  locked: boolean;
  onApply: (text: string) => void;
}) {
  const [state, setState] = useState<AssessNoteDraft>({ text: value, seen: value });
  // Derived state, as the scope note's: an objective that changed under the field resets it during this render.
  const synced = assessNoteDraftFor(state, value);
  if (synced !== state) setState(synced);
  const draft = synced.text;
  const max = objective.max > 0 ? objective.max : OBJECTIVE_MAX;
  const cleaned = objectiveCleanedNote(value, objective.text);

  function commit() {
    onApply(draft.trim());
  }

  return (
    <section aria-labelledby="assess-objective-h" className="space-y-1.5" data-testid="assess-objective">
      {/* The section's heading is the field's one visible name, so the field carries no label of its own (N-17). The field's accessible name repeats it without the help button's words. */}
      <h3 id="assess-objective-h" className="m-0 flex items-center text-[12px] font-medium text-fg-2">
        Objective (optional)
        <HelpInd id="card.code_security_assess_exercise" />
      </h3>
      <Input
        aria-label="Objective (optional)"
        placeholder="For example: read another user's entries"
        value={draft}
        disabled={locked}
        autoComplete="off"
        onChange={(e) => setState({ text: clipObjective(e.target.value.replace(/[\r\n]+/g, " "), max), seen: synced.seen })}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            commit();
          }
        }}
        help={`${objectiveCounterLine(draft, max)}. ${OBJECTIVE_HELP}`}
        data-testid="assess-objective-input"
      />
      {cleaned && (
        <p className="m-0 break-words text-[11.5px] text-fg-2" data-testid="assess-objective-cleaned">
          {cleaned}
        </p>
      )}
    </section>
  );
}
