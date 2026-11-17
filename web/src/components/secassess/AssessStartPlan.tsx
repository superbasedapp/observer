import { Button, Input } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import {
  ASSESS_NONE,
  ASSESS_PREPARE_LABEL,
  ASSESS_PREPARE_WARNING,
  assessPrepareOn,
  assessPrepareSteps,
  assessStartChoice,
  assessStartInForce,
  assessStartLine,
  assessStartNoneWords,
  assessTypeLabel,
  assessStartPlanDetails,
  assessStartText,
  type AssessStart,
} from "@/lib/secAssess";

// AssessStartPlan is how a penetration test or red team starts the
// application (docs/plans/security-assessments-depth-plan-2026-11-14.md W4.1):
// the commands Observer read from the project's own files, most likely first,
// and a field for the developer's own. A command is a list of words with no
// shell, so one that needs quoting cannot be written here; the field says to
// start it yourself and tell the agent. Observer reads files, it does not start
// anything: the agent is told the command, and runs it in the sandbox.
//
// A plan is picked by its `choice` (a plan that runs in a subfolder has its own
// choice string, and the row says which folder), not by its command.
//
// A plan can come with preparation steps (a migrate, a seed). They can change
// local data in the project, for example its database file, so they run only
// when the developer ticks the box under the selected plan: it starts unticked,
// and picking another plan clears it, because the steps belong to one plan.
//
// The text in the field follows the server's effective command until the
// developer types; "Use this command" is the one click that applies it, and the
// dialog's button waits for it, so a command typed and not used is never
// silently dropped.

export function AssessStartPlan({
  start,
  chosen,
  draft,
  locked,
  prepare,
  onChoose,
  onDraft,
  onUse,
  onPrepare,
  note,
}: {
  start: AssessStart;
  /** The developer's choice: a plan's choice, a typed command, ASSESS_NONE, or undefined when the server's pick stands. */
  chosen: string | undefined;
  /** The text being typed; undefined follows the command in force. */
  draft: string | undefined;
  locked: boolean;
  /** The developer's tick of the preparation steps; undefined follows what the server echoes (off unless a held run chose it). */
  prepare?: boolean;
  /** A plan's choice, or ASSESS_NONE. */
  onChoose: (choice: string) => void;
  onDraft: (text: string) => void;
  /** Apply the typed text (empty means no declared command). */
  onUse: (text: string) => void;
  /** Tick or untick the selected plan's preparation steps. */
  onPrepare?: (on: boolean) => void;
  /** The server's sentence for a project with no readable start command (the preflight note), said here and nowhere else. */
  note?: string;
}) {
  const inForce = assessStartInForce(start, chosen);
  const inForceText = assessStartText(start, chosen);
  const text = draft ?? inForceText;
  const dirty = draft !== undefined && draft.trim() !== inForceText.trim();
  const steps = assessPrepareSteps(start, chosen);
  const prepareOn = assessPrepareOn(start, chosen, prepare);
  // With no command to start from, one sentence says so; the start line (which says the same) waits for a command.
  const none = assessStartNoneWords(start, note);
  return (
    <section aria-labelledby="assess-start-h" className="space-y-2" data-testid="assess-start">
      <h3 id="assess-start-h" className="m-0 flex items-center text-[12px] font-medium text-fg-2">
        How the application starts
        <HelpInd id="card.code_security_assess_start" />
      </h3>

      {start.plans.length > 0 && (
        <ul className="m-0 list-none space-y-1 p-0" aria-label="Start commands read from the project">
          {start.plans.map((p, i) => {
            const choice = assessStartChoice(p);
            const selected = inForce !== "" && choice === inForce;
            return (
              <li key={`${i}-${choice}`}>
                <label className="flex cursor-pointer items-start gap-2 rounded-2 border border-line-2 px-2.5 py-1.5">
                  <input
                    type="radio"
                    name="assess-start-plan"
                    className="mt-0.5"
                    checked={selected}
                    disabled={locked}
                    onChange={() => onChoose(choice)}
                    data-testid={`assess-start-plan-${i}`}
                  />
                  <span className="min-w-0 space-y-0.5">
                    <span className="block break-all font-mono text-[11.5px] text-fg-1">{p.command}</span>
                    {assessStartPlanDetails(p, selected).map((d) => (
                      <span key={d} className="block break-words text-[11.5px] text-fg-3">
                        {d}
                      </span>
                    ))}
                  </span>
                </label>
                {selected && steps.length > 0 && (
                  <div className="ml-6 mt-1 space-y-1 rounded-2 border border-warn/40 bg-warn/10 px-2.5 py-1.5" data-testid="assess-prepare">
                    <label className="flex cursor-pointer items-start gap-2">
                      <input
                        type="checkbox"
                        className="mt-0.5"
                        checked={prepareOn}
                        disabled={locked || !onPrepare}
                        onChange={(e) => onPrepare?.(e.target.checked)}
                        data-testid="assess-prepare-check"
                      />
                      <span className="text-fg-1">{ASSESS_PREPARE_LABEL}</span>
                    </label>
                    <ul className="m-0 list-none space-y-0.5 p-0" aria-label="Preparation steps" data-testid="assess-prepare-steps">
                      {steps.map((s) => (
                        <li key={s} className="break-all font-mono text-[11.5px] text-fg-1">
                          {s}
                        </li>
                      ))}
                    </ul>
                    <p className="m-0 break-words text-[11.5px] text-fg-2">{ASSESS_PREPARE_WARNING}</p>
                  </div>
                )}
              </li>
            );
          })}
          <li>
            <label className="flex cursor-pointer items-start gap-2 rounded-2 border border-line-2 px-2.5 py-1.5">
              <input
                type="radio"
                name="assess-start-plan"
                className="mt-0.5"
                checked={inForce === ""}
                disabled={locked}
                onChange={() => onChoose(ASSESS_NONE)}
                data-testid="assess-start-none"
              />
              <span className="text-fg-2">No declared command: the agent looks for one itself</span>
            </label>
          </li>
        </ul>
      )}

      {none !== "" && (
        <p className="m-0 break-words text-fg-2" data-testid="assess-start-none-found">
          {none}
        </p>
      )}

      {!locked && (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (dirty) onUse(text);
          }}
        >
          <div className="min-w-0 flex-1 basis-56">
            <Input
              mono
              label={assessTypeLabel("the command", start.plans.length > 0)}
              placeholder="npm run dev"
              value={text}
              onChange={(e) => onDraft(e.target.value)}
              help="At most 8 words of letters, digits and . _ / : = @ + , - with no quotes or pipes. If yours needs more, start it yourself and tell the agent."
              data-testid="assess-start-input"
            />
          </div>
          <Button type="submit" size="sm" variant="secondary" disabled={!dirty}>
            Use this command
          </Button>
        </form>
      )}
      {start.error && (
        <p role="alert" className="m-0 break-words text-danger" data-testid="assess-start-error">
          {start.error}
        </p>
      )}
      {none === "" && (
        <p className="m-0 break-words text-fg-2" data-testid="assess-start-line">
          {assessStartLine(start)}
        </p>
      )}
    </section>
  );
}
