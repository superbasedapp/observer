import { HelpInd } from "@/components/HelpInd";
import { RETEST_NOTHING_CLOSED, wstgTitle, type ModelVocab } from "@/lib/secAssessModel";
import type { AssessRetestPlan } from "@/lib/secAssess";
import {
  RETEST_HIDDEN_CONSEQUENCE,
  RETEST_MAX,
  retestCountLine,
  retestOfKindWords,
  retestPlanFindings,
  retestPlanLine,
  retestPlanNotes,
  retestRefusedWords,
  retestTargetSuggestion,
} from "@/lib/secAssessRetest";

// AssessRetestPlan is the retest's part of the plan (depth plan W7.2, decision
// D38: labels only): which earlier run it replays, the findings the plan chose
// (each with what the earlier run's checked model stored for it: its requests,
// whether it stored a response condition, whether a value in a request was
// hidden), the findings the server refused by name, and the address the earlier
// run used, which is only a suggestion. It decides nothing: the choice was made
// in the picker and the rules are the server's. A retest closes nothing, and the
// block says so.

export function AssessRetestPlanBlock({ retest, vocab }: { retest: AssessRetestPlan; /** The vocabulary of the model answer the retest was started from, for the words of a category. */ vocab?: ModelVocab }) {
  const chosen = retestPlanFindings(retest);
  const refused = retest.refused ?? [];
  const max = retest.max > 0 ? retest.max : RETEST_MAX;
  const suggestion = retestTargetSuggestion(retest);
  return (
    <section aria-labelledby="assess-retest-h" className="space-y-2" data-testid="assess-retest-plan">
      <h3 id="assess-retest-h" className="m-0 flex items-center text-[12px] font-medium text-fg-2">
        What the retest replays
        <HelpInd id="card.code_security_assess_retest" />
      </h3>
      <p className="m-0 text-fg-2" data-testid="assess-retest-plan-line">
        {`The stored requests of findings from an earlier ${retestOfKindWords(retest.of_kind)}. ${retestPlanLine(retest)} ${retestCountLine(chosen.length, max)}.`}
      </p>
      {chosen.some((f) => f.hidden) && (
        <p className="m-0 text-[11.5px] text-warn" data-testid="assess-retest-hidden-once">
          {RETEST_HIDDEN_CONSEQUENCE}
        </p>
      )}
      {chosen.length > 0 && (
        <ul className="m-0 list-none space-y-1.5 p-0" aria-label="Findings the retest replays" data-testid="assess-retest-plan-findings">
          {chosen.map((f) => {
            const notes = retestPlanNotes(f);
            return (
              <li key={f.id} className="min-w-0 rounded-2 border border-line-2 px-2.5 py-1.5" data-testid="assess-retest-plan-finding" data-finding-id={f.id}>
                <div className="flex flex-wrap items-baseline gap-x-2">
                  <code className="font-mono text-[11px] text-fg-3">{f.id}</code>
                  <span className="min-w-0 break-words font-medium text-fg-1">{f.title}</span>
                </div>
                <p className="m-0 break-words text-[11.5px] text-fg-3">
                  {[f.category ? wstgTitle(f.category, vocab) : "", ...notes.slice(0, 2)].filter((x) => x !== "").join(" · ")}
                </p>
                {f.has_condition && f.condition && (
                  <p className="m-0 break-words text-[11.5px] text-fg-3" data-testid="assess-retest-plan-condition">
                    {`Stored condition: ${f.condition}`}
                  </p>
                )}
                {f.hidden && <p className="m-0 break-words text-[11.5px] text-fg-3">{notes[2]}</p>}
              </li>
            );
          })}
        </ul>
      )}
      {refused.length > 0 && (
        <ul className="m-0 list-none space-y-0.5 p-0 text-warn [overflow-wrap:anywhere]" aria-label="Findings that cannot be replayed" data-testid="assess-retest-refused">
          {refused.map((r) => (
            <li key={`${r.finding}:${r.code}`}>{retestRefusedWords(r.code, r.finding, max)}</li>
          ))}
        </ul>
      )}
      {suggestion && (
        <p className="m-0 break-words text-[11.5px] text-fg-3" data-testid="assess-retest-target-note">
          {"The earlier run tested "}
          <span className="font-mono text-fg-2">{suggestion}</span>
          {". It is filled in under Target as a suggestion: use it and tick that it is yours, or type another address."}
        </p>
      )}
      <p className="m-0 text-[11.5px] text-fg-3">{RETEST_NOTHING_CLOSED}</p>
    </section>
  );
}
