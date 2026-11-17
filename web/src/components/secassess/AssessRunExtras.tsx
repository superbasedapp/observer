import { fmtDateTime } from "@/lib/format";
import { assessRunLabel, type AssessRun } from "@/lib/secAssess";
import { runObjectiveLine, runRetestLine } from "@/lib/secAssessRetest";

// AssessRunExtras is the two lines of a run row that only a red team run and a
// retest run have (depth plan W7.2, W7.3): a red team run's objective, clipped
// (the full text is on the model view's Exercise tab), and a retest run's
// earlier run with the number of findings it was asked to replay. Both are
// text nodes: the objective is the developer's own text and no markup is built
// from it. A run with neither renders nothing.

export function AssessRunExtras({ run, runs }: { run: Pick<AssessRun, "objective" | "retest_of" | "retest_findings">; runs: readonly Pick<AssessRun, "id" | "created_at" | "kind_title">[] }) {
  const earlier = run.retest_of ? runs.find((r) => r.id === run.retest_of) : undefined;
  // The earlier run is named the way every other place names a run (assessRunLabel), never by its id.
  const retest = runRetestLine(run, earlier ? assessRunLabel(earlier.kind_title, earlier.created_at, fmtDateTime) : "");
  const objective = runObjectiveLine(run);
  if (!retest && !objective) return null;
  return (
    <div className="space-y-0.5 break-words text-[11.5px] text-fg-3" data-testid="assess-run-exercise">
      {retest && <div data-testid="assess-run-retest-of">{retest}</div>}
      {objective && (
        <div data-testid="assess-run-objective" title={run.objective}>
          {objective}
        </div>
      )}
    </div>
  );
}
