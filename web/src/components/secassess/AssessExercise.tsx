import type { ReactNode } from "react";
import { Pill } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { useMediaQuery } from "@/lib/useMediaQuery";
import { EXERCISE_STOP_NOTE, HONEST_LIMITS, type PentestDoc } from "@/lib/secAssessModel";
import { CHAIN_EMPTY_WORDS, CHAIN_NO_FINDING, CHAIN_NO_STOP, CHAIN_STOP_HEADING, chainCountsLine, chainRows, objectiveReading, type ChainRow } from "@/lib/secAssessRetest";
import { NARROW_QUERY } from "./ExportMenu";
import { AgentText, SubHeading } from "./modelParts";

// AssessExercise is the Exercise tab of a red team model (depth plan W7.3,
// decision D38): the objective with whose it is, the steps of the chain in the
// order the agent listed them, and what a red team run is not. It is built
// from the model's structure, never from the agent's report: the only text
// of the agent's on the tab is the objective (when it is the agent's), each
// step and each opinion, every one a text node. What would have detected or
// stopped a step is the agent's opinion, headed as one, with the sentence that
// Observer did not test any of it printed beside it. There is no technique
// table and no list of objectives: the agent's words are shown as the agent's.
//
// On a phone (below NARROW_QUERY) five columns do not fit and the table
// scrolled sideways, with the result and the opinion off-screen until panned
// (N-18). There each step is one block, in the same order, with the same
// headings, so every heading still says whose words follow it: "as the agent
// says" on the step and the result, "the agent's opinion" on what would have
// stopped it. A wider window keeps the table.

/** l18 is the honest limit of a red team run, printed on the tab. */
const RED_TEAM_LIMIT = HONEST_LIMITS.find((l) => l.id === "l18")?.text ?? "";

/** The headings of the step's parts, for the table's columns and for each part of a block. */
const STEP_HEADING = "What was done, as the agent says";
const FINDING_HEADING = "Finding used";
const RESULT_HEADING = "Result, as the agent says";

/** StepFinding is the finding a step used by id and title, or the words that it used none. */
function StepFinding({ r }: { r: ChainRow }) {
  return r.finding ? (
    <>
      <code className="font-mono text-[11px] text-fg-3">{r.finding.id}</code>
      <div className="break-words text-fg-1">{r.finding.title}</div>
    </>
  ) : (
    <span className="text-fg-3">{CHAIN_NO_FINDING}</span>
  );
}

/** StepResult is the result of a step as a word. */
function StepResult({ r }: { r: ChainRow }) {
  return (
    <Pill variant={r.result.tone} case="none">
      {r.result.label}
    </Pill>
  );
}

/** StepStop is what the agent says would have stopped a step, or the words that it said nothing. */
function StepStop({ r }: { r: ChainRow }) {
  return r.stop ? <AgentText className="text-fg-2">{r.stop}</AgentText> : <span className="text-fg-3">{CHAIN_NO_STOP}</span>;
}

/** Part is one headed part of a step's block. */
function Part({ heading, testId, children }: { heading: string; testId?: string; children: ReactNode }) {
  return (
    <div className="min-w-0 space-y-0.5" data-testid={testId}>
      <div className="text-[11px] font-medium text-fg-3">{heading}</div>
      {children}
    </div>
  );
}

/** StepBlocks is the steps as one block each, for a phone: nothing in it scrolls sideways. */
function StepBlocks({ rows }: { rows: ChainRow[] }) {
  return (
    <ol className="m-0 list-none space-y-2 p-0" aria-label="Steps of the exercise" data-testid="assess-exercise-blocks">
      {rows.map((r) => (
        <li key={r.n} className="min-w-0 space-y-2 rounded-3 border border-line-2 bg-bg-2 px-3 py-2 text-[12px]" data-testid="assess-exercise-step" data-step={r.n}>
          <div className="font-mono text-[11px] text-fg-3">Step {r.n}</div>
          <Part heading={STEP_HEADING}>
            <AgentText>{r.step}</AgentText>
          </Part>
          <Part heading={FINDING_HEADING} testId="assess-exercise-finding">
            <StepFinding r={r} />
          </Part>
          <Part heading={RESULT_HEADING} testId="assess-exercise-result">
            <StepResult r={r} />
          </Part>
          <Part heading={CHAIN_STOP_HEADING} testId="assess-exercise-stop">
            <StepStop r={r} />
          </Part>
        </li>
      ))}
    </ol>
  );
}

/** StepTable is the steps as a table, for a window wide enough for its five columns. */
function StepTable({ rows }: { rows: ChainRow[] }) {
  return (
    <div tabIndex={0} role="region" aria-label="Steps of the exercise" className="overflow-x-auto rounded-3 border border-line-2 bg-bg-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]">
      <table className="w-full min-w-[640px] border-collapse text-left text-[12px]" data-testid="assess-exercise-table">
        <thead>
          <tr className="border-b border-line-2 text-[11.5px] text-fg-3">
            <th scope="col" className="w-10 px-3 py-2 font-medium">
              Step
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              {STEP_HEADING}
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              {FINDING_HEADING}
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              {RESULT_HEADING}
            </th>
            <th scope="col" className="px-3 py-2 font-medium" data-testid="assess-exercise-stop-heading">
              {CHAIN_STOP_HEADING}
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.n} className="border-b border-line-1 align-top last:border-b-0" data-testid="assess-exercise-step" data-step={r.n}>
              <td className="px-3 py-2 font-mono text-[11px] text-fg-3">{r.n}</td>
              <td className="min-w-0 px-3 py-2">
                <AgentText>{r.step}</AgentText>
              </td>
              <td className="min-w-0 px-3 py-2" data-testid="assess-exercise-finding">
                <StepFinding r={r} />
              </td>
              <td className="px-3 py-2" data-testid="assess-exercise-result">
                <StepResult r={r} />
              </td>
              <td className="min-w-0 px-3 py-2" data-testid="assess-exercise-stop">
                <StepStop r={r} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function AssessExercise({
  pt,
  narrow: narrowOverride,
}: {
  pt: Pick<PentestDoc, "exercise" | "findings">;
  /** Force the phone layout (true) or the table (false), instead of reading the window's width. */
  narrow?: boolean;
}) {
  const measured = useMediaQuery(NARROW_QUERY);
  const narrow = narrowOverride ?? measured;
  const objective = objectiveReading(pt.exercise);
  const rows = chainRows(pt);
  const counts = chainCountsLine(rows);
  return (
    <div className="min-w-0 space-y-4" data-testid="assess-exercise">
      <div className="space-y-1.5" data-testid="assess-exercise-objective" data-source={objective.source}>
        <div className="flex items-center">
          <SubHeading agent={objective.source === "agent"}>Objective</SubHeading>
          <HelpInd id="card.code_security_assess_exercise" />
        </div>
        <p className="m-0 flex flex-wrap items-center gap-2 text-[12px]">
          <Pill variant={objective.source === "developer" ? "accent" : "neutral"} case="none">
            {objective.sourceLabel}
          </Pill>
        </p>
        {objective.text !== "" && <AgentText>{objective.text}</AgentText>}
      </div>

      <div className="space-y-2" data-testid="assess-exercise-chain">
        <SubHeading agent>The steps, in the order the agent lists them</SubHeading>
        {counts && (
          <p className="m-0 text-[11.5px] text-fg-2" data-testid="assess-exercise-counts">
            {counts}
          </p>
        )}
        {rows.length === 0 ? (
          <p className="m-0 text-[12px] text-fg-2" data-testid="assess-exercise-empty">
            {CHAIN_EMPTY_WORDS}
          </p>
        ) : narrow ? (
          <StepBlocks rows={rows} />
        ) : (
          <StepTable rows={rows} />
        )}
        <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-exercise-stop-note">
          {EXERCISE_STOP_NOTE}
        </p>
      </div>

      <div className="space-y-1" data-testid="assess-exercise-limit">
        <SubHeading>What this exercise is not</SubHeading>
        <p className="m-0 text-[12px] text-fg-2">{RED_TEAM_LIMIT}</p>
      </div>
    </div>
  );
}
