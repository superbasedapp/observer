import { useContext } from "react";
import { HelpInd } from "@/components/HelpInd";
import { Button, Pill } from "@/components/primitives";
import type { AssessRun } from "@/lib/secAssess";
import {
  HONEST_LIMITS,
  probeIndex,
  probeLogNote,
  plural,
  type AssessModelResponse,
} from "@/lib/secAssessModel";
import { retestNotLabelled, retestRows, retestSummaryLine, type RetestRow } from "@/lib/secAssessRetest";
import { AssessRetestContext } from "./AssessRetestLabel";
import { ProbeCard } from "./FindingEvidence";
import { AgentText, SubHeading } from "./modelParts";

// AssessRetestView is a retest run's own view (depth plan W7.2, decision D38:
// labels only): a model view with the results of one retest, what it replayed
// and how it was checked. A retest repeats the stored request of findings
// from an earlier penetration test or red team run once, in a copy of the
// project in a box, and labels each finding reproduced, not reproduced or
// inconclusive. The view says once, in the limit printed above its results,
// what a retest is and that nothing was closed and no finding changed (N-12):
// the label belongs on the finding of the earlier run, which the finding's row
// shows. A label of "not reproduced" is a neutral one and never worded as a
// fix. The agent's note is text, and the
// requests a label cites are the helper's log records, each tagged with the
// finding it replayed.

/** Where the labels of a retest are shown. What a retest is and that it closes nothing are said once, by the limit printed above this line (N-12): a view that said it four times before the first label read as protesting. */
export const RETEST_VIEW_LEAD = "The labels are shown on the findings of the run it replayed.";

/** The words on the button that opens the run a retest replayed. */
export const OPEN_REPLAYED_LABEL = "Open the run it replayed";

/** OpenReplayedButton opens the earlier run this retest replayed, so the sentence that the labels are shown there is a control (N-19). It is offered only when that run is on the list and its model can be opened here; otherwise the sentence stands alone. */
function OpenReplayedButton({ run }: { run: string | undefined }) {
  const ctx = useContext(AssessRetestContext);
  if (!run || !ctx.open || !ctx.canOpen(run)) return null;
  const open = ctx.open;
  return (
    <div>
      <Button size="sm" variant="secondary" data-testid="assess-retest-open-replayed" onClick={() => open(run)}>
        {OPEN_REPLAYED_LABEL}
      </Button>
    </div>
  );
}

/** The limit of a retest, printed with its results (limit l20 of the honest limits). It is the one place the view says what a retest is, how a label is read and that nothing was closed. */
const RETEST_LIMIT = HONEST_LIMITS.find((l) => l.id === "l20")?.text ?? "";

/** The finding ids in a sentence, or "none". */
function idList(ids: readonly string[]): string {
  return ids.length === 0 ? "none" : ids.join(", ");
}

/** ResultRow is one finding's label in the results table. */
function ResultRow({ r }: { r: RetestRow }) {
  return (
    <tr className="border-b border-line-1 align-top last:border-b-0" data-testid="assess-retest-result" data-finding-id={r.finding}>
      <td className="min-w-0 px-3 py-2">
        <code className="font-mono text-[11px] text-fg-3">{r.finding}</code>
        <div className="break-words font-medium text-fg-1">{r.title}</div>
      </td>
      <td className="min-w-0 px-3 py-2 text-fg-2">{r.categoryTitle}</td>
      <td className="whitespace-nowrap px-3 py-2" data-testid="assess-retest-result-label">
        <Pill variant={r.label.tone} case="none">
          {r.label.label}
        </Pill>
      </td>
      <td className="min-w-0 space-y-1 px-3 py-2" data-testid="assess-retest-result-evidence">
        {r.evidence ? (
          <>
            <Pill variant={r.evidence.tone} case="none">
              {r.evidence.label}
            </Pill>
            <div className="break-words text-[11.5px] text-fg-3">{r.evidence.detail}</div>
          </>
        ) : (
          <span className="text-fg-3">No log reading: an inconclusive label claims nothing.</span>
        )}
      </td>
      <td className="min-w-0 px-3 py-2">{r.note ? <AgentText className="text-fg-2">{r.note}</AgentText> : <span className="text-fg-3">The agent wrote no note.</span>}</td>
      <td className="min-w-0 px-3 py-2 text-[11.5px] text-fg-2">
        {r.cited.length === 0 ? (
          <span className="text-fg-3">none cited</span>
        ) : (
          <span className="break-words font-mono">{r.cited.map((c) => c.id).join(", ")}</span>
        )}
      </td>
    </tr>
  );
}

/** RetestResults is the Results tab of a retest run: what it is, the count line, the table of labels and the helper's log records the labels cite. */
export function RetestResults({ data, run }: { data: AssessModelResponse; run: Pick<AssessRun, "retest_findings"> & Partial<Pick<AssessRun, "retest_of">> }) {
  const rt = data.record.result.rt;
  const summary = data.record.result.report.rt;
  const rows = retestRows(rt, data.vocab);
  const line = retestSummaryLine(summary);
  const missing = retestNotLabelled(run.retest_findings, rt);
  const byId = probeIndex(data.probes);
  const truncated = data.probe_log?.truncated === true;
  if (!rt) return null;
  return (
    <div className="min-w-0 space-y-4" data-testid="assess-retest-view">
      <div className="space-y-1.5 rounded-2 border border-line-2 bg-bg-2 px-3 py-2" data-testid="assess-retest-lead">
        <p className="m-0 text-[12px] text-fg-1" data-testid="assess-retest-limit">
          {RETEST_LIMIT}
        </p>
        <p className="m-0 text-[11.5px] text-fg-2">{RETEST_VIEW_LEAD}</p>
        <OpenReplayedButton run={run.retest_of} />
      </div>

      <div className="space-y-1.5">
        <div className="flex items-center">
          <SubHeading>Labels</SubHeading>
          <HelpInd id="card.code_security_assess_retest" />
        </div>
        {/* The five counts in one sentence: the same numbers as a row of tiles beside it said it all twice (N-12). */}
        {line && (
          <p className="m-0 text-[12px] text-fg-1" data-testid="assess-retest-summary-line">
            {line}
          </p>
        )}
        <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-retest-started">
          {rt.started ? "The agent says the target started." : "The agent says the target did not start, so no label is backed by the helper's log."}
        </p>
      </div>

      <div className="space-y-1.5">
        <SubHeading>Results</SubHeading>
        {rows.length === 0 ? (
          <p className="m-0 text-[12px] text-fg-2" data-testid="assess-retest-empty">
            The agent labelled no finding. That says nothing about the findings: none was replayed to a label.
          </p>
        ) : (
          <div tabIndex={0} role="region" aria-label="Results of the retest" className="overflow-x-auto rounded-3 border border-line-2 bg-bg-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]">
            <table className="w-full min-w-[820px] border-collapse text-left text-[12px]" data-testid="assess-retest-table">
              <thead>
                <tr className="border-b border-line-2 text-[11.5px] text-fg-3">
                  {["Finding", "Category", "Label", "Observer's reading of the log", "The agent's note", "Requests cited"].map((h) => (
                    <th key={h} scope="col" className="px-3 py-2 font-medium">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <ResultRow key={r.finding} r={r} />
                ))}
              </tbody>
            </table>
          </div>
        )}
        {missing.length > 0 && (
          <p className="m-0 text-[11.5px] text-warn" data-testid="assess-retest-missing">
            {`The agent gave no label for ${idList(missing)}, so nothing was labelled for ${plural(missing.length, "it", "them")} and nothing was closed.`}
          </p>
        )}
      </div>

      {rows.some((r) => r.cited.length > 0) && (
        <div className="space-y-2" data-testid="assess-retest-probes">
          <SubHeading>Requests in the helper log</SubHeading>
          <p className="m-0 text-[11.5px] text-fg-3">What the helper wrote down about each request a label names. The log is a file the agent can write.</p>
          {rows
            .filter((r) => r.cited.length > 0)
            .map((r) => (
              <div key={r.finding} className="space-y-1.5" data-testid="assess-retest-probe-group" data-finding-id={r.finding}>
                <p className="m-0 text-[12px] font-medium text-fg-1">{`${r.finding}: ${r.title}`}</p>
                <div className="grid gap-2 lg:grid-cols-2">
                  {r.cited.map((c) => {
                    const rec = byId.get(c.id);
                    return rec ? (
                      <ProbeCard key={c.id} p={rec} role={c.role} vocab={data.vocab} />
                    ) : (
                      <div key={c.id} className="min-w-0 rounded-2 border border-dashed border-line-2 bg-bg-2 p-2 text-[11.5px] text-fg-2" data-testid="assess-probe-missing" data-probe-id={c.id}>
                        <code className="font-mono text-[11px] text-fg-3">{c.id}</code>
                        {truncated ? ": not shown in this answer." : ": not in the log."}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          {truncated && <p className="m-0 text-[11.5px] text-fg-3">{probeLogNote(data.probe_log)}</p>}
        </div>
      )}
    </div>
  );
}

/** RetestReplayed is the "Replayed" tab of a retest run: the findings it was asked for and what the agent said about the run. */
export function RetestReplayed({ data, run }: { data: AssessModelResponse; run: Pick<AssessRun, "retest_findings"> }) {
  const rt = data.record.result.rt;
  if (!rt) return null;
  const asked = run.retest_findings ?? [];
  const labelled = new Map((rt.results ?? []).map((r) => [r.finding, r] as const));
  const own = (rt.limits ?? []).filter((s) => typeof s === "string" && s !== "");
  return (
    <div className="min-w-0 space-y-4" data-testid="assess-retest-replayed">
      <div className="space-y-1.5">
        <SubHeading>Findings it was asked to replay</SubHeading>
        {asked.length === 0 ? (
          <p className="m-0 text-[12px] text-fg-3">The run records no list of findings.</p>
        ) : (
          <ul className="m-0 list-none space-y-1 p-0 text-[12px]" aria-label="Findings it was asked to replay">
            {asked.map((id) => {
              const r = labelled.get(id);
              return (
                <li key={id} className="min-w-0 break-words text-fg-2" data-testid="assess-retest-asked" data-finding-id={id}>
                  <code className="font-mono text-[11px] text-fg-3">{id}</code>
                  {r?.title ? <span className="text-fg-1">{` ${r.title}`}</span> : null}
                  {r ? null : <span className="text-fg-3">{" (no label was given)"}</span>}
                </li>
              );
            })}
          </ul>
        )}
        <p className="m-0 text-[11.5px] text-fg-3">The requests are the ones stored with each finding when the earlier run was checked. The agent did not choose them, and its own words about the earlier findings were not used.</p>
      </div>
      <div className="space-y-1">
        <SubHeading agent>The agent says</SubHeading>
        {rt.summary ? <AgentText>{rt.summary}</AgentText> : <p className="m-0 text-[11.5px] text-fg-3">The agent wrote no summary.</p>}
      </div>
      {own.length > 0 && (
        <div className="space-y-1">
          <SubHeading agent>The agent&apos;s own limits</SubHeading>
          <ul className="m-0 list-disc space-y-0.5 pl-5 text-[12px] text-fg-1">
            {own.map((s, i) => (
              <li key={i} className="min-w-0 whitespace-pre-wrap break-words">
                {s}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
