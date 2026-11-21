import { useMemo, useState, type ReactNode } from "react";
import { Repeat } from "lucide-react";
import { Button, Modal, TooltipSpan } from "@/components/primitives";
import { RETEST_NOTHING_CLOSED, wstgTitle, type ModelVocab, type PentestDoc } from "@/lib/secAssessModel";
import {
  RETEST_HIDDEN_CHOOSE,
  RETEST_HIDDEN_CONSEQUENCE,
  RETEST_MAX,
  defaultRetestIds,
  retestCandidateNotes,
  retestCandidates,
  retestChosenIds,
  retestCountLine,
  retestGroups,
  retestHiddenCount,
  retestOfferLine,
  toggleRetestId,
  type RetestCandidate,
  type RetestRequest,
} from "@/lib/secAssessRetest";
import type { AssessRun } from "@/lib/secAssess";
import { SubHeading } from "./modelParts";
import { useOverlayEscape } from "./useOverlayEscape";

// The retest picker (depth plan W7.2, decision D38: labels only). From the model
// view of a penetration test or red team run, "Retest findings" lists the
// findings the checked model stored a request for (a reproduction step with a
// method and a path), a checkbox each, and the choice is bounded at the most a
// retest replays. Each finding says what was stored for it: how many requests,
// whether a response condition was stored (without one no label can be backed by
// the log) and whether a stored value was hidden when the finding was kept (so
// the replay may differ from the original request). The findings the replay can
// send in full come first and are the ones chosen to begin with; the ones with a
// hidden value are listed after them with the reason, are not chosen for the
// person, and can still be chosen (a replay without the value can show a weakness
// is there but cannot show it is gone). Choosing opens the retest's
// plan on the same project, where the address of the app is chosen and
// confirmed as for any test: nothing here starts anything, closes a finding or
// changes one. The list is never capped: only the choice is bounded.

/** The sentence at the top of the picker: what a retest does and does not do. */
export const RETEST_PICKER_INTRO =
  "A retest sends the stored requests of the findings you choose again to a fresh copy of your app, and labels each finding reproduced, not reproduced or inconclusive. It closes nothing and changes no finding.";

/** The words of the button that opens the retest's plan. */
export const RETEST_OPEN_PLAN_LABEL = "Open the retest plan";

/** One finding of the picker: a checkbox, the finding and what was stored for it. */
function CandidateRow({ c, checked, vocab, onToggle }: { c: RetestCandidate; checked: boolean; vocab?: ModelVocab; onToggle: (on: boolean) => void }) {
  const notes = retestCandidateNotes(c);
  const cat = c.category === "" ? "" : wstgTitle(c.category, vocab);
  return (
    <li data-testid="assess-retest-choice" data-finding-id={c.id}>
      <label className="flex cursor-pointer items-start gap-2.5 rounded-2 border border-line-2 px-2.5 py-2 hover:bg-bg-2">
        <input type="checkbox" className="mt-0.5 shrink-0" checked={checked} onChange={(e) => onToggle(e.target.checked)} data-testid={`assess-retest-choose-${c.id}`} />
        <span className="min-w-0 flex-1 space-y-0.5">
          <span className="flex flex-wrap items-baseline gap-x-2">
            <code className="font-mono text-[11px] text-fg-3">{c.id}</code>
            <span className="min-w-0 break-words text-[12.5px] font-medium text-fg-1">{c.title}</span>
          </span>
          <span className="block break-words text-[11.5px] text-fg-3">{[cat, ...notes.slice(0, 2)].filter((x) => x !== "").join(" · ")}</span>
          {c.hidden && <span className="block break-words text-[11.5px] text-fg-3">{notes[2]}</span>}
        </span>
      </label>
    </li>
  );
}

/** AssessRetestPicker is the list of findings a retest can replay, with the choice and its count against the bound. */
export function AssessRetestPicker({
  candidates,
  vocab,
  projectHash,
  ofRun,
  onClose,
  onPlan,
}: {
  candidates: RetestCandidate[];
  vocab?: ModelVocab;
  projectHash: string;
  /** The run whose findings are replayed. */
  ofRun: string;
  onClose: () => void;
  /** Opens the retest's plan with the choice. */
  onPlan: (req: RetestRequest) => void;
}) {
  const [chosen, setChosen] = useState<string[]>(() => defaultRetestIds(candidates));
  const [err, setErr] = useState("");
  useOverlayEscape(true, onClose);
  const ids = retestChosenIds(chosen, candidates);
  const { full, hidden } = useMemo(() => retestGroups(candidates), [candidates]);
  // Headings only when there are two groups to tell apart.
  const grouped = full.length > 0 && hidden.length > 0;

  function toggle(id: string, on: boolean) {
    const r = toggleRetestId(ids, id, on, RETEST_MAX);
    setErr(r.error ?? "");
    if (!r.error) setChosen(r.ids);
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Retest findings"
      subtitle="Choose the findings whose stored requests are sent again"
      width={640}
      fullOnPhone
      bodyClassName="px-5 py-4"
      footer={
        <div className="flex w-full flex-wrap items-center justify-between gap-2">
          <p className="m-0 text-[11.5px] text-fg-2" role="status" aria-live="polite" data-testid="assess-retest-count">
            {retestCountLine(ids.length, RETEST_MAX)}
          </p>
          <div className="flex items-center gap-2">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={ids.length === 0} data-testid="assess-retest-open-plan" onClick={() => onPlan({ ofRun, findings: ids, projectHash, vocab })}>
              {RETEST_OPEN_PLAN_LABEL}
            </Button>
          </div>
        </div>
      }
    >
      <div className="space-y-3 text-[12.5px]" data-testid="assess-retest-picker">
        <p className="m-0 text-fg-2">{RETEST_PICKER_INTRO}</p>
        <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-retest-offer">
          {retestOfferLine(candidates.length, RETEST_MAX, hidden.length)}
        </p>
        {err && (
          <p role="alert" className="m-0 text-warn" data-testid="assess-retest-error">
            {err}
          </p>
        )}
        {full.length > 0 && (
          <section className="space-y-1.5" data-testid="assess-retest-full">
            {grouped && <SubHeading>{`Can be sent again in full (${full.length})`}</SubHeading>}
            <ul className="m-0 list-none space-y-1.5 p-0" aria-label={grouped ? "Findings that can be sent again in full" : "Findings with a stored request"}>
              {full.map((c) => (
                <CandidateRow key={c.id} c={c} checked={ids.includes(c.id)} vocab={vocab} onToggle={(on) => toggle(c.id, on)} />
              ))}
            </ul>
          </section>
        )}
        {hidden.length > 0 && (
          <section className="space-y-1.5" data-testid="assess-retest-hidden">
            {grouped && <SubHeading>{`Had a value hidden (${hidden.length})`}</SubHeading>}
            {/* Said once, for the whole group: most findings of a real run carry a session header, so most rows say a value was hidden, and the consequence is the same for each. */}
            <p className="m-0 text-[11.5px] text-warn" data-testid="assess-retest-hidden-once">
              {RETEST_HIDDEN_CONSEQUENCE}
            </p>
            <p className="m-0 text-[11.5px] text-fg-3">{RETEST_HIDDEN_CHOOSE}</p>
            <ul className="m-0 list-none space-y-1.5 p-0" aria-label={grouped ? "Findings with a hidden value" : "Findings with a stored request"}>
              {hidden.map((c) => (
                <CandidateRow key={c.id} c={c} checked={ids.includes(c.id)} vocab={vocab} onToggle={(on) => toggle(c.id, on)} />
              ))}
            </ul>
          </section>
        )}
        <p className="m-0 text-[11.5px] text-fg-3">{RETEST_NOTHING_CLOSED}</p>
      </div>
    </Modal>
  );
}

/** RetestAction is the block over a pen test or red team run's findings: what a retest is, and the button that opens the picker. It offers nothing when the checked model holds no finding with a stored request, and says why the button is off when the project's folder is gone. `closedNote` is the one sentence that nothing was closed, printed in this block when the findings below carry labels (each row has a short tag for it, N-13). */
export function RetestAction({
  run,
  doc,
  vocab,
  onRetest,
  closedNote,
}: {
  run: Pick<AssessRun, "id" | "project_root_hash" | "project_gone">;
  doc: PentestDoc | undefined;
  vocab?: ModelVocab;
  onRetest: (req: RetestRequest) => void;
  closedNote?: ReactNode;
}) {
  const candidates = useMemo(() => retestCandidates(doc), [doc]);
  const [open, setOpen] = useState(false);
  const gone = run.project_gone === true;
  const btn = (
    <Button size="sm" variant="secondary" iconLeft={Repeat} disabled={gone} data-testid="assess-retest-open" onClick={() => setOpen(true)}>
      Retest findings
    </Button>
  );
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 rounded-2 border border-line-2 bg-bg-2 px-3 py-2" data-testid="assess-retest-action">
      <div className="min-w-0 flex-1 basis-64 space-y-0.5">
        <SubHeading>Retest</SubHeading>
        <p className="m-0 text-[11.5px] text-fg-2">{retestOfferLine(candidates.length, RETEST_MAX, retestHiddenCount(candidates))}</p>
        {closedNote}
        {gone && candidates.length > 0 && <p className="m-0 text-[11.5px] text-warn">This project&apos;s folder is no longer on this machine, so there is nothing to retest against.</p>}
      </div>
      {candidates.length > 0 && (gone ? <TooltipSpan content="This project's folder is no longer on this machine.">{btn}</TooltipSpan> : btn)}
      {open && (
        <AssessRetestPicker
          candidates={candidates}
          vocab={vocab}
          projectHash={run.project_root_hash}
          ofRun={run.id}
          onClose={() => setOpen(false)}
          onPlan={(req) => {
            setOpen(false);
            onRetest(req);
          }}
        />
      )}
    </div>
  );
}
