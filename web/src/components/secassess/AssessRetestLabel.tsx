import { createContext, useContext } from "react";
import { Button, InfoDisclosure, Pill, Tooltip } from "@/components/primitives";
import { fmtDateTime } from "@/lib/format";
import { RETEST_NOTHING_CLOSED } from "@/lib/secAssessModel";
import { retestReading, retestStanding, type FindingRetest } from "@/lib/secAssessRetest";
import { AgentText, SubHeading } from "./modelParts";

// AssessRetestLabel is what a finding's row says about the retests of its run
// (depth plan W7.2, decision D38: labels only). A retest replays the stored
// request of a finding once, in a copy of the project in a box, and the model
// answer lists what each retest gave each finding. Here the newest label sits
// in the finding's row as one compact line: the label in words, the reading of
// the request helper's log in the words findings use for theirs, the date, a
// way to the retest's own view, and always the sentence that nothing was
// closed. A finding with more than one retest shows the newest and lists the
// older ones behind a disclosure. A label is never toned or worded as a fix:
// "Not reproduced" is a neutral label, "Reproduced" draws attention, and no
// label is ever green.
//
// The rows do not know which retests their run has, so the model view provides
// them once through AssessRetestContext (the way AssessFixContext provides the
// run), and a row only names its finding. Anywhere else the context is empty
// and a row shows no label, which is also why FindingList renders the same
// without a provider.

/** AssessRetestContextValue is what the model view tells every finding row: the labels by finding, whether a retest's own view can be opened and how. */
export type AssessRetestContextValue = {
  byFinding: ReadonlyMap<string, FindingRetest[]>;
  /** The id of the one element that holds the full sentence that nothing was closed (RetestClosedNote), which every row's tag points at as its description. */
  noteId?: string;
  /** Whether the retest run's own view is available (the run is in the list with a stored model). */
  canOpen: (run: string) => boolean;
  /** Opens the retest run's own view. */
  open?: (run: string) => void;
};

const NO_LABELS: ReadonlyMap<string, FindingRetest[]> = new Map();

/** AssessRetestContext carries the retests of the run on screen. Its default carries none. */
export const AssessRetestContext = createContext<AssessRetestContextValue>({ byFinding: NO_LABELS, canOpen: () => false });

/** The words on the button that opens a retest's own view. */
export const OPEN_RETEST_LABEL = "Open the retest";

/** The short tag every labelled row carries: the full sentence is RETEST_NOTHING_CLOSED, printed once above the findings. */
export const RETEST_CLOSED_TAG = "Not closed";

/** RetestClosedNote is the one place the full sentence that nothing was closed is printed over the findings of a run with labels: in the Retest block, above the table. Each row's tag names it as its description. */
export function RetestClosedNote({ id }: { id?: string }) {
  return (
    <p id={id} className="m-0 text-[11.5px] text-fg-3" data-testid="assess-retest-closed-note">
      {RETEST_NOTHING_CLOSED}
    </p>
  );
}

/** RetestClosedTag is the tag a labelled row carries in place of the sentence: "Not closed", neutral, with the sentence as its tooltip and, for a screen reader, as its description (the note above the table). */
export function RetestClosedTag() {
  const ctx = useContext(AssessRetestContext);
  return (
    <Tooltip content={RETEST_NOTHING_CLOSED}>
      <span
        tabIndex={0}
        aria-describedby={ctx.noteId}
        data-testid="assess-retest-closed"
        className="inline-flex cursor-help rounded-full focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]"
      >
        <Pill variant="neutral" case="none">
          {RETEST_CLOSED_TAG}
        </Pill>
      </span>
    </Tooltip>
  );
}

/** OpenRetestButton opens a retest run's own view, when it can be opened. */
function OpenRetestButton({ run, finding }: { run: string; finding: string }) {
  const ctx = useContext(AssessRetestContext);
  if (!ctx.open || !ctx.canOpen(run)) return null;
  const open = ctx.open;
  return (
    <Button
      size="sm"
      variant="ghost"
      data-testid="assess-retest-open"
      aria-label={`${OPEN_RETEST_LABEL} that labelled ${finding}`}
      onClick={(e) => {
        e.stopPropagation();
        open(run);
      }}
    >
      {OPEN_RETEST_LABEL}
    </Button>
  );
}

/** LabelPills is one retest's label and the reading of its log, as two pills. */
function LabelPills({ r }: { r: FindingRetest }) {
  const w = retestReading(r.result);
  return (
    <>
      <Pill variant={w.label.tone} case="none">
        {w.label.label}
      </Pill>
      {w.evidence ? (
        <Pill variant={w.evidence.tone} case="none">
          {w.evidence.label}
        </Pill>
      ) : (
        <span className="text-fg-3">No log reading</span>
      )}
    </>
  );
}

/** RetestLine is the compact line of a finding's row: the newest retest's label, its evidence word, the short "Not closed" tag, its date and the way to its view; the reason a label has no log behind it; and the older retests behind a disclosure. Renders nothing for a finding no retest labelled. */
export function RetestLine({ finding }: { finding: string }) {
  const ctx = useContext(AssessRetestContext);
  const list = ctx.byFinding.get(finding) ?? [];
  if (list.length === 0) return null;
  const [newest, ...older] = list;
  const w = retestReading(newest.result);
  const why = w.evidence && w.evidence.state !== "logged" ? w.evidence.detail : "";
  // An older retest that said the weakness was there is not left behind a disclosure under a newer label that claims little (N-11).
  const standing = retestStanding(list, fmtDateTime);
  return (
    <div className="mt-1.5 space-y-1" data-testid="assess-retest-line" data-finding-id={finding}>
      <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-[11px]">
        <span className="font-medium text-fg-2">Retest</span>
        <span data-testid="assess-retest-label" className="inline-flex items-center gap-1.5">
          <LabelPills r={newest} />
        </span>
        <RetestClosedTag />
        <span className="text-fg-3" data-testid="assess-retest-date">
          {fmtDateTime(newest.at)}
        </span>
        <OpenRetestButton run={newest.run} finding={finding} />
      </div>
      {why && (
        <p className="m-0 break-words text-[11px] text-fg-3" data-testid="assess-retest-reason">
          {why}
        </p>
      )}
      {standing && (
        <p className="m-0 break-words text-[11px] text-fg-2" data-testid="assess-retest-standing">
          {standing}
        </p>
      )}
      {older.length > 0 && (
        <InfoDisclosure summary={`Older retests (${older.length})`}>
          <ul className="m-0 list-none space-y-1.5 p-0" data-testid="assess-retest-older">
            {older.map((r) => (
              <li key={r.run} className="space-y-0.5" data-testid="assess-retest-older-item">
                <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-[11px]">
                  <LabelPills r={r} />
                  <span className="text-fg-3">{fmtDateTime(r.at)}</span>
                  <OpenRetestButton run={r.run} finding={finding} />
                </div>
              </li>
            ))}
          </ul>
        </InfoDisclosure>
      )}
    </div>
  );
}

/** RetestHistory is the part of an open finding that says what each retest found, in full: the label and what it says, the reading of the log, the agent's note as text, and the date. Renders nothing for a finding no retest labelled. */
export function RetestHistory({ finding }: { finding: string }) {
  const ctx = useContext(AssessRetestContext);
  const list = ctx.byFinding.get(finding) ?? [];
  if (list.length === 0) return null;
  return (
    <div className="space-y-1.5" data-testid="assess-retest-history" data-finding-id={finding}>
      <SubHeading>{list.length === 1 ? "Retest" : "Retests"}</SubHeading>
      <ul className="m-0 list-none space-y-2 p-0">
        {list.map((r) => {
          const w = retestReading(r.result);
          return (
            <li key={r.run} className="min-w-0 space-y-1 rounded-2 border border-line-2 bg-bg-2 p-2" data-testid="assess-retest-entry">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <LabelPills r={r} />
                <span className="text-[11px] text-fg-3">{fmtDateTime(r.at)}</span>
                <OpenRetestButton run={r.run} finding={finding} />
              </div>
              <p className="m-0 break-words text-[11.5px] text-fg-2">{w.label.detail}</p>
              {w.evidence && <p className="m-0 break-words text-[11.5px] text-fg-3">{w.evidence.detail}</p>}
              {!r.started && <p className="m-0 text-[11.5px] text-fg-3">The agent says the target did not start for this retest.</p>}
              {r.result.note && (
                <div className="space-y-0.5">
                  <SubHeading agent>Note</SubHeading>
                  <AgentText>{r.result.note}</AgentText>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
