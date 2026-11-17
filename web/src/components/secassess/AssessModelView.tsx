import { useId, useMemo, useState } from "react";
import { Button, Callout, InfoDisclosure, Modal, Pill, Skeleton, TabPanel, TabStrip, type TabDef } from "@/components/primitives";
import { TitleWithHelp } from "@/components/HelpInd";
import { useApi } from "@/lib/useApi";
import { ApiError, apiReason } from "@/lib/api";
import { fmtDateTime, fmtRelative } from "@/lib/format";
import { ASSESS_REFUSALS, assessAuditLine, assessRefusalWords, type AssessRun } from "@/lib/secAssess";
import {
  assessModelPath,
  bandCounts,
  bandTone,
  defaultSince,
  itemCounts,
  limitsSummary,
  modelOpenable,
  modelSubtitle,
  modelTitle,
  partialNotice,
  plural,
  redactionNote,
  sinceCandidates,
  type AssessModelResponse,
  type ModelRecord,
} from "@/lib/secAssessModel";
import { FIX_AFTER_END_WORDS, assessFixEnabled } from "@/lib/secAssessFix";
import { retestsByFinding, type RetestRequest } from "@/lib/secAssessRetest";
import { AssessExercise } from "./AssessExercise";
import { AssessRetestContext, RetestClosedNote, type AssessRetestContextValue } from "./AssessRetestLabel";
import { RetestAction } from "./AssessRetestPicker";
import { RetestReplayed, RetestResults } from "./AssessRetestView";
import { AssessFixContext } from "./AssessFixButton";
import { CoverageMatrix } from "./CoverageMatrix";
import { ElementMatrix } from "./ElementMatrix";
import { ExportMenu } from "./ExportMenu";
import { FindingList } from "./FindingEvidence";
import { FlowTable } from "./FlowTable";
import { LimitsStrip } from "./LimitsStrip";
import { ModelHeader, ModelOverview } from "./ModelOverview";
import { SystemView } from "./SystemView";
import { ThreatTable } from "./ThreatTable";
import { TreeList } from "./TreeList";
import { AgentText, SubHeading } from "./modelParts";

// AssessModelView is the model view of one assessment run
// (docs/plans/security-assessments-depth-plan-2026-11-14.md, wave 6): the
// checked copy of the agent's model, the way Observer built it, in tabs. A
// threat model has Overview, Threats, Matrix, System, Flows, Attack trees and
// How checked; a penetration test has Coverage first, then Findings and How
// checked. A tab with nothing in it stays, with an
// honest empty state.
//
// What the agent wrote is shown as text and labelled as the agent's. What
// Observer computed (the band, the state of each cited place, the matrix
// cells, the coverage reading) is Observer's. Nothing here says a model is
// right: see the limits on the last tab.

/** The tab ids of both kinds of model view. */
export type ModelTabId = "overview" | "threats" | "matrix" | "system" | "flows" | "trees" | "coverage" | "findings" | "exercise" | "results" | "replayed" | "checked";

type Kind = "tm" | "pt" | "rt" | "none";

function kindOf(contract: string): Kind {
  if (contract === "threatmodel.v1") return "tm";
  if (contract === "pentest.v1") return "pt";
  if (contract === "retest.v1") return "rt";
  return "none";
}

/** The sentence for a run whose checked copy is not stored. */
export const NO_STORED_MODEL_WORDS =
  "No checked copy of this model is stored (it was deleted, or the run was never checked). Validate the run again.";

/** modelErrorWords is what a refused or failed read of the model says, in words: a missing checked copy, the server's own sentence for a 409, else the error's reason. */
export function modelErrorWords(e: unknown): string {
  if (e instanceof ApiError && e.status === 404) {
    return e.body.trim() === "unknown run" ? "This run is no longer listed." : NO_STORED_MODEL_WORDS;
  }
  return assessRefusalWords(e) ?? apiReason(e);
}

/** modelTabs lists the tabs of a record, in order. Every tab of a kind is listed whether or not it has anything to show; a record with no model keeps only How checked. */
export function modelTabs(rec: ModelRecord): TabDef<ModelTabId>[] {
  const kind = kindOf(rec.contract);
  const tm = rec.result?.tm;
  const pt = rec.result?.pt;
  const checked: TabDef<ModelTabId> = { id: "checked", label: "How checked" };
  if (kind === "tm" && tm) {
    const flows = tm.system?.flows?.length ?? 0;
    const trees = tm.attack_trees?.length ?? 0;
    return [
      { id: "overview", label: "Overview" },
      { id: "threats", label: "Threats", ariaLabel: "Threats", count: tm.threats?.length ?? 0 },
      { id: "matrix", label: "Matrix" },
      { id: "system", label: "System" },
      { id: "flows", label: "Flows", ariaLabel: "Flows", count: flows },
      { id: "trees", label: "Attack trees", ariaLabel: "Attack trees", count: trees },
      checked,
    ];
  }
  if (kind === "pt" && pt) {
    return [
      // A red team's account of its exercise comes first: it is what the run was for.
      ...(pt.exercise ? [{ id: "exercise" as const, label: "Exercise" }] : []),
      { id: "coverage", label: "Coverage" },
      { id: "findings", label: "Findings", ariaLabel: "Findings", count: pt.findings?.length ?? 0 },
      checked,
    ];
  }
  if (kind === "rt" && rec.result?.rt) {
    return [{ id: "results", label: "Results", ariaLabel: "Results", count: rec.result.rt.results?.length ?? 0 }, { id: "replayed", label: "Replayed" }, checked];
  }
  return [checked];
}

const TAB_PREFIX = "assess-model";

/** Notices over the tabs: the check is out of date, cited files changed, only the report is kept, the check was partial, secrets are hidden. */
function Notices({ data, onShowChecked }: { data: AssessModelResponse; onShowChecked: () => void }) {
  const drift = data.drift ?? [];
  const note = redactionNote(data.redaction);
  const partial = partialNotice(data.record);
  return (
    <div className="space-y-2">
      {data.stale && (
        <div data-testid="assess-model-stale">
          <Callout tone="warn" title="The agent's model file changed after this check">
            What is shown is the checked copy, which may not match the file now. Check the run again to read the new one.
          </Callout>
        </div>
      )}
      {partial && (
        <div data-testid="assess-model-partial">
          <Callout
            tone="info"
            title={partial.title}
            action={
              <Button size="sm" variant="ghost" onClick={onShowChecked}>
                How checked
              </Button>
            }
          >
            {partial.text}
          </Callout>
        </div>
      )}
      {drift.length > 0 && (
        <div data-testid="assess-model-drift">
          <Callout tone="info" title="Some cited files read differently now">
            {`${drift.length} project ${plural(drift.length, "file reads", "files read")} differently from when the references were checked, so the words about those places may be out of date.`}
            <InfoDisclosure summary="Which files" className="mt-1.5">
              <ul className="m-0 list-none space-y-0.5 p-0">
                {drift.map((f, i) => (
                  <li key={i}>
                    <code className="break-all font-mono text-[11px]">{f}</code>
                  </li>
                ))}
              </ul>
            </InfoDisclosure>
          </Callout>
        </div>
      )}
      {data.record.truncated && (
        <div data-testid="assess-model-truncated">
          <Callout tone="info" title="Only the report is kept">
            The model did not fit the stored copy, so there is no model to show here. What the check found is under How checked.
          </Callout>
        </div>
      )}
      {note && (
        <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-model-redaction">
          {note}
        </p>
      )}
    </div>
  );
}

/** LimitsSummary is kept above the tabs whatever tab is open: what this view does not tell you, in a line or two, with a way to the full list on the last tab. */
function LimitsSummary({ contract, onMore }: { contract: string; onMore: () => void }) {
  const lines = limitsSummary(contract);
  return (
    <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1 rounded-2 border border-line-2 bg-bg-2 px-3 py-2" data-testid="assess-model-limits-summary">
      <div className="min-w-0 flex-1 space-y-0.5">
        <SubHeading>What this does not tell you</SubHeading>
        {lines.map((l, i) => (
          <p key={i} className="m-0 text-[11.5px] text-fg-2">
            {l}
          </p>
        ))}
      </div>
      <Button size="sm" variant="ghost" onClick={onMore}>
        All the limits
      </Button>
    </div>
  );
}

function PentestNotes({ summary, limits }: { summary?: string; limits?: string[] }) {
  const own = (limits ?? []).filter((s) => typeof s === "string" && s !== "");
  return (
    <div className="space-y-3">
      <div className="space-y-1">
        <SubHeading>The agent says</SubHeading>
        {summary ? <AgentText>{summary}</AgentText> : <p className="m-0 text-[11.5px] text-fg-3">The agent wrote no summary.</p>}
      </div>
      {own.length > 0 && (
        <div className="space-y-1">
          <SubHeading>The agent's own limits</SubHeading>
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

export function AssessModelView({
  run,
  runs,
  onClose,
  initialTab,
  initialSince,
  onRetest,
  onOpenRun,
}: {
  run: AssessRun;
  /** Every run of the list: the earlier runs a threat model can be compared with come from it. */
  runs: AssessRun[];
  onClose: () => void;
  /** The tab to open first (a deep link, and tests). */
  initialTab?: ModelTabId;
  /** An earlier run to compare with at first. */
  initialSince?: string;
  /** Opens the retest's plan with the findings the picker chose. Absent: this view offers no retest. */
  onRetest?: (req: RetestRequest) => void;
  /** Opens another run's own view (a retest that labelled a finding of this run). */
  onOpenRun?: (runId: string) => void;
}) {
  // The comparison opens on the earlier run the run was launched with, when that run can still be compared with; a caller that names one (a deep link, a test) wins, and "" means none.
  const [since, setSince] = useState(() => initialSince ?? defaultSince(run, sinceCandidates(run, runs)));
  const [tab, setTab] = useState<ModelTabId | null>(initialTab ?? null);
  // The model is read once; the comparison is a second read that adds only its `since` member, so a comparison the server refuses leaves the model on screen.
  const base = useApi<AssessModelResponse>(assessModelPath(run.id), undefined, [run.id]);
  const cmp = useApi<AssessModelResponse>(since ? assessModelPath(run.id, since) : null, undefined, [run.id, since]);
  const data = base.data;
  const rec = data?.record;
  const kind = rec ? kindOf(rec.contract) : "none";
  const tabs = useMemo(() => (rec ? modelTabs(rec) : []), [rec]);
  const active: ModelTabId = tab !== null && tabs.some((t) => t.id === tab) ? tab : (tabs[0]?.id ?? "checked");
  const tm = rec?.result?.tm;
  const pt = rec?.result?.pt;
  const rt = rec?.result?.rt;
  const report = rec?.result?.report;
  const hasModel = kind === "tm" ? !!tm : kind === "pt" ? !!pt : kind === "rt" ? !!rt : false;
  // A fix may be asked for from a stored model once its run has ended: until then the server refuses (a fix would change the files the run's git check is watching), so the button is not offered and a line says why.
  const fixCtx = useMemo(() => ({ runId: run.id, enabled: assessFixEnabled(hasModel, run.ended_at) }), [run.id, hasModel, run.ended_at]);
  // The labels the run's retests gave its findings, and whether a retest's own view can be opened from here.
  const closedNoteId = useId();
  const retestCtx = useMemo<AssessRetestContextValue>(
    () => ({
      byFinding: retestsByFinding(data?.retests),
      noteId: closedNoteId,
      canOpen: (id) => !!onOpenRun && runs.some((r) => r.id === id && modelOpenable(r)),
      open: onOpenRun,
    }),
    [data?.retests, onOpenRun, runs, closedNoteId],
  );
  // Some finding carries a retest label: the one sentence that nothing was closed is printed over the findings, and each labelled row's tag points at it (N-13).
  const labelled = retestCtx.byFinding.size > 0;

  const candidates = useMemo(() => sinceCandidates(run, runs), [run, runs]);
  const cmpDiff = cmp.data?.since && (!cmp.data.since.prev_run || cmp.data.since.prev_run === since) ? cmp.data.since : undefined;
  const cmpFetching = cmp.loading || cmp.isStale || (cmp.isRefreshing && !cmpDiff);
  const sinceState = {
    value: since,
    onChange: setSince,
    candidates,
    // A comparison already on screen stays while it is read again; a refusal or a failed read shows only when there is none.
    loading: since !== "" && !cmpDiff && !cmp.error && cmpFetching,
    error:
      since === "" || cmpDiff
        ? ""
        : cmp.error
          ? modelErrorWords(cmp.error)
          : !cmpFetching
            ? "The comparison is not available for that run."
            : "",
    diff: since !== "" ? cmpDiff : undefined,
  };

  const validatedAt = rec?.validated_at ?? run.validation?.at;
  const audit = assessAuditLine(run);
  const subtitle = modelSubtitle(run.created_at, validatedAt, fmtDateTime, fmtRelative);
  const showChecked = () => setTab("checked");

  return (
    <Modal
      open
      onClose={onClose}
      title={<TitleWithHelp text={modelTitle(run)} helpId="card.code_security_assess_model" />}
      subtitle={subtitle || undefined}
      width={1240}
      bodyClassName="px-5 py-4"
      footer={
        <div className="flex w-full flex-wrap items-center justify-between gap-2">
          {kind === "rt" ? (
            <p className="m-0 min-w-0 flex-1 basis-64 text-[11.5px] text-fg-3" data-testid="assess-retest-no-export">
              {ASSESS_REFUSALS.retest_no_export.words}
            </p>
          ) : (
            <ExportMenu data={data} run={run} />
          )}
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
      }
    >
      <AssessFixContext.Provider value={fixCtx}>
      <AssessRetestContext.Provider value={retestCtx}>
      <div className="min-w-0 space-y-3" data-testid="assess-model">
        {!data && base.loading && (
          <div className="space-y-2" role="status" aria-label="Loading the model">
            <p className="m-0 text-[12.5px] text-fg-3">Loading the model</p>
            <Skeleton className="h-24 w-full" />
          </div>
        )}
        {!data && base.error && (
          <div className="space-y-2">
            <p role="alert" className="m-0 text-[12.5px] text-fg-2" data-testid="assess-model-error">
              {modelErrorWords(base.error)}
            </p>
            <Button size="sm" variant="secondary" onClick={base.reload}>
              Read again
            </Button>
          </div>
        )}
        {data && rec && (
          <>
            <Notices data={data} onShowChecked={showChecked} />
            <LimitsSummary contract={rec.contract} onMore={showChecked} />
            {hasModel && !fixCtx.enabled && (active === "threats" || active === "findings") && (
              <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-fix-after-end">
                {FIX_AFTER_END_WORDS}
              </p>
            )}
            {!hasModel && !rec.truncated && (
              <div data-testid="assess-model-none">
                <Callout tone="info" title="No model was kept">
                  The file was refused or could not be kept, so there is no model to show. What the check found is under How checked.
                </Callout>
              </div>
            )}
            <TabStrip tabs={tabs} value={active} onChange={setTab} idPrefix={TAB_PREFIX} ariaLabel="Model sections" />

            {kind === "tm" && tm && report && (
              <>
                <TabPanel id="overview" active={active} idPrefix={TAB_PREFIX}>
                  <ModelOverview data={data} doc={tm} since={sinceState} />
                </TabPanel>
                <TabPanel id="threats" active={active} idPrefix={TAB_PREFIX}>
                  <ThreatTable doc={tm} vocab={data.vocab} counts={itemCounts(rec, "threats")} />
                </TabPanel>
                <TabPanel id="matrix" active={active} idPrefix={TAB_PREFIX}>
                  <ElementMatrix doc={tm} cov={report.tm} vocab={data.vocab} />
                </TabPanel>
                <TabPanel id="system" active={active} idPrefix={TAB_PREFIX}>
                  <SystemView doc={tm} vocab={data.vocab} />
                </TabPanel>
                <TabPanel id="flows" active={active} idPrefix={TAB_PREFIX}>
                  <FlowTable doc={tm} mermaid={data.mermaid} />
                </TabPanel>
                <TabPanel id="trees" active={active} idPrefix={TAB_PREFIX}>
                  <TreeList trees={tm.attack_trees} />
                </TabPanel>
              </>
            )}

            {kind === "pt" && pt && report && (
              <>
                <TabPanel id="coverage" active={active} idPrefix={TAB_PREFIX}>
                  <div className="space-y-4">
                    <ModelHeader data={data} />
                    <CoverageMatrix pt={report.pt} claims={pt.coverage} doc={pt} vocab={data.vocab} showCounts={!data.coverage_line} />
                    <PentestNotes summary={pt.summary} limits={pt.limits} />
                  </div>
                </TabPanel>
                <TabPanel id="exercise" active={active} idPrefix={TAB_PREFIX}>
                  {pt.exercise && <AssessExercise pt={pt} />}
                </TabPanel>
                <TabPanel id="findings" active={active} idPrefix={TAB_PREFIX}>
                  <div className="space-y-3">
                    {onRetest && report.state !== "invalid" ? (
                      <RetestAction run={run} doc={pt} vocab={data.vocab} onRetest={onRetest} closedNote={labelled ? <RetestClosedNote id={closedNoteId} /> : undefined} />
                    ) : (
                      labelled && <RetestClosedNote id={closedNoteId} />
                    )}
                    <div className="flex flex-wrap items-center gap-1.5" data-testid="assess-model-bands">
                      {[...bandCounts(pt.findings ?? [])].reverse().map((c) => (
                        <Pill key={c.band} variant={c.n > 0 ? bandTone(c.band) : "neutral"} case="none">
                          {`${c.band} ${c.n}`}
                        </Pill>
                      ))}
                    </div>
                    <FindingList findings={pt.findings} vocab={data.vocab} counts={itemCounts(rec, "findings")} probes={data.probes} probeLog={data.probe_log} evidence={report.evidence} issues={report.issues} />
                  </div>
                </TabPanel>
              </>
            )}

            {kind === "rt" && rt && report && (
              <>
                <TabPanel id="results" active={active} idPrefix={TAB_PREFIX}>
                  <RetestResults data={data} run={run} />
                </TabPanel>
                <TabPanel id="replayed" active={active} idPrefix={TAB_PREFIX}>
                  <RetestReplayed data={data} run={run} />
                </TabPanel>
              </>
            )}

            <TabPanel id="checked" active={active} idPrefix={TAB_PREFIX}>
              <LimitsStrip record={rec} auditLine={audit} />
            </TabPanel>
          </>
        )}
      </div>
      </AssessRetestContext.Provider>
      </AssessFixContext.Provider>
    </Modal>
  );
}
