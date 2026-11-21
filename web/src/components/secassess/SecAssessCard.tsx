import { useEffect, useState } from "react";
import { Play } from "lucide-react";
import { Button, Callout, Card, InfoDisclosure, Pill, Skeleton, TooltipSpan } from "@/components/primitives";
import { TitleWithHelp } from "@/components/HelpInd";
import { useApi } from "@/lib/useApi";
import { apiReason } from "@/lib/api";
import type { SecurityProject } from "@/lib/codeSecurity";
import {
  ASSESS_EMPTY,
  ASSESS_LIST_PATH,
  assessModeTone,
  assessPolling,
  assessRunsUnreadableWords,
  type AssessKind,
  type AssessList,
  type AssessRun,
} from "@/lib/secAssess";
import { cardKinds, retestKindOf, type RetestRequest } from "@/lib/secAssessRetest";
import { AssessModelView } from "./AssessModelView";
import { AssessPlanDialog } from "./AssessPlanDialog";
import { AssessReportDialog } from "./AssessReportDialog";
import { AssessRunsList } from "./AssessRunsList";

// SecAssessCard is the Code security Overview's "Security assessments" card
// (docs/plans/security-assessments-module-plan-2026-11-13.md section 5): the
// assessment kinds the module offers, each with its mode and a Start button
// that opens the plan, the kind that has no agent-shaped launch with why not
// and where to look instead, and the recent runs. It is the module's one
// entry point on the page. Hidden when the route is not installed (Code
// security compiled out, or a daemon without the module).
//
// The runs list refreshes every 15 s while a run can still receive a result
// file, so a report the agent writes shows up without a reload.

const POLL_MS = 15_000;

function KindRow({
  kind,
  canStart,
  startWhy,
  onStart,
}: {
  kind: AssessKind;
  canStart: boolean;
  /** Why Start is disabled ("" when it is not). */
  startWhy: string;
  onStart: (k: AssessKind) => void;
}) {
  const [explain, setExplain] = useState(false);
  const startBtn = (
    <Button size="sm" variant="secondary" iconLeft={Play} disabled={!canStart} onClick={() => onStart(kind)}>
      Start
    </Button>
  );
  return (
    <li className="space-y-1.5 border-b border-line-1 py-2.5 last:border-b-0" data-testid="assess-kind">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0 flex-1 basis-64 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium text-fg-1">{kind.title}</span>
            <Pill variant={assessModeTone(kind)} case="none">
              {kind.mode}
            </Pill>
          </div>
          <p className="m-0 text-[12px] text-fg-2">{kind.summary}</p>
          {kind.launchable && kind.blocked && (
            <p className="m-0 text-[11.5px] text-warn" data-testid="assess-kind-blocked">
              {`Cannot start on this machine right now: ${kind.blocked}`}
            </p>
          )}
        </div>
        {kind.launchable ? (
          startWhy ? (
            <TooltipSpan content={startWhy}>{startBtn}</TooltipSpan>
          ) : (
            startBtn
          )
        ) : (
          <Button size="sm" variant="ghost" aria-expanded={explain} onClick={() => setExplain((v) => !v)}>
            {explain ? "Hide" : "Why not?"}
          </Button>
        )}
      </div>
      {!kind.launchable && explain && (
        <Callout tone="info" title="Nothing to launch" className="mt-1">
          {kind.reason}
          {kind.pointer && <span className="mt-1 block text-fg-3">{kind.pointer}</span>}
        </Callout>
      )}
    </li>
  );
}

/** RunsUnreadable is the callout over the runs list while the run record cannot
 *  be read: it names the file and the steps that free it. There is no button
 *  that moves the file; the developer renames it, and the words say what that
 *  costs. */
function RunsUnreadable({ file }: { file?: string }) {
  const w = assessRunsUnreadableWords(file);
  return (
    <Callout tone="warn" title="The run history could not be read">
      <div data-testid="assess-runs-unreadable">
        <p className="m-0">{w.line}</p>
        <InfoDisclosure summary="How to recover" defaultOpen className="mt-1.5">
          <div className="space-y-1.5">
            <p className="m-0 break-all" data-testid="assess-runs-unreadable-file">
              {w.where}
            </p>
            <p className="m-0">{w.effect}</p>
            <ol className="m-0 list-decimal space-y-0.5 pl-4" aria-label="Steps to recover">
              {w.steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
            <p className="m-0" data-testid="assess-runs-unreadable-cost">
              {w.cost}
            </p>
          </div>
        </InfoDisclosure>
      </div>
    </Callout>
  );
}

export function SecAssessCard({ projects }: { projects: SecurityProject[] }) {
  const [polling, setPolling] = useState(false);
  const list = useApi<AssessList>(ASSESS_LIST_PATH, undefined, [], { refreshMs: polling ? POLL_MS : 0 });
  useEffect(() => setPolling(assessPolling(list.data)), [list.data]);
  const [planKind, setPlanKind] = useState<AssessKind | null>(null);
  // A run held for the organization, once approved: the plan opens on it.
  const [heldRun, setHeldRun] = useState<AssessRun | null>(null);
  const [reportRun, setReportRun] = useState<AssessRun | null>(null);
  const [modelRun, setModelRun] = useState<AssessRun | null>(null);
  // A retest of earlier findings, chosen in a model view: its plan opens over that view.
  const [retestReq, setRetestReq] = useState<RetestRequest | null>(null);

  // Not installed (or a daemon without the route): nothing to show.
  if (list.notInstalled || list.status === 404) return null;
  const data = list.data;
  const heldKind = heldRun ? (data?.kinds.find((k) => k.id === heldRun.kind) ?? null) : null;
  const retestKind = retestKindOf(data?.kinds);
  const hasProject = projects.some((p) => !!p.root_path);
  const startWhy = !data
    ? "Reading the assessments"
    : !data.launch
      ? "This dashboard cannot start a terminal"
      : !hasProject
        ? "No project with a folder on this machine is known yet"
        : "";

  return (
    <Card
      className="min-w-0 xl:col-span-2"
      title={<TitleWithHelp text="Security assessments" helpId="card.code_security_assess" />}
      sub="Start an agent in a terminal on one assessment of a project. It writes a report and its results into the project; you read the report and import the findings here."
      stale={list.isStale}
    >
      <div className="min-w-0 space-y-3" data-testid="assess-card">
        {list.loading && !data && (
          <div className="space-y-2" role="status" aria-label="Loading the assessments">
            <p className="m-0 text-[12.5px] text-fg-3">Loading the assessments</p>
            <Skeleton className="h-16 w-full" />
          </div>
        )}
        {list.error && !data && (
          <div className="space-y-2">
            <p role="alert" className="m-0 text-[12.5px] text-danger">
              {`The assessments could not be read: ${apiReason(list.error)}`}
            </p>
            <Button size="sm" variant="secondary" onClick={list.reload}>
              Retry
            </Button>
          </div>
        )}
        {data && (
          <>
            <ul className="m-0 list-none p-0 text-[12.5px]" aria-label="Assessment kinds">
              {cardKinds(data.kinds).map((k) => (
                <KindRow key={k.id} kind={k} canStart={startWhy === ""} startWhy={startWhy} onStart={setPlanKind} />
              ))}
            </ul>
            <div className="space-y-1.5">
              <h3 className="m-0 text-[12px] font-medium text-fg-2">Recent assessments</h3>
              {data.runs_unreadable && <RunsUnreadable file={data.runs_file} />}
              {data.runs.length === 0 ? (
                // An unreadable record is not "no assessments yet": the callout above says so.
                !data.runs_unreadable && (
                  <p className="m-0 text-[12px] text-fg-3" data-testid="assess-empty">
                    {ASSESS_EMPTY}
                  </p>
                )
              ) : (
                <AssessRunsList
                  runs={data.runs}
                  importAvailable={data.import_available}
                  onReport={setReportRun}
                  onModel={setModelRun}
                  onStartHeld={setHeldRun}
                />
              )}
            </div>
          </>
        )}
      </div>
      {/* Mounted only while open: each open reads its own plan (the plan
          mints the run id) and each report read starts clean. */}
      {planKind && (
        <AssessPlanDialog kind={planKind} projects={projects} runs={data?.runs} launch={data?.launch ?? false} onClose={() => setPlanKind(null)} />
      )}
      {heldKind && heldRun && (
        <AssessPlanDialog
          kind={heldKind}
          heldRun={heldRun}
          projects={projects}
          launch={data?.launch ?? false}
          onClose={() => setHeldRun(null)}
        />
      )}
      {retestReq && retestKind && (
        <AssessPlanDialog
          kind={retestKind}
          retest={retestReq}
          projects={projects}
          runs={data?.runs}
          launch={data?.launch ?? false}
          onClose={() => setRetestReq(null)}
        />
      )}
      {reportRun && <AssessReportDialog run={reportRun} onClose={() => setReportRun(null)} />}
      {/* The model view reads the run from the list as it is now, so a check run while it is open shows. */}
      {modelRun && (
        <AssessModelView
          key={modelRun.id}
          run={data?.runs.find((r) => r.id === modelRun.id) ?? modelRun}
          runs={data?.runs ?? []}
          onClose={() => setModelRun(null)}
          onRetest={retestKind ? setRetestReq : undefined}
          onOpenRun={(id) => {
            const r = data?.runs.find((x) => x.id === id);
            if (r) setModelRun(r);
          }}
        />
      )}
    </Card>
  );
}
