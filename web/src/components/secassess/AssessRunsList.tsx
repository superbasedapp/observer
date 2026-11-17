import { useState } from "react";
import { Link } from "react-router-dom";
import { FileText, Network, Play, ShieldCheck, Square, Trash2, Upload, X } from "lucide-react";
import { Button, Callout, ConfirmButton, Pill, TooltipSpan } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { apiCache } from "@/lib/useApi";
import { ApiError, apiReason, fetchJSON, localConfirmHeaders } from "@/lib/api";
import { fmtDateTime, fmtRelative } from "@/lib/format";
import { toolMeta } from "@/lib/tools";
import { modelOpenable } from "@/lib/secAssessModel";
import { findingsHref } from "@/lib/codeSecurityApi";
import {
  ASSESS_CANCEL_PATH,
  ASSESS_DELETE_DATA_PATH,
  ASSESS_IMPORT_PATH,
  ASSESS_LIST_PATH,
  ASSESS_STOP_PATH,
  ASSESS_VALIDATE_PATH,
  assessAuditLine,
  assessCanDeleteData,
  assessCanStop,
  assessCanValidate,
  assessCloudLine,
  assessCrossed,
  assessHeldRuleLine,
  assessImportConflict,
  assessImportLabel,
  assessImportLine,
  assessImportable,
  assessRelaxLine,
  assessRelaxState,
  assessRefusalWords,
  assessRelaxedLine,
  assessRunMaskLine,
  ASSESS_IMPORT_SETTINGS,
  assessRunLabel,
  assessRunScopeLines,
  assessRunState,
  assessRunWhere,
  assessTimeBoxLine,
  assessValidateLabel,
  assessValidationLine,
  type AssessRun,
} from "@/lib/secAssess";
import { AssessRunExtras } from "./AssessRunExtras";

// AssessRunsList is the recent assessment runs, newest first: the agent, the
// project, where it ran, its state (read live from the result files), the
// next step, the report, and the Import button. Import is always the
// developer's click; it posts the run id and the server reads the findings
// file itself. Nothing here changes a finding.
//
// A run held for the organization (docs/plans/security-assessments-module-
// plan-2026-11-13.md section 13.6) shows each rule's answer, read live from
// the node's verified grant cache, with Approved: start once every rule is
// covered and Cancel request to take the request back. A run that lifted a
// guardrail lists each one, how it ended, and how many verdicts it changed.

function RunRow({
  run,
  runs,
  earlier,
  importAvailable,
  onReport,
  onModel,
  onStartHeld,
}: {
  run: AssessRun;
  /** The whole list: a retest names the earlier run it replayed from it (assessRunLabel). */
  runs: readonly AssessRun[];
  /** The label of the earlier run this one was compared with (assessRunLabel), "" when the list no longer holds it. */
  earlier: string;
  importAvailable: boolean;
  onReport: (r: AssessRun) => void;
  onModel?: (r: AssessRun) => void;
  onStartHeld?: (r: AssessRun) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const state = assessRunState(run);
  const held = run.phase === "held";
  const importLine = assessImportLine(run.import);
  const cloudLine = assessCloudLine(run.cloud);
  const crossed = assessCrossed(run.cloud);
  const canImport = !held && assessImportable(run);
  const relaxedLine = assessRelaxedLine(run.relaxed);
  const timeLine = assessTimeBoxLine(run);
  const auditLine = assessAuditLine(run);
  const canStop = assessCanStop(run);
  const canDeleteData = assessCanDeleteData(run);
  const validationLine = assessValidationLine(run.validation);
  const canValidate = assessCanValidate(run);
  const validateLabel = assessValidateLabel(run);
  const scopeLines = assessRunScopeLines(run, earlier);
  const maskLine = assessRunMaskLine(run);

  async function doImport() {
    setBusy(true);
    setErr("");
    try {
      await fetchJSON(ASSESS_IMPORT_PATH, undefined, {
        method: "POST",
        headers: await localConfirmHeaders(),
        body: JSON.stringify({ run: run.id }),
      });
      apiCache.invalidate(ASSESS_LIST_PATH);
    } catch (e) {
      setErr(assessRefusalWords(e) ?? (e instanceof ApiError && e.status === 409 ? assessImportConflict(e.body) : apiReason(e)));
    } finally {
      setBusy(false);
    }
  }

  async function doCancel() {
    setBusy(true);
    setErr("");
    try {
      await fetchJSON(ASSESS_CANCEL_PATH, undefined, {
        method: "POST",
        headers: await localConfirmHeaders(),
        body: JSON.stringify({ run: run.id }),
      });
      apiCache.invalidate(ASSESS_LIST_PATH);
    } catch (e) {
      setErr(assessRefusalWords(e) ?? (e instanceof ApiError && e.status === 409 ? "The run is no longer waiting for your organization." : apiReason(e)));
    } finally {
      setBusy(false);
    }
  }

  // Stop closes the run's terminal; Delete removes its stored evidence (its
  // checked model and git snapshots); Validate checks the model. All need the
  // confirm token, and the list is read again afterwards so the row shows what
  // the server recorded. A refusal shows the server's own answer in words (the
  // run record cannot be used, the run has not ended, the project is gone);
  // `failure` is only for a 409 that came with no words at all.
  async function post(path: string, body: Record<string, string | boolean>, failure: string) {
    setBusy(true);
    setErr("");
    try {
      await fetchJSON(path, undefined, { method: "POST", headers: await localConfirmHeaders(), body: JSON.stringify(body) });
      apiCache.invalidate(ASSESS_LIST_PATH);
    } catch (e) {
      setErr(assessRefusalWords(e) ?? (e instanceof ApiError && e.status === 409 ? failure : apiReason(e)));
    } finally {
      setBusy(false);
    }
  }

  const validateBtn = (
    <Button
      size="sm"
      variant="secondary"
      iconLeft={ShieldCheck}
      loading={busy}
      onClick={() => void post(ASSESS_VALIDATE_PATH, { run: run.id }, "The model cannot be validated yet.")}
    >
      {validateLabel}
    </Button>
  );

  const importBtn = (
    <Button
      size="sm"
      variant="secondary"
      iconLeft={Upload}
      loading={busy}
      disabled={!importAvailable}
      onClick={() => void doImport()}
    >
      {assessImportLabel(run.state)}
    </Button>
  );

  return (
    <li className="space-y-1.5 border-b border-line-1 py-2.5 last:border-b-0" data-testid="assess-run">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="font-medium text-fg-1">{run.kind_title}</span>
        <span className="text-fg-2">{run.project_name || "Unknown project"}</span>
        <span className="text-fg-3">{fmtRelative(run.created_at)}</span>
        <Pill variant={state.tone} case="none">
          {state.label}
        </Pill>
        {run.reported && (
          <Pill variant="neutral" case="none">
            reported to your organization
          </Pill>
        )}
      </div>
      <div className="text-[11.5px] text-fg-3">
        {held
          ? `${run.target ? `${run.target} · ` : ""}not started`
          : `${toolMeta(run.tool).label} · ${assessRunWhere(run)}${run.seeded ? "" : " · task pasted by hand"}`}
      </div>
      {(scopeLines.scope || scopeLines.previous) && (
        <div className="break-words text-[11.5px] text-fg-3" data-testid="assess-run-scope">
          {scopeLines.scope}
          {scopeLines.scope && scopeLines.previous ? ". " : ""}
          {scopeLines.previous}
        </div>
      )}
      <AssessRunExtras run={run} runs={runs} />
      <div className="text-[11.5px] text-fg-2">{held ? state.next : importLine || state.next}</div>
      {held && run.held && (
        <ul className="m-0 list-none space-y-0.5 p-0 text-[11.5px] text-fg-2" data-testid="assess-run-held">
          {run.held.rules.map((r) => (
            <li key={r.rule}>{assessHeldRuleLine(r)}</li>
          ))}
        </ul>
      )}
      {!held && run.relax && run.relax.length > 0 && (
        <ul className="m-0 list-none space-y-0.5 p-0 text-[11.5px]" data-testid="assess-run-relax" aria-label="Guardrails lifted for this run">
          {run.relax.map((x) => (
            <li key={x.key} className={assessRelaxState(x.state).tone === "warn" ? "text-warn" : "text-fg-2"}>
              {assessRelaxLine(x)}
            </li>
          ))}
        </ul>
      )}
      {timeLine.text && (
        <div className={`text-[11.5px] ${timeLine.tone === "warn" ? "text-warn" : "text-fg-3"}`} data-testid="assess-run-timebox">
          {timeLine.text}
        </div>
      )}
      {auditLine && (
        <div className={`flex flex-wrap items-center text-[11.5px] ${auditLine.tone === "warn" ? "text-warn" : "text-fg-3"}`} data-testid="assess-run-audit">
          {run.audit_limits ? <TooltipSpan content={run.audit_limits}>{auditLine.text}</TooltipSpan> : auditLine.text}
          <HelpInd id="card.code_security_assess_limits" />
        </div>
      )}
      {validationLine && (
        <div
          className={`text-[11.5px] ${validationLine.tone === "warn" ? "text-warn" : validationLine.tone === "danger" ? "text-danger" : "text-fg-3"}`}
          data-testid="assess-run-validation"
        >
          {validationLine.text}
        </div>
      )}
      {maskLine && (
        <div className={`text-[11.5px] ${maskLine.tone === "warn" ? "text-warn" : "text-fg-3"}`} data-testid="assess-run-mask">
          {maskLine.text}
        </div>
      )}
      {relaxedLine && (
        <div className="text-[11.5px] text-fg-2" data-testid="assess-run-relaxed">
          {relaxedLine}
        </div>
      )}
      {cloudLine && (
        <div className={`text-[11.5px] ${crossed ? "text-warn" : "text-fg-3"}`} data-testid="assess-run-cloud">
          {crossed ? `Outside the read-only boundary. ${cloudLine}` : cloudLine}
        </div>
      )}
      {run.project_gone && <div className="text-[11.5px] text-fg-3">This project's folder is no longer on this machine.</div>}
      {err && (
        <div role="alert" className="text-[11.5px] text-danger">
          {err}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        {held && (
          <>
            {run.held?.ready ? (
              <Button size="sm" variant="primary" iconLeft={Play} onClick={() => onStartHeld?.(run)}>
                Approved: start
              </Button>
            ) : (
              <TooltipSpan content="Your organization has not approved this yet. This list updates when it does.">
                <Button size="sm" variant="secondary" iconLeft={Play} disabled>
                  Waiting for your organization
                </Button>
              </TooltipSpan>
            )}
            <Button size="sm" variant="ghost" iconLeft={X} loading={busy} onClick={() => void doCancel()}>
              Cancel request
            </Button>
          </>
        )}
        {canStop && (
          <ConfirmButton
            variant={run.over_time_box ? "danger" : "danger-outline"}
            armedVariant="danger"
            size="sm"
            iconLeft={Square}
            confirmLabel="Stop the run?"
            armedNote="Closes the run's terminal. Work the agent has not saved is lost; the run and anything it already wrote stay."
            timeoutMs={8000}
            loading={busy}
            onConfirm={() => void post(ASSESS_STOP_PATH, { run: run.id }, "The run has no terminal to stop.")}
            ariaLabel={`Stop the ${run.kind_title} run`}
          >
            Stop
          </ConfirmButton>
        )}
        {canValidate &&
          (run.can_stop === true ? (
            <ConfirmButton
              variant="secondary"
              armedVariant="primary"
              size="sm"
              iconLeft={ShieldCheck}
              confirmLabel="Validate now?"
              armedNote="The run is still going, so the model may be partial or change. Validate it again when the run ends."
              timeoutMs={8000}
              loading={busy}
              onConfirm={() => void post(ASSESS_VALIDATE_PATH, { run: run.id, anyway: true }, "The model cannot be validated yet.")}
              ariaLabel={`Validate the ${run.kind_title} model anyway`}
            >
              {validateLabel}
            </ConfirmButton>
          ) : (
            validateBtn
          ))}
        {run.files.report && (
          <Button size="sm" variant="secondary" iconLeft={FileText} onClick={() => onReport(run)}>
            Read report
          </Button>
        )}
        {onModel && modelOpenable(run) && (
          <Button size="sm" variant="secondary" iconLeft={Network} data-testid="assess-open-model" onClick={() => onModel(run)}>
            Open model
          </Button>
        )}
        {canImport &&
          (importAvailable ? (
            importBtn
          ) : (
            <TooltipSpan content="The SARIF import is not turned on, so findings cannot be imported. See the note above the list.">{importBtn}</TooltipSpan>
          ))}
        {canDeleteData && (
          <ConfirmButton
            variant="danger-outline"
            armedVariant="danger"
            size="sm"
            iconLeft={Trash2}
            confirmLabel="Delete evidence?"
            armedNote="Deletes the checked model and git snapshots stored for this run. The run, its report and its findings stay."
            timeoutMs={8000}
            loading={busy}
            onConfirm={() => void post(ASSESS_DELETE_DATA_PATH, { run: run.id }, "The run is no longer listed.")}
            ariaLabel={`Delete the stored evidence of the ${run.kind_title} run`}
          >
            Delete evidence
          </ConfirmButton>
        )}
        {run.state === "imported" && run.import && run.import.findings > 0 && (
          <Link to={findingsHref({ q: run.id })} className="text-[12px] text-accent hover:underline">
            See these findings
          </Link>
        )}
      </div>
    </li>
  );
}

/** earlierLabel is the label of the earlier run a run was compared with, found in the list; "" when the run chose none or the list no longer holds it. */
function earlierLabel(runs: AssessRun[], r: AssessRun): string {
  const id = (r.previous_run ?? "").trim();
  const e = id ? runs.find((x) => x.id === id) : undefined;
  return e ? assessRunLabel(e.kind_title, e.created_at, fmtDateTime) : "";
}

export function AssessRunsList({
  runs,
  importAvailable,
  onReport,
  onModel,
  onStartHeld,
}: {
  runs: AssessRun[];
  importAvailable: boolean;
  onReport: (r: AssessRun) => void;
  /** Opens the model view of a run whose model has been checked. */
  onModel?: (r: AssessRun) => void;
  /** Opens the plan on a run held for the organization once it is approved. */
  onStartHeld?: (r: AssessRun) => void;
}) {
  // A condition that holds for every row is said once, in words, with the way to
  // change it: not as a hover reason on each greyed button, which a touch screen
  // cannot reach and which names a place with no link to it.
  const importOff = !importAvailable && runs.some((r) => r.phase !== "held" && assessImportable(r));
  return (
    <>
      {importOff && (
        <div className="mb-2" data-testid="assess-import-off">
          <Callout tone="info" title="Importing findings is turned off">
            The SARIF import is not turned on here, so Import findings stays greyed on every run.{" "}
            <Link to={ASSESS_IMPORT_SETTINGS} className="text-accent hover:underline" data-testid="assess-import-settings">
              Turn it on in Settings &gt; Components
            </Link>
          </Callout>
        </div>
      )}
      <ul className="m-0 list-none p-0 text-[12.5px]" aria-label="Assessment runs" data-testid="assess-runs">
        {runs.map((r) => (
          <RunRow key={r.id} run={r} runs={runs} earlier={earlierLabel(runs, r)} importAvailable={importAvailable} onReport={onReport} onModel={onModel} onStartHeld={onStartHeld} />
        ))}
      </ul>
    </>
  );
}
