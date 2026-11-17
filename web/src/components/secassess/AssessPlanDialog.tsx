import { useEffect, useId, useMemo, useRef, useState } from "react";
import { Bot, Send } from "lucide-react";
import { Button, Callout, Input, Modal, Pill, Select, Skeleton, TooltipSpan } from "@/components/primitives";
import { HelpInd, TitleWithHelp } from "@/components/HelpInd";
import { useOptionalLaunchDock } from "@/components/LaunchDock";
import { TaskPromptBlock } from "@/components/TaskPromptBlock";
import { apiCache, useApi } from "@/lib/useApi";
import { apiReason, fetchJSON, localConfirmHeaders } from "@/lib/api";
import { projectLabel, type SecurityProject } from "@/lib/codeSecurity";
import {
  ASSESS_HELPER_SETTING,
  ASSESS_LIST_PATH,
  ASSESS_SETTINGS_WHERE,
  ASSESS_NONE,
  ASSESS_NO_CHOICES,
  ASSESS_NO_TICKS,
  ASSESS_REQUEST_PATH,
  assessConfirmWords,
  assessConsentKey,
  assessDefaultProject,
  assessHeldRuleLine,
  assessModeTone,
  assessPlanNotice,
  assessPlanPath,
  assessPreflightApart,
  assessPrimary,
  assessRefusalWords,
  assessReportLine,
  assessRequestBody,
  assessRouteWords,
  assessRowOffered,
  assessSandboxWords,
  assessScopeLine,
  assessSettingsLines,
  assessStartNote,
  assessStartText,
  assessTaskFor,
  assessTypeLabel,
  assessUnapplied,
  assessWaitingLine,
  type AssessChoices,
  type AssessKind,
  type AssessPlan,
  type AssessRun,
  type AssessTicks,
} from "@/lib/secAssess";
import { retestChoices, retestTargetSuggestion, type RetestRequest } from "@/lib/secAssessRetest";
import { AssessBeforeStart } from "./AssessBeforeStart";
import { AssessObjectiveField } from "./AssessObjectiveField";
import { AssessSettingLink } from "./AssessSettingLink";
import { AssessPreviousPicker } from "./AssessPreviousPicker";
import { AssessRequestHelper } from "./AssessRequestHelper";
import { AssessRetestPlanBlock } from "./AssessRetestPlan";
import { AssessScopePicker } from "./AssessScopePicker";
import { AssessStartPlan } from "./AssessStartPlan";
import { useOverlayEscape } from "./useOverlayEscape";

// AssessPlanDialog is the plan of one assessment (docs/plans/security-
// assessments-module-plan-2026-11-13.md sections 1, 4, 5 and 13): the kind,
// the project, for a pentest or red team the target (a candidate read from the
// project's .claude/launch.json, or one typed) and the confirmation of it,
// the guardrails a run may ask to lift with who consents to each, what the
// agent will and will not do, and the exact task text. It decides nothing:
// GET /api/security/assessments/plan runs the server's own rules (E1 to E10)
// and its consent table, and this dialog shows the answer, so a launch the
// server would refuse is shown refused here, with the rule's sentence. "Choose
// agent" then opens the New terminal dialog in task mode, where the agent
// picker is narrowed to the agents the server will accept; the launch route
// judges the rules again. When a ticked guardrail needs the organization, the
// button reads "Ask my organization" and files the request instead, and the run
// waits on the runs list until the grant is in force.
//
// Each open reads its own plan: the plan mints the run id, so the read is
// keyed by a per-open value and is never served from the cache. Opened on a
// held run, the plan replays that run (same id, target and guardrails) so the
// task text read here is the one the agent gets.
//
// The depth plan's choices (docs/plans/security-assessments-depth-plan-2026-
// 11-14.md W3 and W4) sit between the target and the settings in force: for a
// threat model its scope and the earlier run to compare with, for a pen test or
// red team how the application starts and what Observer noticed before it
// does. Each is part of the plan read's address, so changing one reads the plan
// again and the task the developer sees is the task that starts; the same
// choices go to the launch. A choice left alone sends nothing. A start plan's
// preparation steps can change local data in the project, so they run only when
// the developer ticks them under the plan; picking another plan clears the tick.

/** The reason "Choose agent" is disabled is lib/secAssess assessPrimary. */

/** ticksOfRun is the guardrails a held run was filed with. */
function ticksOfRun(run: AssessRun | null | undefined): AssessTicks {
  const rel = run?.relax ?? [];
  return { rules: rel.filter((x) => x.type !== "tier").map((x) => x.key), tier: rel.some((x) => x.type === "tier") };
}

/** choicesOfRun is the scope and comparison a held run was filed with. The
 *  start command is not recorded on the run, so the replay leaves it to the
 *  server. */
function choicesOfRun(run: AssessRun | null | undefined): AssessChoices {
  const out: AssessChoices = {};
  if (run?.scope?.paths && run.scope.paths.length > 0) out.scopePaths = run.scope.paths;
  if (run?.scope?.note) out.scopeNote = run.scope.note;
  if (run?.previous_run) out.previousRun = run.previous_run;
  if (run?.objective) out.objective = run.objective;
  if (run?.retest_of) out.ofRun = run.retest_of;
  if (run?.retest_findings && run.retest_findings.length > 0) out.findings = run.retest_findings;
  return out;
}

export function AssessPlanDialog({
  kind,
  projects,
  launch,
  onClose,
  readKey,
  heldRun,
  runs,
  retest,
}: {
  /** The kind to plan; null keeps the dialog closed. */
  kind: AssessKind | null;
  /** The projects the assessment may be run on (the Code security status read). */
  projects: SecurityProject[];
  /** The dashboard can start a terminal at all (GET /api/security/assessments). */
  launch: boolean;
  onClose: () => void;
  /** Overrides the per-open read key (tests pin it). */
  readKey?: string;
  /** A run held for the organization's approval: the plan replays it. */
  heldRun?: AssessRun | null;
  /** The recent runs: the project the picker starts on is the one assessed last (assessDefaultProject). */
  runs?: AssessRun[];
  /** A retest: the earlier run and the findings the picker chose. The project is the earlier run's and is not offered for change. */
  retest?: RetestRequest | null;
}) {
  const dock = useOptionalLaunchDock();
  const options = useMemo(() => projects.filter((p) => !!p.root_path), [projects]);
  // The project the picker starts on is chosen once, when the dialog opens: a run that appears while it is open never moves the picker.
  const [startHash] = useState(() => assessDefaultProject(options, runs)?.project_root_hash);
  const startProject = options.find((p) => p.project_root_hash === startHash) ?? assessDefaultProject(options, undefined);
  const [picked, setPicked] = useState<string | null>(heldRun?.project_root_hash ?? retest?.projectHash ?? null);
  // A retest never falls back to another project: the earlier run's own is the only one its findings belong to.
  const project = options.find((p) => p.project_root_hash === picked) ?? (retest ? undefined : startProject);
  // The target the plan is read for ("" until one is chosen), and the text
  // being typed.
  const [applied, setApplied] = useState(heldRun?.target ?? "");
  const [typed, setTyped] = useState(heldRun?.target ?? "");
  const [confirmedFor, setConfirmedFor] = useState("");
  // The guardrails the developer ticked. They belong to one project (its
  // locks are read per project), so choosing another project clears them.
  const [ticks, setTicks] = useState<AssessTicks>(() => (heldRun ? ticksOfRun(heldRun) : ASSESS_NO_TICKS));
  // The scope, comparison and start command the developer chose: they belong
  // to one project too. What is typed and not yet applied (a place, a start
  // command) is kept apart, and the button waits for it.
  const [choices, setChoices] = useState<AssessChoices>(() => (retest ? retestChoices(retest) : choicesOfRun(heldRun)));
  const [scopeTyped, setScopeTyped] = useState("");
  const [startDraft, setStartDraft] = useState<string | undefined>(undefined);
  const [asking, setAsking] = useState(false);
  const [askErr, setAskErr] = useState("");
  // The plan read a press on the button is waiting for ("" read address, null: no press waiting).
  const [pressedFor, setPressedFor] = useState<string | null>(null);
  const nonce = useRef(Math.random().toString(36).slice(2, 10));
  const key = readKey ?? nonce.current;

  const wantsPlan = kind != null && kind.launchable && project != null;
  const path = wantsPlan
    ? `${assessPlanPath(kind.id, project.project_root_hash, applied, ticks, heldRun?.id, choices)}&n=${encodeURIComponent(key)}`
    : null;
  const plan = useApi<AssessPlan>(path);
  const data = plan.data;
  // The consent is for one target in one project, not for one read of the
  // plan: every read mints a new run id, so a consent tied to it was lost each
  // time a choice below it (a guardrail, the scope, the objective) read the
  // plan again. A new target or project clears it (applyTarget).
  const confirmKey = data?.target ? assessConsentKey(project?.project_root_hash, data.target) : "";
  const confirmed = confirmKey !== "" && confirmedFor === confirmKey;
  // Data kept on screen from the previous target or project while the new
  // plan is read is not a plan to launch from: it carries the old run id.
  const reading = plan.isStale || plan.isRefreshing;
  // Only a row the server offers can be sent: a stale tick for a row that is
  // no longer offered is dropped here and again by the server.
  const effTicks = useMemo<AssessTicks>(() => {
    const rows = data?.relax?.rows ?? [];
    return {
      rules: ticks.rules.filter((k) => rows.some((r) => r.key === k && assessRowOffered(r))),
      tier: ticks.tier && rows.some((r) => r.type === "tier" && assessRowOffered(r)),
    };
  }, [data, ticks]);
  const primary = data ? assessPrimary(data, effTicks, confirmed, dock != null, launch) : null;
  // The start command in force, as the field shows it (a plan's command, not
  // its choice string), and whether what is typed in it differs: a place or a
  // command typed and not yet used is not in the task, so the button waits for
  // it rather than start without it.
  const startInForce = data?.start
    ? assessStartText(data.start, choices.start)
    : choices.start === undefined || choices.start === ASSESS_NONE
      ? ""
      : choices.start;
  const startDirty = startDraft !== undefined && startDraft.trim() !== startInForce.trim();
  const unapplied = assessUnapplied(scopeTyped, startDirty);
  // A plan being read again does not turn the button off: a choice that is
  // applied when its field loses focus (the objective, the scope note) reads
  // the plan again between the moment a press begins on the button and the
  // moment it ends, and a button that went off in between ate the click (N-8).
  // A press while the plan is read waits for the read instead (pressedFor).
  const planBlock = data ? (primary?.block ?? null) : kind && !kind.launchable ? (kind.reason ?? "This assessment has no launch") : "Reading the plan";
  const block = planBlock ?? unapplied;
  // The reason the button waits, said in words beside it once the plan is read
  // (while it is being read the skeleton already says so). A refusal the
  // dialog shows in its own note is not repeated in full here (N-10).
  const whyWaiting = kind?.launchable && data && !reading ? assessWaitingLine(block, data) : null;
  const whyId = useId();
  const needsTarget = kind?.target === "required";
  const locked = !!heldRun;

  // A retest opens on the address the earlier run used, as a suggestion: it fills the field once and nothing else, and the developer still uses it and ticks that it is theirs.
  const suggested = useRef(false);
  const suggestion = retestTargetSuggestion(data?.retest);
  useEffect(() => {
    if (suggestion && !suggested.current && typed === "" && applied === "") {
      suggested.current = true;
      setTyped(suggestion);
    }
  }, [suggestion, typed, applied]);
  // Over the model view, Escape closes this dialog and not the view under it.
  useOverlayEscape(kind != null && !!retest, onClose);

  function applyTarget(url: string) {
    const t = url.trim();
    setTyped(t);
    setApplied(t);
    setConfirmedFor("");
  }

  function toggleRule(rule: string, on: boolean) {
    setTicks((t) => ({ ...t, rules: on ? [...t.rules.filter((k) => k !== rule), rule] : t.rules.filter((k) => k !== rule) }));
    setAskErr("");
  }

  function toggleTier(on: boolean) {
    setTicks((t) => ({ ...t, tier: on }));
    setAskErr("");
  }

  function choose() {
    if (!data || block || !dock) return;
    const task = assessTaskFor(data, () => apiCache.invalidate(ASSESS_LIST_PATH), effTicks, choices);
    onClose();
    dock.openNewTerminalWithTask(task);
  }

  // Ask my organization: files the request for every ticked rule the
  // organization approves and holds the run. Nothing starts.
  async function ask() {
    if (!data || block) return;
    setAsking(true);
    setAskErr("");
    try {
      await fetchJSON(ASSESS_REQUEST_PATH, undefined, {
        method: "POST",
        headers: await localConfirmHeaders(),
        body: JSON.stringify(assessRequestBody(data, effTicks, choices)),
      });
      apiCache.invalidate(ASSESS_LIST_PATH);
      onClose();
    } catch (e) {
      setAskErr(assessRefusalWords(e) ?? apiReason(e));
    } finally {
      setAsking(false);
    }
  }

  function primaryClick() {
    // The plan on screen is being read again (a choice was just applied): the press waits for that read and then does what the button says, so the first press after typing in a field is never lost (N-8).
    if (reading && path !== null) {
      setPressedFor(path);
      return;
    }
    if (primary?.action === "ask") void ask();
    else if (primary?.action === "start") choose();
  }

  // Run the press that waited, once the plan it waited for is read and only if it is still the plan on screen and nothing stops it: another change since the press, or a refusal, leaves the button for the person to press again.
  const latest = useRef(primaryClick);
  latest.current = primaryClick;
  useEffect(() => {
    if (pressedFor === null || reading) return;
    setPressedFor(null);
    if (path === pressedFor && data && block === null) latest.current();
  }, [pressedFor, reading, path, data, block]);

  const chooseBtn = (
    <Button
      variant="primary"
      iconLeft={primary?.action === "ask" ? Send : Bot}
      loading={asking || pressedFor !== null}
      disabled={block !== null || primary?.action === "wait"}
      aria-describedby={whyWaiting ? whyId : undefined}
      onClick={primaryClick}
    >
      {primary?.label ?? "Choose agent"}
    </Button>
  );

  const relax = data?.relax;
  const scopeLine = assessScopeLine(relax, effTicks);
  const limitLines = assessSettingsLines(data);

  return (
    <Modal
      open={kind != null}
      onClose={onClose}
      title={<TitleWithHelp text={kind ? kind.title : "Security assessment"} helpId="card.code_security_assess_plan" />}
      subtitle={project ? `In ${projectLabel(project)}` : undefined}
      width={680}
      bodyClassName="px-5 py-4"
      footer={
        <div className="flex flex-wrap items-center justify-end gap-2">
          {/* The reason the button waits is text beside it, not only a tooltip: a touch screen has no hover and the tooltip is only on focus. */}
          {whyWaiting && (
            <p id={whyId} className="m-0 min-w-0 flex-1 basis-48 text-left text-[11.5px] text-fg-3" data-testid="assess-choose-reason">
              {whyWaiting}
            </p>
          )}
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          {kind?.launchable && (block ? <TooltipSpan content={block}>{chooseBtn}</TooltipSpan> : chooseBtn)}
        </div>
      }
    >
      {kind && (
        <div className="space-y-4 text-[12.5px]" data-testid="assess-plan">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <Pill variant={assessModeTone(kind)} case="none">
                {kind.mode}
              </Pill>
              <span className="text-fg-3">{assessSandboxWords(kind.sandbox)}</span>
            </div>
            <p className="m-0 text-fg-1">{kind.summary}</p>
            {kind.note && <p className="m-0 text-fg-3">{kind.note}</p>}
          </div>

          {!kind.launchable && (
            <Callout tone="info" title="Nothing to launch">
              {kind.reason}
              {kind.pointer && <span className="mt-1 block text-fg-3">{kind.pointer}</span>}
            </Callout>
          )}

          {kind.launchable && options.length === 0 && (
            <p className="m-0 text-fg-2" data-testid="assess-no-project">
              No project with a folder on this machine is known yet. Work in a project with an agent first, then come back.
            </p>
          )}

          {kind.launchable && options.length > 0 && (
            <Select
              label="Project"
              value={project?.project_root_hash ?? ""}
              disabled={locked || !!retest}
              onChange={(e) => {
                setPicked(e.target.value);
                setTicks(ASSESS_NO_TICKS);
                setChoices(ASSESS_NO_CHOICES);
                setScopeTyped("");
                setStartDraft(undefined);
                applyTarget("");
              }}
              data-testid="assess-project"
            >
              {options.map((p) => (
                <option key={p.project_root_hash} value={p.project_root_hash}>
                  {projectLabel(p)}
                </option>
              ))}
            </Select>
          )}

          {plan.loading && !data && wantsPlan && (
            <div className="space-y-2" role="status" aria-label="Reading the plan">
              <p className="m-0 text-fg-3">Reading the plan</p>
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-24 w-full" />
            </div>
          )}
          {plan.notInstalled && (
            <p className="m-0 text-fg-2">Code security is not installed on this machine, so there is no assessment to start from here.</p>
          )}
          {plan.error && !plan.notInstalled && (
            <div className="space-y-2">
              <p role="alert" className="m-0 text-danger">
                {`The plan could not be read: ${apiReason(plan.error)}`}
              </p>
              <Button size="sm" variant="secondary" onClick={plan.reload}>
                Retry
              </Button>
            </div>
          )}

          {data && (
            <>
              {needsTarget && (
                <section aria-labelledby="assess-target" className="space-y-2" data-testid="assess-target">
                  <h3 id="assess-target" className="m-0 text-[12px] font-medium text-fg-2">
                    Target
                  </h3>
                  {data.candidates.length > 0 && !locked && (
                    <ul className="m-0 list-none space-y-1 p-0" aria-label="Addresses read from the project's launch file">
                      {data.candidates.map((c) => (
                        <li key={c.url}>
                          <label className="flex cursor-pointer items-center gap-2 rounded-2 border border-line-2 px-2.5 py-1.5">
                            <input
                              type="radio"
                              name="assess-target-candidate"
                              checked={data.target_typed && data.target === c.url}
                              onChange={() => applyTarget(c.url)}
                            />
                            <span className="min-w-0 break-all font-mono text-[11.5px] text-fg-1">{c.url}</span>
                            {c.name && <span className="text-fg-3">{c.name}</span>}
                            {c.source && <span className="text-[11.5px] text-fg-3">{`from ${c.source}`}</span>}
                          </label>
                        </li>
                      ))}
                    </ul>
                  )}
                  {!locked && (
                    <form
                      className="flex flex-wrap items-end gap-2"
                      onSubmit={(e) => {
                        e.preventDefault();
                        applyTarget(typed);
                      }}
                    >
                      <div className="min-w-0 flex-1 basis-56">
                        <Input
                          mono
                          label={assessTypeLabel("the address of your development server", data.candidates.length > 0)}
                          placeholder="http://localhost:3000/"
                          value={typed}
                          onChange={(e) => setTyped(e.target.value)}
                          help="Loopback only: localhost, 127.0.0.1 or ::1, with the port."
                          data-testid="assess-target-input"
                        />
                      </div>
                      <Button type="submit" size="sm" variant="secondary" disabled={typed.trim() === ""}>
                        Use this address
                      </Button>
                    </form>
                  )}
                  {data.target_typed && data.target && (
                    <p className="m-0 text-fg-2">
                      Target: <span className="font-mono text-fg-1">{data.target}</span>
                    </p>
                  )}
                  {/* The consent sits directly under the target it is about, not below the guardrails and the list of what the agent is told not to do: the button waits for it, so it must be where the target was just chosen. */}
                  {data.ok && data.target_typed && data.target && (
                    <label className="flex cursor-pointer items-start gap-2 rounded-2 border border-warn/40 bg-warn/10 px-2.5 py-2" data-testid="assess-confirm">
                      <input
                        type="checkbox"
                        className="mt-0.5"
                        checked={confirmed}
                        onChange={(e) => setConfirmedFor(e.target.checked ? confirmKey : "")}
                      />
                      <span className="text-fg-1">{assessConfirmWords(data.target)}</span>
                    </label>
                  )}
                </section>
              )}

              {data.retest && <AssessRetestPlanBlock retest={data.retest} vocab={retest?.vocab} />}

              {data.objective && (
                <AssessObjectiveField
                  objective={data.objective}
                  value={choices.objective ?? ""}
                  locked={locked}
                  onApply={(text) => setChoices((c) => ((c.objective ?? "") === text ? c : { ...c, objective: text === "" ? undefined : text }))}
                />
              )}

              {!data.ok && data.reason && (
                <Callout tone="warn" title="This cannot start here">
                  {assessPlanNotice(data)}
                  {/* The one refusal a first retest is likely to meet says which switch to turn on: it links to that row (N-10). */}
                  {data.code === "retest_helper" && (
                    <span className="mt-1 block">
                      <AssessSettingLink settingKey={ASSESS_HELPER_SETTING} />
                    </span>
                  )}
                </Callout>
              )}

              {data.ok && data.backend && (
                <p className="m-0 text-fg-2" data-testid="assess-sandbox">
                  {`Sandbox: ${data.backend}${data.tier ? `, network ${data.tier === "proxy_only" ? "through Observer's model proxy only" : data.tier}` : ""}.`}
                </p>
              )}
              {data.residual && <p className="m-0 text-[11.5px] text-fg-3">{data.residual}</p>}

              {data.scope && (
                <AssessScopePicker
                  key={project?.project_root_hash ?? ""}
                  scope={data.scope}
                  paths={choices.scopePaths ?? []}
                  note={choices.scopeNote ?? data.scope.note}
                  typed={scopeTyped}
                  locked={locked}
                  onPaths={(p) => setChoices((c) => ({ ...c, scopePaths: p.length > 0 ? p : undefined }))}
                  onNote={(n) => setChoices((c) => ((c.scopeNote ?? "") === n ? c : { ...c, scopeNote: n === "" ? undefined : n }))}
                  onTyped={setScopeTyped}
                />
              )}

              {data.previous && (
                <AssessPreviousPicker
                  previous={data.previous}
                  chosen={choices.previousRun}
                  locked={locked}
                  onChange={(id) => setChoices((c) => ({ ...c, previousRun: id }))}
                />
              )}

              {data.start && (
                <AssessStartPlan
                  start={data.start}
                  chosen={choices.start}
                  draft={startDraft}
                  locked={locked}
                  prepare={choices.prepare}
                  onChoose={(choice) => {
                    // The preparation steps belong to one plan: a new pick starts unticked.
                    setChoices((c) => ({ ...c, start: choice, prepare: undefined }));
                    setStartDraft(undefined);
                  }}
                  onDraft={setStartDraft}
                  onUse={(text) => {
                    setChoices((c) => ({ ...c, start: text.trim() === "" ? ASSESS_NONE : text.trim(), prepare: undefined }));
                    setStartDraft(undefined);
                  }}
                  onPrepare={(on) => setChoices((c) => ({ ...c, prepare: on ? true : undefined }))}
                  note={assessStartNote(data.preflight)}
                />
              )}

              <AssessBeforeStart preflight={assessPreflightApart(data.preflight, data.start)} env={data.env} tools={data.tools} safety={data.safety} />

              {data.probe && <AssessRequestHelper probe={data.probe} />}

              {limitLines.length > 0 && (
                <section aria-labelledby="assess-limits" className="space-y-1.5" data-testid="assess-limits">
                  <h3 id="assess-limits" className="m-0 flex items-center text-[12px] font-medium text-fg-2">
                    Settings in force for this run
                    <HelpInd id="card.code_security_assess_limits" />
                  </h3>
                  <ul className="m-0 list-none space-y-1 p-0">
                    {limitLines.map((l) => (
                      <li key={l.text} className={l.tone === "warn" ? "text-warn" : "text-fg-2"}>
                        {l.text}
                        {l.help && <HelpInd id={l.help} />}
                      </li>
                    ))}
                  </ul>
                  <p className="m-0 text-[11.5px] text-fg-3">
                    Observer checks structure, file references and git state. It does not check that the agent&apos;s reasoning is right. Change
                    these in {ASSESS_SETTINGS_WHERE}.
                  </p>
                </section>
              )}

              {relax && relax.rows.length > 0 && (
                <section aria-labelledby="assess-relax" className="space-y-2" data-testid="assess-relax">
                  <h3 id="assess-relax" className="m-0 flex items-center text-[12px] font-medium text-fg-2">
                    Guardrails for this run
                    <HelpInd id="card.code_security_assess_relax" />
                  </h3>
                  <p className="m-0 text-fg-3">
                    Observer&apos;s guard keeps all of its rules on. {kind.id === "red_team_local" ? "A red team exercise" : "A pen test"} can need one lifted for this run only. Nothing is lifted unless you
                    tick it, and each one needs a consent: yours on a machine you manage yourself, your organization&apos;s on a managed one.
                  </p>
                  <ul className="m-0 list-none space-y-2 p-0">
                    {relax.rows.map((row) => {
                      const offered = assessRowOffered(row);
                      const on = row.type === "tier" ? effTicks.tier : effTicks.rules.includes(row.key);
                      return (
                        <li key={row.key} className="space-y-1 rounded-2 border border-line-2 px-2.5 py-2" data-testid={`assess-relax-${row.key}`}>
                          <div className="flex flex-wrap items-center gap-2">
                            {offered ? (
                              <label className="flex cursor-pointer items-start gap-2">
                                <input
                                  type="checkbox"
                                  className="mt-0.5"
                                  checked={on}
                                  disabled={locked}
                                  onChange={(e) => (row.type === "tier" ? toggleTier(e.target.checked) : toggleRule(row.key, e.target.checked))}
                                />
                                <span className="text-fg-1">{row.title}</span>
                              </label>
                            ) : (
                              <span className="text-fg-2">{row.title}</span>
                            )}
                            <Pill variant={row.route === "org_request" ? "warn" : offered ? "info" : "neutral"} case="none">
                              {assessRouteWords(row.route)}
                            </Pill>
                          </div>
                          <p className="m-0 text-[11.5px] text-fg-3">{row.lifts}</p>
                          <p className="m-0 text-[11.5px] text-fg-2">{row.reason}</p>
                        </li>
                      );
                    })}
                  </ul>
                  {scopeLine && (
                    <p className="m-0 text-warn" data-testid="assess-relax-scope">
                      {scopeLine}
                    </p>
                  )}
                  <p className="m-0 text-[11.5px] text-fg-3" data-testid="assess-relax-report">
                    {assessReportLine(relax)}
                  </p>
                </section>
              )}

              {data.held && (
                <Callout tone={data.held.ready ? "success" : "info"} title={data.held.ready ? "Your organization approved this" : "Waiting for your organization"}>
                  <ul className="m-0 list-none space-y-0.5 p-0" data-testid="assess-held-rules">
                    {data.held.rules.map((r) => (
                      <li key={r.rule}>{assessHeldRuleLine(r)}</li>
                    ))}
                  </ul>
                </Callout>
              )}

              <section aria-labelledby="assess-boundary" className="space-y-1.5">
                <h3 id="assess-boundary" className="m-0 flex items-center text-[12px] font-medium text-fg-2">
                  What the agent is told not to do
                  <HelpInd id="card.code_security_assess_plan" />
                </h3>
                <ul className="m-0 list-disc space-y-1 pl-5 text-fg-2" data-testid="assess-boundary-list">
                  {data.boundary.map((b) => (
                    <li key={b}>{b}</li>
                  ))}
                </ul>
              </section>

              {askErr && (
                <p role="alert" className="m-0 text-danger" data-testid="assess-ask-error">
                  {askErr}
                </p>
              )}

              {data.prompt ? (
                <section aria-labelledby="assess-prompt" className="space-y-1.5">
                  <h3 id="assess-prompt" className="m-0 text-[12px] font-medium text-fg-2">
                    The task the agent gets
                  </h3>
                  <TaskPromptBlock text={data.prompt} testId="assess-prompt-text" />
                  <p className="m-0 text-[11.5px] text-fg-3">
                    Next you pick the agent. The launch policy and your organization&apos;s rules apply as for any new terminal. The agent
                    writes its report and findings into .observer/assessments/{data.run_id}/; you read and import them from the run.
                  </p>
                </section>
              ) : (
                needsTarget && (
                  <p className="m-0 text-fg-3">The task text appears once you have chosen and checked a target.</p>
                )
              )}
            </>
          )}
        </div>
      )}
    </Modal>
  );
}
