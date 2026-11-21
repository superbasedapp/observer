// SandboxSetupPanel.tsx is the sandbox setup checklist (sandbox installation
// lifecycle plan section 3.7), rendered through the compgen registry
// (SANDBOX_SETUP_PANEL, component terminals.sandbox) so a build without the
// Sandboxes and VMs module ships none of it. The New Terminal dialog renders
// it inline (compact) under the Isolation picker; Settings > Terminals >
// Sandbox isolation renders it full size behind each backend's "Set up" or
// "Manage" button.
//
// It talks only to the setup routes of plan 3.6: GET
// /api/terminal/sandbox/setup (the row chooser), GET .../setup/<backend>
// (the plan, passive facts), POST .../check ("Check this machine"), POST
// .../run (one step) and GET .../setup/op/<id> (an in-process op's
// progress). The two POSTs are Local and confirm-token gated; the token is
// read from /api/remote/config exactly as the guided agent install does. The
// request names only the step, the action, the plan fingerprint and, for a
// download, the consent the person saw: the daemon derives every command.
// Every copy decision lives in lib/sandboxSetup.ts; this file owns state.
// When the routes answer 404 component_not_installed or 501, it renders
// nothing.

import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { CircleHelp, Copy, KeyRound, SquareTerminal } from "lucide-react";
import { Button, ComboChip, ConfirmButton, Pill } from "@/components/primitives";
import { ApiError, fetchJSON, localConfirmHeaders } from "@/lib/api";
import { noteWithText, type ErrorNote } from "@/lib/needsSetting";
import { ApiErrorNotice } from "@/components/NeedsSettingNotice";
import { TERMINALS_SANDBOX_BACKENDS_HASH } from "@/lib/nodePageTabs";
import { HostedKeyFields } from "@/components/SandboxHostedStatus";
import { hostedConnectReady } from "@/lib/sandboxParity";
import { useProjectRootOptions } from "@/lib/usePickerSources";
import { useApi } from "@/lib/useApi";
import {
  CONSENT_FOLDER_NOTE,
  DEFAULT_WORKSPACE_PATH,
  WORKSPACE_OPTION_LABEL,
  consentDefault,
  type DefaultWorkspaceView,
} from "@/lib/defaultWorkspace";
import {
  CREDENTIAL_FORM_NOTE,
  CREDENTIAL_STORE_LABEL,
  CREDENTIAL_STORED_NOTE,
  NO_TOKEN_MSG,
  SETUP_HELP_LABEL,
  afterNote,
  consentFolderFor,
  consentLine,
  consentNeedsFolder,
  credentialErrorSentence,
  undoArmedNote,
  credentialFields,
  credentialGuideNote,
  credentialRunFields,
  defaultSetupBackend,
  elevatedGuideHint,
  manageActions,
  maybeWaitingForInput,
  opProgress,
  opProgressLabel,
  parseSetupError,
  planHeadline,
  planInFlight,
  recordView,
  setupErrorSentence,
  setupHelpId,
  setupSettleReprobe,
  setupRoutesAbsent,
  stateChip,
  stepButtonLabel,
  stepButtonRuns,
  stepCopyText,
  summaryFromPlan,
  summaryOptionLabel,
  unknownStepHint,
  type ChipTone,
} from "@/lib/sandboxSetup";
import { waitingForInputNote } from "@/lib/toolUninstall";
import type {
  SandboxSetupAction,
  SandboxSetupOp,
  SandboxSetupPanelProps,
  SandboxSetupPlan,
  SandboxSetupRunRequest,
  SandboxSetupStarted,
  SandboxSetupStep,
  SandboxSetupSummary,
  SandboxSetupSummaryResponse,
} from "@/lib/sandboxSetupTypes";

/**
 * SandboxSetupPanelExtras are this component's additions to the contract's
 * SandboxSetupPanelProps: seeds for render tests (server rendering runs no
 * effect, so no fetch answers there) and a callback that tells the dialog
 * which row the chooser is on, so its resume draft names it.
 */
export type SandboxSetupPanelExtras = {
  /** Seeds GET /api/terminal/sandbox/setup (tests only). */
  initialSummaries?: SandboxSetupSummary[];
  /** Seeds the plan of the starting row (tests only). */
  initialPlan?: SandboxSetupPlan;
  /** The row chooser moved to another backend. */
  onBackendChange?: (backend: string) => void;
  /** A step settled, or a check answered: the caller may probe again. */
  onSettled?: () => void;
  /** The caller came back from a setup terminal (its first plan re-probes). */
  resumed?: boolean;
};

const TONE_VARIANT: Record<ChipTone, "success" | "warn" | "danger" | "info" | "neutral"> = {
  ok: "success",
  warn: "warn",
  bad: "danger",
  info: "info",
  muted: "neutral",
};

// Op statuses that are still moving (internal/toolinstall vocabulary).
const OP_RUNNING = new Set(["installing", "uninstalling", "running", "queued", ""]);

const enc = encodeURIComponent;

// confirmHeaders is the owner-local confirm header from localConfirmHeaders
// (the core command-job list mints it). Never /api/remote/config: that is a
// Remote dashboard route, refused while that component is off. Null when no
// token could be had (the panel then says to reload).
async function confirmHeaders(): Promise<Record<string, string> | null> {
  const headers = await localConfirmHeaders();
  return headers["X-Observer-Confirm"] ? headers : null;
}

export function SandboxSetupPanel(props: SandboxSetupPanelProps & SandboxSetupPanelExtras) {
  const { backend: preselected, onTerminal, onReady, onNavigate, compact = false, initialSummaries, initialPlan, onBackendChange, onSettled, resumed = false } = props;
  const [absent, setAbsent] = useState(false);
  const [summaries, setSummaries] = useState<SandboxSetupSummary[] | null>(initialSummaries ?? null);
  const [backend, setBackend] = useState<string | undefined>(() =>
    initialPlan?.backend ?? (initialSummaries ? defaultSetupBackend(initialSummaries, preselected) : preselected),
  );
  const [plan, setPlan] = useState<SandboxSetupPlan | null>(initialPlan ?? null);
  const [planNonce, setPlanNonce] = useState(0);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<ErrorNote | string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [op, setOp] = useState<(SandboxSetupOp & { step: string }) | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const seededPlan = useRef(initialPlan?.backend);
  const readyFor = useRef<string | null>(null);
  const prevInFlight = useRef<boolean | null>(null);

  // The row chooser's list. A seeded list skips the fetch (tests).
  useEffect(() => {
    if (initialSummaries) return;
    let cancelled = false;
    fetchJSON<SandboxSetupSummaryResponse>("/api/terminal/sandbox/setup")
      .then((r) => {
        if (cancelled) return;
        const rows = r.backends ?? [];
        setSummaries(rows);
        setBackend((cur) => (cur && rows.some((s) => s.backend === cur) ? cur : defaultSetupBackend(rows, preselected)));
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        if (e instanceof ApiError && setupRoutesAbsent(e.status, e.body)) setAbsent(true);
        else setLoadErr(e instanceof ApiError ? setupErrorSentence(e.status, e.body) : setupErrorSentence(0, ""));
      });
    return () => {
      cancelled = true;
    };
    // initialSummaries is a test seed, read once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // A new preselection from the caller (the picker chose another row).
  useEffect(() => {
    if (preselected) setBackend(preselected);
  }, [preselected]);

  useEffect(() => {
    if (backend) onBackendChange?.(backend);
  }, [backend, onBackendChange]);

  // The chosen row's plan (passive facts). Re-check bumps planNonce.
  useEffect(() => {
    if (!backend) return;
    if (seededPlan.current === backend && planNonce === 0) {
      seededPlan.current = undefined;
      return;
    }
    let cancelled = false;
    fetchJSON<SandboxSetupPlan>(`/api/terminal/sandbox/setup/${enc(backend)}`)
      .then((p) => {
        if (!cancelled) {
          setPlan(p);
          setLoadErr(null);
        }
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        if (e instanceof ApiError && setupRoutesAbsent(e.status, e.body)) setAbsent(true);
        else setLoadErr(e instanceof ApiError ? setupErrorSentence(e.status, e.body) : setupErrorSentence(0, ""));
      });
    return () => {
      cancelled = true;
    };
  }, [backend, planNonce]);

  // Poll an in-process op (a download) while it runs, then rebuild the plan.
  useEffect(() => {
    if (!op || !OP_RUNNING.has(op.status)) return;
    let cancelled = false;
    const t = window.setTimeout(() => {
      fetchJSON<SandboxSetupOp>(`/api/terminal/sandbox/setup/op/${enc(op.id)}`)
        .then((o) => {
          if (cancelled) return;
          setOp({ ...o, step: op.step });
          if (!OP_RUNNING.has(o.status)) {
            if (o.error) setErr(o.error);
            setPlanNonce((n) => n + 1);
            // The op may have written config.toml: the caller re-reads (D5).
            onSettled?.();
          }
        })
        .catch((e: unknown) => {
          if (cancelled) return;
          setErr(e instanceof ApiError ? noteWithText(e, setupErrorSentence(e.status, e.body)) : setupErrorSentence(0, ""));
          setOp(null);
          setPlanNonce((n) => n + 1);
        });
    }, 1000);
    return () => {
      cancelled = true;
      window.clearTimeout(t);
    };
  }, [op]);

  // While a step runs in a terminal, re-read the plan and the clock every
  // 15 s, so its record settles and the 90 s waiting hint can appear. Not
  // faster: a plan GET resolves programs through the login-shell PATH.
  const anyInFlight = planInFlight(plan);
  useEffect(() => {
    if (!anyInFlight) return;
    const t = window.setInterval(() => {
      setNow(Date.now());
      setPlanNonce((n) => n + 1);
    }, 15_000);
    return () => window.clearInterval(t);
  }, [anyInFlight]);

  // A step settled (or the first plan after a resume): the caller probes
  // again, so its availability text follows (D-R4-2).
  useEffect(() => {
    if (!plan) return;
    const inFlight = planInFlight(plan);
    const reprobe = setupSettleReprobe(prevInFlight.current, inFlight, resumed);
    prevInFlight.current = inFlight;
    if (reprobe) onSettled?.();
  }, [plan, resumed, onSettled]);

  // The row became ready: tell the caller once per row.
  useEffect(() => {
    if (plan?.ready && readyFor.current !== plan.backend) {
      readyFor.current = plan.backend;
      onReady?.(plan.backend);
    }
  }, [plan, onReady]);

  if (absent) return null;

  // fields is a credential step's typed values: sent once in the run
  // request body and never kept, shown or put in an error here.
  // fromFile is the project a consent step is for (sent as from_file).
  async function run(step: SandboxSetupStep, action: SandboxSetupAction, fields?: Record<string, string>, fromFile?: string) {
    if (!plan || busy) return;
    setBusy(`${action}:${step.prereq}`);
    setErr(null);
    setNote(null);
    try {
      const headers = await confirmHeaders();
      if (!headers) {
        setErr(NO_TOKEN_MSG);
        return;
      }
      const body: SandboxSetupRunRequest = {
        step: step.prereq,
        action,
        fingerprint: plan.fingerprint,
        ...(action !== "undo" && step.consent ? { consent: step.consent } : {}),
        ...(fields ? { fields } : {}),
        ...(fromFile ? { from_file: fromFile } : {}),
      };
      const r = await fetchJSON<SandboxSetupStarted>(`/api/terminal/sandbox/setup/${enc(plan.backend)}/run`, undefined, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
      if (r.kind === "terminal" && r.handle) {
        onTerminal(r.handle, r.label || `${plan.label} setup: ${step.label}`);
        setPlanNonce((n) => n + 1);
      } else if (r.kind === "op" && r.op_id) {
        setOp({ id: r.op_id, status: "installing", done_bytes: 0, total_bytes: step.consent?.bytes ?? 0, step: step.prereq });
      } else if (r.plan) {
        setPlan(r.plan);
        // A step that finished in the request (an Undo, a config write) may
        // have changed config.toml: the caller re-reads its own copy, so an
        // editor on the same page never saves over it with stale values (D5).
        onSettled?.();
      } else {
        setPlanNonce((n) => n + 1);
        onSettled?.();
      }
      if (fields) setNote(CREDENTIAL_STORED_NOTE);
    } catch (e) {
      if (e instanceof ApiError) {
        const parsed = parseSetupError(e.body);
        // 409 plan_changed: show the fresh plan and ask again.
        if (parsed.code === "plan_changed" && parsed.plan) setPlan(parsed.plan);
        setErr(noteWithText(e, fields ? credentialErrorSentence(e.status, e.body) : setupErrorSentence(e.status, e.body)));
      } else {
        setErr(setupErrorSentence(0, ""));
      }
    } finally {
      setBusy(null);
    }
  }

  async function check() {
    if (!plan || busy) return;
    setBusy("check");
    setErr(null);
    setNote(null);
    try {
      const headers = await confirmHeaders();
      if (!headers) {
        setErr(NO_TOKEN_MSG);
        return;
      }
      const p = await fetchJSON<SandboxSetupPlan>(`/api/terminal/sandbox/setup/${enc(plan.backend)}/check`, undefined, {
        method: "POST",
        headers,
        body: "{}",
      });
      setPlan(p);
      onSettled?.();
    } catch (e) {
      setErr(e instanceof ApiError ? noteWithText(e, setupErrorSentence(e.status, e.body)) : setupErrorSentence(0, ""));
    } finally {
      setBusy(null);
    }
  }

  // The chooser's labels follow the open row's latest plan (D-R4-3).
  const shownSummaries = summaries ? summaryFromPlan(summaries, plan) : null;

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setNote("Copied. Paste it into a terminal of your own, then press Re-check.");
    } catch {
      setNote("Copying is not allowed here: select the command above and copy it yourself.");
    }
  }

  return (
    <div
      data-testid="sandbox-setup-panel"
      className={compact ? "mt-1 rounded-2 border border-line-2 bg-bg-2 p-2 text-[11px] [overflow-wrap:anywhere]" : "space-y-2 rounded-2 border border-line-2 p-3 text-[12px] [overflow-wrap:anywhere]"}
    >
      {summaries && summaries.length > 0 && (
        <div className="mb-1">
          <label htmlFor="sandbox-setup-backend" className="mb-0.5 block font-medium text-fg-1">
            Set up a sandbox backend
          </label>
          <select
            id="sandbox-setup-backend"
            value={backend ?? ""}
            onChange={(e) => {
              setErr(null);
              setNote(null);
              setOp(null);
              setBackend(e.target.value);
            }}
            className="w-full rounded-2 border bg-bg-0 px-2 py-1 text-[12px] text-fg-1"
          >
            {(shownSummaries ?? summaries).map((s) => (
              <option key={s.backend} value={s.backend}>
                {summaryOptionLabel(s)}
              </option>
            ))}
          </select>
        </div>
      )}
      {summaries && summaries.length === 0 && <p className="text-fg-3">No sandbox backend can be set up on this machine.</p>}
      {loadErr && (
        <p role="alert" className="text-danger">
          {loadErr}
        </p>
      )}
      {plan && plan.backend === backend && (
        <>
          <p className="font-medium text-fg-1" data-testid="sandbox-setup-headline">
            {planHeadline(plan)}
            {plan.beta && (
              <>
                {" "}
                <Pill variant="warn" case="none">
                  Beta
                </Pill>
              </>
            )}
          </p>
          {plan.beta && (
            <p className="text-fg-3" data-testid="sandbox-setup-beta">
              {plan.beta}
            </p>
          )}
          {!plan.blocked && (
            <div className="my-1 flex flex-wrap items-center gap-2">
              <Button size="sm" variant="secondary" onClick={check} loading={busy === "check"} disabled={!!busy}>
                Check this machine
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setPlanNonce((n) => n + 1)} disabled={!!busy}>
                Re-check
              </Button>
              <span className="text-fg-3">
                {plan.checked
                  ? "Checked just now with this backend's own probe."
                  : "Based on what Observer sees without running anything. Check this machine runs this backend's own probe once."}
              </span>
            </div>
          )}
          <ol className="space-y-1.5" aria-label={`Steps to set up ${plan.label}`}>
            {plan.steps.map((s, i) => (
              <StepRow
                key={s.prereq}
                step={s}
                isNext={i === plan.next}
                compact={compact}
                busy={busy}
                now={now}
                op={op && op.step === s.prereq ? op : null}
                onRun={(a, fromFile) => run(s, a, undefined, fromFile)}
                onStoreKey={(values) => run(s, "run", values)}
                onCopy={copy}
                onOpenTerminal={(h) => onTerminal(h, `${plan.label} setup: ${s.label}`)}
              />
            ))}
          </ol>
        </>
      )}
      <ApiErrorNotice note={err} onNavigate={onNavigate} className="mt-1" plainClassName="mt-1 text-danger" />
      {note && <p className="mt-1 text-fg-2">{note}</p>}
      {compact && (
        <Link to={`/terminals${TERMINALS_SANDBOX_BACKENDS_HASH}`} onClick={onNavigate} className="mt-1 inline-block text-accent hover:underline">
          Manage sandbox backends in Terminals settings
        </Link>
      )}
    </div>
  );
}

function StepRow({
  step,
  isNext,
  compact,
  busy,
  now,
  op,
  onRun,
  onStoreKey,
  onCopy,
  onOpenTerminal,
}: {
  step: SandboxSetupStep;
  isNext: boolean;
  compact: boolean;
  busy: string | null;
  now: number;
  op: (SandboxSetupOp & { step: string }) | null;
  onRun: (a: SandboxSetupAction, fromFile?: string) => void;
  onStoreKey: StoreKeyFn;
  onCopy: (text: string) => void;
  onOpenTerminal: (handle: string) => void;
}) {
  const chip = stateChip(step.state);
  const label = stepButtonLabel(step);
  const runs = stepButtonRuns(step);
  const copyText = stepCopyText(step);
  const settled = step.state === "done" || step.state === "not_applicable";
  const showPrimary = !!label && !settled && (runs ? step.can_run : !!copyText);
  const keyFields = credentialFields(step);
  const rec = step.record;
  const recView = rec ? recordView(rec, step.state === "done") : null;
  const waiting = maybeWaitingForInput(rec, now);
  const helpId = setupHelpId(step);
  const after = afterNote(step.after);
  const hint = credentialGuideNote(step) ?? elevatedGuideHint(step) ?? unknownStepHint(step);
  const progress = op ? opProgress(op.done_bytes, op.total_bytes) : null;
  const actions = compact ? [] : manageActions(step);
  // A consent is for one project: the setup terminal starts in the home
  // directory, which is never uploaded, so the step asks which project first.
  // A Repair or Update of a consent step runs the consent screen again, so
  // it asks too and sends the pick (consentFolderFor).
  const needsProject = step.channel === "hosted_consent" && !settled;
  const showsProject = consentNeedsFolder(step, settled, actions);
  const [project, setProject] = useState("");
  return (
    <li data-step={step.prereq} className={isNext ? "rounded-2 border border-accent/40 p-1.5" : "rounded-2 border border-line-2 p-1.5"}>
      <div className="flex flex-wrap items-center gap-2">
        <Pill variant={TONE_VARIANT[chip.tone]} case="none">
          {chip.label}
        </Pill>
        <span className="font-medium text-fg-1">{step.label}</span>
      </div>
      {step.display &&
        (step.display_is_command ? (
          <code className="mt-0.5 block whitespace-pre-wrap break-all font-mono text-fg-2">{step.display}</code>
        ) : (
          <p className="mt-0.5 text-fg-2">{step.display}</p>
        ))}
      {step.class === "guide" && step.command && (
        <code className="mt-0.5 block whitespace-pre-wrap break-all font-mono text-fg-2" data-testid="sandbox-setup-command">
          {step.command}
        </code>
      )}
      {step.reason && <p className="mt-0.5 text-fg-3">{step.reason}</p>}
      {/* Disclosures and the download consent come BEFORE the button. */}
      {step.disclosure && <p className="mt-0.5 text-warn">Before you run it: {step.disclosure}</p>}
      {step.consent && <p className="mt-0.5 text-fg-2">{consentLine(step.consent)}</p>}
      {after && <p className="mt-0.5 text-fg-3">{after}</p>}
      {hint && <p className="mt-0.5 text-fg-3">{hint}</p>}
      {showsProject && <ConsentProject value={project} onChange={setProject} />}
      {keyFields && <KeyForm prereq={step.prereq} label={step.label} names={keyFields} primary={isNext} busy={busy} onStore={onStoreKey} />}
      {(showPrimary || actions.length > 0 || (rec?.terminal_handle && step.state === "in_flight")) && (
        <div className="mt-1 flex flex-wrap items-center gap-2">
          {showPrimary &&
            (runs ? (
              <Button
                size="sm"
                variant={isNext ? "primary" : "secondary"}
                onClick={() => onRun("run", consentFolderFor(step, "run", project))}
                loading={busy === `run:${step.prereq}`}
                disabled={!!busy || (needsProject && !project)}
              >
                {label}
              </Button>
            ) : (
              <Button size="sm" variant="secondary" iconLeft={Copy} onClick={() => onCopy(copyText ?? "")}>
                {label}
              </Button>
            ))}
          {rec?.terminal_handle && step.state === "in_flight" && (
            <Button size="sm" variant="secondary" iconLeft={SquareTerminal} onClick={() => onOpenTerminal(rec.terminal_handle as string)}>
              Open the install terminal
            </Button>
          )}
          {actions.map((a) =>
            a.action === "undo" ? (
              <ConfirmButton
                key={a.action}
                size="sm"
                variant="secondary"
                confirmLabel="Undo this step?"
                disabled={!!busy}
                loading={busy === `undo:${step.prereq}`}
                armedNote={undoArmedNote(step)}
                onConfirm={() => onRun("undo")}
              >
                {a.label}
              </ConfirmButton>
            ) : (
              <Button
                key={a.action}
                size="sm"
                variant="secondary"
                onClick={() => onRun(a.action, consentFolderFor(step, a.action, project))}
                loading={busy === `${a.action}:${step.prereq}`}
                disabled={!!busy}
              >
                {a.label}
              </Button>
            ),
          )}
        </div>
      )}
      {op && (
        <div className="mt-1">
          <div
            role="progressbar"
            aria-label={`Downloading ${step.label}`}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={progress === null ? undefined : Math.round(progress * 100)}
            className="h-1.5 w-full overflow-hidden rounded-full bg-bg-3"
          >
            <div className="h-full bg-accent" style={{ width: `${Math.round((progress ?? 0) * 100)}%` }} />
          </div>
          <span className="text-fg-3">{opProgressLabel(op.done_bytes, op.total_bytes)}</span>
        </div>
      )}
      {waiting && <p className="mt-0.5 text-warn">{waitingForInputNote}</p>}
      {recView && (
        <p className={recView.tone === "warn" ? "mt-0.5 text-warn" : "mt-0.5 text-fg-3"} data-testid="sandbox-setup-record">
          {recView.line}
          {recView.remedy ? ` ${recView.remedy}` : ""}
        </p>
      )}
      {/* Opens the dashboard's own help drawer at this step's entry: App.tsx's
          delegated data-help-id listener, the path every HelpInd takes. */}
      <button type="button" data-help-id={helpId} data-testid="sandbox-setup-help" className="mt-0.5 inline-flex items-center gap-1 text-accent hover:underline">
        <CircleHelp size={11} aria-hidden /> {SETUP_HELP_LABEL}
      </button>
    </li>
  );
}

/**
 * ConsentProject picks the folder a consent step is for: Observer's default
 * workspace first (a scratch folder that is not a project, GET
 * /api/workspace/default), then the projects this machine has seen (the
 * Hosted sandboxes card's own list).
 */
function ConsentProject({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const roots = useProjectRootOptions(true);
  const ws = useApi<DefaultWorkspaceView>(DEFAULT_WORKSPACE_PATH);
  const workspace = consentDefault(ws.data);
  // Start on the default workspace, once, so a consent never defaults to a
  // real project; with no usable workspace the person picks. The consent
  // screen still lists what would leave before anything is agreed.
  const defaulted = useRef(false);
  useEffect(() => {
    if (defaulted.current || value || !workspace) return;
    defaulted.current = true;
    onChange(workspace);
  }, [value, workspace, onChange]);
  const projects = roots.options.filter((o) => o.id !== workspace);
  const shown = value === workspace && workspace ? `${WORKSPACE_OPTION_LABEL} (${value})` : value || "Pick a folder";
  return (
    <div className="mt-1 space-y-1" data-testid="sandbox-setup-consent-project">
      <span id="sandbox-setup-consent-project" className="block text-fg-2">
        Folder the consent is for
      </span>
      <ComboChip
        label="Folder the consent is for"
        labelledBy="sandbox-setup-consent-project"
        hideTriggerLabel
        fullWidth
        value={value}
        onChange={onChange}
        options={[
          { value: "", label: <span>Pick a folder</span>, searchable: "" },
          ...(workspace
            ? [
                {
                  value: workspace,
                  label: (
                    <span>
                      {WORKSPACE_OPTION_LABEL} <span className="font-mono text-fg-3">{workspace}</span>
                    </span>
                  ),
                  searchable: `${WORKSPACE_OPTION_LABEL} ${workspace}`,
                },
              ]
            : []),
          ...projects.map((o) => ({ value: o.id, label: <span className="font-mono">{o.label}</span>, searchable: o.label })),
        ]}
        buttonValueRender={() => <span className="font-mono">{shown}</span>}
      />
      <span className="block text-fg-3">{CONSENT_FOLDER_NOTE}</span>
    </div>
  );
}

/** StoreKeyFn hands a key step's typed values to the run request. */
type StoreKeyFn = (values: Record<string, string>) => void;

/**
 * KeyForm is a key step's input: the Hosted sandboxes card's own key
 * fields (one per value the provider needs, masked for a secret, never
 * pre-filled). Pressing the button hands the values to the run request and
 * clears every field first, so nothing typed stays on the page; the daemon
 * stores them in the keychain and never sends them back.
 */
function KeyForm({
  prereq,
  label,
  names,
  primary,
  busy,
  onStore,
}: {
  prereq: string;
  label: string;
  names: string[];
  primary: boolean;
  busy: string | null;
  onStore: StoreKeyFn;
}) {
  const [draft, setDraft] = useState<Record<string, string>>({});
  const ready = hostedConnectReady(names, draft);
  return (
    <form
      className="mt-1 space-y-1.5"
      aria-label={label}
      data-testid="sandbox-setup-key-form"
      onSubmit={(e) => {
        e.preventDefault();
        if (!ready || busy) return;
        const values = credentialRunFields(names, draft);
        setDraft({});
        onStore(values);
      }}
    >
      <HostedKeyFields
        names={names}
        values={draft}
        disabled={!!busy}
        onChange={(name, v) => setDraft((cur) => ({ ...cur, [name]: v }))}
        className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[12px] text-fg-1"
      />
      <p className="text-fg-3">{CREDENTIAL_FORM_NOTE}</p>
      <Button type="submit" size="sm" variant={primary ? "primary" : "secondary"} iconLeft={KeyRound} loading={busy === `run:${prereq}`} disabled={!!busy || !ready}>
        {CREDENTIAL_STORE_LABEL}
      </Button>
    </form>
  );
}
