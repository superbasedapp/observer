// LaunchPolicyInline: the New Terminal dialog's inline launch-policy steps
// (Windows 11 Pro rerun 2026-10-25, R3 and R4; operator rule: every CLI or
// config action has a dashboard control). A custom folder that is not on
// [terminal.launch].allowed_project_roots gets an "Allow this folder" step,
// and a launch refused because [terminal.launch].allow_fresh_agent is off
// gets a "Turn on fresh-agent launch" step, each with its own confirm,
// instead of a bare 400 or 403 and a trip to Terminals > Settings. Both
// write through the SAME route Terminals > Settings uses (GET then PUT
// /api/terminal/policy through saveConfigEdit: a dry run, the exact config
// change, then the save at the previewed etag), always as the full policy
// with one field changed, never a partial payload.
//
// The review of that change is shown INSIDE the step (Windows 11 Pro run 4,
// B4): the shell's preview dialog sat behind New terminal, so saving meant
// closing New terminal and opening it again. The step passes its own review
// prompt to the save (lib/launchPolicyStep.ts owns the states), shows the
// diff with the same ConfigSavePreview the shell's dialog uses and a Save
// button, and the dialog stays open with the folder still selected.

import { useEffect, useRef, useState } from "react";
import { ApiError, fetchJSON } from "@/lib/api";
import { saveConfigEdit, type ConfigSavePreviewRequest } from "@/lib/configSectionSave";
import { PolicyStep, type ReviewPrompt, type StepPhase, type StepState } from "@/lib/launchPolicyStep";
import { ConfigSavePreview } from "@/components/ConfigSavePreview";
import { Button } from "@/components/primitives";

export { absolutePath } from "@/lib/launchPolicyStep";

/** The launch policy as GET /api/terminal/policy returns it. */
export type LaunchPolicy = {
  confirm_token: string;
  allow_fresh_agent: boolean;
  allowed_tools: string[] | null;
  allowed_project_roots: string[] | null;
  allow_shell: boolean;
  allow_install?: boolean;
};

/** One change the dialog may make to the launch policy. */
export type LaunchPolicyChange = { addRoot: string } | { allowFresh: true };

/** The review prompt a step hands applyLaunchPolicyChange. */
export type LaunchPolicyReview = ReviewPrompt<ConfigSavePreviewRequest>;

/**
 * policyWithChange is the full policy PUT body with exactly one change: a
 * root appended (once) or fresh-agent launch turned on. Every other field is
 * carried over as read, so the inline step never drops a tool or a root.
 */
export function policyWithChange(p: LaunchPolicy, change: LaunchPolicyChange) {
  const roots = [...(p.allowed_project_roots ?? [])];
  if ("addRoot" in change) {
    const r = change.addRoot.trim();
    if (r && !roots.includes(r)) roots.push(r);
  }
  return {
    allow_fresh_agent: "allowFresh" in change ? true : p.allow_fresh_agent,
    allowed_tools: p.allowed_tools ?? [],
    allowed_project_roots: roots,
    allow_shell: p.allow_shell,
    allow_install: p.allow_install ?? true,
  };
}

/**
 * applyLaunchPolicyChange reads the current policy and saves it with the
 * change: a dry run, then review answers Save or Cancel (a cancelled review
 * rejects with ConfigSaveCancelled and writes nothing). With no review the
 * shell's preview dialog answers, as for every other config save.
 */
export async function applyLaunchPolicyChange(change: LaunchPolicyChange, title: string, review?: LaunchPolicyReview) {
  const p = await fetchJSON<LaunchPolicy>("/api/terminal/policy");
  return saveConfigEdit<{ saved: boolean; restart_required: boolean }>(
    "/api/terminal/policy",
    "terminal.launch",
    policyWithChange(p, change),
    { "X-Observer-Confirm": p.confirm_token },
    { title, prompt: review },
  );
}

/** isFreshLaunchDisabledError recognises the launch route's allow_fresh_agent refusal. */
export function isFreshLaunchDisabledError(e: unknown): boolean {
  const msg = e instanceof Error ? e.message : String(e);
  if (!/fresh-agent launch is disabled|allow_fresh_agent/i.test(msg)) return false;
  return !(e instanceof ApiError) || e.status === 403;
}

type StepProps = {
  /** Open on the confirm question (tests render this state directly). */
  initialConfirming?: boolean;
  /** Open on the review of this change (tests render this state directly). */
  initialReview?: ConfigSavePreviewRequest;
  /** Runs the change with the step's own review; rejects with the reason to show. */
  onConfirm: (review: LaunchPolicyReview) => Promise<void>;
  /** Every phase change (the dialog holds Start while a step is not idle). */
  onPhase?: (phase: StepPhase) => void;
};

function useStep({ initialConfirming, initialReview, onConfirm, onPhase }: StepProps) {
  const confirmRef = useRef(onConfirm);
  confirmRef.current = onConfirm;
  const phaseRef = useRef(onPhase);
  phaseRef.current = onPhase;
  const initial: Partial<StepState<ConfigSavePreviewRequest>> = initialReview
    ? { phase: "reviewing", review: initialReview }
    : initialConfirming
      ? { phase: "confirming" }
      : {};
  const [state, setState] = useState<StepState<ConfigSavePreviewRequest>>({
    phase: "idle",
    review: null,
    err: null,
    ...initial,
  });
  const ctl = useRef<PolicyStep<ConfigSavePreviewRequest> | null>(null);
  if (!ctl.current) ctl.current = new PolicyStep((review) => confirmRef.current(review), setState, initial);
  useEffect(() => {
    phaseRef.current?.(state.phase);
  }, [state.phase]);
  // A step that goes away (the folder changed, the dialog closed) answers
  // an open review with Cancel, so nothing is written unseen, and frees Start.
  useEffect(
    () => () => {
      ctl.current?.dispose();
      phaseRef.current?.("idle");
    },
    [],
  );
  return { state, ctl: ctl.current };
}

const box = "mt-2 rounded-2 border border-warn/40 bg-warn/10 px-2.5 py-2 text-[11px] leading-relaxed text-fg-2";

/** InlineReview is the step's own review: the diff, Save and Cancel. */
function InlineReview({ step }: { step: ReturnType<typeof useStep> }) {
  const req = step.state.review;
  if (!req) return null;
  const saving = step.state.phase === "saving";
  const warnings = req.dryRun.secret_warnings?.length ?? 0;
  return (
    <div className="mt-1.5 space-y-1.5" data-testid="inline-config-review">
      <p className="font-medium text-fg-1">
        Review the change to <span className="font-mono">[{req.section}]</span> in{" "}
        <span className="break-all font-mono">{req.dryRun.config_path}</span>. Nothing is written until you save.
      </p>
      <ConfigSavePreview data={req.dryRun} />
      <div className="flex gap-2">
        <Button
          variant="primary"
          size="sm"
          disabled={saving}
          onClick={() => step.ctl.save()}
          data-testid="inline-config-save"
        >
          {saving ? "Saving…" : warnings > 0 ? "Save anyway" : "Save"}
        </Button>
        <Button variant="ghost" size="sm" disabled={saving} onClick={() => step.ctl.cancelReview()}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

/** ConfirmRow is the step's confirm question with its two buttons. */
function ConfirmRow({
  step,
  question,
  confirmLabel,
  busyLabel,
}: {
  step: ReturnType<typeof useStep>;
  question: string;
  confirmLabel: string;
  busyLabel: string;
}) {
  const busy = step.state.phase === "checking";
  return (
    <div className="mt-1.5">
      <p className="font-medium text-fg-1">{question}</p>
      <div className="mt-1.5 flex gap-2">
        <Button variant="primary" size="sm" disabled={busy} onClick={() => void step.ctl.confirm()}>
          {busy ? busyLabel : confirmLabel}
        </Button>
        <Button variant="ghost" size="sm" disabled={busy} onClick={() => step.ctl.disarm()}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

/**
 * AllowFolderStep: the custom folder is not allow-listed. "Allow this
 * folder" asks once more, then shows the change to allowed_project_roots
 * here and adds the folder on Save.
 */
export function AllowFolderStep(props: StepProps & { path: string }) {
  const s = useStep(props);
  const { phase } = s.state;
  return (
    <div className={box} data-testid="allow-folder-step">
      <p>
        <code className="break-all font-mono">{props.path}</code> is not on the launch allow-list of project folders,
        so a terminal cannot start there yet.
      </p>
      {phase === "confirming" || phase === "checking" ? (
        <ConfirmRow
          step={s}
          question="Allow fresh agents to run in this folder and everything under it? This changes your Observer config; the next step shows the exact change here."
          confirmLabel="Confirm: allow this folder"
          busyLabel="Allowing…"
        />
      ) : phase === "reviewing" || phase === "saving" ? (
        <InlineReview step={s} />
      ) : (
        <Button variant="primary" size="sm" className="mt-1.5" onClick={() => s.ctl.arm()}>
          Allow this folder
        </Button>
      )}
      {s.state.err && <p className="mt-1 text-danger">{s.state.err}</p>}
    </div>
  );
}

/** The 409 sign_in_consent body of POST /api/terminal/launch (lane BOXSIGNIN). */
export type SignInConsent = { tool: string; files: string[]; text: string };

/**
 * signInConsentFromError reads the launch route's sign-in consent question
 * (409 {"error":"sign_in_consent",...}); null for every other error.
 */
export function signInConsentFromError(e: unknown): SignInConsent | null {
  if (!(e instanceof ApiError) || e.status !== 409) return null;
  try {
    const b = JSON.parse(e.body) as Partial<SignInConsent> & { error?: string };
    if (b && b.error === "sign_in_consent" && typeof b.tool === "string" && Array.isArray(b.files) && typeof b.text === "string") {
      return { tool: b.tool, files: b.files.map(String), text: b.text };
    }
  } catch {
    // not the consent body
  }
  return null;
}

/**
 * postLaunchAskingSignIn runs one launch POST (lane BOXSIGNIN): a 409
 * sign_in_consent comes back as the question for the inline sign-in step
 * instead of an error, and the step's answer runs post again with the
 * answer in the body. Every other error is thrown as before.
 */
export async function postLaunchAskingSignIn<T>(post: () => Promise<T>): Promise<{ started: T } | { consent: SignInConsent }> {
  try {
    return { started: await post() };
  } catch (e) {
    const consent = signInConsentFromError(e);
    if (consent) return { consent };
    throw e;
  }
}

/** The sandbox settings as GET /api/terminal/sandbox/config returns them. */
type SandboxConfigReply = { confirm_token: string; sandbox: Record<string, unknown> & { sign_in_seed_tools?: string[] } };

/**
 * sandboxWithSignInTool is the full [terminal.sandbox] PUT body with tool
 * added once to sign_in_seed_tools; every other field is carried over as
 * read, and the read-only catalog and org fields are left out.
 */
export function sandboxWithSignInTool(sandbox: SandboxConfigReply["sandbox"], tool: string) {
  const rest = { ...sandbox };
  delete rest.sign_in_seed_catalog;
  delete rest.sign_in_seed_forbidden;
  const list = [...(sandbox.sign_in_seed_tools ?? [])];
  if (!list.includes(tool)) list.push(tool);
  return { ...rest, sign_in_seed_tools: list };
}

/**
 * rememberSignInSeed saves "always for this tool" through the same route
 * Terminals > Settings uses: a dry run, the review, then the save.
 */
export async function rememberSignInSeed(tool: string, review?: LaunchPolicyReview) {
  const r = await fetchJSON<SandboxConfigReply>("/api/terminal/sandbox/config");
  return saveConfigEdit<{ restart_required: boolean }>(
    "/api/terminal/sandbox/config",
    "terminal.sandbox",
    sandboxWithSignInTool(r.sandbox, tool),
    { "X-Observer-Confirm": r.confirm_token },
    { title: `Remember sign-in seeding for ${tool}`, prompt: review },
  );
}

/**
 * SignInSeedStep: the launch can copy the tool's sign-in into its box (lane
 * BOXSIGNIN). The step shows the consent text (the tool, each file, what
 * the box can do with it, that it is removed when the run ends) and answers
 * in place: copy for this run, start without it, or "Always" (a confirm,
 * then the change to [terminal.sandbox].sign_in_seed_tools reviewed here).
 * The answer starts the launch again; no second dialog opens.
 */
export function SignInSeedStep(
  props: Omit<StepProps, "onConfirm"> & { consent: SignInConsent; onAnswer: (yes: boolean) => void },
) {
  const { consent, onAnswer } = props;
  const s = useStep({
    ...props,
    onConfirm: async (review) => {
      await rememberSignInSeed(consent.tool, review);
      onAnswer(true);
    },
  });
  const { phase } = s.state;
  return (
    <div className={box} data-testid="sign-in-seed-step">
      <p>{consent.text}</p>
      <ul className="mt-1 list-disc pl-4">
        {consent.files.map((f) => (
          <li key={f}>
            <code className="break-all font-mono">~/{f}</code>
          </li>
        ))}
      </ul>
      {phase === "confirming" || phase === "checking" ? (
        <ConfirmRow
          step={s}
          question={`Always copy ${consent.tool}'s sign-in into a sandboxed run that can take it, without asking? This adds ${consent.tool} to [terminal.sandbox].sign_in_seed_tools; the next step shows the exact change here.`}
          confirmLabel="Confirm: always for this tool"
          busyLabel="Saving…"
        />
      ) : phase === "reviewing" || phase === "saving" ? (
        <InlineReview step={s} />
      ) : (
        <div className="mt-1.5 flex flex-wrap gap-2">
          <Button variant="primary" size="sm" onClick={() => onAnswer(true)} data-testid="sign-in-seed-yes">
            Copy my sign-in for this run
          </Button>
          <Button variant="ghost" size="sm" onClick={() => s.ctl.arm()} data-testid="sign-in-seed-always">
            Always for {consent.tool}
          </Button>
          <Button variant="ghost" size="sm" onClick={() => onAnswer(false)} data-testid="sign-in-seed-no">
            Start without it
          </Button>
        </div>
      )}
      {s.state.err && <p className="mt-1 text-danger">{s.state.err}</p>}
    </div>
  );
}

/**
 * FreshLaunchStep: fresh-agent launch is off. "Turn on fresh-agent launch"
 * asks once more, then shows the change to allow_fresh_agent here and sets
 * it on Save.
 */
export function FreshLaunchStep(props: StepProps) {
  const s = useStep(props);
  const { phase } = s.state;
  return (
    <div className={box} data-testid="fresh-launch-step">
      <p>
        Fresh-agent launch is off in the terminal launch settings, so this dashboard cannot start an agent.
      </p>
      {phase === "confirming" || phase === "checking" ? (
        <ConfirmRow
          step={s}
          question="Let this dashboard start fresh agents on this machine? It widens what a dashboard session can run; the next step shows the exact change here."
          confirmLabel="Confirm: turn on fresh-agent launch"
          busyLabel="Turning on…"
        />
      ) : phase === "reviewing" || phase === "saving" ? (
        <InlineReview step={s} />
      ) : (
        <Button variant="primary" size="sm" className="mt-1.5" onClick={() => s.ctl.arm()}>
          Turn on fresh-agent launch
        </Button>
      )}
      {s.state.err && <p className="mt-1 text-danger">{s.state.err}</p>}
    </div>
  );
}
