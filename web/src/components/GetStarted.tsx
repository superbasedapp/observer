import { useCallback, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import { Check, ExternalLink, Plug, TerminalSquare, UserRound } from "lucide-react";
import { Button, ConfirmButton, Icon, Pill, ToolGlyphFrame } from "@/components/primitives";
import { ConnectProgressBlock } from "@/components/ConnectProgress";
import { useApi } from "@/lib/useApi";
import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import { fmtRelative } from "@/lib/format";
import { FIRST_RUN_PATH, type FirstRunResponse } from "@/lib/firstRun";
import { classifyWizardReply } from "@/lib/setupWizardPreview";
import {
  GET_STARTED_SNOOZE_KEY,
  getStartedMode,
  signInStep,
  snoozeRequestInit,
  toolCaptureLabel,
  wiringPlan,
  wiringResultLine,
  type Account,
  type WiringOutcome,
} from "@/lib/getStarted";
import { useAccount, useConnectFlow, type ConnectFlow } from "@/lib/useConnectFlow";
import { useConnectHandoff } from "@/lib/useConnectHandoff";
import { showTwoDashboardsNote } from "@/lib/connectHandoff";
import { HandoffCard, TwoDashboardsNote, useTwoDashboardsNote } from "@/components/ConnectHandoff";

// GetStarted is the one "Get started" panel at the top of Overview (Getting
// started v2). It replaced three things: the first-run dialog that opened by
// itself about detected tools (FirstRunModal stays, reopened from Settings >
// Connected tools and the command palette), the zero-session onboarding card
// and the Connect card. Three steps:
//
//   1. Sign in to superbased (recommended, never required): one button that
//      signs in AND connects this machine through the daemon's connect flow
//      (lib/useConnectFlow.ts); "Continue without an account" skips it.
//   2. Your AI tools: what was found here, how each is captured, and one
//      "Turn on for all" that writes each tool's hooks and proxy route
//      through the same routes Settings > Connected tools' wizard uses
//      (lib/getStarted.ts wiringPlan decides which).
//   3. Use your AI tools as usual.
//
// "Hide" puts it away; it comes back as a one-line strip a week later
// (kept on the daemon). Once this machine is connected the panel is a
// one-line strip naming where, with Open online dashboard, and a "Two
// dashboards" note (once per browser) saying what each dashboard holds.
// While the installer's terminal connects this machine (?connecting=1,
// lib/connectHandoff.ts) one hand-off card stands in for all of it.
// lib/getStarted.ts and lib/connectHandoff.ts hold every decision; this file
// only renders them.

/** The "Continue without an account" choice, kept in this browser only. */
const LOCAL_ONLY_KEY = "sb_get_started_local_only";

function readLocalOnly(): boolean {
  try {
    return globalThis.localStorage?.getItem(LOCAL_ONLY_KEY) === "1";
  } catch {
    return false;
  }
}

function writeLocalOnly(on: boolean): void {
  try {
    if (on) globalThis.localStorage?.setItem(LOCAL_ONLY_KEY, "1");
    else globalThis.localStorage?.removeItem(LOCAL_ONLY_KEY);
  } catch {
    // Storage unavailable: kept for this page view only.
  }
}

/**
 * GetStarted. `embedded` is its place inside the one getting-started surface
 * (first-run plan revision 2, 3.6 and 7.1, GetStartedSurface): the surface
 * owns the frame, the title and Hide (the same daemon-kept snooze), so the
 * panel renders only its three steps and never folds itself. `narrow` lays
 * the steps out in one column (the coding column of the Both track).
 */
export function GetStarted({
  sessions,
  embedded = false,
  narrow = false,
}: {
  sessions: number | null;
  embedded?: boolean;
  narrow?: boolean;
}) {
  const flow = useConnectFlow();
  const { account } = useAccount(flow);
  const handoff = useConnectHandoff(account);
  const note = useTwoDashboardsNote();
  // The brief first-run read carries the snooze time (the same read the
  // shell takes, so the shared cache serves both).
  const brief = useApi<FirstRunResponse>(FIRST_RUN_PATH, { brief: "1" });
  const [snoozedNow, setSnoozedNow] = useState<string | null>(null);
  const [localOnly, setLocalOnly] = useState(readLocalOnly);
  const snoozedAt = embedded ? null : (snoozedNow ?? brief.data?.snoozed?.[GET_STARTED_SNOOZE_KEY] ?? null);
  const decided = brief.data != null || brief.error != null;
  const mode = getStartedMode({
    account: decided ? account : null,
    snoozedAt,
    connecting: flow.active,
    now: Date.now(),
  });

  const hide = useCallback(async () => {
    setSnoozedNow(new Date().toISOString());
    try {
      const token = brief.data?.confirm_token || (await localConfirmHeaders())["X-Observer-Confirm"] || "";
      await fetchJSON("/api/firstrun/seen", undefined, snoozeRequestInit(token));
    } catch {
      // Hidden for this page view; it may come back on a reload.
    }
  }, [brief.data?.confirm_token]);

  const continueLocal = useCallback((on: boolean) => {
    setLocalOnly(on);
    writeLocalOnly(on);
  }, []);

  // The installer's terminal is connecting this machine (?connecting=1):
  // its card stands in for the panel and the strips, so the page offers no
  // second way to connect while the terminal waits. A failed status read
  // (the daemon restarting after the connect) only waits longer.
  if (handoff.phase === "waiting" || handoff.phase === "expired") {
    return <HandoffCard phase={handoff.phase} handoff={handoff.handoff} />;
  }
  if (!account) return null;
  switch (mode) {
    case "connected":
      return (
        <div className="space-y-2">
          <ConnectedStrip account={account} />
          {showTwoDashboardsNote(account, note.dismissed) && <TwoDashboardsNote account={account} onDismiss={note.dismiss} />}
        </div>
      );
    case "strip":
      return <ReturnStrip account={account} flow={flow} onHide={hide} />;
    case "panel":
      return (
        <Panel
          account={account}
          flow={flow}
          sessions={sessions}
          localOnly={localOnly}
          onContinueLocal={continueLocal}
          onHide={hide}
          embedded={embedded}
          narrow={narrow}
        />
      );
    default:
      return null;
  }
}

// ---- the connected strip -------------------------------------------------

/** ConnectedStrip: "Connected to <name> as <email> · Last sent <ago> · [Open online dashboard]". */
export function ConnectedStrip({ account }: { account: Account }) {
  return (
    <div
      role="note"
      data-testid="get-started-connected"
      data-tour="get-started"
      className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-3 border border-success/30 bg-success-soft px-4 py-2 text-small text-fg-2"
    >
      <Icon icon={Check} size="xs" className="shrink-0 text-success" />
      <span className="min-w-0">
        Connected to <span className="font-medium text-fg-1">{account.displayName}</span>
        {account.email && (
          <>
            {" "}
            as <span className="font-medium text-fg-1">{account.email}</span>
          </>
        )}
      </span>
      <span className="text-fg-4" aria-hidden>
        ·
      </span>
      <span className="text-fg-3">{account.lastSentAt ? `Last sent ${fmtRelative(account.lastSentAt)}` : "Nothing sent yet"}</span>
      {account.onlineUrl && (
        <a
          href={account.onlineUrl}
          target="_blank"
          rel="noreferrer noopener"
          data-testid="open-online"
          className="ml-auto inline-flex items-center gap-1 rounded-2 border border-accent/40 bg-accent-soft px-2.5 py-1 text-[11.5px] font-medium text-accent hover:bg-accent/20"
        >
          Open online dashboard
          <Icon icon={ExternalLink} size={11} />
        </a>
      )}
    </div>
  );
}

// ---- the strip that comes back after a week -------------------------------

function ReturnStrip({ account, flow, onHide }: { account: Account; flow: ConnectFlow; onHide: () => void }) {
  const step = signInStep(account, false);
  if (step.kind === "unavailable" || !flow.available) return null;
  const connectOnly = step.kind === "connect";
  return (
    <div
      role="note"
      data-testid="get-started-strip"
      data-tour="get-started"
      className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-3 border border-line-2 bg-bg-1 px-4 py-2 text-small text-fg-2"
    >
      <span className="min-w-0 flex-1">
        {connectOnly
          ? "Connect this machine to see it in your online dashboard."
          : "Sign in to see all your machines in one online dashboard, with history that survives a new laptop. Free."}
      </span>
      <Button size="sm" variant="primary" onClick={() => void flow.start()} loading={flow.busy}>
        {connectOnly ? "Connect this machine" : "Sign in and connect"}
      </Button>
      <Button size="sm" variant="ghost" onClick={onHide}>
        Hide
      </Button>
      <ConnectProgressBlock flow={flow} className="w-full" />
    </div>
  );
}

// ---- the panel -------------------------------------------------------------

function Panel({
  account,
  flow,
  sessions,
  localOnly,
  onContinueLocal,
  onHide,
  embedded = false,
  narrow = false,
}: {
  account: Account;
  flow: ConnectFlow;
  sessions: number | null;
  localOnly: boolean;
  onContinueLocal: (on: boolean) => void;
  onHide: () => void;
  embedded?: boolean;
  narrow?: boolean;
}) {
  const steps = (
    <ol className={clsx("grid gap-3", !narrow && "lg:grid-cols-3", !embedded && "mt-3")} data-testid={embedded ? "get-started-steps" : undefined}>
      <SignInStep account={account} flow={flow} localOnly={localOnly} onContinueLocal={onContinueLocal} />
      <ToolsStep />
      <UseStep sessions={sessions} />
    </ol>
  );
  if (embedded) return steps;
  return (
    <section
      aria-labelledby="sb-get-started-title"
      data-testid="get-started"
      data-tour="get-started"
      className="rounded-3 border border-accent/30 bg-bg-1 p-4"
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 id="sb-get-started-title" className="text-[14px] font-semibold text-fg-0">
            Get started
          </h2>
          <p className="mt-0.5 text-[11.5px] text-fg-3">Everything here works on this machine with or without an account.</p>
        </div>
        <Button size="sm" variant="ghost" onClick={onHide}>
          Hide
        </Button>
      </div>
      {steps}
    </section>
  );
}

function StepFrame({
  n,
  title,
  badge,
  done,
  children,
}: {
  n: number;
  title: string;
  badge?: React.ReactNode;
  done?: boolean;
  children: React.ReactNode;
}) {
  return (
    <li className="flex min-w-0 flex-col gap-2 rounded-2 border border-line-2 bg-bg-2 p-3">
      <div className="flex items-center gap-2">
        <span
          aria-hidden
          className={clsx(
            "grid h-5 w-5 shrink-0 place-items-center rounded-pill border text-[10.5px] font-semibold",
            done ? "border-success/40 bg-success-soft text-success" : "border-line-3 bg-bg-3 text-fg-2",
          )}
        >
          {done ? <Icon icon={Check} size={11} /> : n}
        </span>
        <h3 className="min-w-0 truncate text-[12.5px] font-semibold text-fg-0">{title}</h3>
        {badge}
      </div>
      {children}
    </li>
  );
}

const STEP_TEXT = "text-[11.5px] leading-relaxed text-fg-3";

function SignInStep({
  account,
  flow,
  localOnly,
  onContinueLocal,
}: {
  account: Account;
  flow: ConnectFlow;
  localOnly: boolean;
  onContinueLocal: (on: boolean) => void;
}) {
  const step = signInStep(account, localOnly && !flow.active);
  if (step.kind === "unavailable") {
    return (
      <StepFrame n={1} title="Sign in to superbased">
        <p className={STEP_TEXT}>{step.reason} You can keep using everything here on this machine.</p>
      </StepFrame>
    );
  }
  if (step.kind === "skipped") {
    return (
      <StepFrame n={1} title="Sign in to superbased" done>
        <p className={STEP_TEXT}>Skipped. Everything here keeps working on this machine.</p>
        <div>
          <Button size="sm" variant="ghost" onClick={() => onContinueLocal(false)}>
            Sign in after all
          </Button>
        </div>
      </StepFrame>
    );
  }
  const connectOnly = step.kind === "connect";
  return (
    <StepFrame
      n={1}
      title={connectOnly ? "Connect this machine" : "Sign in to superbased"}
      badge={
        <Pill variant="accent" case="none">
          Recommended
        </Pill>
      }
    >
      <p className={STEP_TEXT}>
        {connectOnly
          ? "You are signed in. Connect this machine to see it in your online dashboard, beside your other machines and your team."
          : "One online dashboard for all your machines, your team, and history that survives a new laptop. Free."}
      </p>
      {!flow.available ? (
        <p className={STEP_TEXT}>Sign in from this machine&apos;s own browser.</p>
      ) : (
        !flow.active && (
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="primary" iconLeft={UserRound} onClick={() => void flow.start()} loading={flow.busy}>
              {connectOnly ? "Connect this machine" : "Sign in and connect this machine"}
            </Button>
            {!connectOnly && (
              <Button size="sm" variant="ghost" onClick={() => onContinueLocal(true)}>
                Continue without an account
              </Button>
            )}
          </div>
        )
      )}
      <ConnectProgressBlock flow={flow} />
      {!flow.active && (
        <p className="text-[10.5px] text-fg-4">You choose where to connect and what is sent on the approval page, before anything is sent.</p>
      )}
    </StepFrame>
  );
}

function ToolsStep() {
  const res = useApi<FirstRunResponse>(FIRST_RUN_PATH);
  const tools = useMemo(() => (res.data?.tools ?? []).filter((t) => t.detected), [res.data]);
  const plan = useMemo(() => wiringPlan(tools), [tools]);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ReturnType<typeof wiringResultLine> | null>(null);
  const n = plan.tools.length;

  const turnOnAll = useCallback(async () => {
    setBusy(true);
    setResult(null);
    const outcomes: WiringOutcome[] = [];
    try {
      const headers = await localConfirmHeaders();
      for (const t of plan.tools) {
        for (const a of t.actions) {
          try {
            const r = await fetch(a.endpoint, { method: "POST", headers, body: JSON.stringify(a.body) });
            const text = await r.text().catch(() => "");
            outcomes.push({ tool: a.tool, step: a.step, kind: classifyWizardReply(a.step, r.status, text, true).kind });
          } catch {
            outcomes.push({ tool: a.tool, step: a.step, kind: "error" });
          }
        }
      }
    } finally {
      setResult(wiringResultLine(outcomes));
      setBusy(false);
      res.reload();
    }
  }, [plan, res]);

  return (
    <StepFrame n={2} title="Your AI tools" done={tools.length > 0 && n === 0}>
      {res.loading && !res.data ? (
        <p className={STEP_TEXT}>Looking for AI tools on this machine...</p>
      ) : tools.length === 0 ? (
        <p className={STEP_TEXT}>
          No AI coding tools found yet. Install one, such as Claude Code, Codex or Cursor, and run it once.
        </p>
      ) : (
        <ul className="space-y-1">
          {tools.slice(0, 6).map((t) => {
            const label = toolCaptureLabel(t);
            return (
              <li key={t.tool} className="flex min-w-0 items-center gap-2 text-[11.5px]">
                <ToolGlyphFrame tool={t.tool} size={16} />
                <span className="min-w-0 flex-1 truncate text-fg-1">{t.name}</span>
                <Pill variant={label.tone} case="none">
                  {label.text}
                </Pill>
              </li>
            );
          })}
          {tools.length > 6 && <li className="text-[10.5px] text-fg-4">And {tools.length - 6} more.</li>}
        </ul>
      )}
      {n > 0 && (
        <div>
          <ConfirmButton
            size="sm"
            variant="primary"
            armedVariant="primary"
            iconLeft={Plug}
            onConfirm={() => void turnOnAll()}
            loading={busy}
            confirmLabel={`Turn on for ${n}?`}
            armedNote="Adds superbased's hooks and proxy route to each tool's own settings. Undo any tool in Settings > Connected tools."
          >
            {`Turn on for all ${n}`}
          </ConfirmButton>
        </div>
      )}
      {result && (
        <p role="status" className={clsx("text-[11px]", result.tone === "success" ? "text-success" : "text-warn")}>
          {result.text}
        </p>
      )}
      {plan.routeLeftToSettings.length > 0 && (
        <p className="text-[10.5px] text-fg-4">
          {plan.routeLeftToSettings.join(", ")}: the proxy route changes how the tool works, so it is a choice in Settings.
        </p>
      )}
      <Link to="/settings?section=tools" className="text-[11px] text-accent hover:underline">
        Settings &gt; Connected tools
      </Link>
    </StepFrame>
  );
}

function UseStep({ sessions }: { sessions: number | null }) {
  // The demo offer from the old onboarding card: only while nothing is
  // captured and the server can seed a sample.
  const demo = useApi<{ available: boolean; active: boolean }>(sessions === 0 ? "/api/demo" : null);
  const [seeding, setSeeding] = useState(false);
  const startDemo = async () => {
    setSeeding(true);
    try {
      await fetchJSON("/api/demo/start", undefined, { method: "POST" });
      window.location.reload();
    } catch {
      setSeeding(false);
    }
  };
  return (
    <StepFrame n={3} title="Use your AI tools" done={(sessions ?? 0) > 0}>
      <p className={STEP_TEXT}>
        <Icon icon={TerminalSquare} size={12} className="mr-1 inline text-fg-4" />
        Use your AI tools as usual. Sessions appear here as they happen.
      </p>
      {(sessions ?? 0) > 0 && (
        <p className="text-[11px] text-fg-2">
          {(sessions ?? 0).toLocaleString("en-US")} session{sessions === 1 ? "" : "s"} so far.{" "}
          <Link to="/sessions" className="text-accent hover:underline">
            See them
          </Link>
        </p>
      )}
      {demo.data?.available && !demo.data.active && (
        <p className="text-[10.5px] text-fg-4">
          Just looking around?{" "}
          <button
            type="button"
            onClick={() => void startDemo()}
            disabled={seeding}
            className="font-medium text-accent hover:underline disabled:opacity-60"
          >
            {seeding ? "Loading the sample..." : "Explore with sample data"}
          </button>
          . Your real data stays untouched.
        </p>
      )}
    </StepFrame>
  );
}
