import { useCallback, useEffect, useRef, useState } from "react";
import type { CSSProperties, RefObject } from "react";
import clsx from "clsx";
import { Link } from "react-router-dom";
import { Button, ConfirmButton, Icon } from "@/components/primitives";
import { ObsLanding } from "@shared/primitives/ObsFlight";
import { useApi } from "@/lib/useApi";
import { localConfirmHeaders } from "@/lib/api";
import { classifyRemoveReply, type RemoveOutcome } from "@/lib/wizardRemove";
import { classifyWizardReply, type WizardOutcome } from "@/lib/setupWizardPreview";
import type { CodexHookTrust, CodexHookTrustEntry, ToolWiring } from "@/lib/types";
import { wizardStepsFor, type WizardStepPlan } from "@/lib/wizardSteps";
import { Check, Dot } from "lucide-react";

// SetupWizard — the guided per-tool init flow (usability arc P4.2 /
// review row B3). One card per integration step (hooks → MCP → proxy
// route); each step shows a dry-run PREVIEW of the exact write, and
// nothing is written until the user clicks that step's own button —
// per-write consent, never a bundled "do everything". Writes are
// byte-equivalent to `observer init` (same registries server-side).

const WIZARD_STEP_IDS = ["hooks", "mcp", "route", "telemetry"] as const;
type StepId = (typeof WIZARD_STEP_IDS)[number];

type StepText = {
  id: StepId;
  title: string;
  blurb: string;
  action: string;
  // Optional honesty note rendered with the step (MCP overhead).
  note?: string;
  // Optional in-dashboard place the note refers to (no config.toml dead end).
  noteLink?: { to: string; label: string };
  body: (tool: string, force: boolean, dryRun: boolean) => unknown;
};

// StepSpec is one step as this tool gets it: the fixed copy plus the plan the
// server's wiring decided (endpoint, whether the write and the removal are
// offered). Which steps exist is never a tool-name list (T-421 item 2).
type StepSpec = StepText & {
  endpoint: (tool: string) => string | null;
  plan: WizardStepPlan;
};

const STEPS: StepText[] = [
  {
    id: "hooks",
    title: "Hooks",
    blurb:
      "Lightweight turn-boundary hooks in the tool's own config - the capture path that needs no proxy.",
    action: "Register hooks",
    body: (tool, force, dry_run) => ({ tool, force, dry_run }),
  },
  {
    id: "mcp",
    title: "MCP server",
    blurb:
      "On-demand project-knowledge queries inside the tool (13 observer tools).",
    note: "Honest trade-off: the registered tool schemas add roughly 1,800 tokens to every turn. Worth it if you use the queries; skip this step if unsure - everything else works without it.",
    action: "Register MCP server",
    body: (tool, force, dry_run) => ({ tool, force, dry_run }),
  },
  {
    id: "route",
    title: "Proxy route",
    blurb:
      "Durable routing through the observer proxy - exact token accounting, conversation compression, and cache tracking.",
    action: "Route through proxy",
    body: (_tool, force, dry_run) => ({ force, dry_run }),
  },
  {
    id: "telemetry",
    title: "Telemetry export (optional)",
    blurb:
      "Point the tool's own OpenTelemetry export at this node's receiver, so its per-call tokens and tool calls land here too. Off unless you click; edits only the exporter keys of the tool's config.",
    note: "Needs this node's OTLP receiver on, loopback only ([ingest.otel] enabled with an HTTP address, allow_non_loopback off), then a daemon restart. When the tool is also routed through the proxy, the proxy keeps owning its tokens.",
    noteLink: { to: "/settings?section=otel", label: "Turn on the receiver in Settings > OTel export" },
    action: "Send telemetry to this node",
    body: (tool, _force, dry_run) => ({ tool, dry_run }),
  },
];

export function SetupWizard({
  tool,
  wiring,
  onChanged,
  initialRemoveOpen = false,
}: {
  tool: string;
  /** The row's server-computed setup / removal actions. */
  wiring?: ToolWiring;
  onChanged: () => void;
  /** Open the Remove panel on mount (a Health remediation deep link). */
  initialRemoveOpen?: boolean;
}) {
  const plans = wizardStepsFor(wiring);
  const all: StepSpec[] = plans.map((plan) => ({
    ...STEPS.find((t) => t.id === plan.id)!,
    endpoint: () => plan.endpoint,
    plan,
  }));
  const steps = all.filter((s) => s.plan.register);
  const notes = all.filter((s) => !s.plan.register && s.plan.note);
  const removable = all.filter((s) => s.plan.remove);
  // D-3 (§9.3): the ★ SETUP COMPLETE ★ moment — fires only when every
  // applicable step reports done. A transitional wizard end-state, not
  // a recurring toast (restraint rules §9.4: the sprite pulse IS the
  // celebration; no sound, no confetti).
  const [doneMap, setDoneMap] = useState<Record<string, boolean>>({});
  const allDone =
    steps.length > 0 && steps.every((s) => doneMap[s.id] === true);
  const rootRef = useRef<HTMLDivElement>(null);
  const fit = useFitToScroller(rootRef);
  return (
    <div
      ref={rootRef}
      style={fit}
      className="my-2 space-y-2 rounded-2 border border-line-2 bg-bg-3 p-3"
    >
      <p className="text-[11px] leading-snug text-fg-3">
        Each step below previews its exact write and runs only when you click
        it - there is no &quot;apply all&quot;. Files written are the same
        bytes <code className="font-mono text-fg-2">observer init</code> would
        write.
      </p>
      {steps.map((s) => (
        <WizardStep
          key={s.id}
          spec={s}
          tool={tool}
          onChanged={onChanged}
          onDoneChange={(done) =>
            setDoneMap((m) => (m[s.id] === done ? m : { ...m, [s.id]: done }))
          }
        />
      ))}
      {notes.map((s) => (
        <div key={s.id} className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2 text-[11px] text-fg-3">
          <span className="font-semibold text-fg-2">{s.title}:</span> {s.plan.note}
        </div>
      ))}
      {tool === "codex" && <CodexTrustCard />}
      <RemovePanel tool={tool} steps={removable} onChanged={onChanged} initialOpen={initialRemoveOpen} />
      {allDone && (
        <div className="flex items-center gap-3 rounded-2 border border-success/30 bg-success-soft px-3 py-2">
          {/* Finish line (D-665..D-669): fly in, land, celebrate twice, rest on idle. */}
          <ObsLanding size={32} />
          <span className="font-mono text-[11px] font-semibold tracking-[0.08em] text-success">
            ★ SETUP COMPLETE ★
          </span>
          <span className="text-[11px] text-fg-3">
            {tool} is fully wired. New sessions land on the next start.
          </span>
        </div>
      )}
    </div>
  );
}

// useFitToScroller keeps the wizard inside the visible part of the
// horizontally scrolling tools table it is rendered in (a full-width table
// row): pinned to the scroller's left edge and as wide as the scroller's
// visible width, so no card is clipped on the right or needs a sideways
// scroll. Outside a scroller it does nothing.
function useFitToScroller(ref: RefObject<HTMLElement>): CSSProperties | undefined {
  const [width, setWidth] = useState<number | null>(null);
  useEffect(() => {
    const el = ref.current;
    const scroller = el?.parentElement?.closest<HTMLElement>(".overflow-x-auto");
    if (!el || !scroller || typeof ResizeObserver === "undefined") return;
    const measure = () => {
      const inset = el.getBoundingClientRect().left - scroller.getBoundingClientRect().left + scroller.scrollLeft;
      setWidth(Math.max(0, Math.floor(scroller.clientWidth - 2 * Math.max(0, inset))));
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(scroller);
    return () => ro.disconnect();
  }, [ref]);
  return width === null ? undefined : { position: "sticky", left: 0, width };
}

// CodexTrustCard — codex requires the user to TRUST each registered
// hook event inside codex itself; observer can only read that state
// (usability arc P4.3 / review row B5). Surfaces the exact
// instruction string the status API computes.
function CodexTrustCard() {
  const trust = useApi<CodexHookTrust>("/api/setup/codex-hooks");
  const t = trust.data;
  if (trust.loading || !t) {
    return (
      <div className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2 font-mono text-[10.5px] text-fg-3">
        probing codex hook trust…
      </div>
    );
  }
  const ok = t.status === "all_trusted";
  const idle = t.status === "no_codex" || t.status === "no_hooks";
  return (
    <div className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={clsx(
            "inline-flex h-4 w-4 items-center justify-center rounded-pill border text-micro font-bold",
            ok
              ? "border-success/40 bg-success-soft text-success"
              : "border-line-2 bg-bg-3 text-fg-4",
          )}
        >
          {ok ? <Icon icon={Check} size={10} label="done" /> : <Icon icon={Dot} size={12} label="not done" />}
        </span>
        <span className="text-[11.5px] font-semibold text-fg-1">
          Hook trust (inside codex)
        </span>
        <span className="basis-full text-[11px] text-fg-3">
          codex runs a registered hook only once it is trusted. Registering
          Observer&apos;s hooks records that trust for Observer&apos;s own entries;
          review or revoke it in codex /hooks.
        </span>
      </div>
      <div className="mt-1 font-mono text-[10.5px] text-fg-3">
        {ok && `all ${t.trusted_events?.length ?? 0} events trusted`}
        {idle && `nothing to trust yet (${t.status.replace("_", " ")})`}
        {!ok && !idle && (
          <>
            <span className={t.status === "needs_trust" || t.status === "needs_register" ? "text-warn" : ""}>
              {t.status.replace(/_/g, " ")}
              {t.entries && t.entries.length > 0 &&
                `: ${(t.untrusted_events?.length ?? 0) + (t.missing_events?.length ?? 0)} of ${t.entries.length} Observer events will not run`}
            </span>
            {t.gate_off && (
              <p className="mt-1 text-danger" data-testid="codex-trust-gate-off">
                Codex hooks not trusted: Observer&apos;s Codex guard gate is off. Run the Register
                hooks step again to record their trust, or approve them in codex /hooks.
              </p>
            )}
            {t.origin && t.origin !== "native" && (
              <p className="mt-1 text-fg-3">home: {t.origin}</p>
            )}
            {t.instruction && (
              <p className="mt-1 whitespace-pre-wrap text-fg-2">
                {t.instruction}
              </p>
            )}
            {(t.status === "needs_trust" || t.status === "config_missing") && (
              <ol className="mt-1 list-decimal pl-4 text-fg-2" data-testid="codex-trust-steps">
                <li>Run the Register hooks step above: it re-registers Observer&apos;s codex hooks and records their trust.</li>
                <li>Or run `codex`, type /hooks and trust every entry whose command runs `observer hook codex`. An entry switched off there stays off until you turn it back on.</li>
                <li>Come back here: the list below updates on the next load.</li>
              </ol>
            )}
          </>
        )}
        {!idle && t.entries && t.entries.length > 0 && (
          <dl
            className="mt-2 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-3 gap-y-0.5"
            data-testid="codex-trust-events"
          >
            {t.entries.map((e) => (
              <div key={e.event} className="contents">
                <dt className="text-fg-2">{e.event}</dt>
                <dd className={clsx(e.state === "trusted" ? "text-success" : "text-warn")}>
                  {CODEX_TRUST_STATE_LABEL[e.state]}
                </dd>
              </div>
            ))}
          </dl>
        )}
        {!idle && !t.hash_verified && t.entries && t.entries.length > 0 && (
          <p className="mt-1 text-fg-4">
            This codex version's trust hash could not be reproduced, so an entry
            changed since you trusted it reads as trusted here.
          </p>
        )}
        {t.other_homes && t.other_homes.length > 0 && (
          <ul className="mt-2 text-fg-3" data-testid="codex-trust-other-homes">
            {t.other_homes.map((o) => (
              <li key={o.origin ?? o.hooks_file}>
                {o.origin ?? "other home"}: {o.status.replace(/_/g, " ")}
                {o.gate_off && " (guard gate off)"}
                {o.instruction && ` - ${o.instruction}`}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

// Per-event state labels for the codex trust card. Registering hooks
// records trust for Observer's own entries (live check 2026-10-20); a
// switched-off entry is only ever turned back on in codex /hooks.
const CODEX_TRUST_STATE_LABEL: Record<CodexHookTrustEntry["state"], string> = {
  trusted: "trusted",
  untrusted: "not trusted yet: register hooks again",
  modified: "changed since trusted: register hooks again",
  disabled: "switched off in /hooks",
  missing: "not registered yet: run the Hooks step or restart the daemon",
};

function WizardStep({
  spec,
  tool,
  onChanged,
  onDoneChange,
}: {
  spec: StepSpec;
  tool: string;
  onChanged: () => void;
  onDoneChange?: (done: boolean) => void;
}) {
  const endpoint = spec.endpoint(tool)!;
  const [state, setState] = useState<{
    done: boolean;
    line: string;
    loading: boolean;
    error: string | null;
    conflict: boolean;
  }>({ done: false, line: "", loading: true, error: null, conflict: false });
  useEffect(() => {
    onDoneChange?.(state.done);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.done]);

  const post = useCallback(
    async (force: boolean, dryRun: boolean): Promise<WizardOutcome> => {
      // The telemetry step's route takes the confirm token on every POST
      // (preview included); the older steps' registration does not.
      const headers = spec.id === "telemetry" ? await localConfirmHeaders() : { "content-type": "application/json" };
      const res = await fetch(endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify(spec.body(tool, force, dryRun)),
      });
      const text = await res.text().catch(() => "");
      return classifyWizardReply(spec.id, res.status, text, !dryRun);
    },
    [endpoint, spec, tool],
  );

  // apply one outcome to the step: a plan line, a conflict, or an error
  // (never an error rendered as a plan, setupWizardPreview.ts).
  const show = useCallback((o: WizardOutcome, keepLine: boolean) => {
    setState((s) => {
      switch (o.kind) {
        case "plan":
          return { done: o.done, line: o.line, loading: false, error: null, conflict: false };
        case "conflict":
          return { done: false, line: "", loading: false, error: o.error, conflict: true };
        default:
          return { ...s, line: keepLine ? s.line : "", loading: false, error: o.error, conflict: false };
      }
    });
  }, []);

  // Preview on mount: a dry-run of the exact write.
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const o = await post(false, true);
        if (alive) show(o, false);
      } catch (e: unknown) {
        if (alive) {
          show({ kind: "error", denied: false, error: e instanceof Error ? e.message : String(e) }, false);
        }
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [endpoint]);

  async function apply(force: boolean) {
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const o = await post(force, false);
      show(o, true);
      if (o.kind === "plan") onChanged();
    } catch (e: unknown) {
      show({ kind: "error", denied: false, error: e instanceof Error ? e.message : String(e) }, true);
    }
  }

  return (
    <div className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={clsx(
            "inline-flex h-4 w-4 items-center justify-center rounded-pill border text-micro font-bold",
            state.done
              ? "border-success/40 bg-success-soft text-success"
              : "border-line-2 bg-bg-3 text-fg-4",
          )}
        >
          {state.done ? <Icon icon={Check} size={10} label="done" /> : <Icon icon={Dot} size={12} label="not done" />}
        </span>
        <span className="text-[11.5px] font-semibold text-fg-1">
          {spec.title}
        </span>
        <span className="flex-1 text-[11px] text-fg-3">{spec.blurb}</span>
        {!state.done && !state.loading && !state.conflict && (
          <Button variant="primary" size="sm" onClick={() => apply(false)}>
            {spec.action}
          </Button>
        )}
        {state.conflict && (
          <Button variant="danger" size="sm" onClick={() => apply(true)}>
            Force overwrite
          </Button>
        )}
      </div>
      {spec.plan.tradeoff && !state.done && (
        <p className="mt-1.5 text-[10.5px] leading-snug text-warn">
          Trade-off: {spec.plan.tradeoff}
        </p>
      )}
      {spec.note && !state.done && (
        <p className="mt-1.5 text-[10.5px] leading-snug text-fg-3">
          {spec.note}
          {spec.noteLink && (
            <>
              {" "}
              <Link to={spec.noteLink.to} className="font-medium text-accent hover:text-accent-strong">
                {spec.noteLink.label}
              </Link>
            </>
          )}
        </p>
      )}
      <div className="mt-1 font-mono text-[10.5px] text-fg-3">
        {state.loading
          ? "probing…"
          : state.error
            ? <span className="text-danger">{state.error}</span>
            : state.line}
      </div>
    </div>
  );
}

// RemovePanel - the wizard's undo (T-421): the dashboard twin of `observer
// uninstall --<tool>`, one step at a time. Each step previews the exact
// change (which entries go, from which file, which of your own entries the
// file keeps) before its own confirm, and only Observer's own entries are
// ever removed. The server runs the same removal the CLI runs.
function RemovePanel({
  tool,
  steps,
  onChanged,
  initialOpen,
}: {
  tool: string;
  steps: StepSpec[];
  onChanged: () => void;
  initialOpen: boolean;
}) {
  const [open, setOpen] = useState(initialOpen);
  if (steps.length === 0) return null;
  return (
    <details
      open={open}
      onToggle={(e) => setOpen((e.currentTarget as HTMLDetailsElement).open)}
      className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2"
      data-testid="wizard-remove-panel"
    >
      <summary className="cursor-pointer text-[11.5px] font-semibold text-fg-2">
        Remove Observer&apos;s wiring from {tool}
      </summary>
      {open && (
        <div className="mt-2 space-y-2">
          <p className="text-[11px] leading-snug text-fg-3">
            The same removal as <code className="font-mono text-fg-2">observer uninstall</code>:
            only Observer&apos;s own entries go, your own hooks and MCP servers in the same file
            stay. Each step previews its change first.
          </p>
          {steps.map((s) => (
            <RemoveStep key={s.id} spec={s} tool={tool} onChanged={onChanged} />
          ))}
        </div>
      )}
    </details>
  );
}

function RemoveStep({ spec, tool, onChanged }: { spec: StepSpec; tool: string; onChanged: () => void }) {
  const endpoint = spec.endpoint(tool)!;
  const [state, setState] = useState<{ loading: boolean; outcome: RemoveOutcome | null; removed: boolean }>({
    loading: true,
    outcome: null,
    removed: false,
  });

  const post = useCallback(
    async (force: boolean, dryRun: boolean): Promise<RemoveOutcome> => {
      const body = spec.id === "route" ? { undo: true, dry_run: dryRun } : { tool, undo: true, force, dry_run: dryRun };
      const res = await fetch(endpoint, { method: "POST", headers: await localConfirmHeaders(), body: JSON.stringify(body) });
      const text = await res.text().catch(() => "");
      return classifyRemoveReply(spec.id, res.status, text, !dryRun);
    },
    [endpoint, spec.id, tool],
  );

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const o = await post(false, true);
        if (alive) setState({ loading: false, outcome: o, removed: false });
      } catch (e: unknown) {
        if (alive) {
          setState({ loading: false, removed: false, outcome: { kind: "error", denied: false, error: e instanceof Error ? e.message : String(e) } });
        }
      }
    })();
    return () => {
      alive = false;
    };
  }, [post]);

  async function apply(force: boolean) {
    setState((s) => ({ ...s, loading: true }));
    try {
      const o = await post(force, false);
      setState({ loading: false, outcome: o, removed: o.kind === "plan" });
      if (o.kind === "plan") onChanged();
    } catch (e: unknown) {
      setState({ loading: false, removed: false, outcome: { kind: "error", denied: false, error: e instanceof Error ? e.message : String(e) } });
    }
  }

  const o = state.outcome;
  const canRemove = !state.loading && !state.removed && o?.kind === "plan" && !o.nothing;
  return (
    <div className="rounded-2 border border-line-1 bg-bg-3/40 px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11.5px] font-semibold text-fg-1">{spec.title}</span>
        <span className="flex-1" />
        {canRemove && (
          <ConfirmButton
            size="sm"
            variant="secondary"
            armedVariant="danger"
            onConfirm={() => void apply(false)}
            confirmLabel={`Remove from ${tool}?`}
            armedNote="Removes only the entries listed below."
          >
            Remove
          </ConfirmButton>
        )}
        {o?.kind === "conflict" && !state.loading && (
          <ConfirmButton
            size="sm"
            onConfirm={() => void apply(true)}
            confirmLabel="Remove anyway?"
            armedNote="The file changed since Observer wrote it; only Observer's own entries are removed."
          >
            Force remove
          </ConfirmButton>
        )}
      </div>
      <div className="mt-1 font-mono text-[10.5px] text-fg-3">
        {state.loading
          ? "probing…"
          : o === null
            ? ""
            : o.kind === "plan"
              ? o.line
              : <span className="text-danger">{o.error}</span>}
      </div>
    </div>
  );
}
