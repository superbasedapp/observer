import { useCallback, useEffect, useState } from "react";
import clsx from "clsx";
import { Obs } from "@/components/Obs";
import { useApi } from "@/lib/useApi";
import type { CodexHookTrust } from "@/lib/types";

// SetupWizard — the guided per-tool init flow (usability arc P4.2 /
// review row B3). One card per integration step (hooks → MCP → proxy
// route); each step shows a dry-run PREVIEW of the exact write, and
// nothing is written until the user clicks that step's own button —
// per-write consent, never a bundled "do everything". Writes are
// byte-equivalent to `observer init` (same registries server-side).

const WIZARD_STEP_IDS = ["hooks", "mcp", "route"] as const;
type StepId = (typeof WIZARD_STEP_IDS)[number];

// One response shape covers all three endpoints' fields.
type WizardResponse = {
  config_path?: string;
  hooks_added?: string[];
  already_set?: string[] | boolean;
  added?: boolean;
  dry_run?: boolean;
  error?: string;
  base_url?: string;
};

type StepSpec = {
  id: StepId;
  title: string;
  blurb: string;
  action: string;
  // Optional honesty note rendered with the step (MCP overhead).
  note?: string;
  endpoint: (tool: string) => string | null;
  body: (tool: string, force: boolean, dryRun: boolean) => unknown;
  summarize: (r: WizardResponse, wrote: boolean) => { done: boolean; line: string };
};

const STEPS: StepSpec[] = [
  {
    id: "hooks",
    title: "Hooks",
    blurb:
      "Lightweight turn-boundary hooks in the tool's own config - the capture path that needs no proxy.",
    action: "Register hooks",
    endpoint: () => "/api/setup/hooks",
    body: (tool, force, dry_run) => ({ tool, force, dry_run }),
    summarize: (r, wrote) => {
      const added = r.hooks_added ?? [];
      const already = Array.isArray(r.already_set) ? r.already_set : [];
      if (added.length === 0 && already.length > 0) {
        return { done: true, line: `${already.length} events registered in ${r.config_path}` };
      }
      if (wrote) {
        return { done: true, line: `registered ${added.length} events in ${r.config_path}` };
      }
      const suffix = already.length > 0 ? ` (${already.length} already set)` : "";
      return { done: false, line: `will register ${added.length} events in ${r.config_path}${suffix}` };
    },
  },
  {
    id: "mcp",
    title: "MCP server",
    blurb:
      "On-demand project-knowledge queries inside the tool (13 observer tools).",
    note: "Honest trade-off: the registered tool schemas add roughly 1,800 tokens to every turn. Worth it if you use the queries; skip this step if unsure - everything else works without it.",
    action: "Register MCP server",
    endpoint: () => "/api/setup/mcp",
    body: (tool, force, dry_run) => ({ tool, force, dry_run }),
    summarize: (r, wrote) => {
      if (r.already_set === true) {
        return { done: true, line: `observer MCP server registered in ${r.config_path}` };
      }
      if (wrote && r.added) {
        return { done: true, line: `registered in ${r.config_path}` };
      }
      return { done: false, line: `will add the observer MCP server to ${r.config_path}` };
    },
  },
  {
    id: "route",
    title: "Proxy route",
    blurb:
      "Durable routing through the observer proxy - exact token accounting, conversation compression, and cache tracking.",
    action: "Route through proxy",
    endpoint: (tool) =>
      tool === "claude-code"
        ? "/api/setup/claude"
        : tool === "codex"
          ? "/api/setup/codex"
          : null,
    body: (_tool, force, dry_run) => ({ force, dry_run }),
    summarize: (r, wrote) => {
      if (r.already_set === true) {
        return { done: true, line: `already routed (${r.base_url ?? r.config_path})` };
      }
      if (wrote && r.added) {
        return { done: true, line: `routed via ${r.base_url} (${r.config_path})` };
      }
      return { done: false, line: `will set ${r.base_url ?? "the proxy URL"} in ${r.config_path}` };
    },
  },
];

export function SetupWizard({
  tool,
  onChanged,
}: {
  tool: string;
  onChanged: () => void;
}) {
  const steps = STEPS.filter((s) => s.endpoint(tool) !== null);
  // D-3 (§9.3): the ★ SETUP COMPLETE ★ moment — fires only when every
  // applicable step reports done. A transitional wizard end-state, not
  // a recurring toast (restraint rules §9.4: the sprite pulse IS the
  // celebration; no sound, no confetti).
  const [doneMap, setDoneMap] = useState<Record<string, boolean>>({});
  const allDone =
    steps.length > 0 && steps.every((s) => doneMap[s.id] === true);
  return (
    <div className="my-2 space-y-2 rounded-2 border border-line-2 bg-bg-1 p-3">
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
      {tool === "codex" && <CodexTrustCard />}
      {allDone && (
        <div className="flex items-center gap-3 rounded-2 border border-success/30 bg-success-soft px-3 py-2">
          <Obs state="jump" size={24} />
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
            "inline-flex h-4 w-4 items-center justify-center rounded-full border text-[10px] font-bold",
            ok
              ? "border-success/40 bg-success-soft text-success"
              : "border-line-2 bg-bg-3 text-fg-4",
          )}
        >
          {ok ? "✓" : "·"}
        </span>
        <span className="text-[11.5px] font-semibold text-fg-1">
          Hook trust (inside codex)
        </span>
        <span className="flex-1 text-[11px] text-fg-3">
          codex asks you to trust each registered hook event before it runs -
          observer can read that state but never set it.
        </span>
      </div>
      <div className="mt-1 font-mono text-[10.5px] text-fg-3">
        {ok && `all ${t.trusted_events?.length ?? 0} events trusted`}
        {idle && `nothing to trust yet (${t.status.replace("_", " ")})`}
        {!ok && !idle && (
          <>
            <span className={t.status === "needs_trust" ? "text-warn" : ""}>
              {t.status.replace(/_/g, " ")}
              {t.untrusted_events && t.untrusted_events.length > 0 &&
                ` - ${t.untrusted_events.length} events untrusted`}
            </span>
            {t.instruction && (
              <p className="mt-1 whitespace-pre-wrap text-fg-2">
                {t.instruction}
              </p>
            )}
          </>
        )}
      </div>
    </div>
  );
}

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
    async (force: boolean, dryRun: boolean): Promise<{ r: WizardResponse; status: number }> => {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(spec.body(tool, force, dryRun)),
      });
      const r = (await res.json().catch(() => ({}))) as WizardResponse;
      return { r, status: res.status };
    },
    [endpoint, spec, tool],
  );

  // Preview on mount: a dry-run of the exact write.
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const { r, status } = await post(false, true);
        if (!alive) return;
        if (status === 409) {
          setState({
            done: false,
            line: "",
            loading: false,
            error: r.error ?? "conflict",
            conflict: true,
          });
          return;
        }
        const sum = spec.summarize(r, false);
        setState({ ...sum, loading: false, error: null, conflict: false });
      } catch (e: unknown) {
        if (alive) {
          setState({
            done: false,
            line: "",
            loading: false,
            error: e instanceof Error ? e.message : String(e),
            conflict: false,
          });
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
      const { r, status } = await post(force, false);
      if (status === 409) {
        setState({
          done: false,
          line: "",
          loading: false,
          error: r.error ?? "conflict - this entry points somewhere you configured deliberately",
          conflict: true,
        });
        return;
      }
      if (status !== 200) {
        setState((s) => ({
          ...s,
          loading: false,
          error: r.error ?? `HTTP ${status}`,
        }));
        return;
      }
      const sum = spec.summarize(r, true);
      setState({ ...sum, loading: false, error: null, conflict: false });
      onChanged();
    } catch (e: unknown) {
      setState((s) => ({
        ...s,
        loading: false,
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }

  return (
    <div className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className={clsx(
            "inline-flex h-4 w-4 items-center justify-center rounded-full border text-[10px] font-bold",
            state.done
              ? "border-success/40 bg-success-soft text-success"
              : "border-line-2 bg-bg-3 text-fg-4",
          )}
        >
          {state.done ? "✓" : "·"}
        </span>
        <span className="text-[11.5px] font-semibold text-fg-1">
          {spec.title}
        </span>
        <span className="flex-1 text-[11px] text-fg-3">{spec.blurb}</span>
        {!state.done && !state.loading && !state.conflict && (
          <button
            type="button"
            onClick={() => apply(false)}
            className="rounded-2 bg-accent px-2.5 py-1 text-[11px] font-semibold text-accent-on hover:opacity-90"
          >
            {spec.action}
          </button>
        )}
        {state.conflict && (
          <button
            type="button"
            onClick={() => apply(true)}
            className="rounded-2 border border-danger bg-danger/10 px-2.5 py-1 text-[11px] font-semibold text-danger hover:bg-danger/20"
          >
            Force overwrite
          </button>
        )}
      </div>
      {spec.note && !state.done && (
        <p className="mt-1.5 text-[10.5px] leading-snug text-fg-3">
          {spec.note}
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
