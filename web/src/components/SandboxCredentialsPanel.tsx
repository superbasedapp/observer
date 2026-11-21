// SandboxCredentialsPanel.tsx is the "Credential injection and run
// re-adoption" sub-panel of the Sandbox isolation card (sandbox plan v2
// sections 5.5, 7.2 and 7.3; gaps G24 and G50; lane GATES-SBX). The card
// mounts it with one line and owns the save. It edits [terminal.sandbox.readopt]
// with pickers only, lists which providers have a key for injection (never a
// key), and lists the local container runs offered for re-adoption. Each half
// renders only while its opt-in component is selected
// (terminals.sandbox.credentials, terminals.sandbox.oci.readopt).
//
// Dashboard CLI parity (plan docs/plans/dashboard-cli-parity-plan-2026-11-06.md,
// lane L3; the operator rule supersedes the D-571 "never a text field here"
// note for this one secret): a key is added here through a password field that
// is never pre-filled, is cleared as soon as Save is pressed and never shows
// the key again (B-G1, POST /api/terminal/sandbox/credentials; guard rule
// R-165 refuses an agent's add). A run offered for re-adoption gets
// "Re-attach in a terminal" (B-G3, decision P-3), which opens a dashboard
// terminal running `observer sandbox readopt <run>`.

import { useState } from "react";
import { Button, ComboChip, ConfirmButton } from "@/components/primitives";
import { fetchJSON } from "@/lib/api";
import type { ComponentsView } from "@/lib/componentState";
import { credKeyProblem, readoptCanReattach } from "@/lib/sandboxParity";
import { useApi } from "@/lib/useApi";

export type SandboxReadoptConfig = {
  bound_minutes: number;
  checkpoint_cap_mib: number;
};

export type CredProvider = { provider: string; label: string; host: string; key_env: string; stored: boolean };
export type CredState = { providers: CredProvider[]; store: string; confirm_token: string };
export type ReadoptRun = { run_id: string; tool: string; project: string; state: string; reason: string; command: string; checkpointed: boolean };
export type ReadoptState = { runs: ReadoptRun[] | null; confirm_token: string };

export const BOUND_MINUTES = [5, 10, 30, 60, 120];
export const CAP_MIB = [512, 1024, 2048, 4096];

// componentActive applies the daemon's opt-in rule for a feature child: a
// configured [components] block with the component active.
export function componentActive(view: ComponentsView | undefined, id: string): boolean {
  if (!view || !view.configured) return false;
  return view.components.some((c) => c.id === id && c.state === "active");
}

export type SandboxCredentialsViewProps = {
  readopt: SandboxReadoptConfig;
  credOn: boolean;
  readoptOn: boolean;
  creds: CredState | null | undefined;
  runs: ReadoptState | null | undefined;
  pinned: Set<string>;
  writable: boolean;
  busy: string;
  err: string | null;
  onChange: (next: SandboxReadoptConfig) => void;
  post: (path: string, body: unknown, key: string, token: string) => void;
  /** keyDraft is what is typed in each provider's key field (never a stored key). */
  keyDraft?: Record<string, string>;
  onKeyDraft?: (provider: string, value: string) => void;
  /** saveKey stores the typed key; absent, no key field renders. */
  saveKey?: (provider: string) => void;
  /** reattach opens a dashboard terminal on an offered run; absent, no button renders. */
  reattach?: (run: string) => void;
};

/** SandboxCredentialsView renders from props only, so a render test needs no fetch. */
export function SandboxCredentialsView(p: SandboxCredentialsViewProps) {
  if (!p.credOn && !p.readoptOn) return null;
  const bound = p.readopt.bound_minutes || 10;
  const cap = p.readopt.checkpoint_cap_mib || 2048;
  const edit = (k: keyof SandboxReadoptConfig) => p.writable && !p.pinned.has("readopt." + k);
  const opts = (vals: number[], cur: number, unit: string) =>
    (vals.includes(cur) ? vals : [...vals, cur].sort((a, b) => a - b)).map((n) => ({ value: String(n), label: <span>{n} {unit}</span>, searchable: `${n} ${unit}` }));
  return (
    <details className="rounded-2 border border-line-2 bg-bg-3 p-3">
      <summary className="cursor-pointer font-medium text-fg-1">
        Credential injection and run re-adoption <span className="ml-1 rounded-1 border border-line-2 px-1 text-[10px] text-fg-3">beta</span>
      </summary>
      <div className="mt-3 space-y-4">
        {p.err && <p className="text-[11px] text-danger">{p.err}</p>}
        {p.credOn && (
          <section className="space-y-2" aria-label="Credential injection">
            <h4 className="font-medium text-fg-1">Credential injection</h4>
            <p className="text-[11px] text-fg-3">
              A hosted sandboxed run whose key stays at home gets only a sentinel in its
              key variable; Observer&apos;s proxy adds your own key on requests to that provider&apos;s model host, and the box
              never sees it. Paste a provider&apos;s key below and save it: it is stored in this machine&apos;s key store, the
              field is cleared at once, and the key is never shown again (same as{" "}
              <span className="font-mono">observer sandbox credentials add &lt;provider&gt;</span>). Only you can add a key: an
              agent&apos;s add is refused. Local runs get no injection in this release. Provider-injected custody (a
              vendor&apos;s own secret broker) is not offered yet.
            </p>
            <ul className="space-y-2">
              {(p.creds?.providers ?? []).map((c) => {
                const draft = p.keyDraft?.[c.provider] ?? "";
                const problem = draft === "" ? null : credKeyProblem(draft);
                return (
                  <li key={c.provider} className="space-y-1 text-[12px]">
                    <div className="flex items-center justify-between gap-2">
                      <span>
                        {c.label} <span className="text-fg-3">({c.host}, box variable <span className="font-mono">{c.key_env}</span>)</span>:{" "}
                        {c.stored ? "key stored" : "no key"}
                      </span>
                      {c.stored && (
                        <ConfirmButton
                          variant="soft"
                          disabled={!p.writable || p.busy !== ""}
                          onConfirm={() => p.post("/api/terminal/sandbox/credentials/remove", { provider: c.provider }, "rm-" + c.provider, p.creds?.confirm_token ?? "")}
                        >
                          Remove
                        </ConfirmButton>
                      )}
                    </div>
                    {p.saveKey && p.onKeyDraft && (
                      <form
                        className="flex flex-wrap items-center gap-2"
                        onSubmit={(e) => {
                          e.preventDefault();
                          if (draft !== "" && !problem) p.saveKey?.(c.provider);
                        }}
                      >
                        <input
                          type="password"
                          aria-label={`${c.label}: ${c.stored ? "replace the key" : "add a key"}`}
                          className="min-w-0 flex-1 rounded-1 border border-line-2 bg-bg-2 px-2 py-1 font-mono text-[12px]"
                          value={draft}
                          placeholder={c.stored ? "paste a new key to replace it" : "paste the key"}
                          autoComplete="off"
                          spellCheck={false}
                          disabled={!p.writable || p.busy !== ""}
                          onChange={(e) => p.onKeyDraft?.(c.provider, e.target.value)}
                        />
                        <Button type="submit" size="sm" variant="soft" disabled={!p.writable || p.busy !== "" || draft === "" || !!problem}>
                          {p.busy === "add-" + c.provider ? "saving…" : c.stored ? "Replace key" : "Save key"}
                        </Button>
                        {problem && <span className="w-full text-[11px] text-warn">{problem}</span>}
                      </form>
                    )}
                  </li>
                );
              })}
            </ul>
            {p.creds && <p className="text-[11px] text-fg-3">Key store: {p.creds.store}</p>}
          </section>
        )}
        {p.readoptOn && (
          <section className="space-y-2" aria-label="Re-adopting container runs">
            <h4 className="font-medium text-fg-1">Re-adopting container runs</h4>
            <p className="text-[11px] text-fg-3">
              A container run whose helper went away is kept on rootful Docker with live-restore or on Podman, and offered here;
              re-attach it with Re-attach in a terminal below, which opens a dashboard terminal on the run (the scrollback starts
              empty and a marker says so). A run nobody re-adopts is removed after the time below. A Podman checkpoint runs only
              when you ask, needs rootful Podman with CRIU, and stays on this machine.
            </p>
            <div className="space-y-1">
              <span id="sandbox-readopt-bound" className="block font-medium text-fg-1">Keep an unadopted run for</span>
              <ComboChip label="Keep an unadopted run for" labelledBy="sandbox-readopt-bound" hideTriggerLabel fullWidth value={String(bound)}
                disabled={!edit("bound_minutes")} onChange={(v) => p.onChange({ ...p.readopt, bound_minutes: Number(v) })}
                options={opts(BOUND_MINUTES, bound, "minutes")} buttonValueRender={() => <span>{bound} minutes</span>} />
            </div>
            <div className="space-y-1">
              <span id="sandbox-readopt-cap" className="block font-medium text-fg-1">Largest checkpoint</span>
              <ComboChip label="Largest checkpoint" labelledBy="sandbox-readopt-cap" hideTriggerLabel fullWidth value={String(cap)}
                disabled={!edit("checkpoint_cap_mib")} onChange={(v) => p.onChange({ ...p.readopt, checkpoint_cap_mib: Number(v) })}
                options={opts(CAP_MIB, cap, "MiB")} buttonValueRender={() => <span>{cap} MiB</span>} />
            </div>
            <ul className="space-y-1">
              {(p.runs?.runs ?? []).length === 0 && <li className="text-[11px] text-fg-3">No run is offered for re-adoption.</li>}
              {(p.runs?.runs ?? []).map((r) => {
                const canAttach = !!p.reattach && readoptCanReattach(r.state);
                return (
                  <li key={r.run_id} className="space-y-1 text-[12px]">
                    <div>
                      <span className="font-mono">{r.run_id}</span> {r.state} {r.tool} <span className="text-fg-3">{r.project}</span>
                    </div>
                    {r.command && (
                      <div className="font-mono text-[11px] text-fg-3">
                        {canAttach && <span className="font-sans">Same as </span>}
                        {r.command}
                      </div>
                    )}
                    <div className="flex flex-wrap gap-2">
                      {canAttach && (
                        <Button size="sm" variant="soft" disabled={!p.writable || p.busy !== ""} onClick={() => p.reattach?.(r.run_id)}>
                          {p.busy === "attach-" + r.run_id ? "opening terminal…" : "Re-attach in a terminal"}
                        </Button>
                      )}
                      {!r.checkpointed && r.state !== "readopted" && (
                        <ConfirmButton variant="soft" disabled={!p.writable || p.busy !== ""}
                          onConfirm={() => p.post("/api/terminal/sandbox/readopt/checkpoint", { run: r.run_id }, "cp-" + r.run_id, p.runs?.confirm_token ?? "")}>
                          Checkpoint
                        </ConfirmButton>
                      )}
                      {r.checkpointed && (
                        <ConfirmButton variant="soft" disabled={!p.writable || p.busy !== ""}
                          onConfirm={() => p.post("/api/terminal/sandbox/readopt/restore", { run: r.run_id }, "rs-" + r.run_id, p.runs?.confirm_token ?? "")}>
                          Restore
                        </ConfirmButton>
                      )}
                      <ConfirmButton variant="soft" disabled={!p.writable || p.busy !== ""}
                        onConfirm={() => p.post("/api/terminal/sandbox/readopt/end", { run: r.run_id }, "end-" + r.run_id, p.runs?.confirm_token ?? "")}>
                        End the run
                      </ConfirmButton>
                    </div>
                  </li>
                );
              })}
            </ul>
          </section>
        )}
      </div>
    </details>
  );
}

export function SandboxCredentialsPanel({
  value,
  view,
  pinned,
  writable,
  onChange,
  onOpenTerminal,
}: {
  value: SandboxReadoptConfig | undefined;
  view: ComponentsView | undefined;
  pinned: Set<string>;
  writable: boolean;
  onChange: (next: SandboxReadoptConfig) => void;
  /** onOpenTerminal shows a just-opened dashboard terminal (the card passes
   * the dock's launch); absent, no re-attach button renders. */
  onOpenTerminal?: (handle: string, label: string) => void;
}) {
  const credOn = componentActive(view, "terminals.sandbox.credentials");
  const readoptOn = componentActive(view, "terminals.sandbox.oci.readopt");
  const creds = useApi<CredState>(credOn ? "/api/terminal/sandbox/credentials" : null, undefined, [credOn]);
  const runs = useApi<ReadoptState>(readoptOn ? "/api/terminal/sandbox/readopt" : null, undefined, [readoptOn]);
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState<string | null>(null);
  // The typed keys live here only until Save: never pre-filled, never logged.
  const [keyDraft, setKeyDraft] = useState<Record<string, string>>({});
  async function post(path: string, body: unknown, key: string, token: string) {
    setBusy(key);
    setErr(null);
    try {
      await fetchJSON(path, undefined, { method: "POST", headers: { "Content-Type": "application/json", "X-Observer-Confirm": token }, body: JSON.stringify(body) });
      creds.reload();
      runs.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy("");
    }
  }
  function saveKey(provider: string) {
    const key = (keyDraft[provider] ?? "").trim();
    // Cleared before the request, so the key never stays on the page.
    setKeyDraft((cur) => ({ ...cur, [provider]: "" }));
    if (key === "") return;
    void post("/api/terminal/sandbox/credentials", { provider, key }, "add-" + provider, creds.data?.confirm_token ?? "");
  }
  async function reattach(run: string) {
    if (!onOpenTerminal) return;
    setBusy("attach-" + run);
    setErr(null);
    try {
      const res = await fetchJSON<{ handle: string }>("/api/terminal/sandbox/readopt/attach", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Observer-Confirm": runs.data?.confirm_token ?? "" },
        body: JSON.stringify({ run }),
      });
      onOpenTerminal(res.handle, `sandbox readopt ${run}`);
      runs.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy("");
    }
  }
  return (
    <SandboxCredentialsView
      readopt={value ?? { bound_minutes: 10, checkpoint_cap_mib: 2048 }}
      credOn={credOn}
      readoptOn={readoptOn}
      creds={creds.data}
      runs={runs.data}
      pinned={pinned}
      writable={writable}
      busy={busy}
      err={err}
      onChange={onChange}
      post={(path, body, key, token) => void post(path, body, key, token)}
      keyDraft={keyDraft}
      onKeyDraft={(provider, v) => setKeyDraft((cur) => ({ ...cur, [provider]: v }))}
      saveKey={saveKey}
      reattach={onOpenTerminal ? (run) => void reattach(run) : undefined}
    />
  );
}
