// SandboxCredentialsPanel.tsx is the "Credential injection and run
// re-adoption" sub-panel of the Sandbox isolation card (sandbox plan v2
// sections 5.5, 7.2 and 7.3; gaps G24 and G50; lane GATES-SBX). The card
// mounts it with one line and owns the save. It edits [terminal.sandbox.readopt]
// with pickers only, lists which providers have a key for injection (never a
// key), and lists the local container runs offered for re-adoption. Each half
// renders only while its opt-in component is selected
// (terminals.sandbox.credentials, terminals.sandbox.oci.readopt). A key is
// added on the command line (`observer sandbox credentials add <provider>`,
// read without echo), never typed into a text field here (D-571), and guard
// rule R-165 refuses an agent's add.

import { useState } from "react";
import { ComboChip, ConfirmButton } from "@/components/primitives";
import { fetchJSON } from "@/lib/api";
import type { ComponentsView } from "@/lib/componentState";
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
              never sees it. Add a key in your own terminal with{" "}
              <span className="font-mono">observer sandbox credentials add &lt;provider&gt;</span> (it is read without echo and
              stored in the OS keychain); an agent cannot run that command. Local runs get no injection in this release.
              Provider-injected custody (a vendor&apos;s own secret broker) is not offered yet.
            </p>
            <ul className="space-y-1">
              {(p.creds?.providers ?? []).map((c) => (
                <li key={c.provider} className="flex items-center justify-between gap-2 text-[12px]">
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
                </li>
              ))}
            </ul>
            {p.creds && <p className="text-[11px] text-fg-3">Key store: {p.creds.store}</p>}
          </section>
        )}
        {p.readoptOn && (
          <section className="space-y-2" aria-label="Re-adopting container runs">
            <h4 className="font-medium text-fg-1">Re-adopting container runs</h4>
            <p className="text-[11px] text-fg-3">
              A container run whose helper went away is kept on rootful Docker with live-restore or on Podman, and offered here;
              re-attach it with <span className="font-mono">observer sandbox readopt &lt;run&gt;</span> (the scrollback starts
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
              {(p.runs?.runs ?? []).map((r) => (
                <li key={r.run_id} className="space-y-1 text-[12px]">
                  <div>
                    <span className="font-mono">{r.run_id}</span> {r.state} {r.tool} <span className="text-fg-3">{r.project}</span>
                  </div>
                  {r.command && <div className="font-mono text-[11px] text-fg-3">{r.command}</div>}
                  <div className="flex gap-2">
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
              ))}
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
}: {
  value: SandboxReadoptConfig | undefined;
  view: ComponentsView | undefined;
  pinned: Set<string>;
  writable: boolean;
  onChange: (next: SandboxReadoptConfig) => void;
}) {
  const credOn = componentActive(view, "terminals.sandbox.credentials");
  const readoptOn = componentActive(view, "terminals.sandbox.oci.readopt");
  const creds = useApi<CredState>(credOn ? "/api/terminal/sandbox/credentials" : null, undefined, [credOn]);
  const runs = useApi<ReadoptState>(readoptOn ? "/api/terminal/sandbox/readopt" : null, undefined, [readoptOn]);
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState<string | null>(null);
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
    />
  );
}
