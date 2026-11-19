// HostedKeyLineControls.tsx is what the New Terminal dialog's hosted key
// line offers under its sentence (decisions SBXD-1 and SBXD-4,
// docs/decisions/sandbox-terminal-decisions-2026-11.md), so a choice is made
// where the person already is, never on another page:
//
//   - "Keep it on this machine": a password field that stores a provider key
//     through the credentials route (POST /api/terminal/sandbox/credentials,
//     owner-local, behind the confirm token; guard rule R-165 refuses an
//     agent's add). The daemon offers it only while credential injection is
//     on and only for a provider whose stored key would keep this launch's
//     key here (sandboxcred.KeepHomeOffers); the field is cleared before the
//     request and the probe is read again after it.
//   - The tool's opt-in in-box key sources: "Also use the keys <tool> saved
//     itself" and "Also copy my <tool> login". Each switch is remembered for
//     the tool ([terminal.sandbox.hosted.tool_keys] / login_seed, through
//     POST /api/terminal/sandbox/hosted/key-sources), and the hosted consent
//     binds the opted-in set, so the next upload asks again before first use.
//
// Every control comes from the daemon's answer (hostedKeyLineControls); this
// file decides nothing about which provider or tool qualifies.

import { useState } from "react";
import { Button } from "@/components/primitives";
import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import { hostedKeyLineControls, type HostedKeyBlock } from "@/lib/newTerminalSandbox";
import { credKeyProblem } from "@/lib/sandboxParity";

export function HostedKeyLineControls({
  block,
  tool,
  toolName,
  onChanged,
}: {
  block: HostedKeyBlock | null;
  tool: string;
  toolName: string;
  /** Called after a stored key or a switch changed: the dialog re-reads its probe. */
  onChanged: () => void;
}) {
  const c = hostedKeyLineControls(block, toolName);
  const [provider, setProvider] = useState("");
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (!block || (!c.where && c.keepHome.length === 0 && !c.toolKeys && !c.loginSeed)) return null;
  const chosen = c.keepHome.find((p) => p.id === provider) ?? c.keepHome[0];
  const problem = draft === "" ? null : credKeyProblem(draft);

  async function post(path: string, body: unknown) {
    setBusy(true);
    setErr(null);
    try {
      await fetchJSON(path, undefined, { method: "POST", headers: await localConfirmHeaders(), body: JSON.stringify(body) });
      onChanged();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function saveKey() {
    const key = draft.trim();
    // Cleared before the request, so the key never stays on the page.
    setDraft("");
    if (!chosen || key === "") return;
    void post("/api/terminal/sandbox/credentials", { provider: chosen.id, key });
  }

  return (
    <div className="mb-3 space-y-2 rounded-2 border border-line-2 bg-bg-3 p-2 text-[12px]" data-testid="new-terminal-hosted-key-controls">
      {c.where && <p className="text-fg-2">{c.where}</p>}
      {chosen && (
        <form
          className="flex flex-wrap items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (draft !== "" && !problem) saveKey();
          }}
        >
          <span className="w-full text-fg-1">Keep it on this machine: paste your {chosen.label}</span>
          {c.keepHome.length > 1 && (
            <select
              aria-label="Which provider's key"
              className="rounded-1 border border-line-2 bg-bg-2 px-2 py-1"
              value={chosen.id}
              disabled={busy}
              onChange={(e) => setProvider(e.target.value)}
            >
              {c.keepHome.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
            </select>
          )}
          <input
            type="password"
            aria-label={`Paste your ${chosen.label}`}
            className="min-w-0 flex-1 rounded-1 border border-line-2 bg-bg-2 px-2 py-1 font-mono text-[12px]"
            value={draft}
            placeholder="paste the key"
            autoComplete="off"
            spellCheck={false}
            disabled={busy}
            onChange={(e) => setDraft(e.target.value)}
          />
          <Button type="submit" size="sm" variant="soft" disabled={busy || draft === "" || !!problem}>
            {busy ? "saving…" : "Save key"}
          </Button>
          <span className="w-full text-[11px] text-fg-3">
            It is kept in this machine&apos;s key store and never shown again; Observer adds it only to this agent&apos;s
            requests to that provider, and the box holds a placeholder.
          </span>
          {problem && <span className="w-full text-[11px] text-warn">{problem}</span>}
        </form>
      )}
      {[
        { src: "tool_keys", ctl: c.toolKeys },
        { src: "login_seed", ctl: c.loginSeed },
      ].map(({ src, ctl }) =>
        ctl ? (
          <label key={src} className="flex items-start gap-2">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={ctl.on}
              disabled={busy}
              onChange={(e) => void post("/api/terminal/sandbox/hosted/key-sources", { tool, source: src, on: e.target.checked })}
            />
            <span>
              <span className="text-fg-1">{ctl.label}</span>
              <span className="block text-[11px] text-fg-3">
                Remembered for {toolName || "this agent"}. The box can read it; you agree to it on the consent screen before
                it is first used.
              </span>
            </span>
          </label>
        ) : null,
      )}
      {err && <p className="text-[11px] text-danger">{err}</p>}
    </div>
  );
}
