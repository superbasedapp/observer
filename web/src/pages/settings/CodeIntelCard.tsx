import { useState } from "react";
import { ConfirmButton, Pill } from "@/components/primitives";
import type { ConfigResponse } from "@/lib/types";
import { markRestartPending, RESTART_HINT } from "@/lib/restartPending";
import type { ConfigKeyPatch, ConfigKeysDryRun, ConfigKeysError, ConfigKeysResponse } from "@/lib/configSchema";
import {
  CODEINTEL_COPY,
  CODEINTEL_ENABLED_KEY,
  codeIntelState,
  codeIntelTogglePatch,
} from "@/lib/codeIntelToggle";

// CodeIntelCard - Settings > Intelligence > Code intelligence (D-307,
// 2026-10-05: code intelligence is OFF by default; the user opts in).
//
// One switch for one key, codeintel.enabled. The write goes through the
// same PUT /api/config/keys path as every schema-driven setting: a dry run
// first (the daemon validates the key and value and computes the diff),
// then the real write under the same etag. Turning it on is the whole
// action; there is no command to run. The other [codeintel] keys render in
// the section's "More settings" card below.

async function putKeys<T>(config: ConfigResponse, patches: ConfigKeyPatch[], dryRun: boolean): Promise<T> {
  const res = await fetch("/api/config/keys", {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      ...(config.confirm_token ? { "X-Observer-Confirm": config.confirm_token } : {}),
    },
    body: JSON.stringify({ base_etag: config.config_etag ?? "", patches, ...(dryRun ? { dry_run: true } : {}) }),
  });
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  if (!res.ok) {
    const e = (body ?? {}) as ConfigKeysError;
    const keyMsg = e.key_errors?.find((k) => k.key === CODEINTEL_ENABLED_KEY)?.message;
    throw new Error(keyMsg || e.message || text || `HTTP ${res.status}`);
  }
  return body as T;
}

export function CodeIntelCard({
  config,
  readOnly,
  onSaved,
}: {
  config: ConfigResponse | null;
  readOnly?: boolean;
  onSaved: () => void;
}) {
  const state = codeIntelState(config?.config);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  async function toggle() {
    const patch = codeIntelTogglePatch(state);
    if (!config || !patch) return;
    setBusy(true);
    setErr(null);
    setDone(null);
    try {
      // Sanity check before the write: the daemon validates the batch and
      // refuses it (unknown key, wrong type, a governed value, a stale etag)
      // without touching config.toml.
      await putKeys<ConfigKeysDryRun>(config, [patch], true);
      const out = await putKeys<ConfigKeysResponse>(config, [patch], false);
      if (out.restart_required_keys.length > 0) {
        markRestartPending("intelligence", out.restart_required_keys);
      }
      setDone(
        patch.value
          ? `Turned on. Indexing starts after a daemon restart: ${RESTART_HINT}.`
          : `Turned off. Applies after a daemon restart: ${RESTART_HINT}.`,
      );
      onSaved();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (state === "unknown") {
    return (
      <div className="mt-4 rounded-3 border border-line-2 bg-bg-2 p-4 text-[11.5px]">
        <div className="text-[12px] font-semibold text-fg-1">Code intelligence</div>
        <p className="m-0 mt-0.5 text-fg-3">State unavailable from this daemon.</p>
      </div>
    );
  }

  const copy = CODEINTEL_COPY[state];
  return (
    <div className="mt-4 rounded-3 border border-line-2 bg-bg-2 p-4 text-[11.5px]" data-testid="codeintel-card">
      <div className="flex flex-wrap items-center gap-2">
        <div className="text-[12px] font-semibold text-fg-1">Code intelligence</div>
        <Pill variant={copy.tone}>{copy.label}</Pill>
      </div>
      <p className="m-0 mt-1 text-fg-3">{copy.summary}</p>
      <ConfirmButton
        variant={state === "off" ? "primary" : "secondary"}
        armedVariant={state === "off" ? "primary" : "danger"}
        className="mt-2"
        onConfirm={toggle}
        disabled={busy || readOnly || !config}
        loading={busy}
        title={readOnly ? "Managed by your organization" : undefined}
        confirmLabel={copy.confirm}
        armedNote={copy.armedNote}
      >
        {copy.action}
      </ConfirmButton>
      {done && <p className="m-0 mt-2 text-success">{done}</p>}
      {err && <p className="m-0 mt-2 text-danger">{err}</p>}
    </div>
  );
}
