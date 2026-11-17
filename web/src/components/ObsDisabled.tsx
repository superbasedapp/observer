import { useState, type ReactNode } from "react";
import { GatedLink } from "@/components/GatedLink";
import { ConfirmButton, EmptyState } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import type { ConfigResponse } from "@/lib/types";
import type { ConfigKeyPatch, ConfigKeysDryRun, ConfigKeysError, ConfigKeysResponse } from "@/lib/configSchema";
import { markRestartPending } from "@/lib/restartPending";
import {
  OBS_KEYS,
  obsEnableDoneLine,
  obsEnableLabel,
  obsEnableNote,
  obsEnablePatches,
  obsEnableState,
  type ObsNeed,
} from "@/lib/obsEnable";

// ObsDisabled: the page-level "observability is off" state for the pages
// whose /api/obs/* routes are registered only when [observability] is
// enabled (Egress, Policies). One component so the two pages cannot drift
// (each held its own copy before 2026-09-28). Since B-S1 (plan
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md) it turns the switches
// on itself: a dry run then the save of the needed keys through
// PUT /api/config/keys (the CodeIntelCard pattern), then the restart banner,
// since the routes register at daemon start. Settings > Observability holds
// the rest of the section.

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
    const keyMsg = e.key_errors?.map((k) => `${k.key}: ${k.message}`).join("; ");
    throw new Error(keyMsg || e.message || text || `HTTP ${res.status}`);
  }
  return body as T;
}

export function ObsDisabled({
  children,
  needs = ["observability"],
}: {
  /** Why this page needs the observability subsystem (one sentence). */
  children: ReactNode;
  /** The switches the page needs on: observability, and for Policies admission too. */
  needs?: ObsNeed[];
}) {
  const cfg = useApi<ConfigResponse>("/api/config");
  const patches = obsEnablePatches(obsEnableState(cfg.data?.config), needs);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [done, setDone] = useState("");

  async function turnOn() {
    if (!cfg.data || patches === null) return;
    setBusy(true);
    setErr("");
    try {
      if (patches.length === 0) {
        // On in config.toml already: only the restart is missing.
        markRestartPending("observability", needs.map((n) => OBS_KEYS[n]));
        setDone(obsEnableDoneLine(false));
        return;
      }
      // The daemon validates the batch (unknown key, wrong type, a governed
      // value, a stale etag) and refuses it without touching config.toml.
      await putKeys<ConfigKeysDryRun>(cfg.data, patches, true);
      const out = await putKeys<ConfigKeysResponse>(cfg.data, patches, false);
      markRestartPending("observability", out.restart_required_keys.length > 0 ? out.restart_required_keys : patches.map((p) => p.key));
      setDone(obsEnableDoneLine(true));
      cfg.reload();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <EmptyState illustration="connect" title="Observability is off">
      <div className="mx-auto max-w-xl text-small leading-relaxed text-fg-3">
        <p>{children} Turn it on here; it takes effect after the daemon restarts.</p>
        <div className="mt-3 flex flex-wrap items-center justify-center gap-2">
          <ConfirmButton
            variant="primary"
            armedVariant="primary"
            onConfirm={() => void turnOn()}
            disabled={busy || !cfg.data || patches === null || done !== ""}
            loading={busy}
            confirmLabel="Turn on?"
            armedNote={obsEnableNote(needs)}
          >
            {obsEnableLabel(needs)}
          </ConfirmButton>
          <GatedLink to="/settings?section=observability" className="text-accent hover:underline">
            Settings &gt; Observability
          </GatedLink>
        </div>
        {cfg.data && patches === null && (
          <p className="mt-2">This daemon did not report the switch's state; turn it on in Settings &gt; Observability.</p>
        )}
        {done && <p className="mt-2 text-success">{done}</p>}
        {err && <p className="mt-2 text-danger">{err}</p>}
      </div>
    </EmptyState>
  );
}
