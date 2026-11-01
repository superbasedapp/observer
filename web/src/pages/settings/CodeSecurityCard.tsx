import { useState } from "react";
import { Link } from "react-router-dom";
import { Select } from "@/components/primitives";
import type { ConfigResponse } from "@/lib/types";
import { markRestartPending } from "@/lib/restartPending";
import type { ConfigKeyPatch, ConfigKeysDryRun, ConfigKeysError, ConfigKeysResponse } from "@/lib/configSchema";
import {
  codeSecurityOptionLabel,
  codeSecurityParse,
  codeSecurityPatch,
  codeSecurityRows,
  codeSecurityValue,
  type CodeSecuritySetting,
  type CodeSecurityValue,
} from "@/lib/codeSecuritySettings";
import type { ComponentsView } from "@/lib/componentState";

// CodeSecurityCard - Settings > Guard > Code security (security pillar
// plan section 6.5, Phase A). The node-dashboard home of the module's
// [security.*] keys: one picker per settings-contract row, written through
// PUT /api/config/keys (a dry run first, then the write under the same
// etag). Rendered only while the `security` component is active; loaded as
// its own chunk, so an inactive or omitted module adds nothing to the page.

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
    const keyMsg = e.key_errors?.find((k) => patches.some((p) => p.key === k.key))?.message;
    throw new Error(keyMsg || e.message || text || `HTTP ${res.status}`);
  }
  return body as T;
}

function SettingRow({
  row,
  config,
  readOnly,
  onSaved,
}: {
  row: CodeSecuritySetting;
  config: ConfigResponse | null;
  readOnly?: boolean;
  onSaved: () => void;
}) {
  const current = codeSecurityValue(config?.config, row);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function choose(next: CodeSecurityValue | null) {
    if (next === null) return;
    const patch = codeSecurityPatch(row, current, next);
    if (!config || !patch) return;
    setBusy(true);
    setErr(null);
    try {
      await putKeys<ConfigKeysDryRun>(config, [patch], true);
      const out = await putKeys<ConfigKeysResponse>(config, [patch], false);
      if (out.restart_required_keys.length > 0) markRestartPending("guard", out.restart_required_keys);
      onSaved();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (current === null) {
    return (
      <div className="text-fg-3">
        {row.label}: value unavailable from this daemon.
      </div>
    );
  }
  return (
    <div>
      <Select
        label={row.label}
        help={row.help}
        value={String(current)}
        disabled={busy || readOnly || !config}
        title={readOnly ? "Managed by your organization" : undefined}
        onChange={(e) => void choose(codeSecurityParse(row, e.target.value))}
        options={row.values.map((v) => ({
          value: String(v),
          label: codeSecurityOptionLabel(row, v),
        }))}
        data-testid={`code-security-setting-${row.key}`}
      />
      {err && <p className="m-0 mt-1 text-danger">{err}</p>}
    </div>
  );
}

export function CodeSecurityCard({
  config,
  components,
  securitySelected,
  readOnly,
  onSaved,
}: {
  config: ConfigResponse | null;
  components: ComponentsView | null | undefined;
  /** GET /api/components/state's security_selected (the opt-in rule). */
  securitySelected: readonly string[] | null | undefined;
  readOnly?: boolean;
  onSaved: () => void;
}) {
  return (
    <div className="mt-4 rounded-3 border border-line-2 bg-bg-2 p-4 text-[11.5px]" data-testid="code-security-card">
      <div className="flex flex-wrap items-center gap-2">
        <div className="text-[12px] font-semibold text-fg-1">Code security</div>
        <Link to="/code-security" className="text-accent hover:underline">
          Open Code security
        </Link>
      </div>
      <p className="m-0 mt-1 text-fg-3">
        Settings of the security module (component security). Changes take effect after the daemon restarts, except the custom scanner schedule rows, which apply within 15 minutes.
      </p>
      <p className="m-0 mt-1 text-fg-3">
        Turning Code security off in Settings &gt; Components also turns off its parts (Secret detection, Code rules):
        they need it. A config file that removes only security keeps it on while a part stays selected, and the
        daemon warns which part to remove too.
      </p>
      <div className="mt-3 grid gap-3">
        {codeSecurityRows(components, securitySelected).map((row) => (
          <SettingRow key={row.key} row={row} config={config} readOnly={readOnly} onSaved={onSaved} />
        ))}
      </div>
    </div>
  );
}
