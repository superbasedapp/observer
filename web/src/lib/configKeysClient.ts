// configKeysClient - PUT /api/config/keys, the one write seam every
// schema-driven setting uses (dry run first, then the save), with the local
// confirm token from GET /api/config. Moved out of components/ObsDisabled.tsx
// (Plane A lane B5) so the Your apps first-run card sends the same request.

import type { ConfigResponse } from "./types";
import type { ConfigKeyPatch, ConfigKeysError } from "./configSchema";

/** putConfigKeys sends one batch; dryRun asks the daemon to validate only.
 *  A refusal throws with the daemon's per-key sentences. */
export async function putConfigKeys<T>(config: ConfigResponse, patches: ConfigKeyPatch[], dryRun: boolean): Promise<T> {
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

