// configKeysPut - one write of PUT /api/config/keys for a card that owns a
// few keys (the Code security Settings card, the Scanners card's image
// driver picker): the base etag and the confirm token come from GET
// /api/config, the confirm token travels in X-Observer-Confirm (demanded by
// the server for a sensitive-tier key), and a refusal throws the server's
// per-key message. Callers run a dry run first, then the write under the
// same etag.

import type { ConfigKeyPatch, ConfigKeysError } from "./configSchema.ts";

/** What a write needs from GET /api/config. */
export type ConfigKeysBase = { config_etag?: string; confirm_token?: string };

/** putConfigKeys sends one batch (dryRun: every check, nothing written). */
export async function putConfigKeys<T>(base: ConfigKeysBase, patches: ConfigKeyPatch[], dryRun: boolean): Promise<T> {
  const res = await fetch("/api/config/keys", {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      ...(base.confirm_token ? { "X-Observer-Confirm": base.confirm_token } : {}),
    },
    body: JSON.stringify({ base_etag: base.config_etag ?? "", patches, ...(dryRun ? { dry_run: true } : {}) }),
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
