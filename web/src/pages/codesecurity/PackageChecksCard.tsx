import { useState } from "react";
import { Card, ConfirmButton, Pill } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import type { ConfigResponse } from "@/lib/types";
import type { ConfigKeyPatch, ConfigKeysError } from "@/lib/configSchema";
import {
  PACKAGE_CHECKS_COPY,
  PACKAGE_CHECKS_ONLINE_KEY,
  packageChecksIndexDownloadNote,
  packageChecksIndexLine,
  packageChecksOnlinePatch,
  packageChecksStage,
  type PackageChecksResponse,
} from "@/lib/packageChecks";

// PackageChecksCard - the Code security page's Package checks card
// (component security.deps; security pillar plan section 8.3, lane
// sec-d1fix milestone 3b). It shows the online checks' disclosure and
// records the accept on an explicit click (POST /api/security/deps with the
// confirm token); `observer start` on a terminal only shows the text. The
// online switch writes security.deps.online through PUT /api/config/keys,
// a dry run first, like every schema-driven setting.
//
// Working surface: calm register, zero delight elements.

async function putOnline(config: ConfigResponse, patch: ConfigKeyPatch, dryRun: boolean): Promise<unknown> {
  const res = await fetch("/api/config/keys", {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      ...(config.confirm_token ? { "X-Observer-Confirm": config.confirm_token } : {}),
    },
    body: JSON.stringify({ base_etag: config.config_etag ?? "", patches: [patch], ...(dryRun ? { dry_run: true } : {}) }),
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
    const keyMsg = e.key_errors?.find((k) => k.key === PACKAGE_CHECKS_ONLINE_KEY)?.message;
    throw new Error(keyMsg || e.message || text || `HTTP ${res.status}`);
  }
  return body;
}

export function PackageChecksCard() {
  const deps = useApi<PackageChecksResponse>("/api/security/deps");
  const config = useApi<ConfigResponse>("/api/config");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const status = deps.data?.status ?? null;
  const stage = packageChecksStage(status);
  if (deps.loading && !deps.data) return null;
  if (deps.error || !status || stage === "inactive") return null;
  const copy = PACKAGE_CHECKS_COPY[stage];

  async function accept() {
    setBusy(true);
    setErr(null);
    try {
      const res = await fetch("/api/security/deps", {
        method: "POST",
        headers: { "content-type": "application/json", "X-Observer-Confirm": deps.data?.confirm_token ?? "" },
        body: JSON.stringify({ accept: true }),
      });
      if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
      deps.reload();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function toggleOnline() {
    if (!config.data || !status) return;
    const patch = packageChecksOnlinePatch(status.online);
    setBusy(true);
    setErr(null);
    try {
      await putOnline(config.data, patch, true);
      await putOnline(config.data, patch, false);
      config.reload();
      deps.reload();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Card title="Package checks" sub="What an agent installs is checked before it runs">
      <div className="space-y-2 text-[12.5px]" data-testid="package-checks-card">
        <div className="flex flex-wrap items-center gap-2">
          <Pill variant={copy.tone}>{copy.label}</Pill>
          <span className="text-fg-3">{copy.summary}</span>
        </div>
        {stage === "waiting" && (
          <>
            <p className="m-0 rounded-2 border border-line-2 bg-bg-2 p-3 text-fg-2">{status.text}</p>
            <ConfirmButton
              variant="primary"
              onConfirm={accept}
              disabled={busy}
              loading={busy}
              confirmLabel="Accept and turn on?"
              armedNote="Records that you read this text; online package checks start with the next install."
            >
              I have read this, turn online checks on
            </ConfirmButton>
          </>
        )}
        {stage === "on" && status.accepted_at && (
          <p className="m-0 text-fg-3">
            Accepted {new Date(status.accepted_at).toLocaleString()} ({status.accepted_on}).
          </p>
        )}
        {status.not_set_up && (
          <p className="m-0 text-fg-3">
            Not set up yet: no signed package list is installed and online checks are not on, so installs are not checked.
          </p>
        )}
        {packageChecksIndexDownloadNote(status) && (
          <p className="m-0 text-fg-3" data-testid="package-checks-index-off">
            {packageChecksIndexDownloadNote(status)}
          </p>
        )}
        <ul className="m-0 list-none p-0 text-fg-3">
          {(status.index ?? []).map((i) => (
            <li key={i.kind}>{packageChecksIndexLine(i)}</li>
          ))}
        </ul>
        {!status.managed && config.data && (
          <ConfirmButton
            variant="secondary"
            armedVariant={status.online ? "danger" : "primary"}
            onConfirm={toggleOnline}
            disabled={busy}
            loading={busy}
            confirmLabel={status.online ? "Turn online checks off?" : "Turn online checks on?"}
            armedNote={`Turns online package checks ${status.online ? "off" : "on"} in the config file (checked by the daemon before it is written).`}
          >
            {status.online ? "Turn online checks off" : "Turn online checks on"}
          </ConfirmButton>
        )}
        {err && <p className="m-0 text-danger">{err}</p>}
      </div>
    </Card>
  );
}
