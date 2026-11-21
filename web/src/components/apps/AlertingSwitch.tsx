// AlertingSwitch - turns machine alerting on from the Alerts page (review
// E-73). Before it the page only said "Turn alerting on in Settings >
// Observability" while rules and channels saved and did nothing. One write,
// `observability.alerts.enabled = true`, through the same PUT
// /api/config/keys every schema-driven setting uses (dry run first, with the
// local confirm token), then the restart banner: the alert loop starts with
// the daemon. Turning it off stays in Settings > Observability.

import { useState } from "react";
import { GatedLink } from "@/components/GatedLink";
import { Button, Callout } from "@/components/primitives";
import { fetchJSON } from "@/lib/api";
import { putConfigKeys } from "@/lib/configKeysClient";
import { markRestartPending } from "@/lib/restartPending";
import { PLACES } from "@/lib/settingsPlaces";
import type { ConfigResponse } from "@/lib/types";
import type { ConfigKeysDryRun, ConfigKeysResponse } from "@/lib/configSchema";

const ALERTS_ENABLED_KEY = "observability.alerts.enabled";

function alertsEnabledInFile(config: unknown): boolean {
  const o = (config as { Observability?: { Alerts?: { Enabled?: unknown } } } | null)?.Observability?.Alerts?.Enabled;
  return o === true;
}

export function AlertingSwitch() {
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState("");
  const [err, setErr] = useState("");

  async function turnOn() {
    setBusy(true);
    setErr("");
    try {
      const cfg = await fetchJSON<ConfigResponse>("/api/config");
      let keys = [ALERTS_ENABLED_KEY];
      if (!alertsEnabledInFile(cfg.config)) {
        const patches = [{ key: ALERTS_ENABLED_KEY, value: true, was: false }];
        await putConfigKeys<ConfigKeysDryRun>(cfg, patches, true);
        const out = await putConfigKeys<ConfigKeysResponse>(cfg, patches, false);
        if (out.restart_required_keys.length > 0) keys = out.restart_required_keys;
      }
      markRestartPending("alerting", keys);
      setDone("Saved. Restart the daemon to start alerting; the restart bar at the top has the button.");
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  // One warn Callout: alerting off is a condition the reader should act on,
  // and the action is right here (Emphasis; every reason links to its fix).
  return (
    <div data-testid="apps-alerting-switch">
      <Callout
        tone={done ? "success" : "warn"}
        title={done ? "Alerting turned on" : "Alerting is off"}
        action={
          done ? undefined : (
            <span className="flex flex-wrap items-center gap-2">
              <Button size="sm" variant="primary" loading={busy} disabled={busy} onClick={() => void turnOn()}>
                Turn alerting on
              </Button>
              <GatedLink to={PLACES.observability_settings.href} className="text-[12px] text-accent hover:underline">
                {PLACES.observability_settings.label}
              </GatedLink>
            </span>
          )
        }
      >
        {done || "Rules and channels are saved but never checked."}
        {err && (
          <span role="alert" className="mt-1 block text-danger">
            {err}
          </span>
        )}
      </Callout>
    </div>
  );
}
