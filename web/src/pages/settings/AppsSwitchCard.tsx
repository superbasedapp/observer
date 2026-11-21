// AppsSwitchCard - the On / off switch at the top of Settings > AI Apps
// (first-run plan revision 2, section 6): the same switch as `observer apps
// on|off`, through the same daemon routes (POST /api/apps/enable, the one
// enable seam, and POST /api/apps/disable). On opens the receiver and the
// pages at once and names what waits for the next start (FR-M01); off takes
// effect at the next start, and the card says so.

import { useState } from "react";
import { Telescope } from "lucide-react";
import { Card, ConfirmButton, Pill } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { localConfirmHeaders } from "@/lib/api";
import { refreshAfterAppsChange } from "@/lib/useComponents";
import { PRODUCT_NAMES } from "@shared/lib/productNames";
import {
  APPS_DISABLE_PATH,
  APPS_ENABLE_PATH,
  APPS_STATUS_PATH,
  appsRequestInit,
  type FirstRunApps,
} from "@/lib/firstRun";
import { consentLines, enableResult, pendingLine, receiverAddress } from "@/lib/planeaFirstRun";

type Status = FirstRunApps & { confirm_token?: string };

/** The switch's state line. */
export type AppsSwitchState = "on" | "off" | "off_next_start" | "bind_failed" | "unavailable" | "unknown";

/** APPS_SWITCH_RULES pick the state, top-down (one test per row). A
 *  receiver that could not bind speaks only once AI Apps was turned on (on,
 *  or saved on): "off" outranks it when AI Apps was never enabled, since the
 *  receiver may be bound for [ingest.otel] alone (review FR-M12). */
export const APPS_SWITCH_RULES: readonly { name: string; when: (a: FirstRunApps) => boolean; state: AppsSwitchState }[] = [
  { name: "not available here", when: (a) => a.available.available === false && !a.on, state: "unavailable" },
  {
    name: "turned on, the receiver could not bind",
    when: (a) => a.receiver.state === "bind_failed" && (a.on || a.configured_on),
    state: "bind_failed",
  },
  { name: "serving, saved off", when: (a) => a.on && !a.configured_on, state: "off_next_start" },
  { name: "on", when: (a) => a.on, state: "on" },
  { name: "off", when: () => true, state: "off" },
];

export function appsSwitchState(a: FirstRunApps | null | undefined): AppsSwitchState {
  if (!a) return "unknown";
  return (APPS_SWITCH_RULES.find((r) => r.when(a)) ?? APPS_SWITCH_RULES[APPS_SWITCH_RULES.length - 1]).state;
}

/** The switch's buttons in a state: turn on (or try the receiver again),
 *  and turn off. With AI Apps saved on and its port taken, both are offered
 *  (FR-M12): retry once the port is free, or turn it off. */
export function appsSwitchButtons(state: AppsSwitchState, a: FirstRunApps | null | undefined): { enable: "" | "Turn on" | "Try again"; disable: boolean } {
  switch (state) {
    case "off":
    case "off_next_start":
      return { enable: "Turn on", disable: false };
    case "bind_failed":
      return { enable: "Try again", disable: !!a?.configured_on };
    case "on":
      return { enable: "", disable: true };
    default:
      return { enable: "", disable: false };
  }
}

const STATE_PILL: Record<AppsSwitchState, { label: string; tone: "success" | "neutral" | "warn" | "danger" }> = {
  on: { label: "On", tone: "success" },
  off: { label: "Off", tone: "neutral" },
  off_next_start: { label: "Off at the next start", tone: "warn" },
  bind_failed: { label: "Receiver not listening", tone: "danger" },
  unavailable: { label: "Not available", tone: "neutral" },
  unknown: { label: "Unknown", tone: "neutral" },
};

export function AppsSwitchCard({ readOnly = false }: { readOnly?: boolean }) {
  const st = useApi<Status>(APPS_STATUS_PATH);
  const [busy, setBusy] = useState(false);
  const [line, setLine] = useState<{ tone: "success" | "danger"; text: string } | null>(null);

  const post = async (path: string) => {
    setBusy(true);
    setLine(null);
    try {
      const token = st.data?.confirm_token || (await localConfirmHeaders())["X-Observer-Confirm"] || "";
      const res = await fetch(path, { ...appsRequestInit(token), credentials: "same-origin" });
      const text = await res.text();
      let body: { ok?: boolean; message?: string; fix?: string; pending_next_start?: string[] } | null = null;
      try {
        body = JSON.parse(text);
      } catch {
        body = null;
      }
      if (res.status === 404) {
        setLine({ tone: "danger", text: "This daemon cannot switch AI Apps in place: restart the daemon to finish." });
      } else {
        setLine(
          enableResult({
            ok: res.ok && body?.ok !== false,
            message: body?.message ?? text.trim(),
            fix: body?.fix,
            pending_next_start: body?.pending_next_start,
          }),
        );
      }
    } catch (e: unknown) {
      setLine({ tone: "danger", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
      // FR-M10: the component state and the routes probe at once.
      refreshAfterAppsChange();
      st.reload();
    }
  };

  return (
    <Card title={`${PRODUCT_NAMES.planea} on this machine`} icon={Telescope}>
      <AppsSwitchView
        apps={st.data}
        busy={busy}
        readOnly={readOnly}
        line={line}
        onEnable={() => void post(APPS_ENABLE_PATH)}
        onDisable={() => void post(APPS_DISABLE_PATH)}
      />
    </Card>
  );
}

export function AppsSwitchView({
  apps,
  busy,
  readOnly,
  line,
  onEnable,
  onDisable,
}: {
  apps: FirstRunApps | null | undefined;
  busy: boolean;
  readOnly: boolean;
  line: { tone: "success" | "danger"; text: string } | null;
  onEnable: () => void;
  onDisable: () => void;
}) {
  const state = appsSwitchState(apps);
  const pill = STATE_PILL[state];
  const buttons = appsSwitchButtons(state, apps);
  const receiver = receiverAddress(apps, null);
  const [where, sentence] = consentLines(apps, receiver);
  const waits = apps?.on ? pendingLine(apps.pending_next_start) : null;
  return (
    <div className="space-y-2 text-[12px]" data-testid="settings-apps-switch" data-state={state}>
      <div className="flex flex-wrap items-center gap-2">
        <Pill variant={pill.tone} case="none">
          {pill.label}
        </Pill>
        {buttons.enable && (
          <ConfirmButton
            size="sm"
            variant="primary"
            armedVariant="primary"
            onConfirm={onEnable}
            disabled={busy || readOnly || apps?.hot_enable === false}
            loading={busy}
            confirmLabel={buttons.enable === "Try again" ? "Try again?" : "Turn on?"}
            armedNote={`${where} ${sentence}`}
          >
            {buttons.enable}
          </ConfirmButton>
        )}
        {buttons.disable && (
          <ConfirmButton
            size="sm"
            variant="secondary"
            onConfirm={onDisable}
            disabled={busy || readOnly}
            loading={busy}
            confirmLabel={apps?.on ? "Turn off at the next start?" : "Turn off?"}
            armedNote={apps?.on ? "The pages keep working until the daemon restarts." : "Saves AI Apps as off in your config file."}
          >
            Turn off
          </ConfirmButton>
        )}
      </div>
      {state === "unavailable" && <p className="text-fg-3">{apps?.available.text}</p>}
      {state !== "unavailable" && (
        <p className="text-fg-3">
          {where} {sentence}
        </p>
      )}
      {apps?.hot_enable === false && state === "off" && (
        <p className="text-fg-3">This dashboard is not served by the daemon: run observer apps on, or turn it on below and restart.</p>
      )}
      {/* U-16: the section's "restart" badge is about the other settings
          on this page; this switch's own timing is the line below. */}
      <p className="text-[11px] text-fg-3">
        Turning on opens the trace receiver and these pages at once; admission checks, egress routing, proxy turn traces,
        alerts and organization sharing start at the next start. Turning off, and the other settings in this section, take
        effect at the next start.
      </p>
      {waits && (
        <p className="text-[11px] text-fg-2" data-testid="settings-apps-pending">
          {waits}
        </p>
      )}
      {line && (
        <p role="status" className={line.tone === "success" ? "text-success" : "text-danger"}>
          {line.text}
        </p>
      )}
    </div>
  );
}
