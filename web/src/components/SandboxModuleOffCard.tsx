// SandboxModuleOffCard.tsx is the Sandbox isolation card on a machine where
// the Sandboxes and VMs module is installed but not turned on (the developer
// edition's fresh install) or blocked (lane L2). Ruling SBXD-9: the card the
// problem shows on turns the module on in place, in one click, with exactly
// the change Settings > Components makes (lib/componentTurnOn); the link to
// Settings > Components stays as the secondary action. Hiding the card for
// an organization that hides the module stays the `hidden` row of
// SANDBOX_CARD_SHAPE_RULES (lib/sandboxSettingsView), so this needs no config
// key of its own.

import { useState } from "react";
import { Link } from "react-router-dom";
import { Button, ChartShell, Pill } from "@/components/primitives";
import { HelpTooltip } from "@shared/primitives/HelpTooltip";
import { turnOnComponent, turnOnView, type TurnOnState } from "@/lib/componentTurnOn";
import { componentsErrorText, componentsLocalOnly, componentsPost } from "@/lib/componentsApi";
import { markRestartPending } from "@/lib/restartPending";
import { COMPONENTS_SETTINGS_PATH } from "@/lib/sandboxIsolation";

/** The Sandboxes and VMs module's component id. */
export const SANDBOX_MODULE_COMPONENT = "terminals.sandbox";

export function SandboxModuleOffCard({
  blocked,
  state,
  onTurnedOn,
  restartClass,
  initial,
}: {
  blocked: boolean;
  state: string;
  /** Called once the module is on: the card's reads are reloaded, so the
   *  editor replaces this card. */
  onTurnedOn?: () => void;
  /** The catalog's restart_class of each component, by id. */
  restartClass?: Record<string, string | undefined>;
  /** The button's first state (tests render each one). */
  initial?: TurnOnState;
}) {
  const to = `${COMPONENTS_SETTINGS_PATH}?component=${encodeURIComponent(SANDBOX_MODULE_COMPONENT)}`;
  const [turnOn, setTurnOn] = useState<TurnOnState>(initial ?? { phase: "idle" });
  const view = turnOnView(turnOn);
  const click = async () => {
    setTurnOn({ phase: "working" });
    const next = await turnOnComponent(
      SANDBOX_MODULE_COMPONENT,
      componentsPost,
      (e) => ({ message: componentsErrorText(e), localOnly: componentsLocalOnly(e) }),
      restartClass,
    );
    setTurnOn(next);
    // The daemon's background work follows at its next restart: the
    // restart banner says so on every page, after this card has become
    // the editor.
    if (next.phase === "needs_restart") markRestartPending("components");
    if (next.phase === "done" || next.phase === "needs_restart") onTurnedOn?.();
  };
  return (
    <ChartShell
      title="Sandbox isolation"
      sub="Run supported agents inside an isolation backend with an isolated home and an explicit workspace."
      right={<Pill variant="neutral">{blocked ? "blocked" : "turned off"}</Pill>}
    >
      <div className="space-y-2 p-1 text-[12px]" data-testid="sandbox-module-off">
        <p className="text-fg-2">
          {blocked
            ? "Sandboxes and VMs is blocked on this machine, so sandbox settings cannot be changed here. Settings > Components says why."
            : "Sandboxes and VMs is installed but turned off on this machine, so there is nothing to set yet. Turn it on here; this card then shows the sandbox settings, including the switch that enables sandboxed launches."}
          <HelpTooltip
            technical
            subject="the sandbox module"
            content={`component ${SANDBOX_MODULE_COMPONENT}: ${state}; CLI: observer components add ${SANDBOX_MODULE_COMPONENT} --yes`}
            className="ml-1 align-middle"
          />
        </p>
        <div className="flex flex-wrap items-center gap-3">
          {!blocked && (
            <Button
              variant="primary"
              size="sm"
              disabled={view.disabled}
              onClick={() => void click()}
              data-testid="sandbox-module-turn-on"
            >
              {view.label}
            </Button>
          )}
          <Link to={to} className="inline-block text-accent hover:underline">
            {blocked ? "Open Settings > Components" : "Or open Settings > Components"}
          </Link>
        </div>
        {!blocked && view.line && (
          <p role={view.alert ? "alert" : "status"} className={view.alert ? "text-danger" : "text-fg-2"}>
            {view.line}
          </p>
        )}
      </div>
    </ChartShell>
  );
}
