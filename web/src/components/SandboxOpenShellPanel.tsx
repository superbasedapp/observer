// SandboxOpenShellPanel.tsx is the "OpenShell sandboxes" sub-panel of the
// Sandbox isolation card (OpenShell build lane O4): the editor for
// [terminal.sandbox.openshell] (gateway_mode, endpoint, version, state_dir)
// beside what the daemon says about the openshell row. The card mounts it
// with one line and owns the save; this panel only edits its own block, and
// renders nothing unless a [components] block selects
// terminals.sandbox.openshell (the driver is opt-in and inactive in every
// distro).
//
// Nothing about the row is worded here: the probe's reason, the gateway
// mode, the prerequisite (decision D4: the docker group, root-equivalent, or
// rootless Podman 5, which the probe still refuses) and the disclosures
// (decision D3: Observer never writes your own gateway config; it owns its
// managed gateway's) are rendered as the daemon serves them, so the panel
// stays right as the backend learns new modes and tiers.

import type { ComponentsView } from "@/lib/componentState";
import { backendNotes, gatewayModeLabel } from "@/lib/sandboxIsolation";
import type { SandboxBackendAvail } from "@/lib/types";

export type SandboxOpenShellConfig = {
  gateway_mode: string;
  endpoint: string;
  version: string;
  state_dir: string;
};

// OPENSHELL_COMPONENT is the driver's catalog id.
const OPENSHELL_COMPONENT = "terminals.sandbox.openshell";

// openShellDriverSelected applies the daemon's opt-in rule
// (sandboxDriverSelected): a configured [components] block with the
// openshell component active.
export function openShellDriverSelected(view: ComponentsView | undefined): boolean {
  if (!view || !view.configured) return false;
  return view.components.some((c) => c.id === OPENSHELL_COMPONENT && c.state === "active");
}

// GATEWAY_MODE_CHOICES are the config's gateway_mode values ("" resolves to
// managed unless an endpoint is set; internal/config EffectiveGatewayMode).
const GATEWAY_MODE_CHOICES: { value: string; label: string }[] = [
  { value: "", label: "Default (Observer's private gateway, unless an endpoint is set)" },
  { value: "managed", label: "Observer's private gateway (managed)" },
  { value: "external", label: "Your own gateway (external)" },
];

/**
 * openShellModeChange applies a gateway mode choice. Managed mode takes no
 * endpoint (the config refuses one: the private gateway picks its own
 * port), and the panel hides the endpoint field there, so the endpoint is
 * cleared with the switch instead of being sent unseen and refused on save
 * (audit finding O4-A6). The default mode keeps it: with an endpoint the
 * default resolves to external and the field stays visible.
 */
export function openShellModeChange(
  value: SandboxOpenShellConfig,
  mode: string,
  onChange: (next: SandboxOpenShellConfig) => void,
): void {
  onChange({ ...value, gateway_mode: mode, endpoint: mode === "managed" ? "" : value.endpoint });
}

/**
 * openShellPinChoices are the version pin picker's options: no pin, then
 * the versions the daemon serves for the row (its tested versions; the web
 * keeps no list of its own). A pin already in config.toml is always
 * selectable: written with a leading "v" it is the matching served
 * version, and a version the daemon does not serve is listed as untested
 * so the picker never silently drops it; when the daemon serves nothing the
 * pin is "not checked" rather than untested.
 */
export function openShellPinChoices(current: string, served: string[]): { value: string; label: string }[] {
  const pin = current.trim();
  const bare = pin.replace(/^v/, "");
  const out = [{ value: "", label: "No pin" }];
  let seen = pin === "";
  for (const v of served) {
    if (!seen && (v === pin || v === bare)) {
      out.push({ value: pin, label: v });
      seen = true;
    } else {
      out.push({ value: v, label: v });
    }
  }
  // With nothing served (an older daemon, or a build without the openshell
  // driver) the pin could not be checked, so it is never called untested
  // (F-029 V2).
  if (!seen) out.push({ value: pin, label: served.length === 0 ? `${pin} (not checked)` : `${pin} (not a tested version)` });
  return out;
}

const inputClass =
  "w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] text-fg-1 disabled:opacity-50";

export function SandboxOpenShellPanel({
  value,
  row,
  view,
  writable,
  onChange,
}: {
  value: SandboxOpenShellConfig;
  /** The openshell row of the probe's backends[], when the daemon sent one. */
  row: SandboxBackendAvail | undefined;
  view: ComponentsView | undefined;
  writable: boolean;
  onChange: (next: SandboxOpenShellConfig) => void;
}) {
  if (!openShellDriverSelected(view)) return null;
  const set = (k: keyof SandboxOpenShellConfig, v: string) => onChange({ ...value, [k]: v });
  const notes = backendNotes(row);
  const mode = gatewayModeLabel(row?.gateway_mode);
  const external = value.gateway_mode === "external" || (value.gateway_mode === "" && value.endpoint.trim() !== "");
  const served = row?.version_pins ?? [];
  const pinChoices = openShellPinChoices(value.version, served);
  return (
    <details className="rounded-2 border border-line-2 bg-bg-3 p-3">
      <summary className="cursor-pointer font-medium text-fg-1">
        {row?.label ?? "OpenShell"} sandboxes{" "}
        <span className="ml-1 rounded-1 border border-line-2 px-1 text-[10px] text-fg-3">beta</span>
      </summary>
      <div className="mt-3 space-y-3">
        {row ? (
          <div className="space-y-1 text-[11px]">
            <span className="block text-fg-2">
              {row.available ? "Available on this machine." : `Not available: ${row.reason || row.verdict || "no reason given"}`}
            </span>
            {mode && <span className="block text-fg-3">Gateway: {mode}.</span>}
            {notes.length > 0 && (
              <ul className="list-disc space-y-0.5 pl-4 text-fg-3" aria-label="About this sandbox">
                {notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            )}
          </div>
        ) : (
          <span className="block text-[11px] text-fg-3">This daemon sent no status for this row yet.</span>
        )}
        <label className="block space-y-1">
          <span className="font-medium text-fg-2">Gateway mode</span>
          <select
            aria-label="Gateway mode"
            name="gateway_mode"
            value={value.gateway_mode}
            disabled={!writable}
            onChange={(e) => openShellModeChange(value, e.target.value, onChange)}
            className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 text-[11px] text-fg-1 disabled:opacity-50"
          >
            {GATEWAY_MODE_CHOICES.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </select>
        </label>
        {external && (
          <label className="block space-y-1">
            <span className="font-medium text-fg-2">Gateway endpoint</span>
            <input
              aria-label="Gateway endpoint"
              value={value.endpoint}
              disabled={!writable}
              placeholder="empty: the openshell CLI's active gateway"
              onChange={(e) => set("endpoint", e.target.value)}
              className={inputClass}
            />
            <span className="block text-[11px] text-fg-3">An https address on this machine&apos;s loopback, with no path.</span>
          </label>
        )}
        <label className="block space-y-1">
          <span className="font-medium text-fg-2">Version pin</span>
          <select
            aria-label="Version pin"
            value={value.version.trim()}
            disabled={!writable}
            onChange={(e) => set("version", e.target.value)}
            className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] text-fg-1 disabled:opacity-50"
          >
            {pinChoices.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </select>
          {served.length === 0 && (
            <span className="block text-[11px] text-fg-3">
              This daemon did not list its tested versions, so a pin cannot be checked here: choose no pin, or keep the pin already set.
            </span>
          )}
        </label>
        <label className="block space-y-1">
          <span className="font-medium text-fg-2">State directory</span>
          <input
            aria-label="State directory"
            value={value.state_dir}
            disabled={!writable}
            placeholder="default: <observer dir>/sandbox-openshell"
            onChange={(e) => set("state_dir", e.target.value)}
            className={inputClass}
          />
        </label>
      </div>
    </details>
  );
}
