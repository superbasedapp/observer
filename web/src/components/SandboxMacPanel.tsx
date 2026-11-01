// SandboxMacPanel.tsx is the "macOS sandboxes (beta)" sub-panel of the
// Sandbox isolation card (sandbox plan v2 sections 9, 10.1 and 13 P5, lane
// SBX-P5): the editor for [terminal.sandbox.seatbelt] and
// [terminal.sandbox.apple_container], the two macOS drivers. Both are beta:
// built from vendor documentation and not yet proven on a Mac (register
// rows MAC-n). The card mounts it with one line and owns the save; this
// panel edits only its own two blocks, and renders nothing unless one of
// the two driver components is selected. Allowing the Keychain widens what
// the box can ask for, so it takes a second, explicit click.

import { useState } from "react";
import { ComboChip, type ComboOption } from "@/components/primitives";
import type { ComponentsView } from "@/lib/componentState";

export type SandboxSeatbeltConfig = {
  allow_keychain: boolean;
  // The Seatbelt driver (lane SBX-UPD): "" means sandbox-exec. The declared
  // fallback mxc-exec-mac is offered only to show why it is refused.
  driver?: string;
};

// SEATBELT_DRIVERS is the closed [terminal.sandbox.seatbelt].driver choice.
const SEATBELT_DRIVERS: ComboOption[] = [
  { value: "sandbox-exec", label: <span className="font-mono">sandbox-exec</span>, detail: "Apple's sandbox-exec with a generated profile (the built driver).", searchable: "sandbox-exec apple" },
  { value: "mxc-exec-mac", label: <span className="font-mono">mxc-exec-mac</span>, detail: "Microsoft's declared fallback. Not built: a launch with it is refused because the fallback driver is not available (register MAC-10).", searchable: "mxc-exec-mac microsoft fallback" },
];

export type SandboxAppleContainerConfig = {
  image: string;
  memory_mib: number;
  cpus: number;
};

// MAC_COMPONENTS are the two driver components this panel edits.
const SEATBELT_COMPONENT = "terminals.sandbox.seatbelt";
const APPLE_COMPONENT = "terminals.sandbox.apple-container";

// DIGEST_RE mirrors the config's digest rule: an image is pinned by
// sha256 digest, never a tag.
const DIGEST_RE = /^[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}$/;

const MEMORY_MIB = [2048, 4096, 8192, 16384];
const CPUS = [2, 4, 6, 8];

// driverSelected reports whether a driver component is selected: a
// configured [components] block with it active (the daemon's opt-in rule,
// sandboxDriverSelected). An unconfigured install selects neither.
function driverSelected(view: ComponentsView | undefined, id: string): boolean {
  if (!view || !view.configured) return false;
  return view.components.some((c) => c.id === id && c.state === "active");
}

function sizes(list: number[], current: number, unit: string): ComboOption[] {
  const all = list.includes(current) || current <= 0 ? list : [...list, current].sort((a, b) => a - b);
  return all.map((n) => ({ value: String(n), label: <span>{n} {unit}</span>, searchable: `${n} ${unit}` }));
}

export function SandboxMacPanel({
  seatbelt,
  appleContainer,
  view,
  pinned,
  writable,
  onChange,
}: {
  seatbelt: SandboxSeatbeltConfig;
  appleContainer: SandboxAppleContainerConfig;
  view: ComponentsView | undefined;
  pinned: Set<string>;
  writable: boolean;
  onChange: (key: "seatbelt" | "apple_container", next: SandboxSeatbeltConfig | SandboxAppleContainerConfig) => void;
}) {
  const [arming, setArming] = useState(false);
  const seatbeltOn = driverSelected(view, SEATBELT_COMPONENT);
  const appleOn = driverSelected(view, APPLE_COMPONENT);
  if (!seatbeltOn && !appleOn) return null;
  const editable = (key: string) => writable && !pinned.has(key);
  const imageBad = appleContainer.image.trim() !== "" && !DIGEST_RE.test(appleContainer.image.trim());
  const setApple = <K extends keyof SandboxAppleContainerConfig>(key: K, v: SandboxAppleContainerConfig[K]) =>
    onChange("apple_container", { ...appleContainer, [key]: v });

  return (
    <details className="rounded-2 border border-line-2 bg-bg-3 p-3">
      <summary className="cursor-pointer font-medium text-fg-1">macOS sandboxes (beta)</summary>
      <div className="mt-3 space-y-3">
        <p className="text-[11px] text-fg-3">
          Beta: built from Apple&apos;s documentation and not yet proven on a Mac. A macOS backend is used only when you
          list it by name in the backend list above (<span className="font-mono">seatbelt</span>,{" "}
          <span className="font-mono">apple-container</span>); automatic selection never picks a beta backend. Nothing
          runs <span className="font-mono">sandbox-exec</span> or <span className="font-mono">container</span> otherwise.
        </p>
        {seatbeltOn && (
          <div className="space-y-2">
            <span className="block font-medium text-fg-1">Seatbelt</span>
            <div className="space-y-1">
              <span id="seatbelt-driver-label" className="block text-fg-2">Driver</span>
              <ComboChip
                label="Seatbelt driver"
                labelledBy="seatbelt-driver-label"
                hideTriggerLabel
                fullWidth
                value={seatbelt.driver || "sandbox-exec"}
                disabled={!editable("seatbelt.driver")}
                onChange={(v) => onChange("seatbelt", { ...seatbelt, driver: v === "sandbox-exec" ? "" : v })}
                options={SEATBELT_DRIVERS}
              />
              {pinned.has("seatbelt.driver") && <span className="block text-[11px] text-fg-3">Set by your organization.</span>}
            </div>
            <label className="flex items-start gap-2 rounded-2 border border-warn/30 bg-warn/5 p-3">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={seatbelt.allow_keychain}
                disabled={!editable("seatbelt.allow_keychain")}
                onChange={(e) => {
                  if (!e.target.checked) {
                    onChange("seatbelt", { ...seatbelt, allow_keychain: false });
                    setArming(false);
                  } else {
                    setArming(true);
                  }
                }}
              />
              <span>
                <span className="font-medium text-warn">Allow the Keychain</span>
                <span className="block text-[11px] text-fg-3">
                  Claude Code and Codex on macOS keep their login in the Keychain. This lets the sandboxed agent ask the
                  Keychain for it; the Keychain still decides per item.
                </span>
                {arming && !seatbelt.allow_keychain && (
                  <button
                    type="button"
                    className="mt-1 rounded-2 border border-warn/50 px-2 py-0.5 text-[11px] text-warn"
                    onClick={() => {
                      onChange("seatbelt", { ...seatbelt, allow_keychain: true });
                      setArming(false);
                    }}
                  >
                    Yes, allow it
                  </button>
                )}
                {pinned.has("seatbelt.allow_keychain") && <span className="block text-[11px] text-fg-3">Set by your organization.</span>}
              </span>
            </label>
          </div>
        )}
        {appleOn && (
          <div className="space-y-2">
            <span className="block font-medium text-fg-1">Apple container (macOS 26, Apple silicon)</span>
            <label className="block space-y-1">
              <span className="font-medium text-fg-2">Image (pinned by digest)</span>
              <input
                type="text"
                value={appleContainer.image}
                disabled={!writable}
                placeholder="registry/name@sha256:..."
                onChange={(e) => setApple("image", e.target.value)}
                className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] text-fg-1 disabled:opacity-50"
              />
              <span className={`block text-[11px] ${imageBad ? "text-danger" : "text-fg-3"}`}>
                {imageBad
                  ? "Use name@sha256:<64 hex>; a tag can change under a run and is refused."
                  : "A linux/arm64 image holding the agent and a linux/arm64 observer. The container has no network but the run's own sockets."}
              </span>
            </label>
            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1">
                <span id="sandbox-apple-memory" className="block font-medium text-fg-1">Memory</span>
                <ComboChip
                  label="Memory"
                  labelledBy="sandbox-apple-memory"
                  hideTriggerLabel
                  fullWidth
                  value={String(appleContainer.memory_mib)}
                  disabled={!editable("apple_container.memory_mib")}
                  onChange={(v) => setApple("memory_mib", Number(v))}
                  options={sizes(MEMORY_MIB, appleContainer.memory_mib, "MiB")}
                  buttonValueRender={() => <span>{appleContainer.memory_mib} MiB</span>}
                />
              </div>
              <div className="space-y-1">
                <span id="sandbox-apple-cpus" className="block font-medium text-fg-1">CPUs</span>
                <ComboChip
                  label="CPUs"
                  labelledBy="sandbox-apple-cpus"
                  hideTriggerLabel
                  fullWidth
                  value={String(appleContainer.cpus)}
                  disabled={!editable("apple_container.cpus")}
                  onChange={(v) => setApple("cpus", Number(v))}
                  options={sizes(CPUS, appleContainer.cpus, "CPUs")}
                  buttonValueRender={() => <span>{appleContainer.cpus}</span>}
                />
              </div>
            </div>
          </div>
        )}
      </div>
    </details>
  );
}
