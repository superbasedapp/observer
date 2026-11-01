// SandboxLandlockPanel.tsx is the "Landlock-only sandboxes" sub-panel of the
// Sandbox isolation card (sandbox plan v2 sections 4.1, 9 and 10.1, lane
// SBX-P3B): the editor for [terminal.sandbox.landlock], the process_lite row
// (Landlock alone, for Linux hosts that block the user namespaces bubblewrap
// needs). The card mounts it with one line and owns the save; this panel only
// edits its own block, and renders nothing unless a [components] block
// selects terminals.sandbox.landlock (the driver is opt-in and inactive in
// every distro). Raising the ABI floor is stricter; it never goes below 9.

import { ComboChip } from "@/components/primitives";
import type { ComponentsView } from "@/lib/componentState";

export type SandboxLandlockConfig = {
  min_abi: number;
};

const MIN_ABI = [9, 10, 11, 12];

// PIN_PREFIX is how the organization's pins name these keys.
const PIN_PREFIX = "landlock.";

// landlockDriverSelected applies the daemon's opt-in rule
// (sandboxDriverSelected): a configured [components] block with
// terminals.sandbox.landlock active.
export function landlockDriverSelected(view: ComponentsView | undefined): boolean {
  if (!view || !view.configured) return false;
  return view.components.some((c) => c.id === "terminals.sandbox.landlock" && c.state === "active");
}

export function SandboxLandlockPanel({
  value,
  view,
  pinned,
  writable,
  onChange,
}: {
  value: SandboxLandlockConfig;
  view: ComponentsView | undefined;
  pinned: Set<string>;
  writable: boolean;
  onChange: (next: SandboxLandlockConfig) => void;
}) {
  if (!landlockDriverSelected(view)) return null;
  const current = value.min_abi || 9;
  const editable = writable && !pinned.has(PIN_PREFIX + "min_abi");
  const options = (MIN_ABI.includes(current) ? MIN_ABI : [...MIN_ABI, current].sort((a, b) => a - b)).map((n) => ({
    value: String(n),
    label: <span>ABI {n}</span>,
    searchable: `ABI ${n}`,
  }));
  return (
    <details className="rounded-2 border border-line-2 bg-bg-3 p-3">
      <summary className="cursor-pointer font-medium text-fg-1">
        Landlock-only sandboxes <span className="ml-1 rounded-1 border border-line-2 px-1 text-[10px] text-fg-3">beta</span>
      </summary>
      <div className="mt-3 space-y-3">
        <p className="text-[11px] text-fg-3">
          Used only when the Landlock (process lite) backend is in the backend list above and a launch picks it
          by name: automatic selection never does. It is for Linux hosts that block the user namespaces bubblewrap needs,
          and it is weaker than bubblewrap: the agent shares the host&apos;s process list, <span className="font-mono">/proc</span>{" "}
          and network. Files are limited to the workspace, the tool&apos;s own state and the run&apos;s temp folder; TCP may
          reach every port except Observer&apos;s own; UDP stays open below Landlock ABI 10. Its only network tier is
          host. Needs Landlock ABI 9 (Linux 7.1 or newer); WSL2&apos;s kernel reports 7. Not yet proven on real hardware
          (register LIN-1).
        </p>
        <div className="space-y-1">
          <span id="sandbox-landlock-abi" className="block font-medium text-fg-1">Lowest Landlock ABI</span>
          <ComboChip
            label="Lowest Landlock ABI"
            labelledBy="sandbox-landlock-abi"
            hideTriggerLabel
            fullWidth
            value={String(current)}
            disabled={!editable}
            onChange={(v) => onChange({ ...value, min_abi: Number(v) })}
            options={options}
            buttonValueRender={() => <span>ABI {current}</span>}
          />
          <span className="block text-[11px] text-fg-3">
            Raising it refuses older kernels; it never goes below 9, the ABI that keeps Observer&apos;s own sockets out of
            reach.
          </span>
          {pinned.has(PIN_PREFIX + "min_abi") && <span className="block text-[11px] text-fg-3">Set by your organization.</span>}
        </div>
      </div>
    </details>
  );
}
