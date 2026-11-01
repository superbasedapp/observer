// SandboxWindowsPanel.tsx is the "Windows sandboxes (MXC)" sub-panel of the
// Sandbox isolation card (sandbox plan v2 sections 9, 10.1 and 13 P6, lane
// SBX-P6): the editor for [terminal.sandbox.mxc], the mxc-process driver
// (Microsoft Execution Containers' ProcessContainer on native Windows 11).
// The card mounts it with one line and owns the save; this panel only edits
// its own block, and renders nothing unless a [components] block selects
// terminals.sandbox.mxc (the driver is opt-in and inactive in every distro).
// Neither key widens what a box may reach.

import { ComboChip } from "@/components/primitives";
import type { ComponentsView } from "@/lib/componentState";

export type SandboxMXCConfig = {
  stop_grace_seconds: number;
  probe_timeout_seconds: number;
};

const STOP_GRACE = [0, 2, 5, 10, 30, 60];
const PROBE_TIMEOUT = [10, 20, 30, 60, 120];

// PIN_PREFIX is how the organization's pins name these keys.
const PIN_PREFIX = "mxc.";

// mxcDriverSelected applies the daemon's opt-in rule (sandboxDriverSelected):
// a configured [components] block with terminals.sandbox.mxc active.
export function mxcDriverSelected(view: ComponentsView | undefined): boolean {
  if (!view || !view.configured) return false;
  return view.components.some((c) => c.id === "terminals.sandbox.mxc" && c.state === "active");
}

function seconds(list: number[], current: number) {
  const all = list.includes(current) ? list : [...list, current].sort((a, b) => a - b);
  return all.map((n) => ({ value: String(n), label: <span>{n} s</span>, searchable: `${n} s` }));
}

export function SandboxWindowsPanel({
  value,
  view,
  pinned,
  writable,
  onChange,
}: {
  value: SandboxMXCConfig;
  view: ComponentsView | undefined;
  pinned: Set<string>;
  writable: boolean;
  onChange: (next: SandboxMXCConfig) => void;
}) {
  if (!mxcDriverSelected(view)) return null;
  const editable = (key: keyof SandboxMXCConfig) => writable && !pinned.has(PIN_PREFIX + key);
  const set = <K extends keyof SandboxMXCConfig>(key: K, v: SandboxMXCConfig[K]) => onChange({ ...value, [key]: v });
  return (
    <details className="rounded-2 border border-line-2 bg-bg-3 p-3">
      <summary className="cursor-pointer font-medium text-fg-1">
        Windows sandboxes (MXC) <span className="ml-1 rounded-1 border border-line-2 px-1 text-[10px] text-fg-3">beta</span>
      </summary>
      <div className="mt-3 space-y-3">
        <p className="text-[11px] text-fg-3">
          On Windows the recommended way is to run the Observer daemon inside WSL2: every Linux backend (bubblewrap,
          Docker or Podman containers) then applies, on every Windows edition. This panel is for a daemon running on
          native Windows.
        </p>
        <p className="text-[11px] text-fg-3">
          Used only when <span className="font-mono">mxc-process</span> is in the backend list above. It needs Windows 11
          build 26100.9278 or 26200.9278 or later where Microsoft&apos;s own check offers the PSEC ProcessContainer tier
          (Windows Home may not offer it; the row then says so). The MXC files ship with Observer and are checked
          against pinned hashes and Microsoft&apos;s signature before use; host file permissions are never changed.
          The model proxy runs in MXC&apos;s least-privileged proxy tier, so the run&apos;s one loopback port checks a
          per-run token on every request. Built from Microsoft&apos;s documentation; not yet proven on real hardware
          (register WIN-1 to WIN-4).
        </p>
        <div className="grid gap-3 md:grid-cols-2">
          <div className="space-y-1">
            <span id="sandbox-mxc-grace" className="block font-medium text-fg-1">Stop grace</span>
            <ComboChip
              label="Stop grace"
              labelledBy="sandbox-mxc-grace"
              hideTriggerLabel
              fullWidth
              value={String(value.stop_grace_seconds)}
              disabled={!editable("stop_grace_seconds")}
              onChange={(v) => set("stop_grace_seconds", Number(v))}
              options={seconds(STOP_GRACE, value.stop_grace_seconds)}
              buttonValueRender={() => <span>{value.stop_grace_seconds} s</span>}
            />
            {pinned.has(PIN_PREFIX + "stop_grace_seconds") && <span className="block text-[11px] text-fg-3">Set by your organization.</span>}
          </div>
          <div className="space-y-1">
            <span id="sandbox-mxc-probe" className="block font-medium text-fg-1">Probe timeout</span>
            <ComboChip
              label="Probe timeout"
              labelledBy="sandbox-mxc-probe"
              hideTriggerLabel
              fullWidth
              value={String(value.probe_timeout_seconds || 30)}
              disabled={!editable("probe_timeout_seconds")}
              onChange={(v) => set("probe_timeout_seconds", Number(v))}
              options={seconds(PROBE_TIMEOUT, value.probe_timeout_seconds || 30)}
              buttonValueRender={() => <span>{value.probe_timeout_seconds || 30} s</span>}
            />
            <span className="block text-[11px] text-fg-3">
              The first run after an update can take seconds while Defender scans the new binary.
            </span>
            {pinned.has(PIN_PREFIX + "probe_timeout_seconds") && <span className="block text-[11px] text-fg-3">Set by your organization.</span>}
          </div>
        </div>
      </div>
    </details>
  );
}
