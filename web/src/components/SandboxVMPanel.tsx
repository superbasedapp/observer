// SandboxVMPanel.tsx is the "microVM sandboxes (Cloud Hypervisor)" sub-panel
// of the Sandbox isolation card (sandbox plan v2 sections 9, 10.1 and 13 P4,
// lane SBX-P4): the editor for [terminal.sandbox.vm], the cloud-hypervisor
// row. The card mounts it with one line and owns the save; this panel only
// edits its own block, and renders nothing unless a [components] block
// selects terminals.sandbox.vm (the driver is opt-in and inactive in every
// distro). No key widens what a VM may reach: it has no network device in
// any tier, and the guest image set is never a path.

import { ComboChip } from "@/components/primitives";
import type { ComponentsView } from "@/lib/componentState";

export type SandboxVMConfig = {
  vmm: string;
  image_set: string;
  vcpus: number;
  memory_mb: number;
  install_cache: boolean;
  workspace_delivery: string;
  cloud_hypervisor_path: string;
  virtiofsd_path: string;
};

const VCPUS = [1, 2, 4, 8, 16];
const MEMORY_MB = [1024, 2048, 4096, 8192, 16384];

// vmDriverSelected applies the daemon's opt-in rule (sandboxDriverSelected):
// a configured [components] block with terminals.sandbox.vm active.
export function vmDriverSelected(view: ComponentsView | undefined): boolean {
  if (!view || !view.configured) return false;
  return view.components.some((c) => c.id === "terminals.sandbox.vm" && c.state === "active");
}

function choices(list: number[], current: number, unit: string) {
  const all = list.includes(current) ? list : [...list, current].sort((a, b) => a - b);
  return all.map((n) => ({ value: String(n), label: <span>{n} {unit}</span>, searchable: `${n} ${unit}` }));
}

export function SandboxVMPanel({
  value,
  view,
  writable,
  onChange,
}: {
  value: SandboxVMConfig;
  view: ComponentsView | undefined;
  writable: boolean;
  onChange: (next: SandboxVMConfig) => void;
}) {
  if (!vmDriverSelected(view)) return null;
  const set = <K extends keyof SandboxVMConfig>(key: K, v: SandboxVMConfig[K]) => onChange({ ...value, [key]: v });
  const vcpus = value.vcpus || 2;
  const memory = value.memory_mb || 4096;
  return (
    <details className="rounded-2 border border-line-2 bg-bg-3 p-3">
      <summary className="cursor-pointer font-medium text-fg-1">
        microVM sandboxes (Cloud Hypervisor) <span className="ml-1 rounded-1 border border-line-2 px-1 text-[10px] text-fg-3">beta</span>
      </summary>
      <div className="mt-3 space-y-3">
        <p className="text-[11px] text-fg-3">
          Used only when <span className="font-mono">cloud-hypervisor</span> is in the backend list above and a launch picks
          it by name: automatic selection never does. Each run is its own microVM with no network device; the terminal and
          the capture relay cross vsock. Needs Linux or WSL2 with a usable <span className="font-mono">/dev/kvm</span>,
          Cloud Hypervisor 54 and virtiofsd, and a signed guest image set imported with{" "}
          <span className="font-mono">observer sandbox content import</span>. Not yet proven end to end on real hardware
          (register LIN-2 onward).
        </p>
        <div className="grid gap-3 md:grid-cols-2">
          <div className="space-y-1">
            <span id="sandbox-vm-vcpus" className="block font-medium text-fg-1">vCPUs</span>
            <ComboChip
              label="vCPUs"
              labelledBy="sandbox-vm-vcpus"
              hideTriggerLabel
              fullWidth
              value={String(vcpus)}
              disabled={!writable}
              onChange={(v) => set("vcpus", Number(v))}
              options={choices(VCPUS, vcpus, "vCPU")}
              buttonValueRender={() => <span>{vcpus} vCPU</span>}
            />
          </div>
          <div className="space-y-1">
            <span id="sandbox-vm-memory" className="block font-medium text-fg-1">Memory</span>
            <ComboChip
              label="Memory"
              labelledBy="sandbox-vm-memory"
              hideTriggerLabel
              fullWidth
              value={String(memory)}
              disabled={!writable}
              onChange={(v) => set("memory_mb", Number(v))}
              options={choices(MEMORY_MB, memory, "MiB")}
              buttonValueRender={() => <span>{memory} MiB</span>}
            />
          </div>
        </div>
        <label className="block space-y-1">
          <span className="block font-medium text-fg-1">Guest image set</span>
          <input
            className="w-full rounded-1 border border-line-2 bg-bg-2 px-2 py-1 font-mono text-[12px]"
            value={value.image_set}
            placeholder="newest verified set"
            disabled={!writable}
            onChange={(e) => set("image_set", e.target.value.trim())}
          />
          <span className="block text-[11px] text-fg-3">A verified set&apos;s version (for example 1.0.0); empty boots the newest. Never a path.</span>
        </label>
        <label className="flex items-start gap-2">
          <input type="checkbox" checked={value.install_cache} disabled={!writable} onChange={(e) => set("install_cache", e.target.checked)} />
          <span>
            <span className="font-medium text-fg-1">First-start install cache</span>
            <span className="block text-[11px] text-fg-3">
              The guest image holds no agent tool. On, a run installs it once into a per-image-set cache disk from the
              tool&apos;s vendor (after you consent, pinned to a version); off, such a run is refused.
            </span>
          </span>
        </label>
        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            checked={value.workspace_delivery === "disk_image"}
            disabled={!writable}
            onChange={(e) => set("workspace_delivery", e.target.checked ? "disk_image" : "virtiofs")}
          />
          <span>
            <span className="font-medium text-fg-1">Deliver workspace copies as a disk image</span>
            <span className="block text-[11px] text-fg-3">
              Off (the default), a copy is shared into the VM by a virtiofsd. On, a clone-local or clone-remote copy is
              written into an ext4 image (no root needed) and read back after the run before its commits are returned and
              scanned. A live workspace and a worktree always use the share.
            </span>
          </span>
        </label>
        <div className="grid gap-3 md:grid-cols-2">
          {(["cloud_hypervisor_path", "virtiofsd_path"] as const).map((key) => (
            <label key={key} className="block space-y-1">
              <span className="block font-medium text-fg-1">{key === "cloud_hypervisor_path" ? "cloud-hypervisor path" : "virtiofsd path"}</span>
              <input
                className="w-full rounded-1 border border-line-2 bg-bg-2 px-2 py-1 font-mono text-[12px]"
                value={value[key]}
                placeholder="found on PATH"
                disabled={!writable}
                onChange={(e) => set(key, e.target.value.trim())}
              />
            </label>
          ))}
        </div>
        <span className="block text-[11px] text-fg-3">
          The monitor is <span className="font-mono">{value.vmm || "cloud-hypervisor"}</span>, the only one supported.
        </span>
      </div>
    </details>
  );
}
