// SandboxWindowsTiersPanel.tsx is the "More Windows sandboxes" sub-panel of
// the Sandbox isolation card (lane GATES-SBX, operator ruling P-129): MXC's
// weaker AppContainer tier (mxc-appcontainer), WSL containers (wslc) and
// Hyper-V isolated containers (hcs), each beta, explicit-only and probe-only
// in this release (a launch is refused by name until its live checks, register
// WIN-4, WIN-5, WIN-9 and WIN-10). The card mounts it with one line and owns
// the save. Each row renders only while its opt-in component is selected.
//
// Dashboard CLI parity (plan docs/plans/dashboard-cli-parity-plan-2026-11-06.md,
// item B-G6): the rows' values are edited here, through the card's one save
// (PUT /api/terminal/sandbox/config), instead of the config file. The MXC
// tier floor is a picker over its closed set; a move off ProcessContainer is a
// loosening, so the card's Save asks for a confirm, and guard rule R-165
// refuses an agent's. An organization pin (restrictive-only, it can hold the
// floor on ProcessContainer) makes the picker read-only. The wslc path, its
// digest-pinned image and the utility VM image folder are typed (no image is
// published yet, so no value makes a row usable); the daemon checks each on
// save.

import { ComboChip, Input } from "@/components/primitives";
import type { ComponentsView } from "@/lib/componentState";
import { componentActive } from "@/components/SandboxCredentialsPanel";
import { MXC_TIER_OPTIONS, absPathProblem, mxcTierLoosens, wslcImageProblem } from "@/lib/sandboxParity";

export type SandboxWSLCConfig = { path: string; image: string };
export type SandboxHCSConfig = { utility_vm_image: string };
// The MXC tier floor, [terminal.sandbox.windows] (R-034): "" no floor,
// "process_container" keeps the AppContainer row off, "appcontainer" allows it.
export type SandboxWindowsConfig = { mxc_tier: string };

export const WINDOWS_TIER_ROWS = [
  {
    id: "mxc-appcontainer",
    component: "terminals.sandbox.mxc.appcontainer",
    name: "MXC AppContainer tier",
    about:
      "For Windows machines where MXC offers no ProcessContainer tier (often Windows Home). Weaker than ProcessContainer: an AppContainer sees every folder whose access list grants ALL APPLICATION PACKAGES. Network tier none only. Your organization can keep this machine on ProcessContainer only (windows.mxc_tier).",
  },
  {
    id: "wslc",
    component: "terminals.sandbox.wslc",
    name: "WSL containers (wslc)",
    about: "Linux containers through Windows 11's wslc CLI, with no network (--network none). The supported wslc version is not recorded yet.",
  },
  {
    id: "hcs",
    component: "terminals.sandbox.hcs",
    name: "Hyper-V isolated containers (HCS)",
    about: "Each run in its own Hyper-V utility VM with no network adapter; Windows Pro, Enterprise or Education with the Containers and Hyper-V features. No utility VM image is published yet.",
  },
];

/** WindowsTiersKey names the three blocks the panel edits. */
export type WindowsTiersKey = "wslc" | "hcs" | "windows";

export function SandboxWindowsTiersPanel({
  wslc,
  hcs,
  windows,
  savedTier,
  view,
  pinned,
  writable = false,
  onChange,
}: {
  wslc: SandboxWSLCConfig | undefined;
  hcs: SandboxHCSConfig | undefined;
  windows?: SandboxWindowsConfig | undefined;
  /** savedTier is the floor last saved, so a loosening edit says so. */
  savedTier?: string;
  view: ComponentsView | undefined;
  pinned?: Set<string>;
  writable?: boolean;
  /** onChange edits one block; absent, every value is read-only. */
  onChange?: (key: WindowsTiersKey, value: SandboxWSLCConfig | SandboxHCSConfig | SandboxWindowsConfig) => void;
}) {
  const rows = WINDOWS_TIER_ROWS.filter((r) => componentActive(view, r.component));
  if (rows.length === 0) return null;
  const editable = (pinKey: string) => !!onChange && writable && !(pinned?.has(pinKey) ?? false);
  const tier = windows?.mxc_tier ?? "";
  const tierPinned = pinned?.has("windows.mxc_tier") ?? false;
  const loosens = mxcTierLoosens(savedTier, tier);
  const w = wslc ?? { path: "", image: "" };
  const h = hcs ?? { utility_vm_image: "" };
  return (
    <details className="rounded-2 border border-line-2 bg-bg-3 p-3">
      <summary className="cursor-pointer font-medium text-fg-1">
        More Windows sandboxes <span className="ml-1 rounded-1 border border-line-2 px-1 text-[10px] text-fg-3">beta</span>
      </summary>
      <div className="mt-3 space-y-3">
        <p className="text-[11px] text-fg-3">
          Each is used only when it is in the backend list above and a launch names it; automatic selection never picks one.
          In this release each only checks this machine (Settings shows why it is or is not available) and a launch is
          refused by name. The values below are saved with the card&apos;s Save.
        </p>
        {rows.map((r) => (
          <section key={r.id} className="space-y-2" aria-label={r.name}>
            <h4 className="font-medium text-fg-1">
              {r.name} <span className="font-mono text-[11px] text-fg-3">{r.id}</span>
            </h4>
            <p className="text-[11px] text-fg-3">{r.about}</p>
            {r.id === "mxc-appcontainer" && (
              <div className="space-y-1">
                <span id="sandbox-mxc-tier" className="block font-medium text-fg-1">MXC tier floor</span>
                <ComboChip
                  label="MXC tier floor"
                  labelledBy="sandbox-mxc-tier"
                  hideTriggerLabel
                  fullWidth
                  value={tier}
                  disabled={!editable("windows.mxc_tier")}
                  onChange={(v) => onChange?.("windows", { mxc_tier: v })}
                  options={MXC_TIER_OPTIONS.map((o) => ({ value: o.value, label: <span>{o.label}</span>, detail: o.detail, searchable: `${o.label} ${o.value}` }))}
                  buttonValueRender={() => <span>{MXC_TIER_OPTIONS.find((o) => o.value === tier)?.label ?? tier}</span>}
                />
                <span className="block text-[11px] text-fg-3">
                  ProcessContainer only keeps this machine off this row.
                  {tierPinned && " Set by your organization, which may only hold it on ProcessContainer."}
                </span>
                {loosens && !tierPinned && (
                  <span className="block text-[11px] text-warn">
                    This loosens isolation: launches may then use MXC&apos;s weaker AppContainer tier. Saving asks you to confirm.
                  </span>
                )}
              </div>
            )}
            {r.id === "wslc" && (
              <div className="grid gap-2 md:grid-cols-2">
                <Input
                  label="wslc.exe"
                  mono
                  value={w.path}
                  placeholder="found on PATH"
                  disabled={!editable("wslc.path")}
                  error={absPathProblem(w.path) ?? undefined}
                  onChange={(e) => onChange?.("wslc", { ...w, path: e.target.value })}
                />
                <Input
                  label="Image (pinned by digest)"
                  mono
                  value={w.image}
                  placeholder="name@sha256:…"
                  disabled={!editable("wslc.image")}
                  error={wslcImageProblem(w.image) ?? undefined}
                  help="Empty leaves the row unavailable: no image is set."
                  onChange={(e) => onChange?.("wslc", { ...w, image: e.target.value })}
                />
              </div>
            )}
            {r.id === "hcs" && (
              <Input
                label="Utility VM image folder"
                mono
                value={h.utility_vm_image}
                placeholder="not set"
                disabled={!editable("hcs.utility_vm_image")}
                error={absPathProblem(h.utility_vm_image) ?? undefined}
                help="The folder of the utility VM's base image layer. Until Observer publishes a signed image there is none it can verify, so the row stays unavailable."
                onChange={(e) => onChange?.("hcs", { utility_vm_image: e.target.value })}
              />
            )}
          </section>
        ))}
      </div>
    </details>
  );
}
