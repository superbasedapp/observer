// SandboxWindowsTiersPanel.tsx is the "More Windows sandboxes" sub-panel of
// the Sandbox isolation card (lane GATES-SBX, operator ruling P-129): MXC's
// weaker AppContainer tier (mxc-appcontainer), WSL containers (wslc) and
// Hyper-V isolated containers (hcs), each beta, explicit-only and probe-only
// in this release (a launch is refused by name until its live checks, register
// WIN-4, WIN-5, WIN-9 and WIN-10). The card mounts it with one line. Each row
// renders only while its opt-in component is selected. Its config values are
// paths and a digest-pinned image, which no picker can offer yet (no image is
// published, so no value makes a row usable); they are shown read-only with
// where they are set (D-571: no free-text field here).

import type { ComponentsView } from "@/lib/componentState";
import { componentActive } from "@/components/SandboxCredentialsPanel";

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

export function SandboxWindowsTiersPanel({
  wslc,
  hcs,
  windows,
  view,
}: {
  wslc: SandboxWSLCConfig | undefined;
  hcs: SandboxHCSConfig | undefined;
  windows?: SandboxWindowsConfig | undefined;
  view: ComponentsView | undefined;
}) {
  const rows = WINDOWS_TIER_ROWS.filter((r) => componentActive(view, r.component));
  if (rows.length === 0) return null;
  const shown = (v: string | undefined) => (v && v.trim() ? <span className="font-mono">{v}</span> : <span>not set</span>);
  return (
    <details className="rounded-2 border border-line-2 bg-bg-3 p-3">
      <summary className="cursor-pointer font-medium text-fg-1">
        More Windows sandboxes <span className="ml-1 rounded-1 border border-line-2 px-1 text-[10px] text-fg-3">beta</span>
      </summary>
      <div className="mt-3 space-y-3">
        <p className="text-[11px] text-fg-3">
          Each is used only when it is in the backend list above and a launch names it; automatic selection never picks one.
          In this release each only checks this machine (Settings shows why it is or is not available) and a launch is
          refused by name.
        </p>
        {rows.map((r) => (
          <section key={r.id} className="space-y-1" aria-label={r.name}>
            <h4 className="font-medium text-fg-1">
              {r.name} <span className="font-mono text-[11px] text-fg-3">{r.id}</span>
            </h4>
            <p className="text-[11px] text-fg-3">{r.about}</p>
            {r.id === "mxc-appcontainer" && (
              <p className="text-[11px] text-fg-3">
                Tier floor: {shown(windows?.mxc_tier)}; the process container floor keeps this machine off this row (set in
                the Windows sandbox section of the config file, or pinned by your organization, which may only hold it on
                the process container floor)
              </p>
            )}
            {r.id === "wslc" && (
              <p className="text-[11px] text-fg-3">
                wslc: {shown(wslc?.path)}; image: {shown(wslc?.image)} (set in the WSL container section of the config file)
              </p>
            )}
            {r.id === "hcs" && (
              <p className="text-[11px] text-fg-3">
                Utility VM image: {shown(hcs?.utility_vm_image)} (set in the Hyper-V container section of the config file)
              </p>
            )}
          </section>
        ))}
      </div>
    </details>
  );
}
