// SandboxNativePanel.tsx is the "The agent's own sandbox" sub-panel of the
// Sandbox isolation card (sandbox plan v2 sections 4.4 and 10.1, D-746 Q17,
// lane SBX-P3D): the editor for [terminal.sandbox].vendor_forced_native and
// a plain account of what Observer does with an agent's own sandbox. The card
// mounts it with one line and owns the save; this panel edits one key.
//
// What it says is what the launch does: a per-run switch the vendor
// documents (a command-line flag or an environment variable) is applied for
// that run only and recorded as disabled_by_observer; a switch that exists
// only as a global setting is never used, so such a launch is refused; a
// vendor managed policy that forces the agent's sandbox on is refused under
// both values today, because no stack where both sandboxes run is built.

import type { ReactNode } from "react";

export type VendorForcedNative = "nest_or_refuse" | "refuse";

// PIN_KEY is how the organization's pins name the key.
const PIN_KEY = "vendor_forced_native";

export const VENDOR_FORCED_OPTIONS: { value: VendorForcedNative; title: string; hint: ReactNode }[] = [
  {
    value: "nest_or_refuse",
    title: "Nest, or refuse (default)",
    hint: (
      <>
        Choose a sandbox where both run (a VM row). None is built yet, so today the launch is refused as a sandbox conflict with the tool.
      </>
    ),
  },
  {
    value: "refuse",
    title: "Refuse",
    hint: <>Refuse at once, so a VM is never chosen on your behalf.</>,
  },
];

// normalizeVendorForced reads the saved value; anything else is the default.
export function normalizeVendorForced(v: string | undefined): VendorForcedNative {
  return v === "refuse" ? "refuse" : "nest_or_refuse";
}

export function SandboxNativePanel({
  value,
  pinned,
  writable,
  onChange,
}: {
  value: string | undefined;
  pinned: Set<string>;
  writable: boolean;
  onChange: (next: VendorForcedNative) => void;
}) {
  const current = normalizeVendorForced(value);
  const orgSet = pinned.has(PIN_KEY);
  const editable = writable && !orgSet;
  return (
    <details className="rounded-2 border border-line-2 bg-bg-3 p-3" data-testid="sandbox-native-panel">
      <summary className="cursor-pointer font-medium text-fg-1">The agent&apos;s own sandbox</summary>
      <div className="mt-3 space-y-3">
        <p className="text-[11px] text-fg-3">
          Some agents run their own sandbox (Codex, Copilot CLI, Claude Code). Inside Observer&apos;s sandbox it may not
          work, because two Seatbelt profiles or two fresh <span className="font-mono">/proc</span> mounts do not nest.
          When it cannot nest, Observer turns it off for that run only, with the switch the vendor documents (for
          example Codex&apos;s <span className="font-mono">--sandbox danger-full-access</span>), and the run records that Observer turned the agent&apos;s own sandbox off; Observer&apos;s sandbox is then the boundary. An agent
          whose only off switch is a global setting is refused instead, so your unsandboxed runs keep their own sandbox.
        </p>
        <fieldset className="space-y-2" disabled={!editable}>
          <legend className="font-medium text-fg-1">When a vendor policy forces the agent&apos;s sandbox on</legend>
          {VENDOR_FORCED_OPTIONS.map((o) => (
            <label key={o.value} className="flex items-start gap-2">
              <input
                type="radio"
                name="sandbox-vendor-forced-native"
                className="mt-0.5"
                value={o.value}
                checked={current === o.value}
                onChange={() => onChange(o.value)}
              />
              <span>
                <span className="font-medium text-fg-1">{o.title}</span>
                <span className="block text-[11px] text-fg-3">{o.hint}</span>
              </span>
            </label>
          ))}
          <span className="block text-[11px] text-fg-3">
            Running without Observer&apos;s sandbox is not an option: it would drop the isolation you asked for. Observer
            detects a forced sandbox only from a policy file the vendor documents (today Claude Code&apos;s
            managed settings file with the sandbox on and required); otherwise the agent&apos;s own refusal
            stays visible.
          </span>
          {orgSet && <span className="block text-[11px] text-fg-3">Set by your organization.</span>}
        </fieldset>
      </div>
    </details>
  );
}
