// PrivateRangesField.tsx is the hosted internet tier's private-range deny
// (decision SBXD-7) in the Hosted sandboxes panel: the shared switch and, for
// each selected provider whose API takes deny rules, a per-provider choice.
// The panel mounts it with one line. Which providers can deny comes from the
// daemon (private_range_deny_capable), never from a list kept here; the
// effect per provider is said again in the New Terminal dialog's "The box's
// network" block and on the consent screen.

import { ComboChip } from "@/components/primitives";
import type { SandboxHostedConfig } from "@/components/SandboxHostedPanel";
import { HelpTooltip } from "@shared/primitives/HelpTooltip";

// The block's fields on the hosted payload; absent from a daemon that
// predates it (the field then renders nothing).
export type HostedPrivateRanges = {
  allow_private_ranges?: boolean;
  // A provider table name to follow, allow or deny.
  private_range_overrides?: Record<string, string>;
  // The provider tables whose vendor's create can deny ranges.
  private_range_deny_capable?: string[];
};

type Driver = { id: string; table: string; name: string };

const OVERRIDES = [
  { value: "follow", label: "Same as above" },
  { value: "deny", label: "Deny for this provider" },
  { value: "allow", label: "Allow for this provider" },
];

// PIN is how the organization's pins name the shared key.
const PIN = "hosted.allow_private_ranges";

export function PrivateRangesField({
  value,
  drivers,
  pinned,
  writable,
  onChange,
}: {
  value: SandboxHostedConfig;
  drivers: Driver[];
  pinned: Set<string>;
  writable: boolean;
  onChange: (next: SandboxHostedConfig) => void;
}) {
  const v = value as SandboxHostedConfig & HostedPrivateRanges;
  if (v.allow_private_ranges === undefined) return null;
  const capable = new Set(v.private_range_deny_capable ?? []);
  const overrides = v.private_range_overrides ?? {};
  const orgSet = pinned.has(PIN);
  const editable = writable && !orgSet;
  const set = (next: HostedPrivateRanges) => onChange({ ...v, ...next } as SandboxHostedConfig);
  const setOverride = (table: string, o: string) => set({ private_range_overrides: { ...overrides, [table]: o } });
  const deniable = drivers.filter((d) => capable.has(d.table));
  const notDeniable = drivers.filter((d) => !capable.has(d.table));
  return (
    <div className="space-y-2 rounded-2 border border-line-2 bg-bg-3 p-3">
      <label className="flex items-start gap-2">
        <input
          type="checkbox"
          className="mt-0.5"
          checked={v.allow_private_ranges}
          disabled={!editable}
          onChange={(e) => set({ allow_private_ranges: e.target.checked })}
        />
        <span>
          <span className="font-medium text-fg-1">Let a box on the internet setting reach private network addresses</span>
          <HelpTooltip
            technical
            subject="the private network setting"
            className="ml-1 align-middle"
            content="[terminal.sandbox.hosted] allow_private_ranges (default false); per provider [terminal.sandbox.hosted.<provider>] allow_private_ranges. Denied: 169.254.0.0/16 (incl. 169.254.169.254), fd00:ec2::254, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7, fe80::/10, 100.64.0.0/10."
          />
          <span className="block text-[11px] text-fg-3">
            Off by default. When off, Observer asks each provider that can do so to refuse the cloud metadata address, link-local and
            private network ranges for the box, and the provider enforces it. Turn it on only for a box that must reach a private network.
            Changing it asks for your agreement again before the next launch.
          </span>
          {orgSet && <span className="block text-[11px] text-fg-3">Set by your organization (it can only keep these ranges denied).</span>}
        </span>
      </label>
      {deniable.map((d) => {
        const id = `sandbox-hosted-${d.id}-private-ranges`;
        const current = overrides[d.table] ?? "follow";
        const label = OVERRIDES.find((o) => o.value === current)?.label ?? current;
        return (
          <div key={d.id} className="space-y-1">
            <span id={id} className="block text-fg-2">
              {d.name}: private network addresses
            </span>
            <ComboChip
              label={`${d.name} private network addresses`}
              labelledBy={id}
              hideTriggerLabel
              fullWidth
              value={current}
              disabled={!editable}
              onChange={(o) => setOverride(d.table, o)}
              options={OVERRIDES.map((o) => ({ value: o.value, label: <span>{o.label}</span>, searchable: o.label }))}
              buttonValueRender={() => <span>{label}</span>}
            />
          </div>
        );
      })}
      {notDeniable.length > 0 && (
        <span className="block text-[11px] text-fg-3">
          {notDeniable.map((d) => d.name).join(", ")}: the provider takes no rule that would refuse these ranges, so on its internet
          setting the box can reach them whatever this setting says. The New Terminal dialog and the agreement screen say so.
        </span>
      )}
    </div>
  );
}
