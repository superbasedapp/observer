// GuardHooksField.tsx is the "Guard in the box" picker of the Hosted
// sandboxes panel (lane HOOKS, decision SBXD-6): whether a hosted box gets
// Observer's hooks for the agent tool, so this machine's guard checks the
// agent's commands there. It edits [terminal.sandbox.hosted].guard_hooks;
// the panel mounts it with one line and owns the save. The internal names
// appear only under "Technical details".

import { ComboChip } from "@/components/primitives";
import { HelpTooltip } from "@shared/primitives/HelpTooltip";

// GUARD_HOOKS are the three values in the order offered ("" from a daemon
// or file that never set it reads as the default, auto).
export const GUARD_HOOKS = [
  { value: "auto", label: "When guard enforcement is on for this machine (default)" },
  { value: "on", label: "Always" },
  { value: "off", label: "Never" },
];

// guardHooksValue is the value the picker shows for a saved one.
export function guardHooksValue(v: string | undefined): string {
  return v && GUARD_HOOKS.some((o) => o.value === v) ? v : "auto";
}

export function GuardHooksField({
  value,
  disabled,
  pinned,
  onChange,
}: {
  value: string | undefined;
  disabled: boolean;
  pinned: boolean;
  onChange: (next: string) => void;
}) {
  const current = guardHooksValue(value);
  return (
    <div className="space-y-1" data-testid="sandbox-hosted-guard-hooks">
      <span id="sandbox-hosted-guard-hooks" className="block font-medium text-fg-1">
        Guard in the box
        <HelpTooltip
          technical
          subject="guard in the box"
          content="[terminal.sandbox.hosted].guard_hooks = auto | on | off; seeds the tool's user settings file in the box home only, for a tool whose hook mechanism a box can be seeded for (hook.BoxHooksCover)"
          className="ml-1 align-middle"
        />
      </span>
      <ComboChip
        label="Guard in the box"
        labelledBy="sandbox-hosted-guard-hooks"
        hideTriggerLabel
        fullWidth
        value={current}
        disabled={disabled}
        onChange={(v) => onChange(v)}
        options={GUARD_HOOKS.map((o) => ({ value: o.value, label: <span>{o.label}</span>, searchable: o.label }))}
        buttonValueRender={() => <span>{GUARD_HOOKS.find((o) => o.value === current)?.label ?? current}</span>}
      />
      <span className="block text-[11px] text-fg-3">
        Observer sets up its hooks for the agent in the box, so this machine&apos;s guard checks the agent&apos;s commands and
        file edits there. If the box&apos;s link to this machine drops, checked actions are blocked until it is back. Nothing
        is written on this machine. The New Terminal dialog says for each launch whether it applies.
      </span>
      {pinned && <span className="block text-[11px] text-fg-3">Set by your organization (it can only turn this on).</span>}
    </div>
  );
}
