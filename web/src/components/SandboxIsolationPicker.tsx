// SandboxIsolationPicker.tsx is the New Terminal dialog's Isolation picker
// (sandbox plan v2 section 9): "None" plus every offered backend from the
// probe, an unavailable one visible and disabled with its drop reason, and
// the one-line summary chip under it. It belongs to the Sandboxes and VMs
// module (component terminals.sandbox) and is rendered through the compgen
// registry (SANDBOX_ISOLATION_PICKER), so a build without the module ships
// none of it. Presentational: the dialog owns the state.

import { ISOLATION_NONE, type IsolationOption } from "@/lib/sandboxIsolation";

export function SandboxIsolationPicker({
  options,
  value,
  disabled,
  reason,
  chip,
  onChange,
}: {
  options: IsolationOption[];
  /** The chosen backend id, or ISOLATION_NONE. */
  value: string;
  disabled: boolean;
  /** Why the picker is disabled (shown in place of the chip). */
  reason: string | null;
  /** The summary chip for the chosen backend. */
  chip: string | null;
  onChange: (value: string) => void;
}) {
  const on = value !== ISOLATION_NONE;
  return (
    <div className="mb-1">
      <label htmlFor="new-terminal-isolation" className="mb-1 block font-medium text-fg-1">
        Isolation
      </label>
      <select
        id="new-terminal-isolation"
        value={value}
        disabled={disabled}
        title={reason ?? undefined}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-2 border bg-bg-0 px-2 py-1.5 text-[12px] text-fg-1"
      >
        {options.map((o) => (
          // Native <option>: title= carries the drop reason (a React tooltip
          // cannot render inside the browser-owned popup).
          <option key={o.id} value={o.id} disabled={o.disabled} title={o.reason}>
            {o.label}
            {o.beta ? " (beta)" : ""}
            {o.disabled ? " (unavailable)" : ""}
          </option>
        ))}
      </select>
      <span className="mt-1 block text-[11px] text-fg-3">
        {reason ??
          (on
            ? chip ??
              "Launch inside a bubblewrap sandbox with an isolated $HOME - the agent can't read or write your real home directory or other projects."
            : "None: the agent runs on the host with your normal home directory.")}
      </span>
    </div>
  );
}
