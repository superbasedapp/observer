// SandboxIsolationPicker.tsx is the New Terminal dialog's Isolation picker
// (sandbox plan v2 section 9): "None" plus every offered backend from the
// probe, an unavailable one visible and disabled with its drop reason, and
// the one-line summary chip under it. It belongs to the Sandboxes and VMs
// module (component terminals.sandbox) and is rendered through the compgen
// registry (SANDBOX_ISOLATION_PICKER), so a build without the module ships
// none of it. Presentational: the dialog owns the state. A backend that is
// only left out of the enabled backends list reads "not enabled", with a
// link to the Settings list that enables it; one whose module is not
// installed reads "module not installed", with a link to Settings >
// Components. When the caller passes onSetup (the New Terminal dialog with
// the setup panel in this build), those two lines become one, "Set up a
// sandbox backend (N available to set up)", and choosing a row that cannot
// run yet opens the setup panel on it instead of being refused (sandbox
// installation lifecycle plan section 3.7).

import { Link } from "react-router-dom";
import { TERMINALS_SANDBOX_BACKENDS_HASH } from "@/lib/nodePageTabs";
import { COMPONENTS_SETTINGS_PATH, ISOLATION_AUTO, ISOLATION_NONE, type IsolationOption, type UnavailableRow } from "@/lib/sandboxIsolation";
import { setupLine } from "@/lib/sandboxSetup";

export function SandboxIsolationPicker({
  options,
  value,
  disabled,
  reason,
  chip,
  notes = [],
  unavailable = [],
  onChange,
  onNavigate,
  onSetup,
  setupBackends,
  setupBeta = [],
}: {
  options: IsolationOption[];
  /** The chosen backend id, or ISOLATION_NONE. */
  value: string;
  disabled: boolean;
  /** Why the picker is disabled (shown in place of the chip). */
  reason: string | null;
  /** The summary chip for the chosen backend. */
  chip: string | null;
  /** The daemon's own sentences about the chosen backend (its
   *  prerequisite, its host note and its disclosures), shown as served. */
  notes?: string[];
  /** The offered backends that cannot run here, each with its reason. */
  unavailable?: UnavailableRow[];
  onChange: (value: string) => void;
  /** Called when the settings link is followed (the dialog closes). */
  onNavigate?: () => void;
  /**
   * Opens the sandbox setup panel, on a row when one is named. Given, the
   * "can run here once enabled" and "need their module" lines become one
   * setup line, and a row that cannot run yet is choosable: choosing it
   * opens the panel on that row. Absent, the picker reads as before.
   */
  onSetup?: (backend?: string) => void;
  /** The rows setup can move forward here (setupCandidates' ids): the
   *  setup line counts them and only they are choosable. Defaults to the
   *  rows that only need enabling or their module. */
  setupBackends?: string[];
  /** The labels of the setup rows whose setup is beta: the setup line
   *  names each with "(beta)". */
  setupBeta?: string[];
}) {
  const on = value !== ISOLATION_NONE;
  const notEnabled = options.filter((o) => o.notEnabled);
  const needsModule = options.filter((o) => o.needsModule);
  const setupIds = new Set(setupBackends ?? [...notEnabled, ...needsModule].map((o) => o.id));
  const count = setupIds.size;
  // With setup offered, a backend row setup can move forward stays
  // choosable: choosing it opens the setup panel on it (None and Automatic
  // never do; a row that can never run here stays disabled).
  const setupChoosable = (o: IsolationOption) =>
    !!onSetup && o.disabled && o.id !== ISOLATION_NONE && o.id !== ISOLATION_AUTO && setupIds.has(o.id);
  // [overflow-wrap:anywhere]: a reason or note can hold a long unbroken
  // token (an image digest reference), which wraps instead of widening the
  // dialog (D-R4-4).
  return (
    <div className="mb-1 [overflow-wrap:anywhere]" data-testid="isolation-picker">
      <label htmlFor="new-terminal-isolation" className="mb-1 block font-medium text-fg-1">
        Isolation
      </label>
      <select
        id="new-terminal-isolation"
        value={value}
        disabled={disabled}
        title={reason ?? undefined}
        onChange={(e) => {
          const picked = options.find((o) => o.id === e.target.value);
          if (picked && setupChoosable(picked)) onSetup?.(picked.id);
          else onChange(e.target.value);
        }}
        className="w-full rounded-2 border bg-bg-0 px-2 py-1.5 text-[12px] text-fg-1"
      >
        {options.map((o) => (
          // Native <option>: title= carries the drop reason (a React tooltip
          // cannot render inside the browser-owned popup).
          <option key={o.id} value={o.id} disabled={o.disabled && !setupChoosable(o)} title={o.reason}>
            {o.label}
            {o.beta ? " (beta)" : ""}
            {setupChoosable(o)
              ? " (set up)"
              : o.notEnabled
                ? " (not enabled)"
                : o.needsModule
                  ? " (module not installed)"
                  : o.disabled
                    ? " (unavailable)"
                    : ""}
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
      {on && !reason && notes.length > 0 && (
        <ul className="mt-1 list-disc space-y-0.5 pl-4 text-[11px] text-fg-3" aria-label="About this sandbox">
          {notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
      {unavailable.length > 0 && (
        <details className="mt-1 text-[11px] text-fg-3">
          <summary className="cursor-pointer">Not available here ({unavailable.length})</summary>
          <ul className="mt-1 space-y-0.5 pl-4">
            {unavailable.map((u) => (
              <li key={u.id}>
                <span className="text-fg-2">{u.label}</span>: {u.reason}
                {/* The daemon's own notes about the row (its prerequisite,
                    which often explains the reason, and its disclosures),
                    beside the reason, as served. */}
                {u.notes.length > 0 && (
                  <ul className="mt-0.5 list-disc space-y-0.5 pl-4" aria-label={`About ${u.label}`}>
                    {u.notes.map((n) => (
                      <li key={n}>{n}</li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        </details>
      )}
      {onSetup && count > 0 && (
        <span className="mt-0.5 block text-[11px] text-fg-3" data-testid="isolation-setup">
          <button type="button" onClick={() => onSetup()} className="text-accent hover:underline">
            {setupLine(count, setupBeta)}
          </button>
        </span>
      )}
      {!onSetup && !disabled && notEnabled.length > 0 && (
        <span className="mt-0.5 block text-[11px] text-fg-3" data-testid="isolation-not-enabled">
          {notEnabled.length === 1 ? "1 backend can" : `${notEnabled.length} backends can`} run here once enabled.{" "}
          <Link to={`/terminals${TERMINALS_SANDBOX_BACKENDS_HASH}`} onClick={onNavigate} className="text-accent hover:underline">
            Enable backends in Terminals settings
          </Link>
        </span>
      )}
      {!onSetup && !disabled && needsModule.length > 0 && (
        <span className="mt-0.5 block text-[11px] text-fg-3" data-testid="isolation-needs-module">
          {needsModule.length === 1 ? "1 backend needs its" : `${needsModule.length} backends need their`} module installed
          first.{" "}
          <Link to={COMPONENTS_SETTINGS_PATH} onClick={onNavigate} className="text-accent hover:underline">
            Install modules in Settings &gt; Components
          </Link>
        </span>
      )}
    </div>
  );
}
