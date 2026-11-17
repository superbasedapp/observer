// SandboxStraceSeizeToggle.tsx is the sandbox card's strace switch (lane
// ptrace, PT-96, operator ruling 2026-11-10): [terminal.sandbox]
// .seccomp_allow_seize, off by default, which lifts PTRACE_SEIZE (and
// nothing else) from Observer's syscall filter so `strace <cmd>` works in a
// sandboxed terminal. Its own owner-local route writes it (POST
// /api/terminal/sandbox/ptrace-seize, with the double-submit confirm token);
// the card's Save never does. The rows come from the daemon: what the switch
// gives each sandbox here, on which containment ground, or why not.

import { useState } from "react";
import { apiReason, fetchJSON } from "@/lib/api";
import { useApi } from "@/lib/useApi";

export const SANDBOX_SEIZE_PATH = "/api/terminal/sandbox/ptrace-seize";

export type SandboxSeizeRow = {
  backend: string;
  label: string;
  lifted: boolean;
  ground?: string;
  reason?: string;
};

export type SandboxSeizeStatus = {
  enabled: boolean;
  seccomp: boolean;
  yama_scope: number | null;
  rows: SandboxSeizeRow[];
  confirm_token?: string;
  config_writable?: boolean;
};

// SEIZE_GROUND_TEXT names each containment ground in plain words.
const SEIZE_GROUND_TEXT: Record<string, string> = {
  pid_namespace: "strace allowed: the sandbox has its own process list",
  yama: "strace allowed: the kernel's Yama setting limits tracing to the run's own child processes",
};

// seizeRowText is one row's words: the ground it rests on, or the daemon's
// reason strace stays blocked there.
export function seizeRowText(r: SandboxSeizeRow): string {
  if (r.lifted) return SEIZE_GROUND_TEXT[r.ground ?? ""] ?? "strace allowed";
  return r.reason ?? "strace stays blocked";
}

export function SandboxStraceSeizeToggle({
  status,
  disabled,
  busy,
  error,
  onChange,
}: {
  status: SandboxSeizeStatus | null;
  disabled: boolean;
  busy: boolean;
  error: string | null;
  onChange: (on: boolean) => void;
}) {
  return (
    <div className="rounded-2 border border-warn/30 bg-warn/5 p-3" data-testid="sandbox-strace-seize" data-config-key="seccomp_allow_seize">
      <label className="flex items-start gap-2">
        <input
          type="checkbox"
          className="mt-0.5"
          aria-label="Allow strace in sandboxed terminals"
          checked={status?.enabled ?? false}
          disabled={disabled || busy || status === null}
          onChange={(e) => onChange(e.target.checked)}
        />
        <span>
          <span className="font-medium text-fg-1">Allow strace in sandboxed terminals</span>
          <span className="block text-[11px] text-fg-3">
            Off by default. On: the syscall filter lets a sandboxed run trace a command it starts itself (strace &lt;command&gt;, which strace 6.14 and later needs). Tracing a process that is already running (strace -p) stays blocked, and nothing else in the filter changes.
          </span>
          <span className="block text-[11px] text-fg-3">
            It applies only where tracing cannot reach a process outside the sandbox: the sandbox has its own process list, or the kernel&apos;s Yama setting limits tracing to the run&apos;s own child processes. Where neither holds, strace stays blocked and the launch says why. Observer never changes a kernel setting. Takes effect on the next launch. Only you can turn this on, here on this machine: not your organization, and not an AI agent.
          </span>
          {status && !status.seccomp && (
            <span className="block text-[11px] text-fg-3">The syscall filter is off, so nothing is blocked now. This switch matters once the filter is on.</span>
          )}
        </span>
      </label>
      {status && status.rows.length > 0 && (
        <ul className="mt-2 space-y-1 text-[11px] text-fg-2" aria-label="What the strace switch gives each sandbox here">
          {status.rows.map((r) => (
            <li key={r.backend}>
              <span className="font-medium text-fg-1">{r.label}</span>: {seizeRowText(r)}
            </li>
          ))}
        </ul>
      )}
      {error && (
        <p role="alert" className="mt-2 text-[11px] text-danger">
          {error}
        </p>
      )}
    </div>
  );
}

// SandboxStraceSeizeCard reads the switch and saves a change at once
// through its own route (the toggle is the whole edit, so there is no
// separate Save).
export function SandboxStraceSeizeCard({ writable }: { writable: boolean }) {
  const res = useApi<SandboxSeizeStatus>(SANDBOX_SEIZE_PATH);
  const [saved, setSaved] = useState<SandboxSeizeStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const status = saved ?? res.data;
  const onChange = async (on: boolean) => {
    setBusy(true);
    setError(null);
    try {
      const out = await fetchJSON<{ strace?: SandboxSeizeStatus }>(SANDBOX_SEIZE_PATH, undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Observer-Confirm": res.data?.confirm_token ?? "" },
        body: JSON.stringify({ enabled: on }),
      });
      if (out.strace && status) setSaved({ ...status, ...out.strace });
      res.reload();
    } catch (e) {
      setError(apiReason(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <SandboxStraceSeizeToggle
      status={status}
      disabled={!writable || res.data?.config_writable === false}
      busy={busy}
      error={error}
      onChange={(on) => void onChange(on)}
    />
  );
}
