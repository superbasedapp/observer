// sandboxIsolation.ts is the one owner of the sandbox copy the New Terminal
// Isolation picker, its summary chip and the terminal run pill share (sandbox
// plan v2 section 9). Pure functions over the probe's backends[] rows and a
// run's isolation evidence, so the three surfaces cannot word the same fact
// three ways.

import type { LaunchIsolation, SandboxAvailability, SandboxBackendAvail } from "./types.ts";

/** The picker value for "no sandbox". */
export const ISOLATION_NONE = "none";

/**
 * The picker value for "let selection pick" (the default entry, lane
 * SBX-P3B): the launch names no backend, exactly as before the picker had a
 * per-launch choice, and selection never takes a beta row (ruling P-062).
 */
export const ISOLATION_AUTO = "auto";

/** One Isolation picker entry. */
export type IsolationOption = {
  id: string;
  label: string;
  disabled: boolean;
  /** Why the entry cannot be chosen (the selection drop reason). */
  reason?: string;
  beta: boolean;
};

// CLASS_LABELS names the closed isolation classes for people.
const CLASS_LABELS: Record<string, string> = {
  none: "no isolation",
  process: "process sandbox",
  container: "container",
  userspace_kernel: "user-space kernel",
  hw_vm: "virtual machine",
};

/** classLabel names an isolation class for people. */
export function classLabel(cls: string | undefined): string {
  return (cls && CLASS_LABELS[cls]) || cls || "unknown isolation";
}

/**
 * captureLabel is the computed capture level as people read it: a C6 run
 * (full only because the egress gateway refuses the model providers) reads
 * "full (gateway-guarded)".
 */
export function captureLabel(level: string | undefined, rule: string | undefined): string {
  if (!level) return "capture not recorded";
  if (level === "full" && rule === "C6") return "full (gateway-guarded)";
  return level.replaceAll("_", " ");
}

/**
 * isolationOptions is the picker's list: "None", then "Automatic" (the
 * default: the daemon picks, never a beta row), then every offered backend
 * for a per-launch choice (planned rows are listed in Settings, not here).
 * Automatic is enabled exactly when the daemon's overall probe says a launch
 * naming no backend would run. An unavailable row stays visible and
 * disabled with its drop reason; a beta row is labelled beta and runs only
 * when chosen here. An older daemon that sends no backends[] gets one entry
 * for the shipped bwrap sandbox, enabled exactly when the legacy probe says
 * it is available.
 */
export function isolationOptions(probe: SandboxAvailability | null): IsolationOption[] {
  const none: IsolationOption = { id: ISOLATION_NONE, label: "None", disabled: false, beta: false };
  if (!probe) return [none];
  const rows = (probe.backends ?? []).filter((b) => b.maturity !== "planned");
  if (rows.length === 0) {
    return [
      none,
      {
        id: probe.backend || "bwrap",
        label: "Process sandbox (bubblewrap)",
        disabled: !probe.available,
        reason: probe.available ? undefined : probe.reason,
        beta: false,
      },
    ];
  }
  const auto: IsolationOption = {
    id: ISOLATION_AUTO,
    label: "Automatic",
    disabled: !probe.available,
    reason: probe.available ? undefined : probe.reason || probe.verdict,
    beta: false,
  };
  return [
    none,
    auto,
    ...rows.map((b) => ({
      id: b.id,
      label: `${b.label} - ${classLabel(b.class)}`,
      disabled: !b.available,
      reason: b.available ? undefined : b.reason || b.verdict,
      beta: b.beta,
    })),
  ];
}

/**
 * defaultIsolationChoice is the entry the picker starts on once the probe
 * answers: Automatic when it is offered and enabled, else (an older daemon)
 * the first enabled entry that is not beta. It never starts on a beta row,
 * so a beta row runs only when the user picks it (ruling P-062).
 */
export function defaultIsolationChoice(opts: IsolationOption[]): string | undefined {
  return opts.find((o) => o.id !== ISOLATION_NONE && !o.disabled && !o.beta)?.id;
}

/**
 * launchBackend is the backend a launch body names for a picker value: none
 * for "None" (no sandbox at all) and for "Automatic" (the daemon picks), so
 * those launches send exactly the body they sent before; the row id
 * otherwise. The server re-validates it against its own probed rows.
 */
export function launchBackend(choice: string): string | undefined {
  return choice === ISOLATION_NONE || choice === ISOLATION_AUTO ? undefined : choice;
}

/**
 * isolationChoiceSummary is the chip for a picker value: for Automatic, the
 * row the daemon says a launch naming no backend takes (the probe's legacy
 * backend field) prefixed "Automatic: "; for a chosen row, that row's chip.
 */
export function isolationChoiceSummary(probe: SandboxAvailability | null, choice: string): string | null {
  if (!probe) return null;
  if (choice === ISOLATION_AUTO) {
    if (!probe.available) return null;
    const picked = isolationSummary(probe.backends?.find((b) => b.id === probe.backend), probe.egress);
    return picked ? `Automatic: ${picked}` : null;
  }
  return isolationSummary(probe.backends?.find((b) => b.id === choice), probe.egress);
}

/**
 * isolationSummary is the one-line chip above Start for a chosen backend on
 * the daemon's network tier: "process sandbox, network internet, capture
 * full (gateway-guarded), beta".
 */
export function isolationSummary(b: SandboxBackendAvail | undefined, egress: string | undefined): string | null {
  if (!b) return null;
  const tier = egress || "internet";
  const parts = [classLabel(b.class), `network ${tier.replaceAll("_", " ")}`];
  const cap = b.capture_by_tier?.[tier];
  if (cap) parts.push(`capture ${cap}`);
  if (b.beta) parts.push("beta");
  return parts.join(", ");
}

// CAUSE_LABELS names the capture relay's closed degraded-cause vocabulary
// (Go owner: internal/sandboxrelayd.DegradedCause) for people.
const CAUSE_LABELS: Record<string, string> = {
  refused: "events refused",
  rate_limited: "events rate-limited",
  dropped: "events lost",
  replayed: "events delivered late",
  hooks_drifted: "hooks changed in the box",
  heartbeat_missed: "heartbeats missed",
};

/**
 * degradedLabel is what lowered a run's capture after launch: "capture no
 * longer complete (hooks changed in the box)" when the box's hook
 * configuration drifted from the launch's (later events may never be
 * sent), else "capture degraded (events refused, ...)".
 */
export function degradedLabel(iso: LaunchIsolation | undefined): string | null {
  if (!iso || !iso.capture_degraded) return null;
  const causes = (iso.capture_causes ?? []).map((c) => CAUSE_LABELS[c] || c.replaceAll("_", " "));
  const why = causes.length ? ` (${causes.join(", ")})` : "";
  const head = iso.capture_causes?.includes("hooks_drifted") ? "capture no longer complete" : "capture degraded";
  return head + why;
}

/**
 * runPillLabel is the run pill on a terminal's header: what the run was
 * actually launched in, from its recorded evidence, and what lowered its
 * capture since.
 */
export function runPillLabel(iso: LaunchIsolation | undefined): string | null {
  if (!iso || !iso.class || iso.class === "none") return null;
  const parts = [iso.backend ? `${iso.backend} (${classLabel(iso.class)})` : classLabel(iso.class)];
  if (iso.egress_tier) parts.push(`network ${iso.egress_tier.replaceAll("_", " ")}`);
  parts.push(`capture ${captureLabel(iso.capture_level, iso.capture_rule)}`);
  const degraded = degradedLabel(iso);
  if (degraded) parts.push(degraded);
  if (iso.verification && iso.verification !== "live") parts.push("beta");
  return parts.join(", ");
}
