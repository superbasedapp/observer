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
  /**
   * The entry is disabled only because it is not in the enabled backends
   * list, and the daemon says it would run here once it is: the picker
   * labels it "not enabled" and links to the setting.
   */
  notEnabled?: boolean;
  /**
   * The entry needs its Sandboxes and VMs module installed first
   * (module_inactive, before or after enabling): the picker links to
   * Settings > Components.
   */
  needsModule?: boolean;
};

/** The selection verdict for a row left out of the enabled backends list. */
export const VERDICT_NOT_ENABLED = "disabled_by_config";

/** The selection verdict for a row whose module is not installed. */
export const VERDICT_MODULE_INACTIVE = "module_inactive";

/** Where a module is installed (Settings > Components). */
export const COMPONENTS_SETTINGS_PATH = "/settings/components";

/**
 * BackendStateName is one of backendState's states, exported for the
 * sandbox setup panel's candidate counts (sandboxSetup.ts setupCandidates).
 */
export type BackendStateName = "available" | "not_enabled" | "needs_module" | "unavailable";

/**
 * backendState is a probed row's status as people read it, the one owner
 * of the copy the Settings backends list and the Isolation picker share:
 *   - available: it runs here now;
 *   - not_enabled: it is left out of the enabled backends list and would
 *     run here once enabled (the only state a checkbox fixes);
 *   - needs_module: its module is not installed on this node, so nothing
 *     else here helps until it is (Settings > Components);
 *   - unavailable: it cannot run here, enabled or not; reason says why,
 *     preferring what selection says once the row is enabled, so a row
 *     that is both off and unsupported names the real blocker.
 */
export function backendState(b: SandboxBackendAvail): {
  state: BackendStateName;
  reason: string;
} {
  if (b.available) return { state: "available", reason: "" };
  if (b.verdict === VERDICT_MODULE_INACTIVE) {
    return { state: "needs_module", reason: b.reason || "its module is not installed on this node" };
  }
  if (b.verdict === VERDICT_NOT_ENABLED) {
    if (b.when_enabled_available) {
      return { state: "not_enabled", reason: "not enabled: turn it on in Terminals > Settings > Backends" };
    }
    if (b.when_enabled_verdict === VERDICT_MODULE_INACTIVE) {
      return { state: "needs_module", reason: b.when_enabled_reason || "its module is not installed on this node" };
    }
    // An older daemon sends no hypothetical: keep its own reason.
    return { state: "unavailable", reason: b.when_enabled_reason || b.when_enabled_verdict || b.reason || b.verdict || "not available" };
  }
  return { state: "unavailable", reason: b.reason || b.verdict || "not available" };
}

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
/**
 * NOT_OFFERED_VERDICTS are probe verdicts that mean "this row is not
 * something this node can turn on" (the org-hosted OpenShell row on a node
 * whose organization publishes no gateway, g1-design.md section 8.4): the
 * picker omits such a row instead of listing it as unavailable. Keyed on the
 * served verdict, never on a backend id.
 */
export const NOT_OFFERED_VERDICTS: ReadonlySet<string> = new Set(["org_gateway_not_offered"]);

/** offeredHere reports whether a row belongs in the picker at all. */
export function offeredHere(b: SandboxBackendAvail): boolean {
  return b.maturity !== "planned" && !(b.verdict && NOT_OFFERED_VERDICTS.has(b.verdict));
}

export function isolationOptions(probe: SandboxAvailability | null): IsolationOption[] {
  const none: IsolationOption = { id: ISOLATION_NONE, label: "None", disabled: false, beta: false };
  if (!probe) return [none];
  const rows = (probe.backends ?? []).filter(offeredHere);
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
    ...rows.map((b) => {
      const s = backendState(b);
      return {
        id: b.id,
        label: `${b.label} - ${classLabel(b.class)}`,
        disabled: !b.available,
        reason: b.available ? undefined : s.reason,
        beta: b.beta,
        notEnabled: s.state === "not_enabled",
        needsModule: s.state === "needs_module",
      };
    }),
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
 * full (gateway-guarded), beta". A row run through a gateway names it
 * ("gateway: Observer's private gateway").
 */
export function isolationSummary(b: SandboxBackendAvail | undefined, egress: string | undefined): string | null {
  if (!b) return null;
  const tier = egress || "internet";
  const parts = [classLabel(b.class), `network ${tier.replaceAll("_", " ")}`];
  const cap = b.capture_by_tier?.[tier];
  if (cap) parts.push(`capture ${cap}`);
  const gw = gatewayModeLabel(b.gateway_mode);
  if (gw) parts.push(`gateway: ${gw}`);
  if (b.beta) parts.push("beta");
  return parts.join(", ");
}

// GATEWAY_MODE_LABELS names the closed gateway modes (Go owner:
// internal/sandboxvocab.GatewayMode) for people.
const GATEWAY_MODE_LABELS: Record<string, string> = {
  managed_local: "Observer's private gateway",
  external: "your own gateway",
};

/** gatewayModeLabel names a row's gateway mode ("" for a row with none). */
export function gatewayModeLabel(mode: string | undefined): string {
  if (!mode) return "";
  return GATEWAY_MODE_LABELS[mode] || mode.replaceAll("_", " ");
}

/**
 * backendNotes are the daemon's own sentences about a row, in the order a
 * person needs them: what it needs on this host (the prerequisite), the
 * driver's note about this host (hint), then each disclosure. Nothing here
 * is worded in web/: the daemon serves every sentence.
 */
export function backendNotes(b: SandboxBackendAvail | undefined): string[] {
  if (!b) return [];
  const out: string[] = [];
  if (b.prerequisite) out.push(b.prerequisite);
  if (b.hint) out.push(b.hint);
  for (const d of b.disclosures ?? []) {
    if (d.text) out.push(d.text);
  }
  return out;
}

/**
 * One offered row the daemon says cannot run here, with its reason and the
 * daemon's own notes about it (prerequisite, hint, disclosures), so the
 * sentence that explains the reason (for the openshell row the D4
 * prerequisite) and the D3 disclosure sit beside it.
 */
export type UnavailableRow = { id: string; label: string; reason: string; notes: string[] };

/**
 * unavailableRows lists each offered row that cannot run here with its
 * reason (a native option's title is not shown by every browser, so the
 * picker also lists them in the open). The reason is backendState's, so a
 * row that is both off and unsupported names the real blocker. A row that
 * only needs enabling, or only its module installed, is left out: the
 * picker counts those on their own lines, each with the link that fixes
 * it, so no row is listed twice with two different stories.
 */
export function unavailableRows(probe: SandboxAvailability | null): UnavailableRow[] {
  return (probe?.backends ?? [])
    .filter((b) => offeredHere(b) && !b.available)
    .map((b) => ({ b, st: backendState(b) }))
    .filter(({ st }) => st.state === "unavailable")
    .map(({ b, st }) => ({ id: b.id, label: b.label, reason: st.reason, notes: backendNotes(b) }));
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
 * seccompRunLabel is the run pill's seccomp part, for the states a user
 * turned [terminal.sandbox].seccomp on for (audit N2-A9, FU4-A2): the filter
 * Observer applied, or that the key could not reach this backend, so the run
 * is not filtered by Observer. Every other state (off, none, the engine's own
 * filter, not recorded) says nothing, so a key-off launch reads as before.
 */
export function seccompRunLabel(iso: LaunchIsolation | undefined): string | null {
  switch (iso?.seccomp) {
    case "observer_default":
      return "seccomp filter observer_default";
    // The strace switch (lane ptrace): Observer's filter with PTRACE_SEIZE
    // lifted, on the containment ground the launch recorded.
    case "observer_seize_pidns":
      return "seccomp filter observer_seize_pidns, strace allowed (the sandbox has its own process list)";
    case "observer_seize_yama":
      return "seccomp filter observer_seize_yama, strace allowed (Yama limits it to the run's own child processes)";
    case "not_applicable":
      return "seccomp not applicable: not filtered by Observer";
    default:
      return null;
  }
}

/** seccompNotFiltered reports a key-on run Observer's filter did not reach. */
export function seccompNotFiltered(iso: LaunchIsolation | undefined): boolean {
  return iso?.seccomp === "not_applicable";
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
  const seccomp = seccompRunLabel(iso);
  if (seccomp) parts.push(seccomp);
  if (iso.verification && iso.verification !== "live") parts.push("beta");
  return parts.join(", ");
}
