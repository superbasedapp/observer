// codeSecuritySettings - the pure half of the Code security Settings card
// (security pillar plan section 6.5, Phase A).
//
// The card is the node-dashboard home of every [security.*] key the
// module has built so far. Each row is a picker (D-571: pickers only) over
// the key's closed value list, and the write goes through the same PUT
// /api/config/keys path every schema-driven setting uses. The rows mirror
// internal/config.SecuritySettings(); the Go test
// TestSecuritySettingsCardRows fails when a contract row is missing here or
// a row here names no contract key.
//
// The card is shown only while the `security` component is active
// (codeSecurityCardVisible): an inactive or omitted module adds nothing to
// the page, and an unknown component state shows nothing (fail closed).

import type { ConfigKeyPatch } from "./configSchema.ts";
import type { ComponentsView } from "./componentState.ts";

/** A picker value: a number (with a unit), an on/off switch or a named choice. */
export type CodeSecurityValue = number | boolean | string;

/** One settings-contract row the card offers. */
export type CodeSecuritySetting = {
  /** Dotted config key (the contract row's Key). */
  key: string;
  /** The catalog component that owns the key; the row shows only while it is active and selected. */
  component: string;
  /** JSON field path of the key in GET /api/config's `config` object. */
  field: string;
  label: string;
  /** The picker's closed values. */
  values: readonly CodeSecurityValue[];
  /** The contract default. */
  defaultValue: CodeSecurityValue;
  /** The unit the picker labels a number with ("" for an on/off row). */
  unit: string;
  help: string;
  /** Optional per-value label (keyed by String(value)), shown instead of the plain value. */
  optionLabels?: Readonly<Record<string, string>>;
};

/** The card's rows, one per built [security.*] key. */
export const CODE_SECURITY_SETTINGS: readonly CodeSecuritySetting[] = [
  {
    key: "security.retention.days",
    component: "security",
    field: "Security.Retention.Days",
    label: "Finding retention",
    values: [90, 180, 365, 730],
    defaultValue: 365,
    unit: "days",
    help: "Closed and suppressed findings older than this are deleted, with their history. Open findings are never deleted.",
  },
  {
    key: "security.deps.install_wait_ms",
    component: "security.deps",
    field: "Security.Deps.InstallWaitMS",
    label: "Install check wait",
    values: [500, 1500, 3000],
    defaultValue: 1500,
    unit: "ms",
    help: "How long an agent's package install waits for the online package check before the offline verdict stands (Package checks).",
  },
  {
    key: "security.deps.min_package_age_h",
    component: "security.deps",
    field: "Security.Deps.MinPackageAgeH",
    label: "Minimum package age",
    values: [0, 24, 72, 168],
    defaultValue: 72,
    unit: "hours",
    help: "An agent install of a package published more recently than this is flagged as too new. 0 switches the check off.",
  },
  {
    key: "security.deps.index_download",
    component: "security.deps",
    field: "Security.Deps.IndexDownload",
    label: "Package index download",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "Downloads Observer's signed lists of malicious and popular package names from superbased.app every 6 hours; it sends nothing about your packages. Off: nothing is fetched and the checks use the index already on disk. Applies within 30 seconds, no restart.",
  },
  {
    key: "security.secrets.write_check",
    component: "security.secrets",
    field: "Security.Secrets.WriteCheck",
    label: "Secret check before writes",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "Checks an agent's proposed write for a secret before it lands (rule S-721). Off: the write is not judged in the hook; the file is still checked after the write and at the commit gate.",
  },
  {
    key: "security.secrets.commit_check",
    component: "security.secrets",
    field: "Security.Secrets.CommitCheck",
    label: "Secret check on commits",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "Checks every commit that lands, human or agent, for secrets and records them as findings. Off: landed commits are not checked; the commit gate's quick scan of an agent's own commit still runs.",
  },
  {
    key: "security.secrets.postwrite_cap_kib",
    component: "security.secrets",
    field: "Security.Secrets.PostWriteCapKiB",
    label: "Largest file checked after a write",
    values: [256, 64],
    defaultValue: 256,
    unit: "KiB",
    help: "A written file larger than this is not checked after the write (the commit gate still covers it). 64 KiB scans less and is honoured on an individual node only: a managed node keeps 256 KiB and its status says so. The check inside the hook is fixed at 16 KiB.",
    optionLabels: { "64": "64 KiB (scans less)" },
  },
  {
    key: "security.deps.unknown_action",
    component: "security.deps",
    field: "Security.Deps.UnknownAction",
    label: "Unknown package install",
    values: ["default", "ask", "deny"],
    defaultValue: "default",
    unit: "",
    help: "What an agent install of a package the index does not know does (rule S-744). Default flags it; ask asks first; deny asks in observe mode and refuses in enforce mode. An org floor can only raise it.",
    optionLabels: { default: "Flag", ask: "Ask", deny: "Deny in enforce" },
  },
  {
    key: "security.deps.online_unknown_action",
    component: "security.deps",
    field: "Security.Deps.OnlineUnknownAction",
    label: "Online check did not answer",
    values: ["default", "ask", "deny"],
    defaultValue: "default",
    unit: "",
    help: "What an agent install does when the online package check could not answer in time (rule S-748). Default flags it in observe mode and asks in enforce mode; ask always asks; deny asks in observe mode and refuses in enforce mode.",
    optionLabels: { default: "Flag in observe, ask in enforce", ask: "Ask", deny: "Deny in enforce" },
  },
  {
    key: "security.scanning.quick_scan_budget_s",
    component: "security",
    field: "Security.Scanning.QuickScanBudgetS",
    label: "Commit quick scan budget",
    values: [2, 5, 10, 30],
    defaultValue: 2,
    unit: "s",
    help: "How long the commit gate waits for the quick scan of an agent's commit. A longer budget only waits longer; an agent whose hook timeout is shorter ends the hook first. An org floor can only raise it.",
  },
  {
    key: "security.scanning.max_scan_staleness_min",
    component: "security",
    field: "Security.Scanning.MaxScanStalenessMin",
    label: "Oldest scan the commit gate trusts",
    values: [0, 1440, 240, 60, 30],
    defaultValue: 0,
    unit: "minutes",
    help: "A project whose newest scan is older than this reads as unknown at the commit gate, so an agent's commit or push asks. 0 is off: the posture's own 5 minute expiry is the only freshness check.",
    optionLabels: { "0": "Off" },
  },
  {
    key: "security.scanning.min_blocking_severity",
    component: "security",
    field: "Security.Scanning.MinBlockingSeverity",
    label: "Least severity that blocks",
    values: ["high", "medium", "low"],
    defaultValue: "high",
    unit: "",
    help: "Open findings of this severity and above gate an agent's commit and push. Lower is stricter.",
    optionLabels: { high: "High", medium: "Medium", low: "Low" },
  },
  {
    key: "security.scanning.history_scan_on_enrol",
    component: "security",
    field: "Security.Scanning.HistoryScanOnEnrol",
    label: "History scan once after setting this",
    values: [false, true],
    defaultValue: false,
    unit: "",
    help: "Runs the bounded commit history scan for secrets over every active project once, within 30 minutes of the key being on (the daemon checks at start and every 30 minutes). Local only, no network call. Turning it off and on again runs it again.",
  },
  {
    key: "security.scanning.reflog_hold_max_age_days",
    component: "security",
    field: "Security.Scanning.ReflogHoldMaxAgeDays",
    label: "Reflog hold age cap",
    values: [0, 90, 30, 14],
    defaultValue: 0,
    unit: "days",
    help: "A commit with a secret that only reflog entries older than this reach is no longer held: an agent's push of it is asked, never allowed, and an unknown run names the cap. 0 is no cap.",
    optionLabels: { "0": "None" },
  },
  {
    key: "security.scanning.reflog_hold_max_entries",
    component: "security",
    field: "Security.Scanning.ReflogHoldMaxEntries",
    label: "Reflog hold depth cap",
    values: [0, 1000, 100],
    defaultValue: 0,
    unit: "entries",
    help: "The same, for a commit only reflog entries deeper than this in their ref's reflog reach. 0 is no cap.",
    optionLabels: { "0": "None" },
  },
  {
    key: "security.trust.prelaunch",
    component: "security.trust",
    field: "Security.Trust.Prelaunch",
    label: "Before an agent starts in an unaccepted repository",
    values: ["warn", "ask"],
    defaultValue: "warn",
    unit: "",
    help: "Warn lets the guard mode decide (observe warns, enforce asks). Ask asks before every launch whose repository trust verdict is not clean. It never lowers an org floor.",
    optionLabels: { warn: "Let the guard mode decide", ask: "Always ask" },
  },
  {
    key: "security.mcp.tools",
    component: "security",
    field: "Security.MCP.Tools",
    label: "Security tools for the agent (MCP)",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "Adds the security findings and change check tools to Observer's MCP server while this module is active. MCP itself stays opt-in (observer init).",
  },
  {
    key: "security.statusline.segment",
    component: "security",
    field: "Security.Statusline.Segment",
    label: "Statusline security segment",
    values: [false, true],
    defaultValue: false,
    unit: "",
    help: "Adds the current project's commit-gate state to observer statusline: sec 2! (blocking findings), sec * (unscanned changes), sec ? (unknown).",
  },
  {
    key: "security.notify.critical",
    component: "security",
    field: "Security.Notify.Critical",
    label: "Desktop notification for critical findings",
    values: [false, true],
    defaultValue: false,
    unit: "",
    help: "Shows a desktop notification once for each new critical finding.",
  },
  {
    key: "security.custom.schedule_hours",
    component: "security.scan.custom",
    field: "Security.Custom.ScheduleHours",
    label: "Scheduled custom scanner runs",
    values: [0, 24, 168],
    defaultValue: 0,
    unit: "hours",
    help: "Runs every accepted custom scanner over the ten most recently active projects of the last week once per this many hours, one run at a time. 0 is off. The schedule starts when the daemon starts with custom scanners selected, so after you first select them restart the daemon; while it runs, a change here applies within 15 minutes with no restart.",
  },
  {
    key: "security.custom.pause_on_battery",
    component: "security.scan.custom",
    field: "Security.Custom.PauseOnBattery",
    label: "Pause scheduled scans on battery",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "Holds scheduled custom scanner runs while this machine runs on battery (peripheral batteries such as a mouse do not count), and while its power state cannot be read (macOS today).",
  },
  {
    key: "security.scan.opengrep.post_write",
    component: "security.scan.opengrep",
    field: "Security.Scan.Opengrep.PostWrite",
    label: "Code rules after agent writes",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "Runs the code rules over the files an agent wrote, about 30 seconds after its last write to the project (never inside a hook, never in the commit gate's quick scan). Needs Opengrep installed. Applies within a minute, no restart.",
  },
  {
    key: "security.scan.opengrep.commit_diff",
    component: "security.scan.opengrep",
    field: "Security.Scan.Opengrep.CommitDiff",
    label: "Code rules on each new commit",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "When a project's HEAD moves, scans only what changed since the previous HEAD; its findings reach the commit gate at the agent's next commit or push. Needs Opengrep installed.",
  },
  {
    key: "security.scan.opengrep.schedule_hours",
    component: "security.scan.opengrep",
    field: "Security.Scan.Opengrep.ScheduleHours",
    label: "Scheduled full code scans",
    values: [0, 24, 168],
    defaultValue: 0,
    unit: "hours",
    help: "Runs a full code scan of each project active in the last week once per this many hours, one scan at a time. A full scan can take minutes and about 1.3 GB of memory on a large repository. 0 is off.",
  },
  {
    key: "security.scan.opengrep.pause_on_battery",
    component: "security.scan.opengrep",
    field: "Security.Scan.Opengrep.PauseOnBattery",
    label: "Pause scheduled code scans on battery",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "Holds scheduled full code scans while this machine runs on battery, and while its power state cannot be read.",
  },
  {
    key: "security.scan.opengrep.feed",
    component: "security.scan.opengrep",
    field: "Security.Scan.Opengrep.Feed",
    label: "Rule pack and engine updates",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "Downloads Observer's signed code rule pack and engine pins from superbased.app every 6 hours; it sends nothing about your projects. Off: the installed or built-in pack is used. A managed node uses its org mirror instead.",
  },
  {
    key: "security.feedback.after_write",
    component: "security.feedback",
    field: "Security.Feedback.AfterWrite",
    label: "Feedback to the agent after writes",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "After a write that produced a new high-confidence finding, the agent reads one short templated line per finding (at most three) with its tool result, on agents whose post-tool hook carries text. Built from rule data only, never from file contents. Off silences it.",
  },
];

/** The `security` component's catalog id. */
export const CODE_SECURITY_COMPONENT = "security";

/**
 * codeSecurityCardVisible reports whether the card shows: only when the
 * component state is known and the `security` row is active.
 */
export function codeSecurityCardVisible(view: ComponentsView | null | undefined): boolean {
  if (!view) return false;
  return view.components.some((c) => c.id === CODE_SECURITY_COMPONENT && c.state === "active");
}

/**
 * codeSecurityRows returns the rows whose owning component is active AND
 * selected: `selected` is GET /api/components/state's `security_selected`,
 * the daemon's one opt-in rule (cmd/observer securitySelected). An opt-in
 * child (security.deps, security.scan.custom, ...) is compiled and resolves
 * active on an install with no [components] block, yet it does not run
 * there, so its pickers would edit keys nothing reads: it shows only once a
 * block names it. A child the user skipped adds no picker, and an unknown
 * component state or an unknown selection shows none (fail closed).
 */
export function codeSecurityRows(
  view: ComponentsView | null | undefined,
  selected: readonly string[] | null | undefined,
): readonly CodeSecuritySetting[] {
  if (!view || !selected) return [];
  const active = new Set(view.components.filter((c) => c.state === "active").map((c) => c.id));
  const chosen = new Set(selected);
  return CODE_SECURITY_SETTINGS.filter((r) => active.has(r.component) && chosen.has(r.component));
}

/**
 * codeSecurityValue reads a row's current value from GET /api/config's
 * `config` object, or null when it is not a number the picker offers (an
 * older daemon, a failed load): an unknown value offers no picker.
 */
export function codeSecurityValue(config: unknown, row: CodeSecuritySetting): CodeSecurityValue | null {
  let cur: unknown = config;
  for (const part of row.field.split(".")) {
    if (!cur || typeof cur !== "object") return null;
    cur = (cur as Record<string, unknown>)[part];
  }
  return (typeof cur === "number" || typeof cur === "boolean" || typeof cur === "string") && row.values.includes(cur) ? cur : null;
}

/** codeSecurityOptionLabel is how the picker shows one value. */
export function codeSecurityOptionLabel(row: CodeSecuritySetting, v: CodeSecurityValue): string {
  const named = row.optionLabels?.[String(v)];
  const base = named ?? (typeof v === "boolean" ? (v ? "On" : "Off") : row.unit ? `${v} ${row.unit}` : String(v));
  return v === row.defaultValue ? `${base} (default)` : base;
}

/**
 * codeSecurityParse turns the picker's string value back into the row's
 * value, or null when it is not one of the row's values.
 */
export function codeSecurityParse(row: CodeSecuritySetting, raw: string): CodeSecurityValue | null {
  return row.values.find((v) => String(v) === raw) ?? null;
}

/**
 * codeSecurityPatch is the single-key patch that moves a row from `was` to
 * `next`, or null when nothing changes or `next` is not one of its values.
 */
export function codeSecurityPatch(
  row: CodeSecuritySetting,
  was: CodeSecurityValue | null,
  next: CodeSecurityValue,
): ConfigKeyPatch | null {
  if (was === null || was === next || !row.values.includes(next)) return null;
  return { key: row.key, value: next, was };
}

/** codeSecurityFieldPaths lists the field paths the card edits, so the
 *  schema card below it never renders them a second time. */
export function codeSecurityFieldPaths(): string[] {
  return CODE_SECURITY_SETTINGS.map((r) => r.field);
}
