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

/** A picker value: a number (with a unit), an on/off switch, a named choice
 *  or a preset list (a list-valued key such as security.licenses.deny is
 *  still a picker, over named presets; D-571). */
export type CodeSecurityValue = number | boolean | string | readonly string[];

/** sameValue compares two picker values: lists by their members, in order,
 *  anything else by identity (so "true" is not true). */
function sameValue(a: CodeSecurityValue, b: CodeSecurityValue): boolean {
  if (Array.isArray(a) || Array.isArray(b)) {
    return Array.isArray(a) && Array.isArray(b) && codeSecurityValueKey(a) === codeSecurityValueKey(b);
  }
  return a === b;
}

/** codeSecurityValueKey is a value's comparable and <option> form: a list
 *  joins with ",", the separator `observer config set` reads. */
export function codeSecurityValueKey(v: CodeSecurityValue): string {
  return Array.isArray(v) ? v.join(",") : String(v);
}

// The licence policy's list presets ([security.licenses], security
// coverage gaps plan section 5). Each preset is one shared array, so the
// default is the same object as its picker value.
const LICENCES_NONE: readonly string[] = [];
const LICENCES_DENY_NETWORK: readonly string[] = ["network_copyleft"];
const LICENCES_DENY_COPYLEFT: readonly string[] = ["network_copyleft", "strong_copyleft"];
const LICENCES_DENY_RESTRICTIVE: readonly string[] = ["network_copyleft", "strong_copyleft", "source_available", "proprietary"];
const LICENCES_ALLOW_PERMISSIVE: readonly string[] = ["permissive"];
const LICENCES_ALLOW_WEAK: readonly string[] = ["permissive", "weak_copyleft"];

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
    key: "security.deps.db_source",
    component: "security.deps",
    field: "Security.Deps.DBSource",
    label: "Vulnerability database source",
    values: ["auto", "feed", "upstream", "import"],
    defaultValue: "auto",
    unit: "",
    help: "Where the dependency scanners' OSV databases come from on this node, after the one-time accept. Auto takes SuperBased's signed mirror on superbased.app and falls back to the OSV project's bucket when the mirror is unavailable; feed takes the mirror only; upstream takes the bucket only; import uses only what `observer security scan db import` installed and fetches nothing. A managed node always uses its organization's mirror.",
    optionLabels: { auto: "Signed mirror, then OSV bucket", feed: "Signed mirror only", upstream: "OSV bucket only", import: "Imported only" },
  },
  {
    key: "security.deps.db_fallback_upstream",
    component: "security.deps",
    field: "Security.Deps.DBFallbackUpstream",
    label: "Fall back to the OSV bucket",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "With the source on auto, downloads from the OSV project's bucket (osv-vulnerabilities.storage.googleapis.com) when SuperBased's signed mirror is not published, cannot be verified or cannot be reached. Off: the databases already on disk stay in use until the mirror answers.",
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
    key: "security.deps.provenance",
    component: "security.deps",
    field: "Security.Deps.Provenance",
    label: "Package provenance check",
    values: ["flag", "off"],
    defaultValue: "flag",
    unit: "",
    help: "Flags an agent install of a version that lacks the build provenance earlier versions carried (rule S-757: npm provenance, PyPI attestations), read from the online check's registry answer. Off: no provenance is read and PyPI gets no extra request.",
    optionLabels: { flag: "Flag", off: "Off" },
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
    key: "security.scan.opengrep.taint_pass",
    component: "security.scan.opengrep",
    field: "Security.Scan.Opengrep.TaintPass",
    label: "Intrafile taint pass on full scans",
    values: ["auto", "off"],
    defaultValue: "auto",
    unit: "",
    help: "After a full code scan, runs the taint rules again with Opengrep's intra-file analysis, in batches under their own time, memory and CPU limits. Its results replace the first pass's taint results only for the files a finished batch read in full; a timeout or crash leaves the first pass's results as they were. Unchanged files come from a local cache. Commit and after-write scans never run it.",
    optionLabels: { auto: "On for full scans", off: "Off" },
  },
  {
    key: "security.scan.opengrep.taint_pass_budget_seconds",
    component: "security.scan.opengrep",
    field: "Security.Scan.Opengrep.TaintPassBudgetSeconds",
    label: "Taint pass time budget",
    values: [0, 120, 300, 600, 900, 1800],
    defaultValue: 0,
    unit: "seconds",
    help: "The taint pass's total time. Scaled (the default) gives 60 s to 900 s by the files it must read this time, 300 s for a repository of about 25,000 source files. Batches that finished before the budget ran out are kept.",
    optionLabels: { "0": "Scaled to the repository" },
  },
  {
    key: "security.scan.opengrep.taint_pass_jobs",
    component: "security.scan.opengrep",
    field: "Security.Scan.Opengrep.TaintPassJobs",
    label: "Taint pass parallel jobs",
    values: [0, 1, 4, 8],
    defaultValue: 0,
    unit: "jobs",
    help: "Opengrep's -j for the taint pass. The default, 2, is half the first pass's, so the second pass never takes the whole machine.",
    optionLabels: { "0": "2 jobs" },
  },
  {
    key: "security.scan.opengrep.taint_pass_memory_mib",
    component: "security.scan.opengrep",
    field: "Security.Scan.Opengrep.TaintPassMemoryMiB",
    label: "Taint pass memory cap",
    values: [0, 1024, 4096, 8192],
    defaultValue: 0,
    unit: "MiB",
    help: "The memory cap of each taint pass batch. The default is 2048 MiB, the first pass's cap. A batch over it is stopped and only that batch is lost.",
    optionLabels: { "0": "2048 MiB" },
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
  // [security.assessments] (docs/plans/security-assessments-module-plan-2026-11-13.md
  // section 13.3): what the agent-run security assessments may ask to lift for
  // one run. The module root owns them, so they show while security is active.
  {
    key: "security.assessments.relax_pentest_local",
    component: "security",
    field: "Security.Assessments.RelaxPentestLocal",
    label: "Penetration test may ask for relaxations",
    values: [false, true],
    defaultValue: false,
    unit: "",
    help: "Lets the penetration test offer its relaxation rows in its plan: lifting the guard rule that stops network and vulnerability scanners for one run, and running under the wider sandbox network. Each is a separate tick you or your organization consent to. Off offers nothing. An organization can pin it off.",
  },
  {
    key: "security.assessments.relax_red_team_local",
    component: "security",
    field: "Security.Assessments.RelaxRedTeamLocal",
    label: "Red team exercise may ask for relaxations",
    values: [false, true],
    defaultValue: false,
    unit: "",
    help: "The same switch for the red team exercise. Off offers nothing. An organization can pin it off.",
  },
  {
    key: "security.assessments.scoped_approval",
    component: "security",
    field: "Security.Assessments.ScopedApproval",
    label: "Assessments may ask to lift a guard rule",
    values: [false, true],
    defaultValue: false,
    unit: "",
    help: "Lets an assessment's plan offer to lift the guard rule that stops network and vulnerability scanners for one run: a time-boxed approval on an individual machine, an organization request on a managed one. Off leaves only the network tier row. An organization can pin it off.",
  },
  {
    key: "security.assessments.max_network_tier",
    component: "security",
    field: "Security.Assessments.MaxNetworkTier",
    label: "Widest sandbox network an assessment may run under",
    values: ["proxy_only", "internet"],
    defaultValue: "proxy_only",
    unit: "",
    help: "Model proxy only: an assessment runs only when the sandbox can reach nothing but Observer's model proxy, and offers no wider network. Internet, listed hosts only: it may also run with a wider network, but only when the sandbox settings list the hosts the box may reach. A sandbox that shares this machine's network is never an option. An organization can pin it to the model proxy only.",
    optionLabels: { proxy_only: "Model proxy only", internet: "Internet, listed hosts only" },
  },
  {
    key: "security.assessments.relaxation_scope",
    component: "security",
    field: "Security.Assessments.RelaxationScope",
    label: "What a guard approval for a run covers",
    values: ["session", "project"],
    defaultValue: "session",
    unit: "",
    help: "Session: the approval covers the run's own terminal session and takes effect once the session is identified. Project: it covers every session in the project the moment the run starts, including unsandboxed ones, until the run ends. A node managed by an organization always uses session.",
    optionLabels: { session: "This run's session", project: "Every session in the project" },
  },
  {
    key: "security.assessments.relaxation_max_minutes",
    component: "security",
    field: "Security.Assessments.RelaxationMaxMinutes",
    label: "Longest a relaxation may last",
    values: [15, 30, 60, 120, 240],
    defaultValue: 60,
    unit: "minutes",
    help: "The hard cap of a guard approval's life, and the window an organization request asks for. The approval itself is renewed every few minutes while the run's terminal is open and ends with it. A node managed by an organization caps this at 60; the organization can lower it further.",
  },
  {
    key: "security.assessments.report_to_org",
    component: "security",
    field: "Security.Assessments.ReportToOrg",
    label: "Report assessment runs to my organization",
    values: [false, true],
    defaultValue: false,
    unit: "",
    help: "Individual machines only. On: each run writes a short audit record (started, ended, imported) that goes up with the guard events when this machine is enrolled and pushing. A node managed by an organization always reports. Off keeps the run record on this machine.",
  },
  // The depth work's run keys (docs/plans/security-assessments-depth-plan-2026-11-14.md
  // section 12): the time box per kind, what happens at the deadline, the git
  // snapshots and how long a run's stored evidence is kept.
  {
    key: "security.assessments.time_box_threat_model_minutes",
    component: "security",
    field: "Security.Assessments.TimeBoxThreatModelMinutes",
    label: "Time box of a threat model run",
    values: [30, 45, 60, 90, 120],
    defaultValue: 60,
    unit: "minutes",
    help: "How long the agent is told it has for a threat model, and when the run row says it is over its time box. The agent checks the clock itself; Observer does not stop it unless you choose that below. A longer time box than the relaxation window means an approval ends first. An organization can lower it.",
  },
  {
    key: "security.assessments.time_box_pentest_local_minutes",
    component: "security",
    field: "Security.Assessments.TimeBoxPentestLocalMinutes",
    label: "Time box of a penetration test run",
    values: [15, 30, 45, 60, 90, 120],
    defaultValue: 45,
    unit: "minutes",
    help: "The same for the penetration test of your own app. An organization can lower it.",
  },
  {
    key: "security.assessments.time_box_red_team_local_minutes",
    component: "security",
    field: "Security.Assessments.TimeBoxRedTeamLocalMinutes",
    label: "Time box of a red team run",
    values: [15, 30, 45, 60, 90, 120],
    defaultValue: 60,
    unit: "minutes",
    help: "The same for the red team exercise. An organization can lower it.",
  },
  {
    key: "security.assessments.time_box_action",
    component: "security",
    field: "Security.Assessments.TimeBoxAction",
    label: "At the time box",
    values: ["stop_button", "auto_close"],
    defaultValue: "stop_button",
    unit: "",
    help: "Stop button: when a run is over its time box the run row offers Stop and nothing is closed for you. Close the terminal: Observer closes the run's terminal at the deadline and records that it did. An organization can pin the second.",
    optionLabels: { stop_button: "Show a Stop button", auto_close: "Close the terminal" },
  },
  {
    key: "security.assessments.boundary_audit",
    component: "security",
    field: "Security.Assessments.BoundaryAudit",
    label: "Check git state around a run",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "Takes a snapshot of the project's git state (HEAD, branch, stash, refs, changed and untracked files) when a run starts and again when its terminal closes, and says whether anything changed in between. It sees only what git sees: files git ignores (.env, local databases, caches, node_modules) are not covered, and a change you make yourself in the same window is counted. It never says the project is clean. Off skips both snapshots and the run row says not checked. Changed and untracked files are compared by their content, up to 400 paths; one that cannot be read in time, is a folder or is over 32 MiB is not compared, and the row then says it was only partly checked.",
  },
  {
    key: "security.assessments.evidence_retention_days",
    component: "security",
    field: "Security.Assessments.EvidenceRetentionDays",
    label: "How long a run's stored evidence is kept",
    values: [0, 30, 90, 180],
    defaultValue: 0,
    unit: "days",
    help: "A run's checked model and git snapshots are stored on this machine beside the run record. The default keeps them for as long as the run is in the record (the newest 100 runs). A number of days deletes older ones. You can delete one run's stored evidence at any time from its row.",
    optionLabels: { "0": "As long as the run is listed" },
  },
  // The model contract's keys (depth plan W1c, section 12): what a threat model
  // or penetration test is asked for, and what the import takes from the checked
  // model. Each default is the widest or the recommended choice.
  {
    key: "security.assessments.tm_frameworks",
    component: "security",
    field: "Security.Assessments.TMFrameworks",
    label: "Threat model frameworks",
    values: ["all", "stride", "stride_linddun", "stride_ai"],
    defaultValue: "all",
    unit: "",
    help: "Which frameworks the agent is asked to work through and the check holds the model to. STRIDE is always included. LINDDUN is asked for on data flows that carry personal data, and the two OWASP AI frameworks only when the project is an AI application, so choosing them costs nothing for a project they do not fit.",
    optionLabels: {
      all: "STRIDE, LINDDUN and the AI frameworks",
      stride: "STRIDE only",
      stride_linddun: "STRIDE and LINDDUN",
      stride_ai: "STRIDE and the AI frameworks",
    },
  },
  {
    key: "security.assessments.tm_method_extras",
    component: "security",
    field: "Security.Assessments.TMMethodExtras",
    label: "Threat model abuse cases and attack trees",
    values: ["both", "abuse_cases", "attack_trees", "neither"],
    defaultValue: "both",
    unit: "",
    help: "An abuse case is a short story of how an attacker would use a threat. An attack tree breaks one attacker goal into steps. When on, the agent is asked for them for the highest-risk threats and the check says when they are missing. Off asks for neither and says nothing about their absence.",
    optionLabels: {
      both: "Abuse cases and attack trees",
      abuse_cases: "Abuse cases only",
      attack_trees: "Attack trees only",
      neither: "Neither",
    },
  },
  {
    key: "security.assessments.pt_categories",
    component: "security",
    field: "Security.Assessments.PTCategories",
    label: "Penetration test categories",
    values: ["all", "web_no_api", "api_only", "auth_access"],
    defaultValue: "all",
    unit: "",
    help: "Which of the twelve test categories (information gathering, configuration, identity, authentication, authorization, sessions, input validation, error handling, cryptography, business logic, client side, API) the agent is asked to cover and the run's coverage count includes. A narrower choice makes a shorter, more focused test; the categories left out are not counted as gaps.",
    optionLabels: {
      all: "All twelve categories",
      web_no_api: "Web application without API testing",
      api_only: "API only",
      auth_access: "Authentication and access control only",
    },
  },
  {
    key: "security.assessments.prompt_selfcheck",
    component: "security",
    field: "Security.Assessments.PromptSelfcheck",
    label: "Ask the agent to check its own result",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "The task tells the agent to run Observer's own check on its assessment file, which prints what Observer would refuse, so the agent can fix its file before it finishes instead of you finding out afterwards. It needs the observer command on the agent's path; if it is missing the agent is told to say so and carry on. Off leaves it out of the task.",
  },
  {
    key: "security.assessments.import_min_band",
    component: "security",
    field: "Security.Assessments.ImportMinBand",
    label: "Lowest risk band that is imported",
    values: ["low", "medium", "high", "critical"],
    defaultValue: "low",
    unit: "",
    help: "When you import a checked model, each missing mitigation or reported weakness that has a location in the code becomes a flag-only finding. This is the lowest inherent risk band that is imported; items under it stay in the model and the run row counts them. The band is a rough ranking from the agent's own likelihood and impact, not a measured score.",
    optionLabels: { low: "Low and above (every one with a location)", medium: "Medium and above", high: "High and above", critical: "Critical only" },
  },
  {
    key: "security.assessments.findings_cap",
    component: "security",
    field: "Security.Assessments.FindingsCap",
    label: "Most findings imported per run",
    values: [0, 25, 50, 100, 250, 500],
    defaultValue: 0,
    unit: "findings",
    help: "No cap imports every finding that has a location, highest risk first, but the importer keeps at most 1,000 results per run whatever this is: a run with more is counted and the run row says how many were past that limit. A number keeps only that many, highest risk first, and the row says how many it left out.",
    optionLabels: { "0": "No cap (the importer keeps at most 1,000 per run)" },
  },
  {
    key: "security.assessments.rerun_dedup",
    component: "security",
    field: "Security.Assessments.RerunDedup",
    label: "Re-runs update findings already imported",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "On, an imported finding is identified by what it is about (the weakness kind, the file and the code) and not by the run, so running the same assessment again updates the findings you already have instead of adding a second copy. Off keeps each run's findings apart, with the run id in each one's name.",
  },
  {
    key: "security.assessments.report_validation_to_org",
    component: "security",
    field: "Security.Assessments.ReportValidationToOrg",
    label: "Report that a model was checked",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "For a run that is reported to your organization (a managed node always reports), also write one content-free row when its model is checked: the run, the result word and counts, never a finding, a path or any text from the model. Off leaves the check out of the report; the launch and end rows are unchanged.",
  },
  {
    key: "security.assessments.ref_match_window_lines",
    component: "security",
    field: "Security.Assessments.RefMatchWindowLines",
    label: "How close the cited text must be to the cited line",
    values: [1, 3, 5, 10, 20, 50],
    defaultValue: 5,
    unit: "lines",
    help: "A reference reads found only when the text the agent quoted is on a code line within this many lines of the first line it cited (1 is the cited line itself). A reference whose text is further away, even inside a long cited range, reads exists with nothing matched near the cited line and earns no credit as found. A larger window is more forgiving of an agent that is a few lines off; it never makes an absent text found.",
  },
  {
    key: "security.assessments.model_max_mib",
    component: "security",
    field: "Security.Assessments.ModelMaxMiB",
    label: "Largest assessment.json that is read",
    values: [1, 2, 4, 8, 16, 32],
    defaultValue: 4,
    unit: "MiB",
    help: "A file over this size is refused whole, with the cap named, and nothing in it is read. This size is the only thing that bounds how many threats, findings or missing mitigations a model may hold (the importer separately keeps at most 1,000 results per run). A larger value reads a larger model and uses more memory when it is checked and shown.",
  },
  {
    key: "security.assessments.ref_budget_files",
    component: "security",
    field: "Security.Assessments.RefBudgetFiles",
    label: "Most files the reference check opens",
    values: [100, 250, 500, 1000, 2000, 5000],
    defaultValue: 500,
    unit: "files",
    help: "Checking a model's references opens each distinct project file it cites. Past this many files, the remaining references read not checked (never found), the check is marked partial and the run row says how many were not checked.",
  },
  {
    key: "security.assessments.ref_budget_mib",
    component: "security",
    field: "Security.Assessments.RefBudgetMiB",
    label: "Most data the reference check reads",
    values: [32, 64, 128, 256, 512, 1024],
    defaultValue: 128,
    unit: "MiB",
    help: "The reference check reads at most this much of the project's files in all. A file that would go past it is not opened, and its references read not checked, with the check marked partial. One file over 4 MiB is never read, whatever this is.",
  },
  {
    key: "security.assessments.ref_budget_seconds",
    component: "security",
    field: "Security.Assessments.RefBudgetSeconds",
    label: "How long the reference check looks",
    values: [5, 10, 20, 30, 60, 120],
    defaultValue: 10,
    unit: "seconds",
    help: "The reference check stops looking at project files after this long. References it had not reached read not checked, and the check is marked partial; nothing is reported found that was not looked at.",
  },
  // Threat-model and penetration-test depth (depth plan W3 and W4): what the
  // task carries about the project, what a pen test box does about .env files,
  // and how many requests it may send.
  {
    key: "security.assessments.grounding",
    component: "security",
    field: "Security.Assessments.Grounding",
    label: "Project facts in the task",
    values: ["full", "without_findings", "off"],
    defaultValue: "full",
    unit: "",
    help: "The task can carry a short digest of facts Observer read from the project's own files: its languages and frameworks, the dependencies by role (authentication, crypto, database, web framework, AI libraries), infrastructure files, an API spec, how its development server starts and, optionally, the rule ids and places of its open findings. The digest is fenced as data from the repository, never as instructions, and capped at 6 KiB. It never contains file contents, secrets or environment values. Without findings leaves the open findings out; Off sends no digest (the plan still reads the folder, for the scope picker and the AI-application step).",
    optionLabels: {
      full: "Facts and open findings",
      without_findings: "Facts only, without open findings",
      off: "No digest",
    },
  },
  {
    key: "security.assessments.workspace_secret_mode",
    component: "security",
    field: "Security.Assessments.WorkspaceSecretMode",
    label: "Environment files in a penetration test",
    values: ["mask", "warn", "refuse", "off"],
    defaultValue: "mask",
    unit: "",
    help: "A penetration test runs in a sandbox over your live project folder, and the sandbox can read the .env files there. Warn says how many there are at the top level of the folder in the plan and tells the agent not to open them; that is a prompt rule, not a barrier. Hide asks the sandbox to hide them inside the box, by file name (.env and its variants, certificate and key files, SSH identity files, package-registry and netrc credentials), as a snapshot taken when the box starts: a file created later, a link to a secret and a secret in a file with another name stay readable, so the agent is still told not to open them. Only a sandbox that can hide files does it; for any other, or when the launcher cannot report what was hidden, it acts as Warn and the plan says why. Once the run has started its row says how many files were hidden and how many places could not be covered. Refuse stops the launch while Observer's findings already hold an open secret in an environment or key file at any depth, and also when the findings cannot be read; it reads findings, not files, so a project nobody has scanned is not covered. Off says nothing. An organization can pin Refuse.",
    optionLabels: {
      mask: "Hide them in the sandbox (acts as Warn where the sandbox cannot)",
      warn: "Warn in the plan and tell the agent",
      refuse: "Refuse while a secret is open in one",
      off: "Say nothing",
    },
  },
  {
    key: "security.assessments.pentest_request_budget",
    component: "security",
    field: "Security.Assessments.PentestRequestBudget",
    label: "Most requests a penetration test sends",
    values: [200, 600, 1200, 2400],
    defaultValue: 600,
    unit: "requests",
    help: "The agent is told to count its requests to the target and to stop and say so at this number. With the request helper on, the helper also refuses requests past it; a request the agent makes another way, with curl or its own code, is not counted. An organization can lower it.",
  },
  {
    key: "security.assessments.pentest_pace_rps",
    component: "security",
    field: "Security.Assessments.PentestPaceRPS",
    label: "Fastest a penetration test sends requests",
    values: [1, 2, 5, 10],
    defaultValue: 5,
    unit: "requests per second",
    help: "The agent is told not to send more than this many requests to the target per second. With the request helper on, the helper also paces the requests that go through it; a request made another way is not paced. An organization can lower it.",
  },
  {
    key: "security.assessments.probe_helper",
    component: "security",
    field: "Security.Assessments.ProbeHelper",
    label: "Request helper for penetration tests",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "On, Observer writes a small Python request helper and its settings file into a penetration test's or red team run's folder before the agent starts (the plan lists both files). The agent sends its requests to the target through it; it sends to the target address only, applies the request budget and pace, and logs each request, which is how a finding can read Helper log matches. The log is a file the agent can write, so a match is not proof. Observer compares the helper's files with what it wrote when the run is checked, not while it ran. The helper hides header values by name and obvious tokens by shape, and keeps the first 1 KiB of a response (best effort, so a response text further in cannot back a finding). The helper needs python3 in the sandbox; without it the helper is left out and the plan says so. Off writes nothing, and every finding's evidence reads No log. An organization can pin it off, never on.",
  },
  {
    key: "security.assessments.display_redaction",
    component: "security",
    field: "Security.Assessments.DisplayRedaction",
    label: "Hide recognised secrets when showing a report or model",
    values: [true, false],
    defaultValue: true,
    unit: "",
    help: "On, a secret Observer recognises (a key, a token, a private key block) is hidden in the text of the report and the model as this dashboard shows them, and the view says how many places were hidden. Names that link one part of the model to another, and file paths, are shown as written, because hiding part of one would break the links between them. The files in your project are always as the agent wrote them, and the free text in the checked copy Observer keeps was already cleaned when it was stored, whatever this says. Off shows the stored text as it is. Observer recognises known secret shapes only, so a hidden secret is not a promise that none is left.",
  },
  {
    key: "security.assessments.diagram_max_nodes",
    component: "security",
    field: "Security.Assessments.DiagramMaxNodes",
    label: "Most nodes the data-flow diagram source draws",
    values: [20, 40, 60, 100, 150, 200],
    defaultValue: 60,
    unit: "nodes",
    help: "A threat model can hold any number of components. The diagram source keeps the ones that take part in the most flows, up to this many, so it stays readable when you paste it into a Mermaid viewer; the view says how many nodes and flows were left out. The model, its tables and its matrix are never cut by this.",
  },
  {
    key: "security.assessments.diagram_label_chars",
    component: "security",
    field: "Security.Assessments.DiagramLabelChars",
    label: "Longest label in the data-flow diagram source",
    values: [20, 40, 60, 80, 120],
    defaultValue: 40,
    unit: "characters",
    help: "A component, actor, zone or flow name longer than this is cut in the diagram source so each box stays small when you paste it into a Mermaid viewer; the view says how many labels were cut. The full names are always in the model's tables.",
  },
  {
    key: "security.licenses.deny",
    component: "security.deps",
    field: "Security.Licenses.Deny",
    label: "Denied dependency licences",
    values: [LICENCES_NONE, LICENCES_DENY_NETWORK, LICENCES_DENY_COPYLEFT, LICENCES_DENY_RESTRICTIVE],
    defaultValue: LICENCES_NONE,
    unit: "",
    help: "A dependency whose licence falls in a denied class is a finding (medium at most, never blocking a commit). A licence with an OR choice is denied only when every choice is. Other SPDX ids can be set with observer config set.",
    optionLabels: {
      "": "None",
      network_copyleft: "Network copyleft (AGPL, SSPL)",
      "network_copyleft,strong_copyleft": "Network and strong copyleft (AGPL, GPL)",
      "network_copyleft,strong_copyleft,source_available,proprietary": "Copyleft, source-available and proprietary",
    },
  },
  {
    key: "security.licenses.allow",
    component: "security.deps",
    field: "Security.Licenses.Allow",
    label: "Allowed dependency licences",
    values: [LICENCES_NONE, LICENCES_ALLOW_PERMISSIVE, LICENCES_ALLOW_WEAK],
    defaultValue: LICENCES_NONE,
    unit: "",
    help: "When set, a dependency whose licence is outside these classes is a finding (medium at most, never blocking a commit). Other SPDX ids can be set with observer config set.",
    optionLabels: {
      "": "Everything not denied",
      permissive: "Permissive only (MIT, BSD, Apache-2.0)",
      "permissive,weak_copyleft": "Permissive and weak copyleft (MPL, LGPL)",
    },
  },
  {
    key: "security.licenses.unknown",
    component: "security.deps",
    field: "Security.Licenses.Unknown",
    label: "Unrecognized dependency licences",
    values: ["ignore", "flag"],
    defaultValue: "ignore",
    unit: "",
    help: "Flag records a low finding for each dependency whose declared licence Observer does not recognize, or that declares none.",
    optionLabels: { ignore: "Ignore", flag: "Flag" },
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
  const parts = row.field.split(".");
  for (const [i, part] of parts.entries()) {
    if (!cur || typeof cur !== "object") return null;
    const obj = cur as Record<string, unknown>;
    // A list key the daemon holds as nil arrives as null: it is the empty list.
    if (i === parts.length - 1 && Array.isArray(row.defaultValue) && part in obj && obj[part] === null) return row.values.find((v) => Array.isArray(v) && v.length === 0) ?? null;
    cur = obj[part];
  }
  if (Array.isArray(cur)) {
    // A list matches a preset by its members, in order; a hand-set list
    // that is no preset offers no picker.
    if (!cur.every((x) => typeof x === "string")) return null;
    const key = codeSecurityValueKey(cur as string[]);
    return row.values.find((v) => Array.isArray(v) && codeSecurityValueKey(v) === key) ?? null;
  }
  return (typeof cur === "number" || typeof cur === "boolean" || typeof cur === "string") && row.values.includes(cur) ? cur : null;
}

/** SINGULAR_UNIT is each plural unit a numeric picker value is labelled with, in the singular, for the value 1 ("1 line", never "1 lines"). A unit that is an abbreviation (KiB, MiB, ms, s) is not in it and reads the same at any count. */
const SINGULAR_UNIT: Readonly<Record<string, string>> = {
  days: "day",
  hours: "hour",
  minutes: "minute",
  seconds: "second",
  lines: "line",
  files: "file",
  nodes: "node",
  jobs: "job",
  entries: "entry",
  findings: "finding",
  requests: "request",
  characters: "character",
  "requests per second": "request per second",
};

/** codeSecurityOptionLabel is how the picker shows one value. */
export function codeSecurityOptionLabel(row: CodeSecuritySetting, v: CodeSecurityValue): string {
  const key = codeSecurityValueKey(v);
  const named = row.optionLabels?.[key];
  const plain = Array.isArray(v) ? (v.length ? v.join(", ") : "None") : String(v);
  const unit = v === 1 ? (SINGULAR_UNIT[row.unit] ?? row.unit) : row.unit;
  const base = named ?? (typeof v === "boolean" ? (v ? "On" : "Off") : unit ? `${plain} ${unit}` : plain);
  return key === codeSecurityValueKey(row.defaultValue) ? `${base} (default)` : base;
}

/**
 * codeSecurityParse turns the picker's string value back into the row's
 * value, or null when it is not one of the row's values.
 */
export function codeSecurityParse(row: CodeSecuritySetting, raw: string): CodeSecurityValue | null {
  return row.values.find((v) => codeSecurityValueKey(v) === raw) ?? null;
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
  if (was === null || sameValue(was, next) || !row.values.some((v) => sameValue(v, next))) return null;
  return { key: row.key, value: next, was };
}

/** codeSecurityFieldPaths lists the field paths the card edits, so the
 *  schema card below it never renders them a second time. */
export function codeSecurityFieldPaths(): string[] {
  return CODE_SECURITY_SETTINGS.map((r) => r.field);
}
