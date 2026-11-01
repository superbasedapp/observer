package config

import (
	"fmt"
	"slices"
)

// SecurityConfig is the [security] block, the security pillar's module
// root (component `security`; security pillar plan section 6.5). It is
// core residue (section 4.3): the struct loads before component state is
// known, and it is validated by the component-aware path, so a bad value
// in an inactive module's section is set aside, never a load error. The
// children's sections ([security.trust], [security.secrets], ...) are
// added by the phases that build them.
type SecurityConfig struct {
	// Retention is [security.retention].
	Retention SecurityRetentionConfig `toml:"retention"`
	// Deps is [security.deps], the install gate (component security.deps,
	// Phase D1).
	Deps SecurityDepsConfig `toml:"deps"`
	// Secrets is [security.secrets] (component security.secrets).
	Secrets SecuritySecretsConfig `toml:"secrets"`
	// MCP is [security.mcp]: the module's MCP tools (a local experience
	// setting).
	MCP SecurityMCPConfig `toml:"mcp"`
	// Statusline is [security.statusline]: the statusline's security
	// segment (a local experience setting).
	Statusline SecurityStatuslineConfig `toml:"statusline"`
	// Notify is [security.notify]: the desktop notification (a local
	// experience setting).
	Notify SecurityNotifyConfig `toml:"notify"`
	// Custom is [security.custom]: scheduled runs of the custom scanners
	// (component security.scan.custom, lane sec-custom2).
	Custom SecurityCustomConfig `toml:"custom"`
	// Feedback is [security.feedback]: feedback to the agent after writes
	// (component security.feedback, lane sec-h).
	Feedback SecurityFeedbackConfig `toml:"feedback"`
	// Scan is [security.scan]: per-driver settings of the scanners that
	// have their own (today [security.scan.opengrep]).
	Scan SecurityScanConfig `toml:"scan"`
	// Scanning is [security.scanning]: the node's own value on the
	// security.scanning floor axes that had no node setting before lane
	// LEFT-SEC, plus the commit hold's reflog caps. Every key defaults to
	// the built-in behaviour it replaces, and an org floor in force only
	// raises it (security_scanning_wire.go securityFloorRows).
	Scanning SecurityScanningConfig `toml:"scanning"`
	// Trust is [security.trust]: the node's own pre-launch trust step
	// (component security.trust).
	Trust SecurityTrustConfig `toml:"trust"`
	// CommitGateFloor is not a setting: the org floor require.commit_gate
	// (managed only) writes "quick_scan" here through the floors' read seam
	// (cmd/observer securityFloorsAppliedAt, lane SEC-P4 decision 9); the
	// daemon signs it into the project's posture, and S-791 to S-794 then
	// take the decision table's managed-floor cells. "" (or "ask") is the
	// node's own commit gate.
	CommitGateFloor string `toml:"-"`
	// PrelaunchTrustFloor is not a setting: the org floor
	// require.prelaunch_trust writes "ask" or "refuse" here through the same
	// seam; the daemon signs it into the project's posture and a launch's
	// trust step is raised to it, never lowered ("" or "warn": the guard
	// mode decides alone).
	PrelaunchTrustFloor string `toml:"-"`
}

// SecurityScanningConfig is [security.scanning] (security plan 4.8 and
// 4.9, lane LEFT-SEC milestone 1). Each picker offers the built-in value
// and stricter ones only; the reflog caps default to none.
type SecurityScanningConfig struct {
	// QuickScanBudgetS is how long the commit gate's quick scan may run, in
	// seconds: one of SecurityQuickScanBudgetsS. Default 2, the fixed
	// individual budget it replaces (D-764 Q21). A longer budget only waits
	// longer; a vendor whose registered hook timeout is shorter ends the
	// hook first (docs/code-security.md).
	QuickScanBudgetS int `toml:"quick_scan_budget_s"`
	// MaxScanStalenessMin reads a project whose newest scan is older than
	// this many minutes as unknown at the commit gate: one of
	// SecurityMaxScanStalenessMin. 0, the default, is off (the posture's
	// own 5 minute expiry is then the only freshness check).
	MaxScanStalenessMin int `toml:"max_scan_staleness_min"`
	// MinBlockingSeverity is the least severity that blocks: one of
	// SecurityMinBlockingSeverities. Default "high".
	MinBlockingSeverity string `toml:"min_blocking_severity"`
	// HistoryScanOnEnrol runs the bounded history scan of every active
	// project once, within 30 minutes of it being on (the daemon checks
	// at start and every 30 minutes; never a network call). Default false.
	HistoryScanOnEnrol bool `toml:"history_scan_on_enrol"`
	// ReflogHoldMaxAgeDays caps how long a reflog entry keeps a commit
	// held: a commit only reflog entries older than this reach is no longer
	// held, its push is asked (never allowed) and an unknown run names the
	// cap. One of SecurityReflogHoldMaxAgeDays; 0, the default, is none.
	ReflogHoldMaxAgeDays int `toml:"reflog_hold_max_age_days"`
	// ReflogHoldMaxEntries caps how deep in a ref's reflog an entry still
	// holds a commit, the same way. One of SecurityReflogHoldMaxEntries;
	// 0, the default, is none.
	ReflogHoldMaxEntries int `toml:"reflog_hold_max_entries"`
}

// The [security.scanning] pickers.
var (
	SecurityQuickScanBudgetsS     = []int{2, 5, 10, 30}
	SecurityMaxScanStalenessMin   = []int{0, 1440, 240, 60, 30}
	SecurityMinBlockingSeverities = []string{"high", "medium", "low"}
	SecurityReflogHoldMaxAgeDays  = []int{0, 90, 30, 14}
	SecurityReflogHoldMaxEntries  = []int{0, 1000, 100}
)

// SecurityTrustConfig is [security.trust] (component security.trust).
type SecurityTrustConfig struct {
	// Prelaunch is the node's own least pre-launch trust step, the
	// node-local twin of the org floor require.prelaunch_trust: "warn"
	// (the default: the guard mode decides) or "ask" (ask before every
	// launch whose trust verdict is not clean). It never lowers an org
	// floor.
	Prelaunch string `toml:"prelaunch"`
}

// SecurityTrustPrelaunch is the picker of [security.trust].prelaunch.
var SecurityTrustPrelaunch = []string{"warn", "ask"}

// SecurityScanConfig is [security.scan].
type SecurityScanConfig struct {
	// Opengrep is [security.scan.opengrep] (component
	// security.scan.opengrep, lane sec-g2).
	Opengrep SecurityOpengrepConfig `toml:"opengrep"`
	Trivy    SecurityTrivyConfig    `toml:"trivy"` // security.scan.trivy, lane GATES-SEC (security_iac.go)
	Kics     SecurityKICSConfig     `toml:"kics"`  // security.scan.kics, lane GATES-SEC (security_iac.go)
}

// SecurityOpengrepConfig is [security.scan.opengrep]: when the code rules
// run and where their content comes from (security pillar plan sections
// 5.5 and 8.5). Every key acts only while the component is selected and
// Opengrep is installed, feed included: with no engine installed nothing
// is fetched, whatever feed says (plans decision log P-061). The daemon
// re-reads them on every pass, so a change applies within a minute, no
// restart needed. All are local
// experience settings; an agent can never change one (guard rule R-165).
type SecurityOpengrepConfig struct {
	// PostWrite scans the files an agent wrote, debounced, a short while
	// after its last write to the project. Default true.
	PostWrite bool `toml:"post_write"`
	// CommitDiff scans what each new commit changed (diff-scoped, against
	// the previous HEAD) when the daemon sees a project's HEAD move, so
	// its findings reach the commit gate at the agent's next commit or
	// push. Default true.
	CommitDiff bool `toml:"commit_diff"`
	// ScheduleHours runs a full scan of each project active in the last
	// week once per this many hours. One of SecurityOpengrepScheduleHours;
	// 0, the default, is off.
	ScheduleHours int `toml:"schedule_hours"`
	// PauseOnBattery holds scheduled runs while the machine runs on
	// battery or its power state cannot be read. Default true.
	PauseOnBattery bool `toml:"pause_on_battery"`
	// Feed downloads the signed observer-code rule pack and engine
	// manifest from superbased.app on an individual node (plain GETs of
	// public files; nothing about your projects is sent), every 6 hours and
	// only while an Opengrep engine is installed (P-061). Default true. A
	// managed node takes both from its org mirror whatever this says.
	Feed bool `toml:"feed"`
}

// SecurityOpengrepScheduleHours are the schedule picker's steps: off,
// daily, weekly.
var SecurityOpengrepScheduleHours = []int{0, 24, 168}

// SecurityFeedbackConfig is [security.feedback] (security pillar plan
// sections 5.11 (c) and 6.5 "Feedback to the agent after writes"). The
// component itself is off unless a [components] block selects it; this
// key lets a developer silence it while it is selected.
type SecurityFeedbackConfig struct {
	// AfterWrite puts up to three templated lines about the session's new
	// high-confidence findings into the agent's post-tool reply, on hosts
	// whose post-tool hook carries context. Default true (it only acts
	// while security.feedback is selected).
	AfterWrite bool `toml:"after_write"`
}

// SecurityCustomConfig is [security.custom]: scheduled runs of the
// accepted custom scanners (security pillar plan section 4.4: background
// only, paused on battery by default). Both are local experience settings.
type SecurityCustomConfig struct {
	// ScheduleHours runs every accepted custom scanner over each project
	// active in the last week once per this many hours, one run at a time.
	// One of SecurityCustomScheduleHours; 0, the default, is off. The
	// running daemon re-reads it every 15 minutes, so a change takes effect
	// within 15 minutes, no restart needed.
	ScheduleHours int `toml:"schedule_hours"`
	// PauseOnBattery holds scheduled runs while the machine runs on
	// battery, and while its power state cannot be read. Default true.
	// Re-read every 15 minutes like ScheduleHours.
	PauseOnBattery bool `toml:"pause_on_battery"`
}

// SecurityCustomScheduleHours are the schedule picker's steps: off, daily,
// weekly.
var SecurityCustomScheduleHours = []int{0, 24, 168}

// SecurityDepsConfig is [security.deps]: the install gate and its online
// lane (security pillar plan sections 5.4, 8.3 and 6.5).
type SecurityDepsConfig struct {
	// Online is "Online package and vulnerability checks" (Q14, D-759):
	// on by default wherever the component is active, disclosed at first
	// run before any query; off means the offline lists only. A managed
	// node sends its queries only to its org relay whatever this says.
	Online bool `toml:"online"`
	// InstallWaitMS is the install-gate wait, one of
	// SecurityDepsInstallWaitMS (default 1500).
	InstallWaitMS int `toml:"install_wait_ms"`
	// MinPackageAgeH is the minimum package age in hours (S-743), one of
	// SecurityDepsMinPackageAgeH (default 72; 0 switches the check off).
	MinPackageAgeH int `toml:"min_package_age_h"`
	// IndexDownload is the off switch of the signed package index download
	// (the malicious and popular lists) from superbased.app (operator
	// ruling PT-19, decision log P-036): true, the default, fetches it
	// every 6 hours wherever the component is active, without the online
	// checks' consent, because the download names none of the developer's
	// packages; false stops the download, and the checks then run with
	// whatever index is on disk (said in `observer security deps status`,
	// the doctor row and the Package checks card). The running daemon
	// re-reads it, so a change needs no restart. Read in one place,
	// depsIndexDownloadAllowed (cmd/observer).
	IndexDownload bool `toml:"index_download"`
	// UnknownAction is what an agent install of a package the index does
	// not know (S-744) does: "default" (the rule's own decision, a flag),
	// "ask" or "deny" (ask in observe, deny in enforce). One of
	// SecurityDepsUnknownActions.
	UnknownAction string `toml:"unknown_action"`
	// OnlineUnknownAction is the same for an install the online check
	// could not answer in time (S-748; its own decision is flag in
	// observe, ask in enforce).
	OnlineUnknownAction string `toml:"online_unknown_action"`
	// ScannerSources is not a setting: the org floor
	// allow.scanner_sources writes the allowed advisory database sources
	// here through the floors' read seam (cmd/observer
	// securityFloorsApplied; lane SEC-E4). nil allows every source.
	ScannerSources []string `toml:"-"`
	// MaxAdvisoryDBAgeH is not a setting: the org floor
	// require.max_advisory_db_age_h writes the oldest advisory data (the
	// package index, the OSV exports) still used, in hours, through the same
	// seam. 0 means each content kind's own age floor.
	MaxAdvisoryDBAgeH int `toml:"-"`
}

// SecurityDepsInstallWaitMS is the picker of [security.deps].install_wait_ms.
var SecurityDepsInstallWaitMS = []int{500, 1500, 3000}

// SecurityDepsUnknownActions is the picker of [security.deps].unknown_action
// and online_unknown_action: today's rule decision, then stricter ones.
var SecurityDepsUnknownActions = []string{"default", "ask", "deny"}

// SecurityDepsMinPackageAgeH is the picker of
// [security.deps].min_package_age_h.
var SecurityDepsMinPackageAgeH = []int{0, 24, 72, 168}

// SecurityMCPConfig is [security.mcp] (security pillar plan sections 6.1
// and 6.5, lane sec-c3).
type SecurityMCPConfig struct {
	// Tools registers get_security_findings and check_change on
	// `observer serve` while the module is active. MCP itself stays opt-in
	// (observer init writes the client entry); this only says whether the
	// module adds its tools to it. Default true.
	Tools bool `toml:"tools"`
}

// SecurityStatuslineConfig is [security.statusline] (lane sec-c3).
type SecurityStatuslineConfig struct {
	// Segment adds the "security" segment to `observer statusline`: the
	// current project's commit-gate posture from the signed posture file
	// ("sec 2!" blocking findings, "sec *" unscanned changes, "sec ?"
	// unknown), read with no daemon call. Default false.
	Segment bool `toml:"segment"`
}

// SecurityNotifyConfig is [security.notify] (lane sec-c3).
type SecurityNotifyConfig struct {
	// Critical shows a desktop notification, through the guard notifier,
	// once for each new critical finding. Default false.
	Critical bool `toml:"critical"`
}

// SecuritySecretsConfig is [security.secrets], the secret checks of
// component security.secrets (security pillar plan section 6.5, lane
// sec-c3). Each switch only narrows what runs; turning one off never
// relaxes the commit gate's decision on findings already open.
type SecuritySecretsConfig struct {
	// WriteCheck is "Secret check before writes": while true the pillar's
	// pre-write rule S-721 judges a write's proposed content in the hook.
	// Off: S-721 is not composed, and a written secret is still found by
	// the post-write seam and the commit gate. Default true.
	WriteCheck bool `toml:"write_check"`
	// CommitCheck is "Secret check on commits": while true the commit
	// scanner records the secrets every landed commit adds as commit
	// findings (S-723). Off: landed commits are not scanned for secrets;
	// the commit gate's quick scan of an agent's own commit is a separate
	// setting and still runs. Default true.
	CommitCheck bool `toml:"commit_check"`
	// PostWriteCapKiB is "Largest file scanned after a write": one of
	// SecurityPostWriteCapsKiB. The hook's cap is fixed at 16 KiB and is not
	// a setting [JSP-2]. Default 256.
	PostWriteCapKiB int `toml:"postwrite_cap_kib"`
}

// SecurityPostWriteCapsKiB is the picker of [security.secrets].postwrite_cap_kib.
var SecurityPostWriteCapsKiB = []int{64, 256}

// SecurityRetentionConfig is [security.retention]: closed and suppressed
// findings older than Days are deleted; open findings never are (section
// 4.6).
type SecurityRetentionConfig struct {
	// Days is one of SecurityRetentionDays. Default 365, matching guard's
	// audit retention.
	Days int `toml:"days"`
}

// SecurityRetentionDays is the picker of [security.retention].days.
var SecurityRetentionDays = []int{90, 180, 365, 730}

// DefaultSecurityConfig is the [security] default.
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		Retention: SecurityRetentionConfig{Days: 365},
		Deps:      SecurityDepsConfig{Online: true, InstallWaitMS: 1500, MinPackageAgeH: 72, IndexDownload: true, UnknownAction: "default", OnlineUnknownAction: "default"},
		Secrets:   SecuritySecretsConfig{WriteCheck: true, CommitCheck: true, PostWriteCapKiB: 256},
		MCP:       SecurityMCPConfig{Tools: true},
		Custom:    SecurityCustomConfig{ScheduleHours: 0, PauseOnBattery: true},
		Feedback:  SecurityFeedbackConfig{AfterWrite: true},
		Scan:      SecurityScanConfig{Opengrep: SecurityOpengrepConfig{PostWrite: true, CommitDiff: true, ScheduleHours: 0, PauseOnBattery: true, Feed: true}},
		Scanning:  SecurityScanningConfig{QuickScanBudgetS: 2, MinBlockingSeverity: "high"},
		Trust:     SecurityTrustConfig{Prelaunch: "warn"},
	}
}

// validateSecurity checks the [security] block's root keys.
func validateSecurity(s SecurityConfig) error {
	if !slices.Contains(SecurityRetentionDays, s.Retention.Days) {
		return fmt.Errorf("config: security.retention.days %d not in %v", s.Retention.Days, SecurityRetentionDays)
	}
	if !slices.Contains(SecurityPostWriteCapsKiB, s.Secrets.PostWriteCapKiB) {
		return fmt.Errorf("config: security.secrets.postwrite_cap_kib %d not in %v", s.Secrets.PostWriteCapKiB, SecurityPostWriteCapsKiB)
	}
	return nil
}

// validateSecurityScanning checks [security.scanning].
func validateSecurityScanning(c SecurityScanningConfig) error {
	ints := []struct {
		key  string
		v    int
		vals []int
	}{
		{"quick_scan_budget_s", c.QuickScanBudgetS, SecurityQuickScanBudgetsS},
		{"max_scan_staleness_min", c.MaxScanStalenessMin, SecurityMaxScanStalenessMin},
		{"reflog_hold_max_age_days", c.ReflogHoldMaxAgeDays, SecurityReflogHoldMaxAgeDays},
		{"reflog_hold_max_entries", c.ReflogHoldMaxEntries, SecurityReflogHoldMaxEntries},
	}
	for _, k := range ints {
		if !slices.Contains(k.vals, k.v) {
			return fmt.Errorf("config: security.scanning.%s %d not in %v", k.key, k.v, k.vals)
		}
	}
	if !slices.Contains(SecurityMinBlockingSeverities, c.MinBlockingSeverity) {
		return fmt.Errorf("config: security.scanning.min_blocking_severity %q not in %v", c.MinBlockingSeverity, SecurityMinBlockingSeverities)
	}
	return nil
}

// validateSecurityTrust checks [security.trust].
func validateSecurityTrust(c SecurityTrustConfig) error {
	if !slices.Contains(SecurityTrustPrelaunch, c.Prelaunch) {
		return fmt.Errorf("config: security.trust.prelaunch %q not in %v", c.Prelaunch, SecurityTrustPrelaunch)
	}
	return nil
}

// validateSecurityCustom checks [security.custom].
func validateSecurityCustom(c SecurityCustomConfig) error {
	if !slices.Contains(SecurityCustomScheduleHours, c.ScheduleHours) {
		return fmt.Errorf("config: security.custom.schedule_hours %d not in %v", c.ScheduleHours, SecurityCustomScheduleHours)
	}
	return nil
}

// validateSecurityOpengrep checks [security.scan.opengrep].
func validateSecurityOpengrep(c SecurityOpengrepConfig) error {
	if !slices.Contains(SecurityOpengrepScheduleHours, c.ScheduleHours) {
		return fmt.Errorf("config: security.scan.opengrep.schedule_hours %d not in %v", c.ScheduleHours, SecurityOpengrepScheduleHours)
	}
	return nil
}

// validateSecurityDeps checks [security.deps].
func validateSecurityDeps(d SecurityDepsConfig) error {
	if !slices.Contains(SecurityDepsInstallWaitMS, d.InstallWaitMS) {
		return fmt.Errorf("config: security.deps.install_wait_ms %d not in %v", d.InstallWaitMS, SecurityDepsInstallWaitMS)
	}
	if !slices.Contains(SecurityDepsMinPackageAgeH, d.MinPackageAgeH) {
		return fmt.Errorf("config: security.deps.min_package_age_h %d not in %v", d.MinPackageAgeH, SecurityDepsMinPackageAgeH)
	}
	if !slices.Contains(SecurityDepsUnknownActions, d.UnknownAction) {
		return fmt.Errorf("config: security.deps.unknown_action %q not in %v", d.UnknownAction, SecurityDepsUnknownActions)
	}
	if !slices.Contains(SecurityDepsUnknownActions, d.OnlineUnknownAction) {
		return fmt.Errorf("config: security.deps.online_unknown_action %q not in %v", d.OnlineUnknownAction, SecurityDepsUnknownActions)
	}
	return nil
}

// SettingClass is the security settings contract's class (section 6.5).
type SettingClass string

// The SettingClass values.
const (
	// SettingPolicy is settable on the node and, for managed nodes, from
	// the admin dashboard.
	SettingPolicy SettingClass = "P"
	// SettingLocal is a local experience setting; the admin sets only a
	// default.
	SettingLocal SettingClass = "U"
	// SettingConsent is a repository-write consent, node only.
	SettingConsent SettingClass = "C"
)

// SecuritySetting is one row of the settings contract (section 6.5): every
// [security.*] key has a row with its class, picker values, default and
// node-dashboard home. A test fails when a key lacks one.
type SecuritySetting struct {
	Key      string
	Class    SettingClass
	Values   string
	Default  string
	NodeHome string
}

// SecuritySettings is the settings contract for the keys built so far.
func SecuritySettings() []SecuritySetting {
	return append([]SecuritySetting{
		{Key: "security.retention.days", Class: SettingPolicy, Values: "90 / 180 / 365 / 730", Default: "365", NodeHome: "Code security"},
		{Key: "security.deps.online", Class: SettingPolicy, Values: "On / Off", Default: "On", NodeHome: "Code security > Package checks"},
		{Key: "security.deps.install_wait_ms", Class: SettingPolicy, Values: "500 / 1500 / 3000", Default: "1500", NodeHome: "Code security"},
		{Key: "security.deps.index_download", Class: SettingPolicy, Values: "On / Off", Default: "On", NodeHome: "Code security"},
		{Key: "security.deps.min_package_age_h", Class: SettingPolicy, Values: "0 / 24 / 72 / 168", Default: "72", NodeHome: "Code security"},
		{Key: "security.secrets.write_check", Class: SettingPolicy, Values: "On / Off", Default: "On", NodeHome: "Code security"},
		{Key: "security.secrets.commit_check", Class: SettingPolicy, Values: "On / Off", Default: "On", NodeHome: "Code security"},
		{Key: "security.secrets.postwrite_cap_kib", Class: SettingPolicy, Values: "256 / 64 (scans less; an individual node only, a managed node keeps 256; the hook's 16 KiB is fixed)", Default: "256", NodeHome: "Code security"},
		{Key: "security.deps.unknown_action", Class: SettingPolicy, Values: "default (flag) / ask / deny", Default: "default", NodeHome: "Code security"},
		{Key: "security.deps.online_unknown_action", Class: SettingPolicy, Values: "default (flag in observe, ask in enforce) / ask / deny", Default: "default", NodeHome: "Code security"},
		{Key: "security.scanning.quick_scan_budget_s", Class: SettingPolicy, Values: "2 / 5 / 10 / 30", Default: "2", NodeHome: "Code security"},
		{Key: "security.scanning.max_scan_staleness_min", Class: SettingPolicy, Values: "0 (off) / 1440 / 240 / 60 / 30", Default: "0 (off)", NodeHome: "Code security"},
		{Key: "security.scanning.min_blocking_severity", Class: SettingPolicy, Values: "high / medium / low", Default: "high", NodeHome: "Code security"},
		{Key: "security.scanning.history_scan_on_enrol", Class: SettingPolicy, Values: "Off / On", Default: "Off", NodeHome: "Code security"},
		{Key: "security.scanning.reflog_hold_max_age_days", Class: SettingPolicy, Values: "0 (none) / 90 / 30 / 14", Default: "0 (none)", NodeHome: "Code security"},
		{Key: "security.scanning.reflog_hold_max_entries", Class: SettingPolicy, Values: "0 (none) / 1000 / 100", Default: "0 (none)", NodeHome: "Code security"},
		{Key: "security.trust.prelaunch", Class: SettingPolicy, Values: "warn (the guard mode decides) / ask", Default: "warn", NodeHome: "Code security"},
		{Key: "security.mcp.tools", Class: SettingLocal, Values: "On / Off", Default: "On (when MCP and the module are active)", NodeHome: "Code security"},
		{Key: "security.statusline.segment", Class: SettingLocal, Values: "Off / On", Default: "Off", NodeHome: "Code security"},
		{Key: "security.notify.critical", Class: SettingLocal, Values: "Off / On", Default: "Off", NodeHome: "Code security"},
		{Key: "security.custom.schedule_hours", Class: SettingLocal, Values: "0 (off) / 24 / 168", Default: "0 (off)", NodeHome: "Code security"},
		{Key: "security.custom.pause_on_battery", Class: SettingLocal, Values: "On / Off", Default: "On", NodeHome: "Code security"},
		{Key: "security.scan.opengrep.post_write", Class: SettingLocal, Values: "On / Off", Default: "On (acts only while security.scan.opengrep is selected and Opengrep is installed)", NodeHome: "Code security"},
		{Key: "security.scan.opengrep.commit_diff", Class: SettingLocal, Values: "On / Off", Default: "On (acts only while security.scan.opengrep is selected and Opengrep is installed)", NodeHome: "Code security"},
		{Key: "security.scan.opengrep.schedule_hours", Class: SettingLocal, Values: "0 (off) / 24 / 168", Default: "0 (off)", NodeHome: "Code security"},
		{Key: "security.scan.opengrep.pause_on_battery", Class: SettingLocal, Values: "On / Off", Default: "On", NodeHome: "Code security"},
		{Key: "security.scan.opengrep.feed", Class: SettingLocal, Values: "On / Off", Default: "On (an individual node; a managed node uses its org mirror)", NodeHome: "Code security"},
		{Key: "security.feedback.after_write", Class: SettingPolicy, Values: "On / Off", Default: "On (acts only while security.feedback is selected, which is off by default)", NodeHome: "Code security"},
		// The one share key outside [security] (plan 6.5 "Share findings with
		// the org", lane SEC-E2): local only, never raised remotely; a
		// managed node follows the managed pull's finding_share instead. Its
		// picker is on the Privacy page (lane SEC-H2).
		{Key: "org_client.share.security", Class: SettingPolicy, Values: "Off / Posture / Findings", Default: "Off", NodeHome: "Privacy"},
	}, iacSecuritySettings()...) // lane GATES-SEC (security_iac.go)
}
