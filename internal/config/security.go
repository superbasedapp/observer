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
	// Reach is [security.reach]: the reachability checks' caps (today the
	// Go source check's, component security.reach.go).
	Reach SecurityReachConfig `toml:"reach"`
	// Assessments is [security.assessments]: what the agent-run security
	// assessments may ask to lift for one run (plan section 13.3).
	Assessments SecurityAssessmentsConfig `toml:"assessments"`
	// Licenses is [security.licenses]: the project licence policy
	// (component security.deps, security_licenses.go).
	Licenses SecurityLicensesConfig `toml:"licenses"`
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
	// Image is [security.scan.image]: the image OS package driver (lane
	// OS-2 T, security_image.go).
	Image SecurityImageScanConfig `toml:"image"`
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
	// TaintPass is the intrafile taint pass of a full scan: after the core
	// pass, the pack's taint-mode rules run again alone with Opengrep's
	// --taint-intrafile, in batches under their own budget, and their
	// results replace the core pass's taint-rule results only for the files
	// a finished batch read in full. "auto" (the default; empty reads as
	// auto) or "off". Diff, commit and post-write scans never run it.
	TaintPass string `toml:"taint_pass"`
	// TaintPassBudgetSeconds is the taint pass's wall budget; 0, the
	// default, scales it with the files it must read (60 s to 900 s, 300 s
	// for about 25,000 files). Otherwise 30 to 3600.
	TaintPassBudgetSeconds int `toml:"taint_pass_budget_seconds"`
	// TaintPassJobs is the taint pass's Opengrep -j; 0, the default, is 2.
	// At most 8.
	TaintPassJobs int `toml:"taint_pass_jobs"`
	// TaintPassMemoryMiB caps each taint pass batch's memory; 0, the
	// default, is 2048. Otherwise 512 to 8192.
	TaintPassMemoryMiB int `toml:"taint_pass_memory_mib"`
}

// validateSecurityOpengrepTaint checks the taint pass keys of
// [security.scan.opengrep] (0 is each number's default).
func validateSecurityOpengrepTaint(c SecurityOpengrepConfig) error {
	switch {
	case c.TaintPass != "" && c.TaintPass != "auto" && c.TaintPass != "off":
		return fmt.Errorf("config: security.scan.opengrep.taint_pass %q is not auto or off", c.TaintPass)
	case c.TaintPassBudgetSeconds != 0 && (c.TaintPassBudgetSeconds < 30 || c.TaintPassBudgetSeconds > 3600):
		return fmt.Errorf("config: security.scan.opengrep.taint_pass_budget_seconds %d not 0 or 30 to 3600", c.TaintPassBudgetSeconds)
	case c.TaintPassJobs < 0 || c.TaintPassJobs > 8:
		return fmt.Errorf("config: security.scan.opengrep.taint_pass_jobs %d not 0 to 8", c.TaintPassJobs)
	case c.TaintPassMemoryMiB != 0 && (c.TaintPassMemoryMiB < 512 || c.TaintPassMemoryMiB > 8192):
		return fmt.Errorf("config: security.scan.opengrep.taint_pass_memory_mib %d not 0 or 512 to 8192", c.TaintPassMemoryMiB)
	}
	return nil
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
	// Provenance is the build-provenance check of an agent install
	// (security coverage-gaps plan 2026-11-13 section 4, rule S-757), one
	// of SecurityDepsProvenance: "flag" (the default) reads, for an
	// answered online check, whether the version installed lacks the
	// provenance an earlier version carried (npm provenance, PyPI
	// attestations) and flags it; "off" makes no PyPI provenance request
	// and sets no provenance state.
	Provenance string `toml:"provenance"`
	// DBSource is where an INDIVIDUAL node's OSV databases (the dependency
	// scanners' local copy) come from, one of SecurityDepsDBSources: "auto"
	// (the default) takes SuperBased's signed mirror on superbased.app and
	// falls back to the OSV project's bucket when the mirror is unavailable
	// and DBFallbackUpstream allows it; "feed" takes the mirror only (a
	// failure keeps the last-known-good, reported); "upstream" takes the
	// bucket only; "import" takes only what `observer security scan db
	// import <dir>` installed and makes no request. A managed node ignores
	// it: its databases come from its org mirror only. Read once per
	// refresh (cmd/observer depsSourcePlan), so a change needs no restart.
	DBSource string `toml:"db_source"`
	// DBFallbackUpstream lets db_source = "auto" fall back to the OSV
	// bucket when the signed mirror is not published, not verifiable or
	// unreachable. Default true; false keeps the last-known-good instead.
	DBFallbackUpstream bool `toml:"db_fallback_upstream"`
	// Match is the package lookup mode (OS and CI vulnerability scanning
	// plan sections 13.9 and 13.10, lane RM-2), one of
	// SecurityDepsMatchModes: "local" matches against the downloaded
	// databases; "remote" downloads no database and looks every ecosystem
	// up at SuperBased (hash-prefix shards, never a package name); "both"
	// matches locally where a database is installed and looks up only the
	// rest. "" (the default) is not chosen: an install whose database
	// accept is recorded reads "local", a fresh one reads "not scanned"
	// (lookup_not_chosen) until the developer picks on the Privacy page's
	// Package lookup card or with `observer security lookup mode`. Remote
	// and both need the developer's own signed remote-lookup consent
	// (osv-remote-consent.json), never an agent's (R-165). A managed node
	// ignores it: its organization decides. Re-read at every scan.
	Match string `toml:"match"`
	// RemoteVia is how a remote lookup is answered, one of
	// SecurityDepsRemoteVia: "shards" (the default and the only value this
	// build serves). "service" is reserved for a SuperBased matcher service
	// (plan section 13.9, M2) and refused by validation.
	RemoteVia string `toml:"remote_via"`
	// RemoteKinds are the package kinds a remote lookup covers, a subset of
	// SecurityDepsRemoteKinds: "language" (lockfile packages) and "actions"
	// (GitHub Actions). nil or empty means every kind this build serves;
	// "os" (an image's OS packages) is reserved and refused by validation
	// until remote lookup serves images.
	RemoteKinds []string `toml:"remote_kinds"`
	// RemotePrivate is whether a remote lookup sends private and internal
	// package names too, one of SecurityDepsRemotePrivate: "withhold" (the
	// default: a name not provably public is never looked up, and the run
	// is never clean) or "send", which needs its own signed consent
	// (osv-remote-private-consent.json).
	RemotePrivate string `toml:"remote_private"`
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

// SecurityDepsProvenance is the picker of [security.deps].provenance.
var SecurityDepsProvenance = []string{"flag", "off"}

// SecurityDepsDBSources is the picker of [security.deps].db_source.
var SecurityDepsDBSources = []string{"auto", "feed", "upstream", "import"}

// SecurityDepsMatchModes is the picker of [security.deps].match ("" is not
// chosen).
var SecurityDepsMatchModes = []string{"local", "remote", "both"}

// SecurityDepsRemoteVia is the picker of [security.deps].remote_via in this
// build; SecurityDepsRemoteViaReserved are values a later build may serve.
var (
	SecurityDepsRemoteVia         = []string{"shards"}
	SecurityDepsRemoteViaReserved = []string{"service"}
)

// SecurityDepsRemoteKinds is the vocabulary of [security.deps].remote_kinds
// in this build; SecurityDepsRemoteKindsReserved are kinds a later build
// may serve.
var (
	SecurityDepsRemoteKinds         = []string{"language", "actions"}
	SecurityDepsRemoteKindsReserved = []string{"os"}
)

// SecurityDepsRemotePrivate is the picker of [security.deps].remote_private.
var SecurityDepsRemotePrivate = []string{"withhold", "send"}

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
		Retention:   SecurityRetentionConfig{Days: 365},
		Deps:        SecurityDepsConfig{Online: true, InstallWaitMS: 1500, MinPackageAgeH: 72, IndexDownload: true, UnknownAction: "default", OnlineUnknownAction: "default", Provenance: "flag", DBSource: "auto", DBFallbackUpstream: true, RemoteVia: "shards", RemotePrivate: "withhold"},
		Secrets:     SecuritySecretsConfig{WriteCheck: true, CommitCheck: true, PostWriteCapKiB: 256},
		MCP:         SecurityMCPConfig{Tools: true},
		Custom:      SecurityCustomConfig{ScheduleHours: 0, PauseOnBattery: true},
		Feedback:    SecurityFeedbackConfig{AfterWrite: true},
		Scan:        SecurityScanConfig{Opengrep: SecurityOpengrepConfig{PostWrite: true, CommitDiff: true, ScheduleHours: 0, PauseOnBattery: true, Feed: true, TaintPass: "auto"}},
		Scanning:    SecurityScanningConfig{QuickScanBudgetS: 2, MinBlockingSeverity: "high"},
		Trust:       SecurityTrustConfig{Prelaunch: "warn"},
		Licenses:    DefaultSecurityLicensesConfig(),
		Assessments: DefaultSecurityAssessmentsConfig(),
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
	return validateSecurityOpengrepTaint(c)
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
	if !slices.Contains(SecurityDepsProvenance, d.Provenance) {
		return fmt.Errorf("config: security.deps.provenance %q not in %v", d.Provenance, SecurityDepsProvenance)
	}
	if !slices.Contains(SecurityDepsDBSources, d.DBSource) {
		return fmt.Errorf("config: security.deps.db_source %q not in %v", d.DBSource, SecurityDepsDBSources)
	}
	if d.Match != "" && !slices.Contains(SecurityDepsMatchModes, d.Match) {
		return fmt.Errorf("config: security.deps.match %q not in %v", d.Match, SecurityDepsMatchModes)
	}
	if d.RemoteVia != "" && !slices.Contains(SecurityDepsRemoteVia, d.RemoteVia) {
		if slices.Contains(SecurityDepsRemoteViaReserved, d.RemoteVia) {
			return fmt.Errorf("config: security.deps.remote_via %q is not in this build (only %v)", d.RemoteVia, SecurityDepsRemoteVia)
		}
		return fmt.Errorf("config: security.deps.remote_via %q not in %v", d.RemoteVia, SecurityDepsRemoteVia)
	}
	for _, k := range d.RemoteKinds {
		if slices.Contains(SecurityDepsRemoteKinds, k) {
			continue
		}
		if slices.Contains(SecurityDepsRemoteKindsReserved, k) {
			return fmt.Errorf("config: security.deps.remote_kinds %q is not in this build (only %v)", k, SecurityDepsRemoteKinds)
		}
		return fmt.Errorf("config: security.deps.remote_kinds %q not in %v", k, SecurityDepsRemoteKinds)
	}
	if d.RemotePrivate != "" && !slices.Contains(SecurityDepsRemotePrivate, d.RemotePrivate) {
		return fmt.Errorf("config: security.deps.remote_private %q not in %v", d.RemotePrivate, SecurityDepsRemotePrivate)
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
		{Key: "security.deps.db_source", Class: SettingLocal, Values: "auto (signed mirror, then the OSV bucket) / feed / upstream / import", Default: "auto (an individual node; a managed node uses its org mirror)", NodeHome: "Code security"},
		{Key: "security.deps.db_fallback_upstream", Class: SettingLocal, Values: "On / Off", Default: "On", NodeHome: "Code security"},
		// The package lookup posture (lane RM-2, plan section 13.10): the
		// individual developer's to set, from the Privacy page; a managed
		// node's organization decides (no remote toggle on the node).
		{Key: "security.deps.match", Class: SettingLocal, Values: "local (download the databases) / remote (SuperBased lookup) / both (local first, remote for the gaps)", Default: "not chosen (an install with the database accept reads local)", NodeHome: "Privacy"},
		{Key: "security.deps.remote_via", Class: SettingLocal, Values: "shards (service reserved)", Default: "shards", NodeHome: "Privacy"},
		{Key: "security.deps.remote_kinds", Class: SettingLocal, Values: "language, actions (os reserved)", Default: "every kind this build serves", NodeHome: "Privacy"},
		{Key: "security.deps.remote_private", Class: SettingLocal, Values: "withhold / send", Default: "withhold", NodeHome: "Privacy"},
		{Key: "security.deps.unknown_action", Class: SettingPolicy, Values: "default (flag) / ask / deny", Default: "default", NodeHome: "Code security"},
		{Key: "security.deps.online_unknown_action", Class: SettingPolicy, Values: "default (flag in observe, ask in enforce) / ask / deny", Default: "default", NodeHome: "Code security"},
		{Key: "security.deps.provenance", Class: SettingPolicy, Values: "flag / off", Default: "flag", NodeHome: "Code security"},
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
		{Key: "security.scan.opengrep.taint_pass", Class: SettingLocal, Values: "auto / off", Default: "auto (full scans only, while security.scan.opengrep is selected and Opengrep is installed)", NodeHome: "Code security"},
		{Key: "security.scan.opengrep.taint_pass_budget_seconds", Class: SettingLocal, Values: "0 (scaled) / 30 to 3600", Default: "0 (scaled, 60 s to 900 s)", NodeHome: "Code security"},
		{Key: "security.scan.opengrep.taint_pass_jobs", Class: SettingLocal, Values: "0 (2) / 1 to 8", Default: "0 (2)", NodeHome: "Code security"},
		{Key: "security.scan.opengrep.taint_pass_memory_mib", Class: SettingLocal, Values: "0 (2048) / 512 to 8192", Default: "0 (2048)", NodeHome: "Code security"},
		// The Go source check's caps (3b-src, security_reach.go): shown on the
		// Scanners card's Go source check row, set in the settings editor or
		// with `observer config set` (the developer's; R-165).
		{Key: "security.reach.go.source_memory_mib", Class: SettingLocal, Values: "0 (12288) / 512 to 65536", Default: "0 (12288; GOMEMLIMIT at 90 %)", NodeHome: "Code security > Scanners"},
		{Key: "security.reach.go.source_timeout_seconds", Class: SettingLocal, Values: "0 (1200) / 60 to 7200", Default: "0 (1200 s per go.mod)", NodeHome: "Code security > Scanners"},
		{Key: "security.reach.go.source_max_modules", Class: SettingLocal, Values: "0 (16) / 1 to 64", Default: "0 (16 go.mod files)", NodeHome: "Code security > Scanners"},
		{Key: "security.feedback.after_write", Class: SettingPolicy, Values: "On / Off", Default: "On (acts only while security.feedback is selected, which is off by default)", NodeHome: "Code security"},
		// The one share key outside [security] (plan 6.5 "Share findings with
		// the org", lane SEC-E2): local only, never raised remotely; a
		// managed node follows the managed pull's finding_share instead. Its
		// picker is on the Privacy page (lane SEC-H2).
		{Key: "org_client.share.security", Class: SettingPolicy, Values: "Off / Posture / Findings", Default: "Posture", NodeHome: "Privacy"},
	}, slices.Concat(iacSecuritySettings(), imageSecuritySettings(), licenseSecuritySettings(), assessmentsSecuritySettings())...) // lanes GATES-SEC (security_iac.go), OS-2 T (security_image.go), licences (security_licenses.go) and assessments (security_assess.go)
}
