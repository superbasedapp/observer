package dashapi

import "context"

// SecurityScanStep is one scanner the Code security page's "Scan now" can
// run on this node: a selected security.scan.* driver with its manual run.
// Ready false names why the step is skipped (the component is not
// selected, the engine is not installed), so the page lists it honestly
// rather than dropping it.
type SecurityScanStep struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`
}

// SecurityScanResult outcomes beyond a scan run's own (clean, findings,
// unknown, not_scanned, failed).
const (
	// SecurityScanSkipped is a step that did not start (not ready).
	SecurityScanSkipped = "skipped"
	// SecurityScanBusy is a step whose machine-wide scan lease another
	// scan (the daemon's loop, a CLI run) holds.
	SecurityScanBusy = "busy"
)

// SecurityScanResult is one step's outcome on one project.
type SecurityScanResult struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Outcome  string `json:"outcome"`
	Reason   string `json:"reason,omitempty"`
	Findings int    `json:"findings"`
	New      int    `json:"new"`
	// Online is set only on the step that can match online, when the job
	// asked for online checks: SecurityScanOnlineChecked when the online
	// matching ran, otherwise the reason it did not (an online gate reason
	// such as online_checks_off for this project, or
	// SecurityScanOnlineNeedsSCALIBR), so a run is never shown as checked
	// online when only the local databases were read.
	Online string `json:"online,omitempty"`
	// StartedAt (RFC3339) and DurationMS are when the dashboard's job
	// started the step and how long it ran; set by the job, not the seam.
	StartedAt  string `json:"started_at,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

// SecurityScanOptions are one "Scan now" job's options, handed to every
// step of it; a step that has no use for an option ignores it. The zero
// value is the scan the page ran before the options existed.
type SecurityScanOptions struct {
	// Online asks the dependency step to also match online, as `observer
	// security scan --online` does and behind the same gate (decision P-1
	// of docs/plans/dashboard-cli-parity-plan-2026-11-06.md): the
	// ecosystems no local database covers against api.osv.dev (the
	// organization's relay on a managed node), and git submodules by their
	// pinned commit ids.
	Online bool
}

// The online check's words beyond the online gate's own reasons
// (online_checks_off, disclosure_not_shown).
const (
	// SecurityScanOnlineChecked: the online matching ran on the project.
	SecurityScanOnlineChecked = "checked"
	// SecurityScanOnlineNeedsSCALIBR: only the linked SCALIBR driver
	// (security.scan.scalibr) matches online; osv-scanner reads the local
	// databases only.
	SecurityScanOnlineNeedsSCALIBR = "online_needs_scalibr"
	// SecurityScanOnlineUnavailable: the gate was open but no online
	// matcher could be built for the project.
	SecurityScanOnlineUnavailable = "online_unavailable"
)

// SecurityScanOnline is the online dependency check's state as the scan
// dialog shows it, read under the organization-wide floor (a project's own
// section may still forbid it there; that project's step result then says
// so). Step is the scanner step the option applies to. Open reports that
// the step may match online on this node; otherwise Reason is the first
// closed row (online_checks_off, disclosure_not_shown,
// SecurityScanOnlineNeedsSCALIBR). Relay reports a managed node: its
// online matching goes to its organization's relay, and its git submodules
// are not checked online.
type SecurityScanOnline struct {
	Step   string `json:"step"`
	Open   bool   `json:"open"`
	Reason string `json:"reason,omitempty"`
	Relay  bool   `json:"relay,omitempty"`
}

// SecurityExtractor is one row of the dependency scan's closed extractor
// table (the SCALIBR facade's, internal/secscan/scalibrfacade
// extractorTable) as the Code security page's Coverage tab lists it: its
// kind (lockfile, manifest, artifact), its OSV ecosystem and the files it
// reads, in the table's own words.
type SecurityExtractor struct {
	Kind      string `json:"kind"`
	Ecosystem string `json:"ecosystem"`
	Files     string `json:"files"`
}

// SecurityScanNow is the dashboard seam of the Code security page's "Scan
// now" (wired from cmd/observer/security_scan_now.go). Steps lists the
// scanners and whether each can run; Scan runs one step on the project at
// root through the same manual run its CLI verb calls (`observer security
// code scan`, `security iac scan`, `security scan`, `security
// actionlint`), recorded through the one findings writer. A nil
// SecurityScanNow leaves only the dashboard's own history step.
//
// Extractors, when set, lists the linked dependency extractors (the
// dashboard may not import the facade itself: only the scan command and
// the scan child may, tests/invariant/security_scan_egress_test.go); nil,
// or a build without SCALIBR, leaves the Coverage tab's file lists empty.
//
// Scan takes the job's options (SecurityScanOptions). Online, when set,
// reports the online dependency check's state for the scan dialog; nil (a
// build without the dependency scanners) offers no online option, and a
// request asking for one is refused.
type SecurityScanNow struct {
	Steps      func(ctx context.Context) []SecurityScanStep
	Scan       func(ctx context.Context, root, step string, opts SecurityScanOptions) SecurityScanResult
	Extractors func() []SecurityExtractor
	Online     func(ctx context.Context) SecurityScanOnline
}
