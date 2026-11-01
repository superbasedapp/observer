package hookctx

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Security is Event.Security, the security pillar's hook-side facts
// (security pillar plan docs/plans/security-pillar-plan-2026-10-19.md
// section 4.7 item 2 and section 4.8). The type is owned by internal/policy
// beside the guard Event its Match closures read (the type contract of lane
// sec-a); this alias keeps the seam's API, so what Fill produces is exactly
// what the guard event carries.
type Security = policy.Security

// PostureState is one of the five project states the hook derives in
// section 4.8 of the security pillar plan.
type PostureState = policy.SecurityPosture

// The posture states, re-exported from internal/policy.
const (
	// PostureAbsent: the security module is inactive, or no pillar child is
	// in the active pack set. No pillar rule is composed.
	PostureAbsent = policy.SecurityPostureAbsent
	// PostureUnknown: the posture is missing, does not verify, has expired,
	// was rolled back, is over its cap, names other policy or bundle
	// versions, has overflowed, or has no entry for the project. Never
	// treated as clean (plan principle PR14). Fill also uses it when the
	// posture provider fails.
	PostureUnknown = policy.SecurityPostureUnknown
	// PostureDirty: agent activity since the last clean quick scan has not
	// been scanned.
	PostureDirty = policy.SecurityPostureDirty
	// PostureBlocking: open, new, high-confidence blocking findings.
	PostureBlocking = policy.SecurityPostureBlocking
	// PostureClean: nothing known and nothing unscanned.
	PostureClean = policy.SecurityPostureClean
)

// CommitForm is the parsed commit the quick scan covers (section 4.8: the
// plain form, `-a`, pathspecs, `--amend`; a push is the git_push sink). It
// is the git_commit classifier's output (policy.GitWrite).
type CommitForm = policy.GitWrite

// QuickScanRequest asks for the section 4.8 quick scan at a git_commit or
// git_push sink: the project, the parsed commit form and the dirty counter
// value the hook saw.
type QuickScanRequest struct {
	ProjectRoot string
	Form        CommitForm
	DirtySeen   uint64
	// OnlyWhen, when set, is asked with the Security facts the same Fill
	// read just before: false skips the scan (no answer, no Issue), so a
	// commit in a project whose state no rule reads the scan for (clean,
	// absent) costs no daemon round trip. Never sent over the wire.
	OnlyWhen func(Security) bool
}

// QuickScanVerdict is the quick scan's answer (section 4.8).
type QuickScanVerdict = policy.QuickScanVerdict

// The quick-scan verdicts, re-exported from internal/policy.
const (
	// QuickScanClean: the diff the commit would record is clean.
	QuickScanClean = policy.QuickScanClean
	// QuickScanBlocking: the scan found a blocking finding.
	QuickScanBlocking = policy.QuickScanBlocking
	// QuickScanUnknown: over budget, daemon busy, git unavailable, or the
	// scanner failed. Fill also uses it when the provider fails.
	QuickScanUnknown = policy.QuickScanUnknown
)

// QuickScanResult is a quick scan's answer. The verdict is what the commit
// gate rules decide on; Findings are the blocking hits it found (never a
// matched value); DirtyCovered is the dirty counter value a clean answer
// covered, which the daemon records in the posture so the next commit is
// clean without a wait.
type QuickScanResult struct {
	Verdict      QuickScanVerdict
	Findings     []policy.SecurityHit
	DirtyCovered uint64
}

// InstallRequest asks for the install-time package check (security plan
// section 5.4) of one event: an install command or a manifest edit. The
// provider reads the event; the seam passes nothing else.
type InstallRequest struct {
	ProjectRoot string
	Event       *policy.Event
}

// InstallResult is the install check's answer: one check per package, and
// the two flags the rules read.
type InstallResult struct {
	Checks         []policy.InstallCheck
	CustomRegistry bool
	Manifest       bool
}

// InstallChecker is the install check provider.
type InstallChecker func(ctx context.Context, req InstallRequest) (InstallResult, error)

// InstallCheckFailed is the reason code of the synthetic check recorded
// when the provider fails, panics or overruns: unknown, never clean.
const InstallCheckFailed = "install_check_failed"
