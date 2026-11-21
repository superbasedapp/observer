package dashapi

import (
	"context"
	"errors"
)

// securitydast.go is the dashboard seam of the Code security page's DAST
// card (component security.dast; security coverage gaps plan
// docs/plans/security-coverage-gaps-plan-2026-11-13.md section 2) and of
// the Projects tab's SBOM export (section 3). Plain types only: the
// dashboard never links the DAST lane (internal/secdastnet) or the
// inventory owner, so cmd/observer injects the funcs
// (security_dast_dashboard.go, security_sbom_dashboard.go).

// The refusals a SecurityDAST.Run (or Accept) returns, wrapped; the
// dashboard maps each to its status with errors.Is.
var (
	// ErrDASTNotSelected: security.dast is not selected on this node.
	ErrDASTNotSelected = errors.New("the security.dast component is not selected")
	// ErrDASTNotAccepted: the developer's one accept is not recorded.
	ErrDASTNotAccepted = errors.New("the DAST checker is not accepted yet")
	// ErrDASTBadTarget: the URL is not a loopback dev server with a port.
	ErrDASTBadTarget = errors.New("not a dev server on this machine")
	// ErrDASTBusy: another DAST run started from the dashboard is running.
	ErrDASTBusy = errors.New("a DAST run is already running")
)

// DASTState is the DAST card's state: whether security.dast is selected,
// whether the developer's one accept is recorded (when, where), and the
// accept text, the same words the CLI shows.
type DASTState struct {
	Selected   bool   `json:"selected"`
	Accepted   bool   `json:"accepted"`
	AcceptedAt string `json:"accepted_at,omitempty"`
	AcceptedOn string `json:"accepted_on,omitempty"`
	AcceptText string `json:"accept_text"`
}

// DASTCandidate is one dev-server URL a project's own files name, with
// where it came from and whether the kernel's listen table shows its port
// listening ("yes", "no", or "" where the table cannot be read). Nothing is
// dialed to list it.
type DASTCandidate struct {
	URL       string `json:"url"`
	Name      string `json:"name"`
	Source    string `json:"source"`
	Listening string `json:"listening"`
}

// DASTOriginRun is one origin's last stored run on a project: when it ran
// (RFC3339), its outcome and how many findings it reported.
type DASTOriginRun struct {
	Origin   string `json:"origin"`
	At       string `json:"at"`
	Outcome  string `json:"outcome"`
	Findings int    `json:"findings"`
}

// DASTRunResult is one run's result as the card shows it: the URL checked,
// the outcome (complete, partial, unreachable), the requests made, the
// checks evaluated, the findings reported and how many were new.
type DASTRunResult struct {
	Target   string `json:"target"`
	Outcome  string `json:"outcome"`
	Requests int    `json:"requests"`
	Checks   int    `json:"checks"`
	Findings int    `json:"findings"`
	New      int    `json:"new"`
	// Reason is the first unanswered probe's error on an unreachable run.
	Reason string `json:"reason,omitempty"`
}

// SecurityDAST is the DAST card's seam. State reads the selection and the
// accept; Candidates lists a project's dev-server candidates; LastRuns the
// project's stored per-origin runs; Accept records the developer's accept
// (surface dashboard); Run checks url (loopback only) once and stores the
// findings against projectRoot, one run at a time. Run refuses, with the
// errors above, unless security.dast is selected and accepted.
type SecurityDAST struct {
	State      func(ctx context.Context) DASTState
	Candidates func(ctx context.Context, projectRoot string) []DASTCandidate
	LastRuns   func(ctx context.Context, projectRoot string) []DASTOriginRun
	Accept     func(ctx context.Context) error
	Run        func(ctx context.Context, projectRoot, url string, insecureTLS bool) (DASTRunResult, error)
}

// SecurityProjectSBOM renders the project's SBOM (CycloneDX JSON) from the
// inventory its last dependency scan stored; ok false when there is none.
type SecurityProjectSBOM func(ctx context.Context, projectRoot string) (doc []byte, ok bool, err error)
