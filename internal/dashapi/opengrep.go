package dashapi

import "context"

// OpengrepStatus is the code rules' state for the Code security page's
// Code rules card (component security.scan.opengrep, lane SEC-G2): the
// guided install's plan and the developer's size consent, the engine and
// its verification, the rule pack and where it came from, the last run, the
// triggers and isolation.
type OpengrepStatus struct {
	// Selected is false when the component is not selected (opt-in): the
	// card then says so and offers nothing.
	Selected bool `json:"selected"`
	Managed  bool `json:"managed"`

	// The install plan: Blocked is its first closed reason (with a plain
	// BlockedText), else what an install fetches.
	Blocked       string `json:"blocked,omitempty"`
	BlockedText   string `json:"blocked_text,omitempty"`
	Source        string `json:"source,omitempty"`
	PinFrom       string `json:"pin_from,omitempty"`
	Version       string `json:"version,omitempty"`
	OS            string `json:"os,omitempty"`
	Arch          string `json:"arch,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	URL           string `json:"url,omitempty"`
	DownloadBytes int64  `json:"download_bytes,omitempty"`
	TreeBytes     int64  `json:"tree_bytes,omitempty"`
	TreeFiles     int    `json:"tree_files,omitempty"`
	// ConsentText is what the dialog shows, the same words the CLI shows.
	ConsentText string `json:"consent_text,omitempty"`
	// Consented reports a consent that covers this pin.
	Consented   bool   `json:"consented"`
	ConsentedAt string `json:"consented_at,omitempty"`
	ConsentedOn string `json:"consented_on,omitempty"`
	By          string `json:"by,omitempty"`
	// Installed: the guided install's path holds this pin's binary.
	Installed   bool   `json:"installed"`
	InstalledAt string `json:"installed_at,omitempty"`
	// Installing and LastError report the dashboard's install job.
	Installing bool   `json:"installing"`
	LastError  string `json:"last_error,omitempty"`

	// Engine is what the driver would run (empty: none found) and
	// Verification its decision in plain words.
	Engine       string `json:"engine,omitempty"`
	Verification string `json:"verification,omitempty"`
	// The rule pack in use: version, source (floor or imported),
	// freshness, a note when an installed one was set aside, and the last
	// fetch of the feed or the mirror.
	PackVersion   string `json:"pack_version,omitempty"`
	PackSource    string `json:"pack_source,omitempty"`
	PackFreshness string `json:"pack_freshness,omitempty"`
	PackNote      string `json:"pack_note,omitempty"`
	FetchSource   string `json:"fetch_source,omitempty"`
	FetchAt       string `json:"fetch_at,omitempty"`
	FetchError    string `json:"fetch_error,omitempty"`
	// LastRun is the newest recorded run's time, outcome and labels.
	LastRunAt      string   `json:"last_run_at,omitempty"`
	LastRunOutcome string   `json:"last_run_outcome,omitempty"`
	LastRunLabels  []string `json:"last_run_labels,omitempty"`
	// The triggers as configured, and whether runs are isolated here.
	PostWrite     bool   `json:"post_write"`
	CommitDiff    bool   `json:"commit_diff"`
	ScheduleHours int    `json:"schedule_hours"`
	Isolation     string `json:"isolation,omitempty"`
}

// Opengrep is the dashboard seam of the code rules, wired from
// cmd/observer/security_opengrep_dash.go. Status reads; Install records the
// developer's size consent given in the card's dialog and starts the
// install (on a managed node, from the org mirror, with no consent). sha256
// is the pin the dialog showed: Install refuses any other pin in force with
// *OpengrepPinChanged, so a consent is never recorded for a pin the
// developer did not see (lane SEC-G2 audit finding 3). A nil Opengrep (a
// build without the component, a test) answers 404.
type Opengrep struct {
	Status  func(ctx context.Context) (OpengrepStatus, error)
	Install func(ctx context.Context, sha256 string) error
}

// OpengrepPinChanged is Install's refusal when the pin in force is not the
// one the dialog showed; SHA256 is the current pin ("" when none).
type OpengrepPinChanged struct {
	SHA256 string
}

// Error implements error.
func (e *OpengrepPinChanged) Error() string {
	if e.SHA256 == "" {
		return "the Opengrep pin changed since the dialog was shown, and no pin is in force now; nothing was recorded"
	}
	return "the Opengrep pin changed since the dialog was shown (now sha256 " + e.SHA256 + "); nothing was recorded: review the new pin and accept again"
}
