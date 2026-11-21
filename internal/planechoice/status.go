package planechoice

// LatestTrace is the newest app trace this machine holds: identifiers and a
// time only, never content.
type LatestTrace struct {
	TraceID   string `json:"trace_id"`
	Name      string `json:"name,omitempty"`
	Service   string `json:"service,omitempty"`
	StartedAt string `json:"started_at,omitempty"`
}

// AppsStatus is the plain fact set the daemon reports about AI Apps on this
// machine. The daemon (cmd/observer) gathers it; the dashboard reads it
// through one seam and never imports the obs subsystem.
type AppsStatus struct {
	// InBuild: app observability is compiled into this binary.
	InBuild bool
	// Component is the obs component's state.
	Component ComponentState
	// On: AI Apps is serving in this process (routes and trace handler).
	On bool
	// ConfiguredOn: [observability] enabled in the saved config (it may be
	// on in the file while this process waits, or off in the file while
	// this process still serves until the next start).
	ConfiguredOn bool
	// HotEnable: this daemon can turn AI Apps on without a restart.
	HotEnable bool
	Receiver  Receiver
	// LatestTrace is nil when no trace has arrived (or AI Apps is off in
	// this process and nothing was read).
	LatestTrace *LatestTrace
	Consent     ConsentFacts
	// Pending: see EnableFacts.Pending.
	Pending []string
}
