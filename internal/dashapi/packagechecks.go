package dashapi

import "context"

// PackageChecksStatus is the install gate's state for the Code security
// page's Package checks card (component security.deps; security pillar
// plan section 8.3): the online setting, whether the first-run disclosure
// was accepted (and where), its text, whether package checks are set up at
// all, and the signed index kinds.
type PackageChecksStatus struct {
	// Active reports that the security.deps component runs on this node.
	Active bool `json:"active"`
	// Online is the [security.deps] online setting.
	Online bool `json:"online"`
	// Managed reports a managed node (its queries go to the org relay).
	Managed bool `json:"managed"`
	// Accepted reports that the disclosure's current text was accepted;
	// AcceptedAt (RFC3339) and AcceptedOn (dashboard or cli) say when and
	// where.
	Accepted   bool   `json:"accepted"`
	AcceptedAt string `json:"accepted_at,omitempty"`
	AcceptedOn string `json:"accepted_on,omitempty"`
	// IndexDownload is the [security.deps].index_download switch: false
	// means nothing is fetched and the checks use the index on disk
	// (operator ruling PT-19).
	IndexDownload bool `json:"index_download"`
	// Text is the disclosure text this node is shown.
	Text string `json:"text"`
	// NotSetUp reports that no signed index was ever installed and online
	// checks are off or not accepted: nothing can check a package yet.
	NotSetUp bool `json:"not_set_up"`
	// Index is one row per signed index kind.
	Index []PackageChecksIndex `json:"index"`
}

// PackageChecksIndex is one signed index kind's state.
type PackageChecksIndex struct {
	Kind string `json:"kind"`
	// State is installed, not_installed or unreadable.
	State     string `json:"state"`
	Version   int64  `json:"version,omitempty"`
	Freshness string `json:"freshness,omitempty"`
	// LastFailure is the last refresh's failure reason, if any.
	LastFailure string `json:"last_failure,omitempty"`
}

// PackageChecks is the install gate's dashboard seam, wired from
// cmd/observer/security_deps_dash.go. Status reads; Accept records that the
// developer read the disclosure on the dashboard (an explicit action, the
// consent that turns online checks on). A nil PackageChecks (a build
// without the component, a test) makes the route answer 404.
type PackageChecks struct {
	Status func(ctx context.Context) (PackageChecksStatus, error)
	Accept func(ctx context.Context) error
}
