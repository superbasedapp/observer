package dashapi

import "context"

// ScannerDBStatus is the dependency scanners' OSV database download state
// for the Code security page's Scanners card (operator ruling PT-19 (2):
// ask once, then automatic).
type ScannerDBStatus struct {
	// Accepted reports the developer's one-time accept of the download;
	// AcceptedAt (RFC3339), AcceptedOn (dashboard or cli) and By (the
	// local account) say when, where and who.
	Accepted   bool   `json:"accepted"`
	AcceptedAt string `json:"accepted_at,omitempty"`
	AcceptedOn string `json:"accepted_on,omitempty"`
	By         string `json:"by,omitempty"`
	// ApproxMB and Source are what the confirm dialog shows: the first
	// download's size, about, and the host it comes from.
	ApproxMB int    `json:"approx_mb"`
	Source   string `json:"source"`
	// Text is the accept text, the same words the CLI shows.
	Text string `json:"text"`
	// Managed reports a managed node: its databases come from the org
	// mirror, so there is nothing to accept.
	Managed bool `json:"managed"`
	// Blocked is the download gate's first closed reason ("" when the
	// download may run).
	Blocked string `json:"blocked,omitempty"`
	// Installed is how many ecosystems have a database on disk.
	Installed int `json:"installed"`
}

// ScannerDB is the dashboard seam of the scanner database accept, wired
// from cmd/observer/security_scan_dash.go. Status reads; Accept records the
// developer's accept given in the dashboard's confirm dialog. A nil
// ScannerDB (a build without the component, a test) makes the accept route
// answer 404 and the Scanners card show no accept.
type ScannerDB struct {
	Status func(ctx context.Context) (ScannerDBStatus, error)
	Accept func(ctx context.Context) error
}
