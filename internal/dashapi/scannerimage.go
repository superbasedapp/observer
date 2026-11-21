package dashapi

// ScannerImageStatus is the image OS package driver's state for the
// Scanners card (OS and CI vulnerability scanning plan section 6.7, lane
// OS-2 T): which driver scans images ([security.scan.image] driver), what
// this build and machine carry for each, and Trivy's database accept and
// age. Read-only; the driver key is changed with `observer security scan
// image driver <name>` (never by an agent: R-165).
type ScannerImageStatus struct {
	// Driver is the driver in force ("scalibr" or "trivy"); Configured the
	// key's own value ("" for the default); Default what "" reads as in this
	// build; Choices the drivers this build compiles.
	Driver     string   `json:"driver"`
	Configured string   `json:"configured,omitempty"`
	Default    string   `json:"default"`
	Choices    []string `json:"choices"`
	// ScalibrCompiled and TrivyCompiled report the two drivers in this
	// build.
	ScalibrCompiled bool `json:"scalibr_compiled"`
	TrivyCompiled   bool `json:"trivy_compiled"`
	// Trivy is the Trivy driver's state; nil when it is not in this build.
	Trivy *ScannerTrivyImageStatus `json:"trivy,omitempty"`
}

// ScannerTrivyImageStatus is the Trivy image driver's binary and database
// state.
type ScannerTrivyImageStatus struct {
	// Selected reports security.scan.image.trivy, security.scan.trivy and
	// security.deps all selected.
	Selected bool `json:"selected"`
	// Installed reports a Trivy binary found (the guided install or PATH);
	// Pinned that a verified pin covers it; Decision the pin decision in
	// words; Version the tested version.
	Installed bool   `json:"installed"`
	Pinned    bool   `json:"pinned"`
	Decision  string `json:"decision,omitempty"`
	Tested    string `json:"tested_version"`
	// DB is the database's accept and install state.
	DB ScannerTrivyDBStatus `json:"db"`
}

// ScannerTrivyDBStatus is Trivy's database: its one accept and the
// installed generation.
type ScannerTrivyDBStatus struct {
	// Accepted reports the developer's accept; AcceptedAt (RFC3339),
	// AcceptedOn (dashboard or cli) and By say when, where and who.
	Accepted   bool   `json:"accepted"`
	AcceptedAt string `json:"accepted_at,omitempty"`
	AcceptedOn string `json:"accepted_on,omitempty"`
	By         string `json:"by,omitempty"`
	// Text is the accept text, the same words the CLI shows; Source the
	// hosts; ApproxDownloadMB and ApproxDiskMB the sizes it states.
	Text             string `json:"text"`
	Source           string `json:"source"`
	ApproxDownloadMB int    `json:"approx_download_mb"`
	ApproxDiskMB     int    `json:"approx_disk_mb"`
	// Managed reports a managed node: its organization's mirror does not
	// serve Trivy's database yet, so nothing is accepted or downloaded.
	Managed bool `json:"managed"`
	// Blocked is the download gate's first closed reason ("" when the
	// download may run).
	Blocked string `json:"blocked,omitempty"`
	// Installed reports a database on disk; Epoch is what runs record;
	// UpdatedAt and NextUpdate (RFC3339) the database's own metadata;
	// AgeHours its age; Bytes what it takes on disk.
	Installed  bool    `json:"installed"`
	Epoch      string  `json:"epoch,omitempty"`
	UpdatedAt  string  `json:"updated_at,omitempty"`
	NextUpdate string  `json:"next_update,omitempty"`
	CheckedAt  string  `json:"checked_at,omitempty"`
	AgeHours   float64 `json:"age_hours,omitempty"`
	Bytes      int64   `json:"bytes,omitempty"`
	// LastError is the last refresh's fixed reason ("" after a success);
	// the installed database stays in use.
	LastError string `json:"last_error,omitempty"`
}
