package dashapi

import "context"

// IaCScannerRow is one IaC engine's row on the Code security page's
// data-driven Scanners card (lane GATES-SEC): the same fields every driver
// row carries there.
type IaCScannerRow struct {
	Component string   `json:"component"`
	Driver    string   `json:"driver"`
	Kind      string   `json:"kind"`
	Compiled  bool     `json:"compiled"`
	Platform  string   `json:"platform"`
	Beta      bool     `json:"beta"`
	Note      string   `json:"note"`
	Labels    []string `json:"labels"`
	Selected  bool     `json:"selected"`
	// Install is the plan the dialog shows (empty when no guided install
	// applies): the pin, its size and the consent text.
	InstallPin     string `json:"install_pin,omitempty"`
	InstallBytes   int64  `json:"install_bytes,omitempty"`
	InstallConsent string `json:"install_consent,omitempty"`
	InstallBlocked string `json:"install_blocked,omitempty"`
	Installed      bool   `json:"installed"`
}

// IaC is the IaC engines' seam (components security.scan.trivy and
// security.scan.kics, lane GATES-SEC). Rows never start a process and, for
// an engine that is not selected, read nothing but the selection. Install
// records the developer's consent for the pin the dialog showed (sha256)
// and installs; a changed pin is refused. Nil answers 404 on
// /api/security/iac/install.
type IaC struct {
	Rows    func(ctx context.Context) []IaCScannerRow
	Install func(ctx context.Context, engine, sha256 string) error
}
