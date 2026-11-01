//go:build sbo_omit_security || sbo_omit_security_scan_opengrep

package dashboard

import "net/http"

// opengrepDriverRow mirrors the Scanners card's driver row.
type opengrepDriverRow struct {
	Component string   `json:"component"`
	Driver    string   `json:"driver"`
	Kind      string   `json:"kind"`
	Compiled  bool     `json:"compiled"`
	Platform  string   `json:"platform"`
	Beta      bool     `json:"beta"`
	Note      string   `json:"note"`
	Labels    []string `json:"labels"`
	Selected  bool     `json:"selected"`
}

// handleSecurityOpengrep refuses: the code rules are not in this build.
func (s *Server) handleSecurityOpengrep(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.scan.opengrep")
}

// opengrepScannerRow says the driver is not in this build.
func (s *Server) opengrepScannerRow(*http.Request) opengrepDriverRow {
	return opengrepDriverRow{
		Component: "security.scan.opengrep", Driver: "opengrep", Kind: "process", Platform: "unsupported",
		Note: "Not in this build: the code rules (Opengrep) are left out.", Labels: []string{},
	}
}
