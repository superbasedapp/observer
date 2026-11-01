//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package dashboard

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// security_opengrep.go serves /api/security/code/install, the Code
// security page's Code rules card (component security.scan.opengrep, lane
// SEC-G2): GET reads the code rules' state through the injected seam
// (Options.Opengrep) and mints the confirm token; POST records the
// developer's size consent given in the card's dialog and starts the guided
// install. Owner-local (consent is never a remote viewer's action); 404
// unless the component is selected (the daemon's one opt-in rule); guard
// rule R-165 denies an agent posting to it. It also gives the Scanners
// card its Opengrep row (opengrepScannerRow).

// opengrepComponent is the catalog id; it requires security.code.
const opengrepComponent = "security.scan.opengrep"

// opengrepDriverCompiled reports that this build carries the driver.
const opengrepDriverCompiled = true

// opengrepSelected reports whether the component and security.code are
// selected under the daemon's opt-in rule (fails closed).
func (s *Server) opengrepSelected(r *http.Request) bool {
	snap, ok := s.comps.live(r.Context())
	sel := s.opts.SecuritySelected
	return ok && sel != nil && sel(snap, opengrepComponent) && sel(snap, "security.code")
}

// opengrepDriverRow has exactly the fields of the Scanners card's driver
// row (securityScannerRow, converted there), so this file does not need
// the dependency scanners' build.
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

type securityOpengrepResponse struct {
	Status       any    `json:"status"`
	ConfirmToken string `json:"confirm_token,omitempty"`
}

func (s *Server) handleSecurityOpengrep(w http.ResponseWriter, r *http.Request) {
	og := s.opts.Opengrep
	if og == nil || og.Status == nil {
		writeCompiledOut(w, opengrepComponent)
		return
	}
	if !s.opengrepSelected(r) {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error":  "not_selected",
			"detail": "the code rules are not selected: add security.scan.opengrep under [components]",
		})
		return
	}
	switch r.Method {
	case http.MethodGet:
		st, err := og.Status(r.Context())
		if err != nil {
			http.Error(w, "code rules state unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityOpengrepResponse{Status: st, ConfirmToken: setConfirmCookie(w, r)})
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		if og.Install == nil {
			writeCompiledOut(w, opengrepComponent)
			return
		}
		// The body carries the pin the dialog showed (lane SEC-G2 audit
		// finding 3); a missing or other pin is refused with the current one.
		var body struct {
			SHA256 string `json:"sha256"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		if err := og.Install(r.Context(), body.SHA256); err != nil {
			var changed *dashapi.OpengrepPinChanged
			if errors.As(err, &changed) {
				writeJSONStatus(w, http.StatusConflict, map[string]string{
					"error": "pin_changed", "message": changed.Error(), "sha256": changed.SHA256,
				})
				return
			}
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		st, err := og.Status(r.Context())
		if err != nil {
			http.Error(w, "code rules state unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityOpengrepResponse{Status: st})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// opengrepScannerRow is the Scanners card's Opengrep row: selected or not,
// installed or not, with the newest run's labels. It reads the seam's
// status only while the component is selected, so a node that never chose
// it reads nothing and starts nothing.
func (s *Server) opengrepScannerRow(r *http.Request) opengrepDriverRow {
	row := opengrepDriverRow{
		Component: opengrepComponent, Driver: "opengrep", Kind: "process", Compiled: opengrepDriverCompiled,
		Platform: opengrepPlatform(runtime.GOOS, runtime.GOARCH), Labels: []string{},
	}
	row.Beta = row.Platform != "supported"
	if !s.opengrepSelected(r) {
		row.Note = "Not selected: the code rules are opt-in (add security.scan.opengrep under [components]). Nothing is installed, downloaded or run."
		return row
	}
	row.Selected = true
	row.Note = "Selected: see the Code rules card."
	if og := s.opts.Opengrep; og != nil && og.Status != nil {
		if st, err := og.Status(r.Context()); err == nil {
			row.Labels = append(row.Labels, st.LastRunLabels...)
			switch {
			case st.Engine == "":
				row.Note = "Selected, not installed: no process starts. Install it from the Code rules card."
			default:
				row.Note = "Selected: " + st.Verification
			}
		}
	}
	return row
}

// opengrepPlatform is the driver row's platform support (the driver's own
// Row is the source; repeated here to keep the dashboard free of the
// driver package): linux amd64 supported, the other published platforms
// untested.
func opengrepPlatform(goos, goarch string) string {
	switch {
	case goos == "linux" && goarch == "amd64":
		return "supported"
	case goos == "linux" && goarch == "arm64", goos == "darwin", goos == "windows" && goarch == "amd64":
		return "untested"
	}
	return "unsupported"
}
