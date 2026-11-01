//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"net/http"
	"path/filepath"
	"runtime"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_scanners.go serves GET /api/security/scanners, the Code security
// page's Scanners card (security pillar plan sections 4.4 and 8.7, Phase
// D2): the two dependency drivers with what this build carries and their
// platform label (beta on Windows and macOS, D-764 Q25), the local OSV
// databases with their epochs, the labels of each driver's newest recorded
// run ("not isolated", "untested engine version"), and the OSV attribution
// text. It starts no process and reads no project: only the database
// store's epochs file and the newest sec_scan_runs row per driver. A
// feature-owned file of security.deps: with sbo_omit_security_deps (or
// sbo_omit_security) security_scanners_omit.go answers instead. Whether a
// driver is selected, and whether osv-scanner is installed, are the CLI's
// to say (`observer security scan status`); this card does not resolve
// binaries. The route answers 404 unless the daemon's one opt-in rule
// (Options.SecuritySelected, cmd/observer/security_optin.go) selects a
// driver and its parent security.deps, so an install with no [components]
// block sees no card, like the custom scanners and the git hooks.

// securityScannersActive reports whether either dependency driver is
// selected, with its parent security.deps, through Options.SecuritySelected.
// With no component service or no rule wired it is not (fails closed).
func (s *Server) securityScannersActive(r *http.Request) bool {
	snap, ok := s.comps.live(r.Context())
	sel := s.opts.SecuritySelected
	if !ok || sel == nil || !sel(snap, "security.deps") {
		return false
	}
	return sel(snap, depscan.ScalibrComponent) || sel(snap, depscan.OSVComponent)
}

type securityScannerRow struct {
	Component string `json:"component"`
	Driver    string `json:"driver"`
	Kind      string `json:"kind"`
	// Compiled is false when this build leaves the driver out.
	Compiled bool   `json:"compiled"`
	Platform string `json:"platform"`
	Beta     bool   `json:"beta"`
	Note     string `json:"note"`
	// Labels are what the driver's newest recorded run says about itself
	// ("not isolated", "untested engine version"), the same words the CLI
	// prints (depscan.RunLabels, lane SEC-DEPS3 item 6); empty when none.
	Labels []string `json:"labels"`
	// Selected is set on the Opengrep row (an opt-in driver: false means
	// not selected); the dependency drivers' rows leave it false.
	Selected bool `json:"selected"`
}

type securityDatabaseRow struct {
	Ecosystem    string `json:"ecosystem"`
	Installed    bool   `json:"installed"`
	LastModified string `json:"last_modified,omitempty"`
	Size         int64  `json:"size,omitempty"`
	FetchedAt    string `json:"fetched_at,omitempty"`
	LastError    string `json:"last_error,omitempty"`
}

type securityScannersResponse struct {
	Drivers     []securityScannerRow  `json:"drivers"`
	Databases   []securityDatabaseRow `json:"databases"`
	Attribution string                `json:"attribution"`
	// DB is the database download's accept state (operator ruling PT-19
	// (2)); absent when the seam is not wired.
	DB any `json:"db,omitempty"`
}

func (s *Server) handleSecurityScanners(w http.ResponseWriter, r *http.Request) {
	if !s.securityScannersActive(r) {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error":  "not_selected",
			"detail": "no dependency driver is selected: add security.scan.scalibr or security.scan.osv (and security.deps) under [components]",
		})
		return
	}
	resp := securityScannersResponse{Drivers: []securityScannerRow{}, Databases: []securityDatabaseRow{}, Attribution: depscan.Attribution}
	scal := depscan.ScalibrRow(nil)
	osv := depscan.OSVRow()
	scalNote := "Linked OSV-SCALIBR, run in a child process of the daemon."
	if !scalibrDriverCompiled {
		scalNote = "Not in this build (developer and minimal distros): dependencies it would scan show as not scanned."
	}
	var st *store.Store
	if db := s.db(); db != nil {
		st = store.New(db)
	}
	for _, d := range []struct {
		row      secscan.DriverRow
		compiled bool
		note     string
	}{
		{scal, scalibrDriverCompiled, scalNote},
		{osv, osvDriverCompiled, "A separately installed osv-scanner, never bundled. Not installed: no process starts and dependencies show as not scanned; `observer security scan install-osv-scanner` shows how to install it."},
	} {
		labels := []string{}
		if st != nil {
			if notes, err := st.SecLatestRunNotes(r.Context(), d.row.ID); err == nil {
				labels = append(labels, depscan.RunLabels(notes)...)
			}
		}
		resp.Drivers = append(resp.Drivers, securityScannerRow{
			Component: d.row.ComponentID, Driver: d.row.ID, Kind: string(d.row.Kind), Compiled: d.compiled,
			Platform: string(depscan.PlatformSupport(d.row, runtime.GOOS, runtime.GOARCH, "")),
			Beta:     depscan.Beta(d.row, runtime.GOOS, runtime.GOARCH), Note: d.note, Labels: labels,
		})
	}
	// The code rules' driver (lane SEC-G2): listed whether or not it is
	// selected, so an install that never chose it reads "not selected".
	resp.Drivers = append(resp.Drivers, securityScannerRow(s.opengrepScannerRow(r)))
	resp.Drivers = append(resp.Drivers, s.iacScannerRows(r)...) // lane GATES-SEC (security_iac.go)
	resolved, _ := config.ResolveGlobalPath(s.opts.ConfigPath)
	eps, _ := osvdb.Open(filepath.Join(secposture.LayoutFor(resolved).Dir, "osv")).Epochs()
	for _, eco := range depscan.Ecosystems() {
		row := securityDatabaseRow{Ecosystem: eco}
		if e, ok := eps[eco]; ok {
			row.Installed = e.Installed()
			row.LastModified, row.Size, row.LastError = e.LastModified, e.Size, e.LastError
			if !e.FetchedAt.IsZero() {
				row.FetchedAt = e.FetchedAt.UTC().Format(time.RFC3339)
			}
		}
		resp.Databases = append(resp.Databases, row)
	}
	if sdb := s.opts.ScannerDB; sdb != nil && sdb.Status != nil {
		if st, err := sdb.Status(r.Context()); err == nil {
			resp.DB = st
		}
	}
	writeJSON(w, resp)
}
