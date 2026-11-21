//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// scannerSnapSvc is a components service that only answers State.
type scannerSnapSvc struct {
	ComponentsService
	snap componentstate.Snapshot
}

func (f scannerSnapSvc) State(context.Context) (componentstate.Snapshot, error) { return f.snap, nil }

// scannerRule is a stand-in for the daemon's opt-in rule: selected only
// under a configured block that names the id.
func scannerRule(ids ...string) func(componentstate.Snapshot, string) bool {
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	return func(snap componentstate.Snapshot, id string) bool { return snap.Configured && set[id] }
}

// TestSecurityScannersOptInGate: the route (and so the Scanners card)
// answers 404 unless the opt-in rule selects a dependency driver and
// security.deps; no component service, no rule, a legacy snapshot with no
// [components] block, or a driver without its parent all hide it.
func TestSecurityScannersOptInGate(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	configured := componentstate.Snapshot{Configured: true}
	cases := []struct {
		name string
		svc  ComponentsService
		rule func(componentstate.Snapshot, string) bool
		want int
	}{
		{"no component service", nil, scannerRule("security.deps", "security.scan.scalibr"), http.StatusNotFound},
		{"no rule wired", scannerSnapSvc{snap: configured}, nil, http.StatusNotFound},
		{"no [components] block", scannerSnapSvc{snap: componentstate.Snapshot{}}, scannerRule("security.deps", "security.scan.scalibr", "security.scan.osv"), http.StatusNotFound},
		{"driver without security.deps", scannerSnapSvc{snap: configured}, scannerRule("security.scan.osv"), http.StatusNotFound},
		{"security.deps alone", scannerSnapSvc{snap: configured}, scannerRule("security.deps"), http.StatusNotFound},
		{"scalibr selected", scannerSnapSvc{snap: configured}, scannerRule("security.deps", "security.scan.scalibr"), http.StatusOK},
		{"osv selected", scannerSnapSvc{snap: configured}, scannerRule("security.deps", "security.scan.osv"), http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{opts: Options{ConfigPath: cfg, SecuritySelected: c.rule}}
			s.comps.svc = c.svc
			w := httptest.NewRecorder()
			s.handleSecurityScanners(w, httptest.NewRequest(http.MethodGet, "/api/security/scanners", nil))
			if w.Code != c.want {
				t.Fatalf("status %d, want %d: %s", w.Code, c.want, w.Body)
			}
		})
	}
}

// TestHandleSecurityScanners: the Scanners card lists both drivers with
// their platform label, every ecosystem's database (none installed on a
// fresh home), and the OSV attribution.
func TestHandleSecurityScanners(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{opts: Options{ConfigPath: cfg, SecuritySelected: scannerRule("security.deps", "security.scan.scalibr")}}
	s.comps.svc = scannerSnapSvc{snap: componentstate.Snapshot{Configured: true}}
	w := httptest.NewRecorder()
	s.handleSecurityScanners(w, httptest.NewRequest(http.MethodGet, "/api/security/scanners", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp securityScannersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Drivers) != 3 || resp.Drivers[0].Component != "security.scan.scalibr" || resp.Drivers[1].Component != "security.scan.osv" {
		t.Fatalf("drivers %+v", resp.Drivers)
	}
	// The code rules' driver is listed too (lane SEC-G2): opt-in, so a node
	// that did not select it reads "off", with the switch that turns it on.
	if og := resp.Drivers[2]; og.Component != "security.scan.opengrep" || og.Selected || !strings.HasPrefix(og.Note, "Off:") || !strings.Contains(og.Note, "Scanners tab") {
		t.Fatalf("opengrep row %+v", og)
	}
	// Every store ecosystem has a row, in the store's sorted order, GitHub
	// Actions (S-779) and the six of the 2026-11-06 coverage review among
	// them.
	var dbEcos []string
	for _, d := range resp.Databases {
		dbEcos = append(dbEcos, d.Ecosystem)
	}
	if !slices.Equal(dbEcos, depscan.Ecosystems()) || len(dbEcos) != 15 || !slices.Contains(dbEcos, "GitHub Actions") || !slices.Contains(dbEcos, "Pub") {
		t.Fatalf("databases %+v", resp.Databases)
	}
	for _, d := range resp.Databases {
		if d.Installed {
			t.Fatalf("%s reads installed on a fresh home", d.Ecosystem)
		}
	}
	if resp.Attribution == "" {
		t.Fatal("the attribution text must be served")
	}
	// The osv-scanner row points at its own "How to install" (dashboard CLI
	// parity plan, B-CS3), never at a terminal command, and the offer is the
	// one the CLI prints, carrying the reviewed pin.
	if osv := resp.Drivers[1]; strings.Contains(osv.Note, "observer ") {
		t.Fatalf("the osv-scanner row sends the user to a terminal: %q", osv.Note)
	}
	switch {
	case osvDriverCompiled && (resp.OSVInstall == nil || len(resp.OSVInstall.Ways) == 0 ||
		!strings.Contains(resp.OSVInstall.Text(), depscan.OSVScannerLinuxAMD64) || !strings.Contains(resp.Drivers[1].Note, "How to install")):
		t.Fatalf("osv install offer %+v, note %q", resp.OSVInstall, resp.Drivers[1].Note)
	case !osvDriverCompiled && resp.OSVInstall != nil:
		t.Fatalf("a build without security.scan.osv offers its install: %+v", resp.OSVInstall)
	}
}

// TestSecurityScannersRunLabels pins lane SEC-DEPS3 item 6: the card shows
// what each driver's newest recorded run says about itself ("not
// isolated", "untested engine version"), the CLI's words, read from the
// run's fixed notes; a driver with no run, or a run with no such note,
// carries no label.
func TestSecurityScannersRunLabels(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(dir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	now := time.Now().UTC()
	for i, r := range []struct {
		driver string
		notes  []string
	}{
		{depscan.ScalibrID, []string{depscan.UntestedVersionPrefix + ": an older run."}},
		{depscan.ScalibrID, []string{depscan.NotIsolatedPrefix + ": the scan child ran with network access."}},
	} {
		if err := st.InsertSecScanRun(context.Background(), store.SecScanRun{
			ProjectRootHash: "h", Driver: r.driver, Scope: "scheduled", Outcome: "clean",
			Coverage: secscan.Coverage{Outcome: secscan.OutcomeClean, Notes: r.notes}, StartedAt: now.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}
	s, err := New(Options{DB: database, ConfigPath: cfg, SecuritySelected: scannerRule("security.deps", "security.scan.scalibr")})
	if err != nil {
		t.Fatal(err)
	}
	s.comps.svc = scannerSnapSvc{snap: componentstate.Snapshot{Configured: true}}
	w := httptest.NewRecorder()
	s.handleSecurityScanners(w, httptest.NewRequest(http.MethodGet, "/api/security/scanners", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp securityScannersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, d := range resp.Drivers {
		got[d.Driver] = d.Labels
	}
	if !slices.Equal(got[depscan.ScalibrID], []string{"not isolated"}) {
		t.Fatalf("scalibr labels %v, want the newest run's [not isolated]", got[depscan.ScalibrID])
	}
	if len(got[depscan.OSVID]) != 0 {
		t.Fatalf("osv has no run, so no label: %v", got[depscan.OSVID])
	}
}
