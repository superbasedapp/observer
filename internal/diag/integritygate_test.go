package diag

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
)

// sparseDBFile makes a file of the given apparent size without writing the
// bytes: the size injected into the db.integrity gate.
func sparseDBFile(t *testing.T, size int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "observer.db")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return path
}

// TestCheckDBIntegrityGated pins live finding D8 (2026-09-28): `observer
// doctor cline` ran a whole-database PRAGMA quick_check (751 s on a 27 GB DB)
// ignoring the integrity_check_max_gb cap the daemon's startup honours. One
// case per gate row. A CLOSED database handle stands in for "the probe must
// not run": querying it fails, so a skipped case returning OK proves the
// pragma was never issued.
func TestCheckDBIntegrityGated(t *testing.T) {
	ctx := context.Background()
	live := routingGapDB(t)
	closed := routingGapDB(t)
	_ = closed.Close()

	big := sparseDBFile(t, int64(1)<<30+1) // just over a 1 GB cap
	small := sparseDBFile(t, 4096)
	cfgFor := func(path string, maxGB int) config.Config {
		var c config.Config
		c.Observer.DBPath = path
		c.Observer.DB.IntegrityCheckMaxGB = maxGB
		return c
	}

	for _, tc := range []struct {
		name       string
		opts       DoctorOptions
		wantRan    bool
		wantPinned bool
		wantMsg    []string
	}{
		{
			name:       "per_tool_scope_defers",
			opts:       DoctorOptions{DB: closed, Scope: "cline", Config: cfgFor(small, 8)},
			wantPinned: true,
			wantMsg:    []string{"skipped", "`observer doctor cline`", "`observer doctor db`", "--integrity"},
		},
		{
			name:    "unscoped_over_cap_skips",
			opts:    DoctorOptions{DB: closed, Config: cfgFor(big, 1)},
			wantMsg: []string{"skipped", "integrity_check_max_gb = 1", "startup", "`observer doctor db`"},
		},
		{
			name:    "unscoped_under_cap_runs",
			opts:    DoctorOptions{DB: live, Config: cfgFor(small, 1)},
			wantRan: true,
		},
		{
			name:    "unscoped_gate_disabled_runs",
			opts:    DoctorOptions{DB: live, Config: cfgFor(big, 0)},
			wantRan: true,
		},
		{
			name:    "explicit_db_scope_runs_over_cap",
			opts:    DoctorOptions{DB: live, Scope: "db", Config: cfgFor(big, 1)},
			wantRan: true,
		},
		{
			name:       "forced_under_tool_scope_runs_and_prints",
			opts:       DoctorOptions{DB: live, Scope: "cline", ForceIntegrity: true, Config: cfgFor(big, 1)},
			wantRan:    true,
			wantPinned: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := checkDBIntegrityGated(ctx, tc.opts)
			if c.Name != "db.integrity" || c.Status != StatusOK {
				t.Fatalf("check = %+v, want an OK db.integrity line", c)
			}
			if ran := c.Message == "PRAGMA quick_check ok"; ran != tc.wantRan {
				t.Errorf("probe ran = %v, want %v (%s)", ran, tc.wantRan, c.Message)
			}
			if c.pinned != tc.wantPinned {
				t.Errorf("pinned = %v, want %v", c.pinned, tc.wantPinned)
			}
			for _, w := range tc.wantMsg {
				if !strings.Contains(c.Message, w) {
					t.Errorf("message missing %q: %s", w, c.Message)
				}
			}
			if tc.wantPinned {
				// The scoped output keeps the line, but it never counts as
				// a filter match of its own.
				r := Report{Checks: []Check{c}}.Filter(tc.opts.Scope)
				if len(r.Checks) != 1 || r.Matched() != 0 {
					t.Errorf("Filter(%q) kept %d, matched %d; want 1 kept, 0 matched", tc.opts.Scope, len(r.Checks), r.Matched())
				}
			}
		})
	}
}

// A skip line carries the last recorded probe verdict, so skipping never
// hides a known result.
func TestCheckDBIntegrityGatedCarriesLastVerdict(t *testing.T) {
	ctx := context.Background()
	live := routingGapDB(t)
	if err := db.RunStartupMaintenance(ctx, live); err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	cfg.Observer.DBPath = sparseDBFile(t, 4096)
	cfg.Observer.DB.IntegrityCheckMaxGB = 8
	c := checkDBIntegrityGated(ctx, DoctorOptions{DB: live, Scope: "cursor", Config: cfg})
	if !strings.HasPrefix(c.Message, "skipped") {
		t.Fatalf("message = %s, want skipped", c.Message)
	}
	if len(c.Details) != 1 || !strings.HasPrefix(c.Details[0], "last recorded quick_check: ok at ") {
		t.Errorf("details = %v, want the recorded ok verdict", c.Details)
	}
}
