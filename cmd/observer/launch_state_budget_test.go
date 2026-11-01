package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestStateLoadNeverCreatesTheDatabase (OSH-R-007): the launch gate's state
// load never creates the node database. With no database file, a launch in
// a sandbox box or one a daemon runs or spawned refuses (it cannot see the
// node database, so a managed budget cannot be checked); a standalone launch
// on a host that never ran Observer gets an in-memory database. In every
// case nothing is written to disk. Before the fix the loader created the
// directory and an empty database, which reads as "not enrolled".
func TestStateLoadNeverCreatesTheDatabase(t *testing.T) {
	for _, tc := range []struct {
		name      string
		boxed     bool
		daemon    bool
		wantAllow bool
	}{
		{"in a box", true, false, false},
		{"a daemon child", false, true, false},
		{"standalone, never ran Observer", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "missing", "observer.db")
			cfgPath := filepath.Join(dir, "config.toml")
			if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf("[observer]\ndb_path = %q\n", dbPath)), 0o600); err != nil {
				t.Fatal(err)
			}
			r := &launchGateRun{
				ctx: context.Background(), tool: "claude-code", configPath: cfgPath,
				inSandboxFn: func() bool { return tc.boxed }, daemonRunsFn: func() bool { return tc.daemon },
			}
			s := gateStateLoad(r)
			defer r.close()
			if (s.refuse == nil) != tc.wantAllow {
				t.Fatalf("refuse = %v, want allow=%v", s.refuse, tc.wantAllow)
			}
			if s.refuse != nil && !strings.Contains(s.refuse.Error(), "cannot see the node database") {
				t.Fatalf("refusal %v does not say why", s.refuse)
			}
			if tc.wantAllow && r.database == nil {
				t.Fatal("a standalone launch got no database for the rows below")
			}
			if tc.wantAllow && r.database.Stats().MaxOpenConnections != 1 {
				t.Fatalf("the in-memory database allows %d connections, each its own empty database", r.database.Stats().MaxOpenConnections)
			}
			if _, err := os.Stat(filepath.Dir(dbPath)); !os.IsNotExist(err) {
				t.Fatalf("the launch created the database directory: %v", err)
			}
		})
	}
}

// TestDashboardFreshAdmitsTheManagedBudgetDaemonSide (OSH-R-007): a
// dashboard fresh launch walks the managed hard-budget rows daemon-side,
// before the PTY spawns, from the daemon's own config and database: on a
// managed node holding enforce.budget whose Guard cannot enforce the budget
// the launch is refused there, not only by the inner launcher; an
// individual node is admitted. Before the fix the dashboard path ran no
// budget row at all.
func TestDashboardFreshAdmitsTheManagedBudgetDaemonSide(t *testing.T) {
	walk := func(cfgPath string) error {
		r := &launchGateRun{
			ctx: context.Background(), path: launchPathDashboardFresh, tool: "claude-code",
			configPath: cfgPath, stateSource: loadConfigAndDBNoCreate, daemonRunsFn: func() bool { return true },
		}
		return walkLaunchGates(r, launchGates)
	}
	cfgPath, _ := writeManagedBudgetLaunchFixture(t, true, "observe")
	if err := walk(cfgPath); err == nil {
		t.Fatal("a managed hard budget the Guard cannot enforce was admitted on the dashboard path")
	}
	indPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "observe")
	rewriteBudgetLaunchEnrolment(t, dbPath, func(e *store.Enrolment) { e.Tenancy = orgcontract.TenancyIndividual })
	rewriteBudgetLaunchGrant(t, dbPath, func(g *store.EnrolmentGrant) {
		g.ConsentMode = govern.ConsentInteractive
		g.ExpiresAt = time.Now().UTC().Add(-time.Hour)
		g.SignedExpiresAt = g.ExpiresAt
	})
	if err := walk(indPath); err != nil {
		t.Fatalf("an individual node was refused: %v", err)
	}
	// A plain shell starts no agent: the budget rows allow it at once.
	r := &launchGateRun{
		ctx: context.Background(), path: launchPathDashboardFresh, tool: "shell",
		configPath: cfgPath, stateSource: loadConfigAndDBNoCreate, daemonRunsFn: func() bool { return true }, budgetExempt: true,
	}
	if err := walkLaunchGates(r, launchGates); err != nil {
		t.Fatalf("a plain shell was refused: %v", err)
	}
}
