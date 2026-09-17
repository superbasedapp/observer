package main

import (
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// openStackTestDB opens a throwaway observer DB for the terminal-stack builders,
// which wrap it in a store but issue no queries at construction time.
func openStackTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

// surfaceTestConfig returns a default config with the two terminal-surface gates
// set explicitly, so a test drives ONLY the enablement predicates under test.
func surfaceTestConfig(allowLaunch, attach bool) config.Config {
	cfg := config.Default()
	cfg.Handoff.AllowDashboardLaunch = allowLaunch
	cfg.Terminal.Attach.Enabled = attach
	return cfg
}

// TestBuildTerminalSurfacesGating pins the decoupled per-surface enablement:
// the attach host is wired on [terminal.attach].enabled ALONE and the dashboard
// launch manager on [handoff].allow_dashboard_launch ALONE — independently. The
// headline row is "gate off, attach on": attach must still serve (WP-A goal).
func TestBuildTerminalSurfacesGating(t *testing.T) {
	if !termsession.PTYSupported() {
		t.Skip("no in-process PTY backend on this OS — buildTerminalStack returns nil")
	}
	cases := []struct {
		name        string
		allowLaunch bool
		attach      bool
		wantLaunch  bool
		wantAttach  bool
	}{
		// The decoupling under test: dashboard-launch gate OFF, attach ON → the
		// attach host still serves, and no launch manager is wired.
		{"gate off, attach on", false, true, false, true},
		{"gate on, attach off", true, false, true, false},
		{"both on", true, true, true, true},
		{"both off", false, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			surfaces, err := buildTerminalSurfaces(context.Background(), surfaceTestConfig(tc.allowLaunch, tc.attach), openStackTestDB(t), slog.Default(), nil)
			if err != nil {
				t.Fatalf("buildTerminalSurfaces: %v", err)
			}
			t.Cleanup(surfaces.close) // no-op when nothing was built

			if got := surfaces.launchMgr != nil; got != tc.wantLaunch {
				t.Errorf("launchMgr present = %v, want %v", got, tc.wantLaunch)
			}
			// launchStatus tracks the launch surface (it is the dashboard's F4
			// status provider); it is nil whenever the launch manager is nil.
			if surfaces.launchMgr == nil && surfaces.launchStatus != nil {
				t.Errorf("launchStatus must be nil when the launch manager is nil")
			}
			if got := surfaces.attachHost != nil; got != tc.wantAttach {
				t.Errorf("attachHost present = %v, want %v", got, tc.wantAttach)
			}
		})
	}
}

// TestAttachServesWithoutDashboardLaunchGate is WP-A deliverable (a): with the
// dashboard-launch gate OFF and [terminal.attach].enabled ON, the attach socket
// serves (a non-nil host over the shared stack, no launch manager), and a spawn
// round-trip through the host's launch path works. The round-trip uses the
// established fake launcher + PTY-manager stubs (attach_test.go) so no real PTY
// is spawned.
func TestAttachServesWithoutDashboardLaunchGate(t *testing.T) {
	if !termsession.PTYSupported() {
		t.Skip("no in-process PTY backend on this OS")
	}
	// (1) Decoupling: attach is wired off the shared stack even though the
	// dashboard-launch gate is off (so no launch manager exists).
	surfaces, err := buildTerminalSurfaces(context.Background(), surfaceTestConfig(false, true), openStackTestDB(t), slog.Default(), nil)
	if err != nil {
		t.Fatalf("buildTerminalSurfaces: %v", err)
	}
	t.Cleanup(surfaces.close)
	if surfaces.launchMgr != nil {
		t.Fatal("launch manager must be nil when [handoff].allow_dashboard_launch is off")
	}
	if surfaces.attachHost == nil {
		t.Fatal("attach host must serve when [terminal.attach].enabled is on, regardless of the launch gate")
	}

	// (2) Spawn round-trip over a host built the same way, with the fake
	// launcher/PTY-manager idiom (a real spawn would fork a process). A
	// grounded, subcommand-matched request must return a live Session.
	host := newAttachHost(
		&fakeAttachLauncher{res: termsvc.LaunchResult{Handle: "H1", RunID: "R1"}},
		successAttachMgr{},
		nil,
	)
	sess, err := host.LaunchAttachable(context.Background(), attachsock.SpawnRequest{Tool: "claude-code", Subcommand: "claude"})
	if err != nil {
		t.Fatalf("LaunchAttachable round-trip: %v", err)
	}
	if sess.Handle() != "H1" || sess.RunID() != "R1" {
		t.Errorf("round-trip session = (handle %q, run %q), want (H1, R1)", sess.Handle(), sess.RunID())
	}
	// NB: do not Detach here — successAttachMgr hands back a zero-value lease
	// whose Release would deref a nil session (the stub never drives a real
	// PTY). The Session's Handle/RunID above already prove the round-trip.
}

// TestAttachDisabledNoHost is WP-A deliverable (b): with [terminal.attach].
// enabled OFF, no attach host is built (start.go then serves no socket and
// prints the honest-disabled message naming the exact config key). The launch
// surface is unaffected.
func TestAttachDisabledNoHost(t *testing.T) {
	if !termsession.PTYSupported() {
		t.Skip("no in-process PTY backend on this OS")
	}
	surfaces, err := buildTerminalSurfaces(context.Background(), surfaceTestConfig(true, false), openStackTestDB(t), slog.Default(), nil)
	if err != nil {
		t.Fatalf("buildTerminalSurfaces: %v", err)
	}
	t.Cleanup(surfaces.close)
	if surfaces.attachHost != nil {
		t.Error("attach host must be nil when [terminal.attach].enabled is off — no socket is served")
	}
	if surfaces.launchMgr == nil {
		t.Error("the launch surface must be unaffected by the attach gate")
	}
}

// TestTerminalStackSharesOneManager is WP-A deliverable (c): with BOTH surfaces
// enabled, the dashboard launch manager and the attach host are derived off the
// SAME termsession.Manager + termsvc.Service — exactly one PTY stack per daemon
// (the one-owner invariant, CLAUDE.md #4). Asserted by pointer identity.
func TestTerminalStackSharesOneManager(t *testing.T) {
	if !termsession.PTYSupported() {
		t.Skip("no in-process PTY backend on this OS")
	}
	stack, err := buildTerminalStack(context.Background(), surfaceTestConfig(true, true), openStackTestDB(t), slog.Default(), nil)
	if err != nil {
		t.Fatalf("buildTerminalStack: %v", err)
	}
	if stack == nil {
		t.Fatal("expected a stack on a PTY-capable OS")
	}
	t.Cleanup(stack.close)

	lm := stack.launchManager()
	host, ok := stack.attachHost().(*attachHost)
	if !ok {
		t.Fatalf("attachHost() returned %T, want *attachHost", stack.attachHost())
	}

	// One Manager: the launch adapter, the attach host, and the stack all point
	// at the same *termsession.Manager.
	hostMgr, ok := host.mgr.(*termsession.Manager)
	if !ok {
		t.Fatalf("attach host mgr is %T, want *termsession.Manager", host.mgr)
	}
	if lm.mgr != stack.mgr || hostMgr != stack.mgr {
		t.Errorf("Manager identity split: launch=%p attach=%p stack=%p — must all be one", lm.mgr, hostMgr, stack.mgr)
	}

	// One Service: same for the termsvc.Service behind both surfaces.
	hostSvc, ok := host.svc.(*termsvc.Service)
	if !ok {
		t.Fatalf("attach host svc is %T, want *termsvc.Service", host.svc)
	}
	if lm.svc != stack.svc || hostSvc != stack.svc {
		t.Errorf("Service identity split: launch=%p attach=%p stack=%p — must all be one", lm.svc, hostSvc, stack.svc)
	}
}
