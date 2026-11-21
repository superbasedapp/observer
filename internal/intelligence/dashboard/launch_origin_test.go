package dashboard

import (
	"context"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// TestTerminalLaunchRecordsOrigin pins lane cli-2 on the dashboard: a
// launch asks Options.LaunchCaller with the connection's two ends and its
// answer reaches the launch spec (an agent's is held instead,
// TestAgentDashboardLaunchIsHeldUntilAHumanConfirms); with no resolver wired the launch is
// recorded unknown (fixes-1, audit M2 (b)).
func TestTerminalLaunchRecordsOrigin(t *testing.T) {
	t.Run("resolver answers", func(t *testing.T) {
		lm := &fakeLaunchManager{}
		database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = database.Close() })
		var sawClient netip.AddrPort
		s, err := New(Options{DB: database, LaunchManager: lm, LaunchCaller: func(_ context.Context, client, _ netip.AddrPort) (string, string) {
			sawClient = client
			return "human_dashboard", ""
		}})
		if err != nil {
			t.Fatal(err)
		}
		rec := postGUILaunch(t, s.Handler(), terminalLaunchRequest{Tool: "claude-code"})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
		}
		if !sawClient.IsValid() {
			t.Fatal("the resolver was not given the connection's client end")
		}
		if lm.lastFreshSpec.Initiator != "human_dashboard" {
			t.Fatalf("fresh spec origin = %q/%q", lm.lastFreshSpec.Initiator, lm.lastFreshSpec.ParentSessionID)
		}
	})
	t.Run("no resolver is unknown, never a human", func(t *testing.T) {
		lm := &fakeLaunchManager{}
		s := newLaunchTestServer(t, lm)
		rec := postGUILaunch(t, s.Handler(), terminalLaunchRequest{Tool: "claude-code"})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
		}
		if lm.lastFreshSpec.Initiator != "unknown" || lm.lastFreshSpec.ParentSessionID != "" {
			t.Fatalf("fresh spec origin = %q/%q", lm.lastFreshSpec.Initiator, lm.lastFreshSpec.ParentSessionID)
		}
	})
}
