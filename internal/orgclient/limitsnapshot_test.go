package orgclient

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestPushOnce_SessionLimitSnapshots drives the lane F-WIRE per-session
// rate-limit window wire through the real push loop: the linked window ships
// on the envelope, and a later tick whose only news is UNSHIPPABLE snapshots
// (no linked session) pushes nothing yet still persists the cursor past them,
// so an idle node does not re-scan them forever and a long unshippable run
// cannot pin the wire below a later shippable window.
func TestPushOnce_SessionLimitSnapshots(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}
	srv, env := capturePushServer(t)
	bindPub(srv, enrolFixture(t, s, bs, srv.URL))
	ctx := context.Background()

	cfg := config.OrgClientConfig{
		Enabled: true, PushIntervalSeconds: config.DefaultPushIntervalSeconds,
		MaxPushBytes: config.DefaultMaxPushBytes, KeychainID: config.DefaultKeychainID,
		Share: config.OrgClientShareConfig{FullContent: true},
	}
	seedFreshAction(t, s, "limit-a") // session s1, claude-code
	util := 0.37
	if err := s.InsertLimitSnapshot(ctx, models.LimitSnapshot{
		ScopeHash: "scope-secret", Provider: "anthropic", SessionID: "s1",
		ObservedAt: time.Unix(1790000000, 0).UTC(), Window5hUtil: &util, Status: "allowed",
	}); err != nil {
		t.Fatalf("InsertLimitSnapshot: %v", err)
	}
	if r, err := New(cfg, s, bs, "test-version", http.DefaultClient, quietLogger()).PushOnce(ctx); err != nil || r.Empty {
		t.Fatalf("PushOnce: res=%+v err=%v", r, err)
	}
	if len(env.SessionLimitSnapshots) != 1 {
		t.Fatalf("envelope carried %d session limit rows, want 1", len(env.SessionLimitSnapshots))
	}
	if r := env.SessionLimitSnapshots[0]; r.SessionID != "s1" || r.Tool != models.ToolClaudeCode ||
		r.Provider != "anthropic" || r.Window5hUtil == nil || *r.Window5hUtil != 0.37 {
		t.Fatalf("row = %+v, want the s1 claude-code anthropic window", r)
	}

	// Only unshippable snapshots arrive: no session id, and a session the
	// node has never seen.
	for _, sid := range []string{"", "ghost-session", ""} {
		if err := s.InsertLimitSnapshot(ctx, models.LimitSnapshot{
			ScopeHash: "scope-secret", Provider: "anthropic", SessionID: sid,
			ObservedAt: time.Unix(1790000100, 0).UTC(), Window5hUtil: &util,
		}); err != nil {
			t.Fatalf("InsertLimitSnapshot: %v", err)
		}
	}
	head, err := s.CurrentMaxIDs(ctx)
	if err != nil {
		t.Fatalf("CurrentMaxIDs: %v", err)
	}
	*env = orgcontract.PushEnvelope{AgentVersion: "untouched"}
	r, err := New(cfg, s, bs, "test-version", http.DefaultClient, quietLogger()).PushOnce(ctx)
	if err != nil {
		t.Fatalf("PushOnce 2: %v", err)
	}
	if !r.Empty || env.AgentVersion != "untouched" {
		t.Fatalf("a tick with only unshippable snapshots pushed: res=%+v env.agent_version=%q", r, env.AgentVersion)
	}
	cur, err := s.LoadPushCursor(ctx)
	if err != nil {
		t.Fatalf("LoadPushCursor: %v", err)
	}
	if cur.LimitSnapshots != head.LimitSnapshots {
		t.Fatalf("cursor = %d, want %d: the empty tick must persist progress past unshippable rows",
			cur.LimitSnapshots, head.LimitSnapshots)
	}
}
