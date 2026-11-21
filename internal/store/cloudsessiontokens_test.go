package store

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/shiptoken"
)

func TestCloudSessionShipTokens(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

	if ok, err := s.HasActiveCloudSessionShipToken(ctx, now); err != nil || ok {
		t.Fatalf("fresh node has an active token: %v %v", ok, err)
	}
	m, _ := shiptoken.Generate(rand.Reader)
	tok := CloudSessionShipToken{TokenID: m.ID, TokenHash: m.Hash, Label: "laptop via tailscale", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.InsertCloudSessionShipToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertCloudSessionShipToken(ctx, CloudSessionShipToken{TokenID: "bad", TokenHash: "x"}); err == nil {
		t.Fatal("a malformed row was accepted")
	}
	if ok, _ := s.HasActiveCloudSessionShipToken(ctx, now); !ok {
		t.Fatal("no active token after mint")
	}
	if ok, _ := s.HasActiveCloudSessionShipToken(ctx, now.Add(time.Hour)); ok {
		t.Fatal("an expired token still counts as active")
	}
	got, err := s.CloudSessionShipTokenByHash(ctx, shiptoken.Hash(m.Token))
	if err != nil || got.TokenID != m.ID || got.Label != tok.Label || got.Status(now) != shiptoken.StatusActive {
		t.Fatalf("by hash = %+v, %v", got, err)
	}
	if _, err := s.CloudSessionShipTokenByHash(ctx, shiptoken.Hash("other")); !errors.Is(err, ErrShipTokenNotFound) {
		t.Fatalf("unknown hash: %v", err)
	}
	if err := s.TouchCloudSessionShipToken(ctx, m.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	ok, err := s.RevokeCloudSessionShipToken(ctx, m.ID, now.Add(2*time.Minute))
	if err != nil || !ok {
		t.Fatalf("revoke = %v %v", ok, err)
	}
	if ok, err := s.RevokeCloudSessionShipToken(ctx, m.ID, now); err != nil || ok {
		t.Fatalf("second revoke = %v %v", ok, err)
	}
	if _, err := s.RevokeCloudSessionShipToken(ctx, "cst_000000000000000000000000", now); !errors.Is(err, ErrShipTokenNotFound) {
		t.Fatalf("unknown revoke: %v", err)
	}
	list, _ := s.ListCloudSessionShipTokens(ctx)
	if len(list) != 1 || list[0].UseCount != 1 || list[0].Status(now) != shiptoken.StatusRevoked {
		t.Fatalf("list = %+v", list)
	}
	if ok, _ := s.HasActiveCloudSessionShipToken(ctx, now); ok {
		t.Fatal("a revoked token still counts as active")
	}
}

func TestLandCloudSessionEnvelope(t *testing.T) {
	ctx := context.Background()
	s, db := newTestStore(t)
	// A local checkout of the repository the cloud session worked on.
	if _, err := s.UpsertProject(ctx, "/home/me/repo", "github.com/acme/repo"); err != nil {
		t.Fatal(err)
	}
	env := orgcontract.PushEnvelope{
		Sessions: []orgcontract.SessionRow{
			{
				ID: "cse-1", Tool: "claude-code", GitRemote: "git@github.com:acme/repo.git", GitBranch: "claude/x",
				ProjectRoot: "/home/user/repo", ExecutionLocation: "vendor_cloud", VendorSessionRef: "cse_01ABC",
			},
			{ID: "cse-2", Tool: "claude-code", ProjectRoot: "/home/user/other"},
		},
		Actions: []orgcontract.ActionRow{
			{SessionID: "cse-1", SourceEventID: "e1", Timestamp: "2026-10-31T10:00:01Z", Tool: "claude-code", ActionType: "read_file", Target: "a.go", Success: true},
			{SessionID: "cse-2", SourceEventID: "e2", Timestamp: "2026-10-31T10:00:02Z", Tool: "claude-code", ActionType: "run_command", Success: true},
		},
		TokenUsage: []orgcontract.TokenUsageRow{
			{SessionID: "cse-1", SourceEventID: "t1", Timestamp: "2026-10-31T10:00:03Z", Tool: "claude-code", Model: "claude-sonnet-4", InputTokens: 100, OutputTokens: 20, Source: "jsonl", Reliability: "approximate"},
		},
		APITurns: []orgcontract.APITurnRow{{SessionID: "cse-1"}},
	}
	adm := shiptoken.Admit(env, shiptoken.Binding{})
	const tokA, tokB = "cst_aaaaaaaaaaaaaaaaaaaaaaaa", "cst_bbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := s.LandCloudSessionEnvelope(ctx, adm.Envelope, "not-a-token-id"); err == nil {
		t.Fatal("landing without a ship token id must fail")
	}
	res, err := s.LandCloudSessionEnvelope(ctx, adm.Envelope, tokA)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ingest.ActionsInserted != 2 || res.Ingest.TokensInserted != 1 || res.Stamped != 1 || res.Tagged != 2 {
		t.Fatalf("result %+v", res)
	}
	if res.Projects[shiptoken.ProjectFromRemote] != 1 || res.Projects[shiptoken.ProjectUnattributed] != 1 || res.NotLanded["api_turns"] != 1 {
		t.Fatalf("result %+v", res)
	}
	var root string
	if err := db.QueryRow(`SELECT p.root_path FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = 'cse-1'`).Scan(&root); err != nil {
		t.Fatal(err)
	}
	if root != "/home/me/repo" {
		t.Fatalf("cloud session filed under %q, want the local checkout", root)
	}
	if err := db.QueryRow(`SELECT p.root_path FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = 'cse-2'`).Scan(&root); err != nil {
		t.Fatal(err)
	}
	if root != shiptoken.UnattributedCloudRoot {
		t.Fatalf("unresolved session filed under %q", root)
	}
	ex, err := s.LoadSessionExecution(ctx, "cse-1")
	if err != nil || ex.ExecutionLocation != "vendor_cloud" || ex.VendorSessionRef != "cse_01ABC" {
		t.Fatalf("execution %+v %v", ex, err)
	}
	var sandboxRoots int
	_ = db.QueryRow(`SELECT COUNT(*) FROM projects WHERE root_path LIKE '/home/user/%'`).Scan(&sandboxRoots)
	if sandboxRoots != 0 {
		t.Fatal("a sandbox filesystem root became a node project")
	}
	// CA-D18: both sessions are tagged sandbox-reported with the token id.
	for _, sid := range []string{"cse-1", "cse-2"} {
		if via, err := s.SessionReportedVia(ctx, sid); err != nil || via != tokA {
			t.Fatalf("%s reported via %q (%v), want %q", sid, via, err, tokA)
		}
	}
	// Idempotent re-send under the same token lands nothing new.
	res, err = s.LandCloudSessionEnvelope(ctx, adm.Envelope, tokA)
	if err != nil || res.Ingest.ActionsInserted != 0 || res.Tagged != 0 || len(res.SkippedSessions) != 0 {
		t.Fatalf("same-token re-send %+v %v", res, err)
	}
	// Under another token: both sessions belong to tokA, so the batch is
	// skipped whole (ledger CLOUDSESS-8) and the first tag stands.
	res, err = s.LandCloudSessionEnvelope(ctx, adm.Envelope, tokB)
	if err != nil || res.Ingest.ActionsInserted != 0 || res.Stamped != 0 || res.Tagged != 0 {
		t.Fatalf("re-send %+v %v", res, err)
	}
	if res.SkippedSessions[shiptoken.SessionSkipOtherToken] != 2 || res.SkippedRows["actions"] != 2 || res.SkippedRows["token_usage"] != 1 {
		t.Fatalf("other-token re-send skipped %+v / %+v", res.SkippedSessions, res.SkippedRows)
	}
	if via, _ := s.SessionReportedVia(ctx, "cse-1"); via != tokA {
		t.Fatalf("re-tagged to %q", via)
	}
	var actions, tokens int
	_ = db.QueryRow(`SELECT COUNT(*) FROM actions WHERE session_id IN ('cse-1','cse-2')`).Scan(&actions)
	_ = db.QueryRow(`SELECT COUNT(*) FROM token_usage WHERE session_id = 'cse-1'`).Scan(&tokens)
	if actions != 2 || tokens != 1 {
		t.Fatalf("after re-send: %d actions, %d token rows; want 2 and 1", actions, tokens)
	}
}

// TestCloudSessionShipTokenEnvironmentAndActive pins the per-environment
// lookup and the active-secret check the node OTLP receiver uses (CA-D18,
// CLOUDTEL-1).
func TestCloudSessionShipTokenEnvironmentAndActive(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	m, err := shiptoken.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InsertCloudSessionShipToken(ctx, CloudSessionShipToken{
		TokenID: m.ID, TokenHash: m.Hash, Label: "Web Env", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.ActiveCloudSessionShipTokenForEnvironment(ctx, " web env ", now); err != nil || !ok || got.TokenID != m.ID {
		t.Fatalf("environment lookup %+v %v %v", got, ok, err)
	}
	cases := []struct {
		name   string
		secret string
		at     time.Time
		want   bool
	}{
		{"the active secret", m.Token, now, true},
		{"malformed", "not-a-token", now, false},
		{"unknown", "sbocs_" + strings.Repeat("A", 43), now, false},
		{"expired", m.Token, now.Add(2 * time.Hour), false},
	}
	for _, tc := range cases {
		if _, ok, err := s.ActiveCloudSessionShipToken(ctx, tc.secret, tc.at); err != nil || ok != tc.want {
			t.Errorf("%s: ok=%v err=%v, want %v", tc.name, ok, err, tc.want)
		}
	}
	if _, err := s.RevokeCloudSessionShipToken(ctx, m.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ActiveCloudSessionShipToken(ctx, m.Token, now); ok {
		t.Fatal("a revoked secret is still accepted")
	}
}
