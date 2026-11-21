package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/shiptoken"
)

const (
	landTokA = "cst_aaaaaaaaaaaaaaaaaaaaaaaa"
	landTokB = "cst_bbbbbbbbbbbbbbbbbbbbbbbb"
)

// TestLandCloudSessionSourceFileIsSynthetic pins ledger CLOUDSESS-12 at the
// landing seam: whatever source_file a sandbox claims (a UNC share, a home
// secret file, a Windows path), the stored row carries the synthetic
// cloud-session key, so no node reader can be pointed at it.
func TestLandCloudSessionSourceFileIsSynthetic(t *testing.T) {
	ctx := context.Background()
	s, db := newTestStore(t)
	planted := []string{
		`\\attacker.example@SSL\share\a.jsonl`,
		"//attacker.example/share/a.jsonl",
		"/home/me/.codex/auth.json",
		`C:\Users\me\.codex\auth.json`,
	}
	env := orgcontract.PushEnvelope{Sessions: []orgcontract.SessionRow{{ID: "cse-src", Tool: "claude-code"}}}
	for i, p := range planted {
		env.Actions = append(env.Actions, orgcontract.ActionRow{
			SessionID: "cse-src", SourceEventID: fmt.Sprintf("e%d", i), SourceFile: p,
			Timestamp: "2026-10-31T10:00:01Z", Tool: "claude-code", ActionType: "read_file", Success: true,
		})
		env.TokenUsage = append(env.TokenUsage, orgcontract.TokenUsageRow{
			SessionID: "cse-src", SourceEventID: fmt.Sprintf("t%d", i), SourceFile: p,
			Timestamp: "2026-10-31T10:00:02Z", Tool: "claude-code", Model: "claude-sonnet-4", InputTokens: 1, Source: "jsonl", Reliability: "approximate",
		})
	}
	res, err := s.LandCloudSessionEnvelope(ctx, shiptoken.Admit(env, shiptoken.Binding{}).Envelope, landTokA)
	if err != nil || res.Ingest.ActionsInserted != len(planted) || res.Ingest.TokensInserted != len(planted) {
		t.Fatalf("land %+v %v", res, err)
	}
	rows, err := db.Query(`SELECT source_file FROM actions WHERE session_id = 'cse-src'
	                        UNION ALL SELECT source_file FROM token_usage WHERE session_id = 'cse-src'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			t.Fatal(err)
		}
		n++
		if !strings.HasPrefix(f, shiptoken.CloudSourcePrefix) {
			t.Errorf("stored source_file %q is not the synthetic key", f)
		}
		for _, p := range planted {
			if strings.Contains(f, p) {
				t.Errorf("stored source_file %q keeps the sandbox path %q", f, p)
			}
		}
	}
	if n != 2*len(planted) {
		t.Fatalf("%d rows, want %d", n, 2*len(planted))
	}
	// The handoff substrate (handoffsvc, MCP get_session_message) lists no
	// readable transcript for the session.
	sub, err := s.LoadHandoffSubstrate(ctx, "cse-src")
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.SourceFiles) != 0 {
		t.Fatalf("handoff source files %v", sub.SourceFiles)
	}
}

// TestLandCloudSessionSkipsSessionsItDidNotCreate pins ledger CLOUDSESS-8:
// a batch that names a session the node captured itself, or one another
// token created, writes nothing into it (no rows, no project move, no
// execution stamp, no tag), while its own new session lands.
func TestLandCloudSessionSkipsSessionsItDidNotCreate(t *testing.T) {
	ctx := context.Background()
	s, db := newTestStore(t)
	if _, err := s.Ingest(ctx, []models.ToolEvent{{
		Tool: models.ToolClaudeCode, SourceFile: "/home/me/.claude/projects/x/local-1.jsonl", SourceEventID: "l1",
		SessionID: "local-1", ProjectRoot: "/home/me/repo", Timestamp: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC),
		ActionType: models.ActionRunCommand, Target: "ls", RawToolName: "Bash", Success: true,
	}}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	var projectBefore int64
	if err := db.QueryRow(`SELECT project_id FROM sessions WHERE id = 'local-1'`).Scan(&projectBefore); err != nil {
		t.Fatal(err)
	}
	// A session another token created.
	other := orgcontract.PushEnvelope{
		Sessions: []orgcontract.SessionRow{{ID: "cse-other", Tool: "claude-code"}},
		Actions:  []orgcontract.ActionRow{{SessionID: "cse-other", SourceEventID: "o1", Timestamp: "2026-10-31T10:00:00Z", Tool: "claude-code", ActionType: "read_file", Success: true}},
	}
	if _, err := s.LandCloudSessionEnvelope(ctx, other, landTokB); err != nil {
		t.Fatal(err)
	}

	env := orgcontract.PushEnvelope{
		Sessions: []orgcontract.SessionRow{
			{ID: "local-1", Tool: "claude-code", GitRemote: "git@github.com:evil/repo.git", ExecutionLocation: "vendor_cloud", VendorSessionRef: "cse_EVIL"},
			{ID: "cse-other", Tool: "claude-code", ExecutionLocation: "vendor_cloud"},
			{ID: "cse-mine", Tool: "claude-code"},
		},
		Actions: []orgcontract.ActionRow{
			{SessionID: "local-1", SourceEventID: "f1", Timestamp: "2026-10-31T10:00:01Z", Tool: "claude-code", ActionType: "run_command", Target: "rm -rf /", Success: true},
			{SessionID: "cse-other", SourceEventID: "f2", Timestamp: "2026-10-31T10:00:01Z", Tool: "claude-code", ActionType: "run_command", Success: true},
			{SessionID: "cse-mine", SourceEventID: "m1", Timestamp: "2026-10-31T10:00:01Z", Tool: "claude-code", ActionType: "read_file", Success: true},
		},
		TokenUsage: []orgcontract.TokenUsageRow{
			{SessionID: "local-1", SourceEventID: "ft1", Timestamp: "2026-10-31T10:00:02Z", Tool: "claude-code", Model: "claude-sonnet-4", InputTokens: 999999, Source: "jsonl", Reliability: "approximate"},
		},
	}
	res, err := s.LandCloudSessionEnvelope(ctx, shiptoken.Admit(env, shiptoken.Binding{}).Envelope, landTokA)
	if err != nil {
		t.Fatal(err)
	}
	if res.SkippedSessions[shiptoken.SessionSkipLocal] != 1 || res.SkippedSessions[shiptoken.SessionSkipOtherToken] != 1 {
		t.Fatalf("skipped sessions %+v", res.SkippedSessions)
	}
	if res.SkippedRows["sessions"] != 2 || res.SkippedRows["actions"] != 2 || res.SkippedRows["token_usage"] != 1 {
		t.Fatalf("skipped rows %+v", res.SkippedRows)
	}
	if res.Ingest.ActionsInserted != 1 || res.Ingest.TokensInserted != 0 || res.Tagged != 1 || res.Stamped != 0 {
		t.Fatalf("result %+v", res)
	}
	var actions, tokens int
	_ = db.QueryRow(`SELECT COUNT(*) FROM actions WHERE session_id = 'local-1'`).Scan(&actions)
	_ = db.QueryRow(`SELECT COUNT(*) FROM token_usage WHERE session_id = 'local-1'`).Scan(&tokens)
	if actions != 1 || tokens != 0 {
		t.Fatalf("local session now has %d actions, %d token rows; want 1 and 0", actions, tokens)
	}
	var projectAfter int64
	_ = db.QueryRow(`SELECT project_id FROM sessions WHERE id = 'local-1'`).Scan(&projectAfter)
	if projectAfter != projectBefore {
		t.Fatalf("local session moved from project %d to %d", projectBefore, projectAfter)
	}
	if ex, err := s.LoadSessionExecution(ctx, "local-1"); err != nil || ex.ExecutionLocation != "" || ex.VendorSessionRef != "" {
		t.Fatalf("local session stamped %+v %v", ex, err)
	}
	for sid, want := range map[string]string{"local-1": "", "cse-other": landTokB, "cse-mine": landTokA} {
		if via, _ := s.SessionReportedVia(ctx, sid); via != want {
			t.Errorf("%s reported via %q, want %q", sid, via, want)
		}
	}
	var otherActions int
	_ = db.QueryRow(`SELECT COUNT(*) FROM actions WHERE session_id = 'cse-other'`).Scan(&otherActions)
	if otherActions != 1 {
		t.Fatalf("another token's session has %d actions, want 1", otherActions)
	}
}

// TestLandCloudSessionVolumeCap pins the node volume cap: a batch that
// would take the token past its cap is refused whole, the remaining
// capacity is reported, and another token has its own cap.
func TestLandCloudSessionVolumeCap(t *testing.T) {
	ctx := context.Background()
	s, db := newTestStore(t)
	prev := cloudSessionRowCap
	cloudSessionRowCap = 5
	t.Cleanup(func() { cloudSessionRowCap = prev })

	batch := func(sid string, from, n int) orgcontract.PushEnvelope {
		env := orgcontract.PushEnvelope{Sessions: []orgcontract.SessionRow{{ID: sid, Tool: "claude-code"}}}
		for i := from; i < from+n; i++ {
			env.Actions = append(env.Actions, orgcontract.ActionRow{
				SessionID: sid, SourceEventID: fmt.Sprintf("e%d", i), Timestamp: "2026-10-31T10:00:01Z",
				Tool: "claude-code", ActionType: "read_file", Success: true,
			})
		}
		return env
	}
	cases := []struct {
		name      string
		tok       string
		env       orgcontract.PushEnvelope
		exhausted bool
		remaining int64
	}{
		{"three rows of five", landTokA, batch("cap-a", 0, 3), false, 2},
		{"a re-send counts no new rows", landTokA, batch("cap-a", 0, 2), false, 2},
		{"three more would pass the cap", landTokA, batch("cap-a", 3, 3), true, 2},
		{"exactly the remaining two", landTokA, batch("cap-a", 3, 2), false, 0},
		{"one more is refused", landTokA, batch("cap-a", 5, 1), true, 0},
		{"another token has its own cap", landTokB, batch("cap-b", 0, 5), false, 0},
	}
	for _, tc := range cases {
		res, err := s.LandCloudSessionEnvelope(ctx, tc.env, tc.tok)
		var ex ShipTokenVolumeExhaustedError
		switch {
		case tc.exhausted:
			if !errors.As(err, &ex) || ex.Remaining != tc.remaining || ex.Cap != 5 {
				t.Fatalf("%s: err %v (%+v), want exhausted with %d left", tc.name, err, ex, tc.remaining)
			}
		case err != nil:
			t.Fatalf("%s: %v", tc.name, err)
		case res.RowsRemaining != tc.remaining:
			t.Fatalf("%s: %d remaining, want %d", tc.name, res.RowsRemaining, tc.remaining)
		}
	}
	var a int
	_ = db.QueryRow(`SELECT COUNT(*) FROM actions WHERE session_id = 'cap-a'`).Scan(&a)
	if a != 5 {
		t.Fatalf("token A landed %d rows, want its cap of 5", a)
	}
}

// TestActiveShipTokenChecksIgnoreTheListCap pins finding 4 of the ingest
// review: the route gate, the per-environment lookup and the mint cap read
// every active token, not the 200-row display list, so a long mint/revoke
// history cannot hide an active token.
func TestActiveShipTokenChecksIgnoreTheListCap(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	insert := func(label string, created time.Time, revoked bool) CloudSessionShipToken {
		t.Helper()
		m, err := shiptoken.Generate(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tok := CloudSessionShipToken{TokenID: m.ID, TokenHash: m.Hash, Label: label, CreatedAt: created, ExpiresAt: now.Add(time.Hour)}
		if err := s.InsertCloudSessionShipToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
		if revoked {
			if _, err := s.RevokeCloudSessionShipToken(ctx, tok.TokenID, created); err != nil {
				t.Fatal(err)
			}
		}
		return tok
	}
	// The oldest rows are the active ones; 210 newer revoked rows push
	// them out of the display list.
	old := now.Add(-48 * time.Hour)
	held := insert("held env", old, false)
	for i := 1; i < MaxActiveCloudSessionShipTokens; i++ {
		insert(fmt.Sprintf("env %d", i), old.Add(time.Duration(i)*time.Second), false)
	}
	for i := 0; i < 210; i++ {
		insert(fmt.Sprintf("churn %d", i), now.Add(-time.Duration(210-i)*time.Minute), true)
	}
	list, err := s.ListCloudSessionShipTokens(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range list {
		if tk.Status(now) == shiptoken.StatusActive {
			t.Fatal("test setup: an active token is still inside the display list")
		}
	}
	if ok, err := s.HasActiveCloudSessionShipToken(ctx, now); err != nil || !ok {
		t.Fatalf("route gate: %v %v, want active", ok, err)
	}
	if got, ok, err := s.ActiveCloudSessionShipTokenForEnvironment(ctx, "HELD ENV", now); err != nil || !ok || got.TokenID != held.TokenID {
		t.Fatalf("environment lookup %+v %v %v", got, ok, err)
	}
	var heldErr ShipTokenEnvironmentHeldError
	if _, err := s.MintCloudSessionShipToken(ctx, rand.Reader, "held env", 0, now); !errors.As(err, &heldErr) {
		t.Fatalf("mint for a held environment: %v", err)
	}
	if _, err := s.MintCloudSessionShipToken(ctx, rand.Reader, "a new env", 0, now); !errors.Is(err, ErrShipTokenTooMany) {
		t.Fatalf("mint past the active cap: %v", err)
	}
	// At and after expiry, and once revoked, nothing is active.
	if ok, _ := s.HasActiveCloudSessionShipToken(ctx, now.Add(time.Hour)); ok {
		t.Fatal("an expired token still counts as active")
	}
}
