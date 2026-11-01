//go:build !sbo_omit_security

package store

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// TestLoadChangeFactsApprovedAsks: an ask or deny a person approved, or an
// org grant exempted, is counted as an approved ask (lane SEC-F2B); a plain
// ask is not.
func TestLoadChangeFactsApprovedAsks(t *testing.T) {
	t.Parallel()
	s, projectID, _ := ownershipFixture(t)
	ctx := context.Background()
	for i, row := range []struct{ decision, degraded string }{
		{"ask", ""}, {"flag", "approved"}, {"flag", "org_grant"}, {"deny", ""},
	} {
		var degraded any
		if row.degraded != "" {
			degraded = row.degraded
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO guard_events (ts, session_id, rule_id, decision, degraded_from, chain_prev, chain_hash)
			VALUES ('2026-10-23T00:00:00Z', 'sA', 'S-791', ?, ?, '', ?)`, row.decision, degraded, strings.Repeat("0", 63)+string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
	f, skip, err := s.LoadChangeFacts(ctx, projectID, strings.Repeat("a", 64), "c1sha", 0)
	if err != nil || skip != "" {
		t.Fatalf("skip %q err %v", skip, err)
	}
	if f.GuardEvents != 4 || f.GuardAsks != 1 || f.GuardDenies != 1 || f.GuardApprovedAsks != 2 {
		t.Fatalf("guard counts %d events %d asks %d denies %d approved", f.GuardEvents, f.GuardAsks, f.GuardDenies, f.GuardApprovedAsks)
	}
}

// TestLoadBoxChangeFacts: a commit a sandbox box returned names the run's
// correlated sessions (confidence floor held) and is skipped when the run
// has none.
func TestLoadBoxChangeFacts(t *testing.T) {
	t.Parallel()
	s, projectID, _ := ownershipFixture(t)
	ctx := context.Background()
	for _, r := range []struct {
		session string
		conf    float64
	}{{"sA", 0.9}, {"sB", 0.2}} {
		if _, err := s.db.ExecContext(ctx, `INSERT INTO terminal_run_session (run_id, session_id, confidence, source, observed_at)
			VALUES ('run-1', ?, ?, 'oob', '2026-10-23T00:00:00Z')`, r.session, r.conf); err != nil {
			t.Fatal(err)
		}
	}
	bc := BoxCommit{SHA: "boxsha", Files: []ChangeFileFacts{{PathHash: "ph", RelPath: "b.go", Added: 3}}}
	f, skip, err := s.LoadBoxChangeFacts(ctx, projectID, strings.Repeat("a", 64), "run-1", bc)
	if err != nil || skip != "" {
		t.Fatalf("skip %q err %v", skip, err)
	}
	if strings.Join(f.Sessions, ",") != "sA" || len(f.Files) != 1 || len(f.Tools) == 0 {
		t.Fatalf("box facts %+v", f)
	}
	if _, skip, _ := s.LoadBoxChangeFacts(ctx, projectID, "h", "run-none", bc); skip != ChangeSkipNotOwned {
		t.Fatalf("a run with no session: skip %q", skip)
	}
}

// TestChangeWireEnvelope: the envelope rides the wire row unless its
// payload holds a shape-certain secret the text gate cannot see through
// base64 (lane SEC-F2B).
func TestChangeWireEnvelope(t *testing.T) {
	mk := func(payload string) []byte {
		return []byte(`{"payloadType":"application/vnd.superbased.change-record.v1+json","payload":"` +
			base64.StdEncoding.EncodeToString([]byte(payload)) + `","signatures":[{"keyid":"k","sig":"AA=="}]}`)
	}
	if got := changeWireEnvelope(mk(`{"models":["claude-opus"]}`)); got == "" {
		t.Fatal("a clean envelope was left out")
	}
	if got := changeWireEnvelope(mk(`{"models":["ghp_Zq8mWv3TnR6yKp2LsX9uBd4HjF7cGe1NwQ"]}`)); got != "" {
		t.Fatalf("an envelope carrying a secret shipped: %s", got)
	}
	if changeWireEnvelope([]byte("not json")) != "" || changeWireEnvelope(nil) != "" {
		t.Fatal("a malformed envelope shipped")
	}
}
