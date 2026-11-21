package store

import (
	"context"
	"testing"
	"time"
)

// TestGuardRegistersShipOnAManagedNode pins G2 (managed policy visibility,
// 2026-11-12) and review finding 3: a managed node ships its guard approval
// and pin registers whole whatever its content posture (a managed node ships
// full content), so a pin row's Name always agrees with its PinKey; an
// individual node without raw content ships neither.
func TestGuardRegistersShipOnAManagedNode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tc := range []struct {
		name      string
		share     ShareOptions
		wantRows  int
		wantGrant string
	}{
		{"managed, no raw content", ShareOptions{Managed: true}, 1, "alice@example.com"},
		{"managed, raw content", ShareOptions{Managed: true, FullContent: true}, 1, "alice@example.com"},
		{"individual, raw content", ShareOptions{FullContent: true}, 1, "alice@example.com"},
		{"individual, no raw content", ShareOptions{}, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			now := time.Now().UTC()
			if _, err := s.InsertGuardApproval(ctx, GuardApprovalRow{
				TS: now, RuleID: "R-101", Scope: "session",
				SessionID: "sess-1", GrantedBy: "alice@example.com",
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.UpsertGuardPin(ctx, GuardPinRow{
				Kind: "mcp_server", Name: "github", Client: "claude-code",
				PinHash: "deadbeef", FirstSeen: now, LastVerified: now, Status: "pinned",
			}); err != nil {
				t.Fatal(err)
			}
			batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@acme.example", tc.share, ScopeOptions{})
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			if len(batch.GuardApprovals) != tc.wantRows || len(batch.GuardPins) != tc.wantRows {
				t.Fatalf("shipped %d approvals and %d pins, want %d each", len(batch.GuardApprovals), len(batch.GuardPins), tc.wantRows)
			}
			if tc.wantRows == 0 {
				return
			}
			a := batch.GuardApprovals[0]
			if a.RuleID != "R-101" || a.Scope != "session" || a.GrantedBy != tc.wantGrant {
				t.Fatalf("approval = %+v", a)
			}
			p := batch.GuardPins[0]
			if p.Name != "github" || p.PinKey != guardPinKey(p.Kind, p.Name, p.Client) {
				t.Fatalf("pin name %q and key %q disagree", p.Name, p.PinKey)
			}
		})
	}
}
