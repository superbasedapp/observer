package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/turnmerge"
)

// TestMergeTurnByRequestIDNeverInserts pins D6 / F10: a Plane A span only
// enriches an existing api_turns row and never creates one, and a legacy
// Plane A row is never touched (so a merge cannot relabel it into a source
// the Plane B push would ship).
func TestMergeTurnByRequestIDNeverInserts(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	seed := []models.APITurn{
		{RequestID: "req-proxy", Source: SourceProxy, Provider: "anthropic", Model: "m", InputTokens: 900, OutputTokens: 90, CostUSD: 0.5, Timestamp: now},
		{RequestID: "req-agent", Source: SourceAgentOTel, Provider: "anthropic", Model: "m", InputTokens: 10, OutputTokens: 1, Timestamp: now},
		{RequestID: "req-legacy", Source: SourceObsOTLP, Provider: "anthropic", Model: "m", InputTokens: 10, OutputTokens: 1, Timestamp: now},
	}
	for _, r := range seed {
		if _, err := s.InsertAPITurn(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name, req, wantSrc string
		wantAction         turnmerge.Action
		wantRows           int
		wantInput          int64
	}{
		{"no row: nothing is inserted", "req-none", "", turnmerge.ActionNoChange, 0, 0},
		{"proxy row: exact tokens win, source kept", "req-proxy", SourceProxy, turnmerge.ActionNoChange, 1, 900},
		{"own-agent row (equal rank): tokens never raised (R-A14)", "req-agent", SourceAgentOTel, turnmerge.ActionNoChange, 1, 10},
		{"legacy Plane A row: untouched", "req-legacy", SourceObsOTLP, turnmerge.ActionNoChange, 1, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			act, _, err := s.MergeTurnByRequestID(ctx, models.APITurn{
				RequestID: tc.req, Source: SourceObsOTLP, Provider: "anthropic", Model: "m", InputTokens: 50, OutputTokens: 5,
			})
			if err != nil {
				t.Fatal(err)
			}
			if act != tc.wantAction {
				t.Errorf("action = %v, want %v", act, tc.wantAction)
			}
			var n int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_turns WHERE request_id = ?`, tc.req).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != tc.wantRows {
				t.Fatalf("rows = %d, want %d", n, tc.wantRows)
			}
			if n == 0 {
				return
			}
			var src string
			var in int64
			if err := db.QueryRowContext(ctx, `SELECT COALESCE(source,''), input_tokens FROM api_turns WHERE request_id = ?`, tc.req).Scan(&src, &in); err != nil {
				t.Fatal(err)
			}
			if src != tc.wantSrc || in != tc.wantInput {
				t.Errorf("row = (%q, %d), want (%q, %d)", src, in, tc.wantSrc, tc.wantInput)
			}
		})
	}

	// An empty request id has no dedup key and must not insert either.
	if _, _, err := s.MergeTurnByRequestID(ctx, models.APITurn{Source: SourceObsSDK, InputTokens: 1}); err != nil {
		t.Fatal(err)
	}
	var total int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_turns`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != len(seed) {
		t.Errorf("api_turns rows = %d, want %d (merge-only must never insert)", total, len(seed))
	}
}

// TestPlaneATurnsNeverPushed pins the Plane A discriminator on the api_turns
// push (F10): a legacy Plane A row stays on the node but never ships, in the
// cursor lane or the eligible count, under any share mode.
func TestPlaneATurnsNeverPushed(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, r := range []models.APITurn{
		{RequestID: "req-proxy", Source: SourceProxy, Provider: "anthropic", Model: "m", InputTokens: 1, Timestamp: now},
		{RequestID: "req-otlp", Source: SourceObsOTLP, Provider: "anthropic", Model: "m", InputTokens: 1, Timestamp: now},
		{RequestID: "req-sdk", Source: SourceObsSDK, Provider: "anthropic", Model: "m", InputTokens: 1, Timestamp: now},
	} {
		if _, err := s.InsertAPITurn(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	for _, share := range []ShareOptions{{}, {FullContent: true}, {AdminManaged: true}} {
		b, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@acme.example", share, ScopeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(b.APITurns) != 1 || b.APITurns[0].RequestID != "req-proxy" {
			got := make([]string, 0, len(b.APITurns))
			for _, r := range b.APITurns {
				got = append(got, r.RequestID)
			}
			t.Errorf("share %+v: pushed api_turns = %v, want [req-proxy]", share, got)
		}
	}
	c, err := s.PushEligibleCounts(ctx, PushCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if c.APITurns != 1 {
		t.Errorf("eligible api_turns = %d, want 1", c.APITurns)
	}
}

func TestIsPlaneATurnSource(t *testing.T) {
	t.Parallel()
	for src, want := range map[string]bool{
		SourceObsOTLP: true, SourceObsSDK: true,
		SourceProxy: false, SourceCCOTel: false, SourceAgentOTel: false, "": false,
	} {
		if got := IsPlaneATurnSource(src); got != want {
			t.Errorf("IsPlaneATurnSource(%q) = %v, want %v", src, got, want)
		}
	}
	if got, want := PlaneATurnSourceSQL("t"), "COALESCE(t.source,'') IN ('sdk_otlp','otlp_trace')"; got != want {
		t.Errorf("PlaneATurnSourceSQL = %q, want %q", got, want)
	}
}
